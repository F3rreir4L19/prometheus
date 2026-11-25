//! Passive domain selection. Discovery hints carry no inventory completeness or scope authority.

mod collectors;
pub use collectors::{parse_crtsh, parse_subfinder, ProviderCandidates, MAX_PROVIDER_BYTES};

use std::collections::BTreeSet;

use domain::{Action, Decision, ScopeSnapshotId};
use scope_engine::{canonicalize_domain, ScopeEngine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_INVENTORY_BYTES: usize = 1024 * 1024;
pub const MAX_DISCOVERY_BYTES: usize = 24 * 1024 * 1024;
const MAX_INVENTORY_RECORDS: usize = 50_000;
const MAX_DISCOVERY_RECORDS: usize = 250_000;
const MAX_DOMAIN_INPUT_BYTES: usize = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PassiveInputError {
    #[error("passive input exceeds the byte limit")]
    ByteLimit,
    #[error("passive input exceeds the record limit")]
    RecordLimit,
    #[error("invalid discovery index JSON")]
    InvalidIndex,
    #[error("invalid passive provider JSON")]
    InvalidProvider,
    #[error("passive input requires the current valid snapshot")]
    InactiveSnapshot,
}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct SelectionCounts {
    pub allowed: usize,
    pub denied: usize,
    pub unknown: usize,
    pub duplicates: usize,
    pub malformed: usize,
}

pub struct InventorySelection {
    pub domains: Vec<String>,
    pub counts: SelectionCounts,
}

pub struct DiscoverySelection {
    candidates: Vec<String>,
    pub counts: SelectionCounts,
}

impl DiscoverySelection {
    pub fn candidates(&self) -> &[String] {
        &self.candidates
    }
}

/// Select concrete domains from one UTF-8 hostname per line. Invalid lines are counted without
/// retaining their original bytes. The caller can then mark the run partial.
pub fn filter_inventory(
    input: &[u8],
    engine: &ScopeEngine,
    active_snapshot: &ScopeSnapshotId,
    now: u64,
) -> Result<InventorySelection, PassiveInputError> {
    if input.len() > MAX_INVENTORY_BYTES {
        return Err(PassiveInputError::ByteLimit);
    }
    let mut selector = Selector::new(engine, active_snapshot, now)?;
    selector.read_lines(input, MAX_INVENTORY_RECORDS)?;
    Ok(InventorySelection {
        domains: selector.domains.into_iter().collect(),
        counts: selector.counts,
    })
}

/// Re-evaluate every well-formed candidate against the current passive policy. The parser's
/// count preserves malformed input without passing raw provider output to storage or logging.
pub fn filter_live_candidates(
    candidates: &[String],
    malformed: usize,
    engine: &ScopeEngine,
    active_snapshot: &ScopeSnapshotId,
    now: u64,
) -> Result<InventorySelection, PassiveInputError> {
    if candidates.len() > MAX_INVENTORY_RECORDS {
        return Err(PassiveInputError::RecordLimit);
    }
    let mut selector = Selector::new(engine, active_snapshot, now)?;
    selector.counts.malformed = malformed;
    for candidate in candidates {
        selector.consider(candidate);
    }
    Ok(InventorySelection {
        domains: selector.domains.into_iter().collect(),
        counts: selector.counts,
    })
}

/// Accept `bounty-targets-data`'s line-oriented `domains.txt` or its HackerOne JSON array.
/// Only literal hostnames enter the result. A URL, wildcard, or unrelated metadata field is
/// never expanded into a hostname.
pub fn filter_discovery_index(
    input: &[u8],
    engine: &ScopeEngine,
    active_snapshot: &ScopeSnapshotId,
    now: u64,
) -> Result<DiscoverySelection, PassiveInputError> {
    if input.len() > MAX_DISCOVERY_BYTES {
        return Err(PassiveInputError::ByteLimit);
    }
    let mut selector = Selector::new(engine, active_snapshot, now)?;
    if input.trim_ascii_start().starts_with(b"[") {
        let programs: Vec<IndexProgram> =
            serde_json::from_slice(input).map_err(|_| PassiveInputError::InvalidIndex)?;
        let mut targets = programs
            .into_iter()
            .flat_map(|program| program.targets.in_scope);
        for target in targets.by_ref().take(MAX_DISCOVERY_RECORDS) {
            if matches!(target.asset_type.as_str(), "URL" | "DOMAIN") {
                selector.consider(&target.asset_identifier);
            }
        }
        if targets.next().is_some() {
            return Err(PassiveInputError::RecordLimit);
        }
    } else {
        selector.read_lines(input, MAX_DISCOVERY_RECORDS)?;
    }
    Ok(DiscoverySelection {
        candidates: selector.domains.into_iter().collect(),
        counts: selector.counts,
    })
}

#[derive(Deserialize)]
struct IndexProgram {
    targets: IndexTargets,
}

#[derive(Deserialize)]
struct IndexTargets {
    in_scope: Vec<IndexTarget>,
}

#[derive(Deserialize)]
struct IndexTarget {
    asset_type: String,
    asset_identifier: String,
}

struct Selector<'a> {
    engine: &'a ScopeEngine,
    snapshot: &'a ScopeSnapshotId,
    now: u64,
    domains: BTreeSet<String>,
    counts: SelectionCounts,
}

impl<'a> Selector<'a> {
    fn new(
        engine: &'a ScopeEngine,
        active_snapshot: &'a ScopeSnapshotId,
        now: u64,
    ) -> Result<Self, PassiveInputError> {
        let snapshot = engine.snapshot();
        if &snapshot.id != active_snapshot
            || !(snapshot.valid_from..snapshot.expires_at).contains(&now)
        {
            return Err(PassiveInputError::InactiveSnapshot);
        }
        Ok(Self {
            engine,
            snapshot: active_snapshot,
            now,
            domains: BTreeSet::new(),
            counts: SelectionCounts::default(),
        })
    }

    fn read_lines(&mut self, input: &[u8], max_records: usize) -> Result<(), PassiveInputError> {
        let mut records = 0;
        for line in input.split(|byte| *byte == b'\n').map(<[u8]>::trim_ascii) {
            if line.is_empty() || line.starts_with(b"#") {
                continue;
            }
            records += 1;
            if records > max_records {
                return Err(PassiveInputError::RecordLimit);
            }
            match std::str::from_utf8(line) {
                Ok(line) => self.consider(line),
                Err(_) => self.counts.malformed += 1,
            }
        }
        Ok(())
    }

    fn consider(&mut self, raw: &str) {
        if raw.len() > MAX_DOMAIN_INPUT_BYTES {
            self.counts.malformed += 1;
            return;
        }
        let Some(domain) = canonicalize_domain(raw) else {
            self.counts.malformed += 1;
            return;
        };
        match self
            .engine
            .evaluate(self.snapshot, self.now, Action::Passive, &domain)
            .decision
        {
            Decision::Allow => {
                if self.domains.insert(domain) {
                    self.counts.allowed += 1;
                } else {
                    self.counts.duplicates += 1;
                }
            }
            Decision::Deny => self.counts.denied += 1,
            Decision::Unknown => self.counts.unknown += 1,
        }
    }
}

#[cfg(test)]
mod tests;
