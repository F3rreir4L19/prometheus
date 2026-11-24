//! Offline deterministic authorization over an explicitly selected immutable snapshot.

mod target;

use std::collections::HashSet;

use domain::{Action, Decision, Effect, ScopeRule, ScopeSnapshot, ScopeSnapshotId, ScopeSource};
use serde::{Deserialize, Serialize};
use target::{Matcher, Target};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("invalid scope document")]
    InvalidDocument,
    #[error("unsupported scope document version")]
    UnsupportedVersion,
    #[error("invalid snapshot metadata or source")]
    InvalidSnapshot,
    #[error("invalid rule at index {0}")]
    InvalidRule(usize),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    snapshot: ScopeSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    RuleAllow,
    RuleDeny,
    NoMatchingRule,
    MalformedTarget,
    InactiveSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Verdict<'a> {
    pub decision: Decision,
    pub reason: Reason,
    pub rule_id: Option<&'a str>,
}

impl Verdict<'_> {
    pub fn is_allowed(&self) -> bool {
        self.decision == Decision::Allow
    }

    pub fn malformed() -> Self {
        Self::new(Decision::Unknown, Reason::MalformedTarget, None)
    }

    fn new(decision: Decision, reason: Reason, rule_id: Option<&str>) -> Verdict<'_> {
        Verdict {
            decision,
            reason,
            rule_id,
        }
    }
}

#[derive(Debug)]
struct CompiledRule {
    rule: ScopeRule,
    matcher: Matcher,
}

#[derive(Debug)]
pub struct ScopeEngine {
    snapshot_id: ScopeSnapshotId,
    valid_from: u64,
    expires_at: u64,
    source_hash: blake3::Hash,
    rules: Vec<CompiledRule>,
}

impl ScopeEngine {
    /// Import the versioned reviewed document. JSON is accepted as a subset of YAML.
    pub fn from_yaml(input: &[u8]) -> Result<Self, ScopeError> {
        let document: Document =
            serde_yaml::from_slice(input).map_err(|_| ScopeError::InvalidDocument)?;
        if document.version != 1 {
            return Err(ScopeError::UnsupportedVersion);
        }
        let snapshot = document.snapshot;
        if snapshot.source != ScopeSource::ManualReviewed
            || !valid_id(&snapshot.id.0)
            || !valid_id(&snapshot.program_id.0)
            || snapshot.valid_from >= snapshot.expires_at
            || snapshot
                .supersedes_id
                .is_some_and(|previous| previous == snapshot.id || !valid_id(&previous.0))
        {
            return Err(ScopeError::InvalidSnapshot);
        }

        let mut ids = HashSet::new();
        let mut rules = Vec::with_capacity(snapshot.rules.len());
        for (index, rule) in snapshot.rules.into_iter().enumerate() {
            if !valid_id(&rule.id.0) || !ids.insert(rule.id.clone()) || rule.actions.is_empty() {
                return Err(ScopeError::InvalidRule(index));
            }
            let matcher =
                Matcher::compile(rule.kind, &rule.target).ok_or(ScopeError::InvalidRule(index))?;
            rules.push(CompiledRule { rule, matcher });
        }
        Ok(Self {
            snapshot_id: snapshot.id,
            valid_from: snapshot.valid_from,
            expires_at: snapshot.expires_at,
            source_hash: blake3::hash(input),
            rules,
        })
    }

    pub fn snapshot_id(&self) -> &ScopeSnapshotId {
        &self.snapshot_id
    }

    pub fn source_hash(&self) -> blake3::Hash {
        self.source_hash
    }

    /// The caller supplies the job snapshot ID and loads this engine from the active revision.
    pub fn evaluate(
        &self,
        job_snapshot: &ScopeSnapshotId,
        now: u64,
        action: Action,
        raw: &str,
    ) -> Verdict<'_> {
        if job_snapshot != &self.snapshot_id || !(self.valid_from..self.expires_at).contains(&now) {
            return Verdict::new(Decision::Unknown, Reason::InactiveSnapshot, None);
        }
        let Some(target) = Target::parse(raw) else {
            return Verdict::malformed();
        };
        let mut allowed = None;
        for CompiledRule { rule, matcher } in &self.rules {
            if rule.actions.contains(&action)
                && matcher.matches(&target, rule.effect == Effect::Deny)
            {
                let id = Some(rule.id.0.as_str());
                match rule.effect {
                    Effect::Deny => return Verdict::new(Decision::Deny, Reason::RuleDeny, id),
                    Effect::Allow => allowed = allowed.or(id),
                }
            }
        }
        if allowed.is_some() {
            Verdict::new(Decision::Allow, Reason::RuleAllow, allowed)
        } else {
            Verdict::new(Decision::Unknown, Reason::NoMatchingRule, None)
        }
    }

    /// Validate an absolute URL independently at each hop. Relative locations require mediation.
    pub fn evaluate_redirect_hop(
        &self,
        job_snapshot: &ScopeSnapshotId,
        now: u64,
        action: Action,
        location: &str,
    ) -> Verdict<'_> {
        if matches!(Target::parse(location), Some(Target::Url(_))) {
            self.evaluate(job_snapshot, now, action, location)
        } else {
            Verdict::malformed()
        }
    }
}

pub fn canonicalize_target(input: &str) -> Option<String> {
    Target::parse(input).map(|target| target.canonical())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
