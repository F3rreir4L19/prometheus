use std::collections::BTreeSet;

use domain::{
    Action, AssetId, CollectionCompleteness, DeltaDetected, DeltaKind, ObservationId,
    PassiveSource, ToolRunId,
};
use scope_engine::{canonicalize_domain, ScopeEngine};
use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};

use crate::{
    publication::{load_published_head, publication_event_id},
    stable_id, StorageError,
};

pub const MAX_INVENTORY_DOMAINS: usize = 10_000;
const MAX_RUN_DELTAS: usize = 20_000;
const INVENTORY_VERSION: &str = "1";
// SHA-256 of the identity of the built-in inventory reader contract, `prometheus:local-inventory:v1`.
const INVENTORY_CONTRACT_SHA256: &str =
    "2124136efdc206bc4ec931fcfa9a95c13f8f75070de7a6941a6b54f51489fdbe";
// SHA-256 of the built-in CT reader identity, `prometheus:crtsh:v1`.
const CRTSH_CONTRACT_SHA256: &str =
    "5b8678a3ea0cb89dbc32ea4ad1288a18fe3a273974601de813c6e275fc526030";
// SHA-256 of the local test reader identity, `prometheus:crtsh-loopback:v1`.
const CRTSH_LOOPBACK_CONTRACT_SHA256: &str =
    "ee5cb53c54b5489940d154bdcfb5192556f08ff9a903fe105e72ed213701d1e2";

#[derive(Clone, Copy)]
pub struct PassiveRunInput<'a> {
    pub run_key: &'a str,
    pub observed_at: u64,
    pub completeness: CollectionCompleteness,
    pub domains: &'a [String],
}

#[derive(Debug, Eq, PartialEq)]
pub struct PassiveRunResult {
    pub run_id: ToolRunId,
    pub deltas: Vec<DeltaDetected>,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveRunAudit {
    pub denied: usize,
    pub unknown: usize,
    pub malformed: usize,
    pub duplicates: usize,
    pub failed_collections: usize,
}

#[derive(Clone, Copy)]
pub enum LiveTool<'a> {
    Crtsh,
    CrtshLoopback,
    Subfinder { version: &'a str, sha256: &'a str },
}

impl LiveTool<'_> {
    pub(crate) fn source(self) -> PassiveSource {
        match self {
            Self::Crtsh => PassiveSource::Crtsh,
            Self::CrtshLoopback => PassiveSource::CrtshLoopback,
            Self::Subfinder { .. } => PassiveSource::Subfinder,
        }
    }

    pub(crate) fn validate(self) -> Result<(), StorageError> {
        if let Self::Subfinder { version, sha256 } = self {
            if version.is_empty()
                || version.len() > 64
                || !version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-+".contains(&byte))
                || sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(StorageError::InvalidCollector);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct LiveRunProvenance<'a> {
    pub tool: LiveTool<'a>,
    pub started_at: u64,
    pub audit: LiveRunAudit,
}

pub struct LiveRunReplay {
    pub result: PassiveRunResult,
    pub audit: LiveRunAudit,
    pub present_count: usize,
}

pub(crate) fn validate_run_key(run_key: &str) -> Result<(), StorageError> {
    if run_key.is_empty()
        || run_key.len() > 128
        || !run_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(StorageError::InvalidRunKey);
    }
    Ok(())
}

pub(crate) fn run_id(engine: &ScopeEngine, collector: &str, run_key: &str) -> String {
    stable_id(
        "tool-run",
        &[&engine.snapshot().program_id.0, collector, run_key],
    )
}

pub(crate) async fn ensure_published_head(
    connection: &mut SqliteConnection,
    engine: &ScopeEngine,
    now: u64,
) -> Result<(), StorageError> {
    let snapshot = engine.snapshot();
    if !(snapshot.valid_from..snapshot.expires_at).contains(&now) {
        return Err(StorageError::InactiveScope);
    }
    let digest = engine.source_hash().to_hex();
    load_published_head(connection, &snapshot.program_id.0)
        .await?
        .filter(|head| head.id == snapshot.id.0 && head.source_hash == digest.as_str())
        .ok_or(StorageError::InactiveScope)?;
    Ok(())
}

/// Revalidate a normalized local inventory and commit it against the same published head.
/// An exact retry returns the original deltas. Collection time must increase per program.
pub async fn record_passive_run(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    input: PassiveRunInput<'_>,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<PassiveRunResult, StorageError> {
    write_passive_run(pool, engine, input, None, clock).await
}

/// Persist only affirmative observations from a passive provider. The current head, scope digest,
/// and every hostname are revalidated under the SQLite write lock.
pub async fn record_collector_run(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    input: PassiveRunInput<'_>,
    provenance: LiveRunProvenance<'_>,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<PassiveRunResult, StorageError> {
    if input.completeness != CollectionCompleteness::Partial
        || engine.snapshot().passive_live.is_none()
    {
        return Err(StorageError::InvalidCollector);
    }
    provenance.tool.validate()?;
    write_passive_run(pool, engine, input, Some(provenance), clock).await
}

/// A live run key identifies a capture. Reusing it recovers the original result without dispatch.
pub async fn replay_collector_run(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    source: PassiveSource,
    run_key: &str,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<Option<LiveRunReplay>, StorageError> {
    if source == PassiveSource::Fixture || engine.snapshot().passive_live.is_none() {
        return Err(StorageError::InvalidCollector);
    }
    validate_run_key(run_key)?;
    let id = run_id(engine, source.as_str(), run_key);
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    ensure_published_head(&mut tx, engine, clock()?).await?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT r.scope_snapshot_id, r.deltas_json, t.exit_metadata_json FROM passive_runs r
         JOIN tool_runs t ON t.id = r.id WHERE r.id = ?",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((snapshot_id, deltas, metadata)) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    if snapshot_id != engine.snapshot_id().0 {
        return Err(StorageError::RunCollision);
    }
    #[derive(Deserialize)]
    struct Metadata {
        present_count: usize,
        audit: LiveRunAudit,
    }
    let metadata: Metadata = serde_json::from_str(&metadata)?;
    let deltas = serde_json::from_str(&deltas)?;
    ensure_published_head(&mut tx, engine, clock()?).await?;
    tx.commit().await?;
    Ok(Some(LiveRunReplay {
        result: PassiveRunResult {
            run_id: ToolRunId(id),
            deltas,
            replayed: true,
        },
        audit: metadata.audit,
        present_count: metadata.present_count,
    }))
}

pub async fn last_collector_observed_at(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    source: PassiveSource,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<Option<u64>, StorageError> {
    if source == PassiveSource::Fixture || engine.snapshot().passive_live.is_none() {
        return Err(StorageError::InvalidCollector);
    }
    let mut tx = pool.begin().await?;
    ensure_published_head(&mut tx, engine, clock()?).await?;
    let last = last_observed_at(&mut tx, &engine.snapshot().program_id.0, source.as_str()).await?;
    tx.commit().await?;
    last.map(u64::try_from)
        .transpose()
        .map_err(StorageError::from)
}

async fn last_observed_at(
    connection: &mut SqliteConnection,
    program: &str,
    collector: &str,
) -> Result<Option<i64>, StorageError> {
    Ok(sqlx::query_scalar(
        "SELECT MAX(observed_at) FROM passive_runs WHERE program_id = ? AND collector = ?",
    )
    .bind(program)
    .bind(collector)
    .fetch_one(connection)
    .await?)
}

async fn write_passive_run(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    input: PassiveRunInput<'_>,
    live: Option<LiveRunProvenance<'_>>,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<PassiveRunResult, StorageError> {
    let snapshot = engine.snapshot();
    let validity = snapshot.valid_from..snapshot.expires_at;
    validate_run_key(input.run_key)?;
    if input.domains.len() > MAX_INVENTORY_DOMAINS {
        return Err(StorageError::InventoryLimit);
    }
    let canonical_domains: BTreeSet<_> = input
        .domains
        .iter()
        .map(|domain| canonicalize_domain(domain).ok_or(StorageError::UnauthorizedDomain))
        .collect::<Result<_, _>>()?;
    let digest = engine.source_hash().to_hex();
    let observed_at_sql = i64::try_from(input.observed_at)?;
    let source = live.map_or(PassiveSource::Fixture, |run| run.tool.source());
    let collector = source.as_str();
    let run_id = run_id(engine, collector, input.run_key);
    let completeness = match input.completeness {
        CollectionCompleteness::Complete => "complete",
        CollectionCompleteness::Partial => "partial",
    };
    let fixture_input = (
        digest.as_str(),
        input.observed_at,
        completeness,
        &canonical_domains,
    );
    let provenance = ToolProvenance::from_tool(live.map(|run| run.tool));
    let input_bytes = match live {
        Some(run) => serde_json::to_vec(&(
            fixture_input,
            run.started_at,
            run.audit,
            provenance.version,
            provenance.sha256,
        ))?,
        None => serde_json::to_vec(&fixture_input)?,
    };
    let input_hash = blake3::hash(&input_bytes).to_hex();

    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let now = clock()?;
    ensure_published_head(&mut tx, engine, now).await?;
    let started_at = live.map_or(now, |run| run.started_at);
    if !validity.contains(&input.observed_at) || input.observed_at > started_at || started_at > now
    {
        return Err(StorageError::InvalidObservationTime);
    }
    let now_sql = i64::try_from(now)?;
    if canonical_domains.iter().any(|domain| {
        !engine
            .evaluate(&snapshot.id, now, Action::Passive, domain)
            .is_allowed()
    }) {
        return Err(StorageError::UnauthorizedDomain);
    }

    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT input_hash, deltas_json FROM passive_runs WHERE id = ?")
            .bind(&run_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((existing_hash, deltas_json)) = existing {
        if existing_hash != input_hash.as_str() {
            return Err(StorageError::RunCollision);
        }
        let deltas = serde_json::from_str(&deltas_json)?;
        if !validity.contains(&clock()?) {
            return Err(StorageError::InactiveScope);
        }
        tx.commit().await?;
        return Ok(PassiveRunResult {
            run_id: ToolRunId(run_id),
            deltas,
            replayed: true,
        });
    }

    let last_observed_at = last_observed_at(&mut tx, &snapshot.program_id.0, collector).await?;
    if last_observed_at.is_some_and(|last| observed_at_sql <= last) {
        return Err(StorageError::NonMonotonicRun);
    }

    let write = InventoryWrite {
        engine,
        run_id: &run_id,
        collector,
        observed_at: input.observed_at,
        observed_at_sql,
    };
    let metadata = provenance.metadata(
        completeness,
        canonical_domains.len(),
        live.map(|run| run.audit),
    );
    write
        .write_tool_run(
            &mut tx,
            (i64::try_from(started_at)?, now_sql),
            provenance,
            &metadata,
        )
        .await?;
    if let Some(run) = live {
        write
            .write_candidate_audit(&mut tx, now_sql, run.audit)
            .await?;
    }
    let mut deltas = Vec::new();
    if let Some(event) = write.first_run_scope_change(&mut tx).await? {
        deltas.push(event);
    }
    for domain in &canonical_domains {
        if let Some(delta) = write.record_presence(&mut tx, domain).await? {
            deltas.push(delta);
        }
    }
    if input.completeness == CollectionCompleteness::Complete {
        write
            .record_absences(&mut tx, &canonical_domains, now, &mut deltas)
            .await?;
    }
    sqlx::query(
        "INSERT INTO passive_runs (
             id, program_id, scope_snapshot_id, collector, observed_at, input_hash, completeness, deltas_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&run_id)
    .bind(&snapshot.program_id.0)
    .bind(&snapshot.id.0)
    .bind(collector)
    .bind(observed_at_sql)
    .bind(input_hash.as_str())
    .bind(completeness)
    .bind(serde_json::to_string(&deltas)?)
    .execute(&mut *tx)
    .await?;
    if !validity.contains(&clock()?) {
        return Err(StorageError::InactiveScope);
    }
    tx.commit().await?;
    Ok(PassiveRunResult {
        run_id: ToolRunId(run_id),
        deltas,
        replayed: false,
    })
}

pub(crate) struct ToolProvenance<'a> {
    pub(crate) version: &'a str,
    pub(crate) sha256: &'a str,
    pub(crate) sha256_subject: &'static str,
}

impl<'a> ToolProvenance<'a> {
    pub(crate) fn from_tool(tool: Option<LiveTool<'a>>) -> Self {
        match tool {
            None => Self {
                version: INVENTORY_VERSION,
                sha256: INVENTORY_CONTRACT_SHA256,
                sha256_subject: "built_in_inventory_contract",
            },
            Some(LiveTool::Crtsh) => Self {
                version: "1",
                sha256: CRTSH_CONTRACT_SHA256,
                sha256_subject: "built_in_crtsh_contract",
            },
            Some(LiveTool::CrtshLoopback) => Self {
                version: "1",
                sha256: CRTSH_LOOPBACK_CONTRACT_SHA256,
                sha256_subject: "built_in_crtsh_loopback_contract",
            },
            Some(LiveTool::Subfinder { version, sha256 }) => Self {
                version,
                sha256,
                sha256_subject: "manifest_binary_pin",
            },
        }
    }

    fn metadata(
        &self,
        completeness: &str,
        present_count: usize,
        audit: Option<LiveRunAudit>,
    ) -> String {
        let mut metadata = serde_json::json!({
            "completeness": completeness,
            "present_count": present_count,
            "sha256_subject": self.sha256_subject,
        });
        if let Some(audit) = audit {
            metadata["audit"] = serde_json::json!(audit);
        }
        metadata.to_string()
    }
}

struct InventoryWrite<'a> {
    engine: &'a ScopeEngine,
    run_id: &'a str,
    collector: &'a str,
    observed_at: u64,
    observed_at_sql: i64,
}

impl InventoryWrite<'_> {
    async fn write_tool_run(
        &self,
        connection: &mut SqliteConnection,
        times: (i64, i64),
        provenance: ToolProvenance<'_>,
        metadata: &str,
    ) -> Result<(), StorageError> {
        let snapshot_id = &self.engine.snapshot_id().0;
        let job_id = stable_id("inventory-job", &[self.run_id]);
        let decision_id = stable_id("inventory-allow", &[self.run_id]);
        sqlx::query(
            "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision)
             VALUES (?, ?, ?, 'passive_ingest_gate', 'ALLOW')",
        )
        .bind(&decision_id)
        .bind(snapshot_id)
        .bind(times.1)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            "INSERT INTO jobs (id, scope_snapshot_id, action, policy_decision_id)
             VALUES (?, ?, 'passive', ?)",
        )
        .bind(&job_id)
        .bind(snapshot_id)
        .bind(&decision_id)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            "INSERT INTO tool_runs (
                 id, job_id, tool, tool_version, tool_sha256, scope_snapshot_id,
                 policy_decision_id, started_at, finished_at, exit_metadata_json
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(self.run_id)
        .bind(&job_id)
        .bind(self.collector)
        .bind(provenance.version)
        .bind(provenance.sha256)
        .bind(snapshot_id)
        .bind(&decision_id)
        .bind(times.0)
        .bind(times.1)
        .bind(metadata)
        .execute(&mut *connection)
        .await?;
        Ok(())
    }

    async fn write_candidate_audit(
        &self,
        connection: &mut SqliteConnection,
        now: i64,
        audit: LiveRunAudit,
    ) -> Result<(), StorageError> {
        for (decision, count) in [("DENY", audit.denied), ("UNKNOWN", audit.unknown)] {
            if count == 0 {
                continue;
            }
            let details = serde_json::json!({"count": count, "tool_run_id": self.run_id});
            sqlx::query(
                "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision, details_json)
                 VALUES (?, ?, ?, 'passive_candidate_gate', ?, ?)",
            )
            .bind(stable_id("passive-candidate-gate", &[self.run_id, decision]))
            .bind(&self.engine.snapshot_id().0)
            .bind(now)
            .bind(decision)
            .bind(details.to_string())
            .execute(&mut *connection)
            .await?;
        }
        Ok(())
    }

    async fn first_run_scope_change(
        &self,
        connection: &mut SqliteConnection,
    ) -> Result<Option<DeltaDetected>, StorageError> {
        let snapshot_id = self.engine.snapshot_id();
        let delta_json: Option<String> = sqlx::query_scalar(
            "SELECT json_extract(a.details_json, '$.delta') FROM audit_events a
             WHERE a.id = ?1 AND a.scope_snapshot_id = ?2 AND a.event_type = 'scope_changed'
             AND NOT EXISTS (
                 SELECT 1 FROM passive_runs r WHERE r.scope_snapshot_id = ?2 AND r.collector = ?3
             )",
        )
        .bind(publication_event_id(snapshot_id))
        .bind(&snapshot_id.0)
        .bind(self.collector)
        .fetch_optional(connection)
        .await?;
        Ok(delta_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?)
    }

    async fn record_presence(
        &self,
        connection: &mut SqliteConnection,
        domain: &str,
    ) -> Result<Option<DeltaDetected>, StorageError> {
        let program_id = &self.engine.snapshot().program_id.0;
        let existing_asset_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM assets WHERE program_id = ? AND kind = 'host' AND canonical_key = ?",
        )
        .bind(program_id)
        .bind(domain)
        .fetch_optional(&mut *connection)
        .await?;
        let new_asset = existing_asset_id.is_none();
        let asset_id =
            existing_asset_id.unwrap_or_else(|| stable_id("host", &[program_id, domain]));
        let previous: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT status, exact_hash FROM observations WHERE asset_id = ? AND collector = ?
             ORDER BY observed_at DESC, id DESC LIMIT 1",
        )
        .bind(&asset_id)
        .bind(self.collector)
        .fetch_optional(&mut *connection)
        .await?;
        sqlx::query(
            "INSERT INTO assets (id, program_id, kind, canonical_key, first_seen_at, last_seen_at)
             VALUES (?, ?, 'host', ?, ?4, ?4)
             ON CONFLICT (program_id, kind, canonical_key) DO UPDATE SET
                first_seen_at = MIN(first_seen_at, excluded.first_seen_at),
                last_seen_at = MAX(last_seen_at, excluded.last_seen_at)",
        )
        .bind(&asset_id)
        .bind(program_id)
        .bind(domain)
        .bind(self.observed_at_sql)
        .execute(&mut *connection)
        .await?;

        let hash = stable_id("inventory-fact", &[domain, "present"]);
        let observation_id = self
            .write_observation(connection, &asset_id, "present", &hash)
            .await?;
        let kind = if new_asset {
            Some(DeltaKind::NewAsset)
        } else {
            match previous.as_ref() {
                Some((status, _)) if status == "absent" => Some(DeltaKind::ReactivatedAsset),
                Some((status, Some(previous_hash)))
                    if status == "present" && previous_hash != &hash =>
                {
                    Some(DeltaKind::ChangedAsset)
                }
                _ => None,
            }
        };
        match kind {
            Some(kind) => self
                .write_delta(connection, kind, asset_id, observation_id)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn record_absences(
        &self,
        connection: &mut SqliteConnection,
        present: &BTreeSet<String>,
        now: u64,
        deltas: &mut Vec<DeltaDetected>,
    ) -> Result<(), StorageError> {
        let snapshot = self.engine.snapshot();
        let mut cursor = String::new();
        loop {
            let page: Vec<(String, String)> = sqlx::query_as(
                "SELECT a.id, a.canonical_key FROM assets a
                 WHERE a.program_id = ? AND a.kind = 'host' AND a.id > ?
                 AND (SELECT o.status FROM observations o WHERE o.asset_id = a.id AND o.collector = ?
                      ORDER BY o.observed_at DESC, o.id DESC LIMIT 1) = 'present'
                 ORDER BY a.id LIMIT 256",
            )
            .bind(&snapshot.program_id.0)
            .bind(&cursor)
            .bind(self.collector)
            .fetch_all(&mut *connection)
            .await?;
            let Some((last, _)) = page.last() else {
                break;
            };
            cursor.clone_from(last);
            for (asset_id, canonical) in page {
                if present.contains(&canonical)
                    || canonicalize_domain(&canonical).as_deref() != Some(canonical.as_str())
                    || !self
                        .engine
                        .evaluate(&snapshot.id, now, Action::Passive, &canonical)
                        .is_allowed()
                {
                    continue;
                }
                if deltas.len() >= MAX_RUN_DELTAS {
                    return Err(StorageError::DeltaLimit);
                }
                let hash = stable_id("inventory-fact", &[&canonical, "absent"]);
                let observation_id = self
                    .write_observation(connection, &asset_id, "absent", &hash)
                    .await?;
                deltas.push(
                    self.write_delta(connection, DeltaKind::AbsentAsset, asset_id, observation_id)
                        .await?,
                );
            }
        }
        Ok(())
    }

    async fn write_observation(
        &self,
        connection: &mut SqliteConnection,
        asset_id: &str,
        status: &str,
        exact_hash: &str,
    ) -> Result<ObservationId, StorageError> {
        let snapshot = self.engine.snapshot();
        let observation_id = stable_id("inventory-observation", &[self.run_id, asset_id]);
        sqlx::query(
            "INSERT INTO observations (
                 id, program_id, asset_id, scope_snapshot_id, observed_at, collector,
                 status, metadata_json, exact_hash, tool_run_id
             ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)",
        )
        .bind(&observation_id)
        .bind(&snapshot.program_id.0)
        .bind(asset_id)
        .bind(&snapshot.id.0)
        .bind(self.observed_at_sql)
        .bind(self.collector)
        .bind(status)
        .bind(exact_hash)
        .bind(self.run_id)
        .execute(connection)
        .await?;
        Ok(ObservationId(observation_id))
    }

    async fn write_delta(
        &self,
        connection: &mut SqliteConnection,
        kind: DeltaKind,
        asset_id: String,
        observation_id: ObservationId,
    ) -> Result<DeltaDetected, StorageError> {
        let event_id = stable_id("inventory-delta", &[&observation_id.0, kind.as_str()]);
        let delta = DeltaDetected {
            kind,
            scope_snapshot_id: self.engine.snapshot_id().clone(),
            asset_id: Some(AssetId(asset_id)),
            observation_id: Some(observation_id),
            occurred_at: self.observed_at,
        };
        let details = serde_json::json!({"delta": delta, "tool_run_id": self.run_id});
        sqlx::query(
            "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision, details_json)
             VALUES (?, ?, ?, ?, 'ALLOW', ?)",
        )
        .bind(event_id)
        .bind(&delta.scope_snapshot_id.0)
        .bind(self.observed_at_sql)
        .bind(kind.as_str())
        .bind(details.to_string())
        .execute(connection)
        .await?;
        Ok(delta)
    }
}
