use std::collections::BTreeSet;

use domain::{
    Action, AssetId, CollectionCompleteness, DeltaDetected, DeltaKind, ObservationId, ToolRunId,
};
use scope_engine::{canonicalize_domain, ScopeEngine};
use sqlx::{SqliteConnection, SqlitePool};

use crate::{
    publication::{load_published_head, publication_event_id},
    stable_id, StorageError,
};

pub const MAX_INVENTORY_DOMAINS: usize = 10_000;
const MAX_RUN_DELTAS: usize = 20_000;
const INVENTORY_COLLECTOR: &str = "local_inventory";
const INVENTORY_VERSION: &str = "1";
// SHA-256 of the identity of the built-in inventory reader contract, `prometheus:local-inventory:v1`.
const INVENTORY_CONTRACT_SHA256: &str =
    "2124136efdc206bc4ec931fcfa9a95c13f8f75070de7a6941a6b54f51489fdbe";

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

/// Revalidate a normalized local inventory and commit it against the same published head.
/// An exact retry returns the original deltas. Collection time must increase per program.
pub async fn record_passive_run(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    input: PassiveRunInput<'_>,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<PassiveRunResult, StorageError> {
    let snapshot = engine.snapshot();
    let validity = snapshot.valid_from..snapshot.expires_at;
    if input.run_key.is_empty()
        || input.run_key.len() > 128
        || !input
            .run_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(StorageError::InvalidRunKey);
    }
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
    let run_id = stable_id(
        "tool-run",
        &[&snapshot.program_id.0, INVENTORY_COLLECTOR, input.run_key],
    );
    let completeness = match input.completeness {
        CollectionCompleteness::Complete => "complete",
        CollectionCompleteness::Partial => "partial",
    };
    let input_hash = blake3::hash(&serde_json::to_vec(&(
        digest.as_str(),
        input.observed_at,
        completeness,
        &canonical_domains,
    ))?)
    .to_hex();

    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let now = clock()?;
    if !validity.contains(&now) {
        return Err(StorageError::InactiveScope);
    }
    if !validity.contains(&input.observed_at) || input.observed_at > now {
        return Err(StorageError::InvalidObservationTime);
    }
    let now_sql = i64::try_from(now)?;
    let head = load_published_head(&mut tx, &snapshot.program_id.0).await?;
    let head = head
        .filter(|head| head.id == snapshot.id.0 && head.source_hash == digest.as_str())
        .ok_or(StorageError::InactiveScope)?;
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

    let last_observed_at: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(observed_at) FROM passive_runs WHERE program_id = ? AND collector = ?",
    )
    .bind(&snapshot.program_id.0)
    .bind(INVENTORY_COLLECTOR)
    .fetch_one(&mut *tx)
    .await?;
    if last_observed_at.is_some_and(|last| observed_at_sql <= last) {
        return Err(StorageError::NonMonotonicRun);
    }

    let write = InventoryWrite {
        engine,
        run_id: &run_id,
        observed_at: input.observed_at,
        observed_at_sql,
    };
    write
        .write_tool_run(&mut tx, now_sql, completeness, canonical_domains.len())
        .await?;
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
    .bind(&head.id)
    .bind(INVENTORY_COLLECTOR)
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

struct InventoryWrite<'a> {
    engine: &'a ScopeEngine,
    run_id: &'a str,
    observed_at: u64,
    observed_at_sql: i64,
}

impl InventoryWrite<'_> {
    async fn write_tool_run(
        &self,
        connection: &mut SqliteConnection,
        now_sql: i64,
        completeness: &str,
        present_count: usize,
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
        .bind(now_sql)
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
        let metadata = serde_json::json!({
            "completeness": completeness,
            "present_count": present_count,
            "sha256_subject": "built_in_inventory_contract"
        });
        sqlx::query(
            "INSERT INTO tool_runs (
                 id, job_id, tool, tool_version, tool_sha256, scope_snapshot_id,
                 policy_decision_id, started_at, finished_at, exit_metadata_json
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?8, ?8, ?9)",
        )
        .bind(self.run_id)
        .bind(&job_id)
        .bind(INVENTORY_COLLECTOR)
        .bind(INVENTORY_VERSION)
        .bind(INVENTORY_CONTRACT_SHA256)
        .bind(snapshot_id)
        .bind(&decision_id)
        .bind(now_sql)
        .bind(metadata.to_string())
        .execute(&mut *connection)
        .await?;
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
        .bind(INVENTORY_COLLECTOR)
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
        .bind(INVENTORY_COLLECTOR)
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
            .bind(INVENTORY_COLLECTOR)
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
        .bind(INVENTORY_COLLECTOR)
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
