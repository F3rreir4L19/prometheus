use domain::{DeltaDetected, DeltaKind, Effect, ScopeSnapshotId, TargetKind};
use scope_engine::ScopeEngine;
use sqlx::{SqliteConnection, SqlitePool};

use crate::{stable_id, StorageError};

#[derive(sqlx::FromRow)]
pub(crate) struct PublishedHead {
    pub(crate) id: String,
    pub(crate) source_hash: String,
    valid_from: i64,
    fetched_at: i64,
}

pub(crate) async fn load_published_head(
    connection: &mut SqliteConnection,
    program_id: &str,
) -> Result<Option<PublishedHead>, StorageError> {
    Ok(sqlx::query_as(
        "SELECT s.id, s.source_hash, s.valid_from, s.fetched_at
         FROM program_scope_heads h JOIN scope_snapshots s
         ON s.id = h.scope_snapshot_id WHERE h.program_id = ?",
    )
    .bind(program_id)
    .fetch_optional(connection)
    .await?)
}

/// Persist the reviewed document and seal its rules before replacing the program's active scope.
pub async fn publish_reviewed_scope(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    clock: impl Fn() -> Result<u64, StorageError>,
) -> Result<Option<DeltaDetected>, StorageError> {
    let snapshot = engine.snapshot();
    let validity = snapshot.valid_from..snapshot.expires_at;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let now = clock()?;
    if !validity.contains(&now) {
        return Err(StorageError::InactiveScope);
    }
    let now_sql = i64::try_from(now)?;
    let valid_from = i64::try_from(snapshot.valid_from)?;
    let expires_at = i64::try_from(snapshot.expires_at)?;
    let digest = engine.source_hash().to_hex();
    let head = load_published_head(&mut tx, &snapshot.program_id.0).await?;
    if let Some(head) = head.as_ref().filter(|head| head.id == snapshot.id.0) {
        if head.source_hash != digest.as_str() {
            return Err(StorageError::RevisionCollision);
        }
        if !validity.contains(&clock()?) {
            return Err(StorageError::InactiveScope);
        }
        tx.commit().await?;
        return Ok(None);
    }

    let previous = head.as_ref().map(|head| head.id.as_str());
    if previous != snapshot.supersedes_id.as_ref().map(|s| s.0.as_str())
        || head
            .as_ref()
            .is_some_and(|head| valid_from < head.valid_from || now_sql < head.fetched_at)
    {
        return Err(StorageError::RevisionConflict);
    }
    let existing: Option<String> =
        sqlx::query_scalar("SELECT source_hash FROM scope_snapshots WHERE id = ?")
            .bind(&snapshot.id.0)
            .fetch_optional(&mut *tx)
            .await?;
    if existing.is_some() {
        return Err(StorageError::RevisionCollision);
    }

    sqlx::query(
        "INSERT INTO programs (id, platform, state, policy_profile)
         VALUES (?, 'manual', 'active', 'passive_inventory') ON CONFLICT (id) DO NOTHING",
    )
    .bind(&snapshot.program_id.0)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO scope_snapshots (
             id, program_id, source, source_hash, fetched_at, valid_from, expires_at, supersedes_id
         ) VALUES (?, ?, 'manual_reviewed', ?, ?, ?, ?, ?)",
    )
    .bind(&snapshot.id.0)
    .bind(&snapshot.program_id.0)
    .bind(digest.as_str())
    .bind(now_sql)
    .bind(valid_from)
    .bind(expires_at)
    .bind(previous)
    .execute(&mut *tx)
    .await?;
    for (ordinal, rule) in snapshot.rules.iter().enumerate() {
        let effect = match rule.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        };
        let target_type = match rule.kind {
            TargetKind::Domain => "domain",
            TargetKind::Wildcard => "wildcard",
            TargetKind::UrlPrefix => "url_prefix",
            TargetKind::Ip => "ip",
            TargetKind::Cidr => "cidr",
        };
        sqlx::query(
            "INSERT INTO scope_rules (
                 id, scope_snapshot_id, ordinal, effect, target_type, target, action_policy_json, provenance
             ) VALUES (?, ?, ?, ?, ?, ?, ?, 'manual_reviewed')",
        )
        .bind(&rule.id.0)
        .bind(&snapshot.id.0)
        .bind(i64::try_from(ordinal)?)
        .bind(effect)
        .bind(target_type)
        .bind(&rule.target)
        .bind(serde_json::to_string(&rule.actions)?)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO program_scope_heads (program_id, scope_snapshot_id) VALUES (?, ?)
         ON CONFLICT (program_id) DO UPDATE SET scope_snapshot_id = excluded.scope_snapshot_id",
    )
    .bind(&snapshot.program_id.0)
    .bind(&snapshot.id.0)
    .execute(&mut *tx)
    .await?;

    let event = DeltaDetected {
        kind: DeltaKind::ScopeChanged,
        scope_snapshot_id: snapshot.id.clone(),
        asset_id: None,
        observation_id: None,
        occurred_at: now,
    };
    let details = serde_json::json!({"delta": event, "previous_snapshot_id": previous});
    sqlx::query(
        "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision, details_json)
         VALUES (?, ?, ?, ?, 'ALLOW', ?)",
    )
    .bind(publication_event_id(&snapshot.id))
    .bind(&snapshot.id.0)
    .bind(now_sql)
    .bind(event.kind.as_str())
    .bind(details.to_string())
    .execute(&mut *tx)
    .await?;
    if !validity.contains(&clock()?) {
        return Err(StorageError::InactiveScope);
    }
    tx.commit().await?;
    Ok(Some(event))
}

pub(crate) fn publication_event_id(scope_snapshot_id: &ScopeSnapshotId) -> String {
    stable_id("scope-publication", &[&scope_snapshot_id.0])
}
