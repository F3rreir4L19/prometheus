//! SQLite metadata and append-only audit. Database files must be on a local filesystem.

mod passive;
mod publication;

pub use passive::{record_passive_run, PassiveRunInput, PassiveRunResult, MAX_INVENTORY_DOMAINS};
pub use publication::publish_reviewed_scope;

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use domain::{AuditEvent, Decision, ProgramId, ScopeSnapshotId};
use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use thiserror::Error;

static MIGRATOR: Migrator = sqlx::migrate!();

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite error")]
    Sqlite(#[from] sqlx::Error),
    #[error("SQLite migration error")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("timestamp outside SQLite integer range")]
    InvalidTime(#[from] std::num::TryFromIntError),
    #[error("clock is outside the supported Unix range")]
    Clock(#[from] std::time::SystemTimeError),
    #[error("file-backed SQLite requires WAL mode")]
    WalUnavailable,
    #[error("scope revision is inactive or does not match the published document")]
    InactiveScope,
    #[error("scope revision does not supersede the current head")]
    RevisionConflict,
    #[error("scope revision ID already has different contents")]
    RevisionCollision,
    #[error("invalid passive inventory timestamp")]
    InvalidObservationTime,
    #[error("passive inventory run key is invalid")]
    InvalidRunKey,
    #[error("passive inventory run key already has different contents")]
    RunCollision,
    #[error("passive inventory timestamps must increase for each program and collector")]
    NonMonotonicRun,
    #[error("passive inventory contains a malformed or unauthorized domain")]
    UnauthorizedDomain,
    #[error("passive inventory exceeds the domain limit")]
    InventoryLimit,
    #[error("passive inventory exceeds the per-run delta limit")]
    DeltaLimit,
    #[error("could not encode or decode storage metadata")]
    Metadata,
}

impl From<serde_json::Error> for StorageError {
    fn from(_: serde_json::Error) -> Self {
        Self::Metadata
    }
}

pub fn unix_time_seconds() -> Result<u64, StorageError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn stable_id(label: &str, fields: &[&str]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"prometheus-storage-v1\0");
    for field in std::iter::once(&label).chain(fields) {
        hash.update(&(field.len() as u64).to_le_bytes());
        hash.update(field.as_bytes());
    }
    hash.finalize().to_hex().to_string()
}

pub async fn open_local(path: &Path) -> Result<SqlitePool, StorageError> {
    let options = options()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::WalUnavailable);
    }
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

pub async fn open_in_memory() -> Result<SqlitePool, StorageError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options().in_memory(true))
        .await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

fn options() -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .pragma("recursive_triggers", "ON")
}

pub async fn active_snapshot_id(
    pool: &SqlitePool,
    program: &ProgramId,
    now: u64,
) -> Result<Option<ScopeSnapshotId>, StorageError> {
    let id: Option<String> = sqlx::query_scalar(
        "SELECT s.id FROM program_scope_heads h JOIN scope_snapshots s
         ON s.id = h.scope_snapshot_id
         WHERE h.program_id = ?1 AND s.valid_from <= ?2 AND ?2 < s.expires_at",
    )
    .bind(&program.0)
    .bind(i64::try_from(now)?)
    .fetch_optional(pool)
    .await?;
    Ok(id.map(ScopeSnapshotId))
}

pub async fn append_audit(pool: &SqlitePool, event: &AuditEvent) -> Result<(), StorageError> {
    let decision = match event.decision {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
        Decision::Unknown => "UNKNOWN",
    };
    sqlx::query(
        "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&event.id.0)
    .bind(&event.scope_snapshot_id.0)
    .bind(i64::try_from(event.occurred_at)?)
    .bind(&event.event_type)
    .bind(decision)
    .execute(pool)
    .await?;
    Ok(())
}
