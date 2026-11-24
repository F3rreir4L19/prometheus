//! SQLite metadata and append-only audit. Database files must be on a local filesystem.

use std::{path::Path, time::Duration};

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
    #[error("file-backed SQLite requires WAL mode")]
    WalUnavailable,
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
