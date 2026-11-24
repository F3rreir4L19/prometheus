use domain::{AuditEvent, AuditEventId, Decision, ProgramId, ScopeSnapshotId};
use sqlx::SqlitePool;
use storage::{active_snapshot_id, append_audit, open_in_memory, open_local};

async fn seed(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "INSERT INTO programs VALUES ('p', 'manual', 'lab', 'active', 'lab');
         INSERT INTO scope_snapshots VALUES ('s1', 'p', 'manual_reviewed', 'digest', 0, 0, 10, NULL);
         INSERT INTO scope_snapshots VALUES ('s2', 'p', 'manual_reviewed', 'digest2', 0, 0, 20, 's1');
         INSERT INTO program_scope_heads VALUES ('p', 's1');
         INSERT INTO assets VALUES ('a1', 'p', 'host', 'lab.example', 1, 1);
         INSERT INTO observations
            (id, program_id, asset_id, scope_snapshot_id, observed_at, collector, status, metadata_json)
            VALUES ('o1', 'p', 'a1', 's1', 1, 'fixture', 'present', '{}');",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
async fn schema_enforces_provenance_and_immutability() -> anyhow::Result<()> {
    let pool = open_in_memory().await?;
    seed(&pool).await?;
    let program = ProgramId("p".into());
    let old = ScopeSnapshotId("s1".into());
    assert_eq!(
        active_snapshot_id(&pool, &program, 1).await?,
        Some(old.clone())
    );
    assert_eq!(active_snapshot_id(&pool, &program, 10).await?, None);
    sqlx::query("UPDATE program_scope_heads SET scope_snapshot_id = 's2' WHERE program_id = 'p'")
        .execute(&pool)
        .await?;
    assert_eq!(
        active_snapshot_id(&pool, &program, 10).await?,
        Some(ScopeSnapshotId("s2".into()))
    );
    append_audit(
        &pool,
        &AuditEvent {
            id: AuditEventId("audit1".into()),
            scope_snapshot_id: old,
            occurred_at: 1,
            decision: Decision::Unknown,
            event_type: "shadow".into(),
        },
    )
    .await?;
    sqlx::raw_sql(
        "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision)
         VALUES ('allow2', 's2', 10, 'job_gate', 'ALLOW'), ('unknown2', 's2', 10, 'job_gate', 'UNKNOWN');
         INSERT INTO jobs VALUES ('allowed_job', 's2', 'http', 'allow2');",
    )
    .execute(&pool)
    .await?;
    for invalid in [
        "UPDATE program_scope_heads SET scope_snapshot_id = 's1' WHERE program_id = 'p'",
        "UPDATE jobs SET scope_snapshot_id = 's1' WHERE id = 'allowed_job'",
        "INSERT INTO jobs VALUES ('held_job', 's2', 'http', 'unknown2')",
        "UPDATE scope_snapshots SET source_hash = 'other' WHERE id = 's1'",
        "INSERT INTO scope_rules VALUES ('r1', 's1', 0, 'allow', 'domain', 'a.example', '[]', NULL, 'manual')",
        "UPDATE observations SET status = 'missing' WHERE id = 'o1'",
        "UPDATE audit_events SET decision = 'ALLOW' WHERE id = 'audit1'",
        "DELETE FROM audit_events WHERE id = 'audit1'",
        "INSERT OR REPLACE INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision)
         VALUES ('audit1', 's1', 2, 'tampered', 'ALLOW')",
        "INSERT INTO jobs VALUES ('j1', 'missing', 'http', 'audit1')",
        "INSERT INTO jobs VALUES ('j1', 's2', 'http', 'audit1')",
    ] {
        assert!(sqlx::query(invalid).execute(&pool).await.is_err(), "{invalid}");
    }
    Ok(())
}

#[tokio::test]
async fn file_database_uses_wal_and_safe_connection_settings() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("prometheus.sqlite");
    let pool = open_local(&path).await?;
    seed(&pool).await?;
    let mut first = pool.acquire().await?;
    let mut second = pool.acquire().await?;
    for conn in [&mut first, &mut second] {
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&mut **conn)
            .await?;
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut **conn)
            .await?;
        let timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&mut **conn)
            .await?;
        assert_eq!(mode, "wal");
        assert_eq!(fk, 1);
        assert_eq!(timeout, 5000);
    }
    drop((first, second));
    pool.close().await;
    let reopened = open_local(&path).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM observations")
        .fetch_one(&reopened)
        .await?;
    assert_eq!(count, 1);
    reopened.close().await;
    Ok(())
}
