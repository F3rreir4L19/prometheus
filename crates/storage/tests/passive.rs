use std::cell::Cell;

use domain::{CollectionCompleteness::*, DeltaKind, ProgramId};
use scope_engine::ScopeEngine;
use sqlx::SqlitePool;
use storage::{
    active_snapshot_id, open_in_memory, open_local, publish_reviewed_scope, record_passive_run,
    PassiveRunInput, PassiveRunResult, StorageError,
};

fn scope(id: &str, previous: Option<&str>, blocked: &str) -> anyhow::Result<ScopeEngine> {
    let previous = previous.unwrap_or("null");
    let yaml = format!(
        r#"version: 1
snapshot:
  id: {id}
  program_id: lab
  source: manual_reviewed
  valid_from: 1
  expires_at: 100
  supersedes_id: {previous}
  rules:
    - {{ id: allow, effect: allow, kind: wildcard, target: '*.example.test', actions: [passive] }}
    - {{ id: deny, effect: deny, kind: domain, target: {blocked}, actions: [passive] }}
    - {{ id: action, effect: allow, kind: domain, target: http-only.example.org, actions: [http] }}
"#,
    );
    Ok(ScopeEngine::from_yaml(yaml.as_bytes())?)
}

async fn run(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    run_key: &str,
    observed_at: u64,
    completeness: domain::CollectionCompleteness,
    names: &[&str],
) -> Result<PassiveRunResult, StorageError> {
    let domains = names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    record_passive_run(
        pool,
        engine,
        PassiveRunInput {
            run_key,
            observed_at,
            completeness,
            domains: &domains,
        },
        || Ok(observed_at),
    )
    .await
}

fn kinds(result: &PassiveRunResult) -> Vec<DeltaKind> {
    result.deltas.iter().map(|delta| delta.kind).collect()
}

#[tokio::test]
async fn publish_seals_rules_and_rejects_a_stale_or_colliding_writer() -> anyhow::Result<()> {
    let pool = open_in_memory().await?;
    let old = scope("r1", None, "deny.example.test")?;
    let new = scope("r2", Some("r1"), "deny.example.test")?;
    assert_eq!(
        publish_reviewed_scope(&pool, &old, || Ok(3))
            .await?
            .map(|event| event.kind),
        Some(DeltaKind::ScopeChanged)
    );
    assert!(publish_reviewed_scope(&pool, &old, || Ok(4))
        .await?
        .is_none());
    let colliding = scope("r1", None, "other.example.test")?;
    assert!(matches!(
        publish_reviewed_scope(&pool, &colliding, || Ok(5)).await,
        Err(StorageError::RevisionCollision)
    ));
    assert!(matches!(
        run(&pool, &colliding, "collision", 5, Partial, &[]).await,
        Err(StorageError::InactiveScope)
    ));
    publish_reviewed_scope(&pool, &new, || Ok(6)).await?;
    let obsolete = scope("r3", Some("r1"), "deny.example.test")?;
    assert!(matches!(
        publish_reviewed_scope(&pool, &obsolete, || Ok(7)).await,
        Err(StorageError::RevisionConflict)
    ));
    assert!(matches!(
        run(&pool, &old, "old", 7, Complete, &[]).await,
        Err(StorageError::InactiveScope)
    ));
    assert_eq!(
        active_snapshot_id(&pool, &ProgramId("lab".to_owned()), 7).await?,
        Some(new.snapshot_id().clone())
    );
    let revisions: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT id, supersedes_id, source_hash FROM scope_snapshots ORDER BY id")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        revisions,
        vec![
            ("r1".into(), None, old.source_hash().to_hex().to_string()),
            (
                "r2".into(),
                Some("r1".into()),
                new.source_hash().to_hex().to_string()
            )
        ]
    );
    let stored_rules: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, action_policy_json, provenance FROM scope_rules
         WHERE scope_snapshot_id = 'r1' ORDER BY ordinal",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        stored_rules,
        vec![
            (
                "allow".into(),
                r#"["passive"]"#.into(),
                "manual_reviewed".into()
            ),
            (
                "deny".into(),
                r#"["passive"]"#.into(),
                "manual_reviewed".into()
            ),
            (
                "action".into(),
                r#"["http"]"#.into(),
                "manual_reviewed".into()
            ),
        ]
    );
    let scope_events: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT json_extract(details_json, '$.previous_snapshot_id') FROM audit_events
         WHERE event_type = 'scope_changed' ORDER BY occurred_at",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(scope_events, vec![None, Some("r1".into())]);
    Ok(())
}

#[tokio::test]
async fn expiration_rolls_back_publication_and_inventory_writes() -> anyhow::Result<()> {
    let pool = open_in_memory().await?;
    let engine = scope("r1", None, "deny.example.test")?;
    let now = Cell::new(99);
    assert!(matches!(
        publish_reviewed_scope(&pool, &engine, || Ok(now.replace(100))).await,
        Err(StorageError::InactiveScope)
    ));
    assert_eq!(
        active_snapshot_id(&pool, &engine.snapshot().program_id, 99).await?,
        None
    );
    publish_reviewed_scope(&pool, &engine, || Ok(98)).await?;

    now.set(99);
    assert!(matches!(
        record_passive_run(
            &pool,
            &engine,
            PassiveRunInput {
                run_key: "expires-during-write",
                observed_at: 98,
                completeness: Complete,
                domains: &["fresh.example.test".to_owned()],
            },
            || Ok(now.replace(100)),
        )
        .await,
        Err(StorageError::InactiveScope)
    ));
    let remaining: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM observations),
                (SELECT COUNT(*) FROM tool_runs), (SELECT COUNT(*) FROM audit_events)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(remaining, (0, 0, 0, 1));
    Ok(())
}

#[tokio::test]
async fn partial_absence_and_reappearance_preserve_temporal_history() -> anyhow::Result<()> {
    let db = tempfile::tempdir()?;
    let pool = open_local(&db.path().join("inventory.sqlite")).await?;
    let engine = scope("r1", None, "deny.example.test")?;
    publish_reviewed_scope(&pool, &engine, || Ok(1)).await?;
    let first = run(
        &pool,
        &engine,
        "r-first",
        2,
        Complete,
        &[
            "Web.Example.Test.",
            "other.example.test",
            "web.example.test",
        ],
    )
    .await?;
    assert_eq!(
        kinds(&first),
        [
            DeltaKind::ScopeChanged,
            DeltaKind::NewAsset,
            DeltaKind::NewAsset
        ]
    );
    let repeat = run(
        &pool,
        &engine,
        "r-first",
        2,
        Complete,
        &["web.example.test", "other.example.test"],
    )
    .await?;
    assert!(repeat.replayed && !first.replayed);
    assert_eq!(repeat.run_id, first.run_id);
    assert_eq!(repeat.deltas, first.deltas);
    assert!(matches!(
        run(&pool, &engine, "r-first", 2, Complete, &[]).await,
        Err(StorageError::RunCollision)
    ));
    assert!(matches!(
        run(&pool, &engine, "same-second", 2, Partial, &[]).await,
        Err(StorageError::NonMonotonicRun)
    ));
    assert!(run(
        &pool,
        &engine,
        "r-partial",
        3,
        Partial,
        &["other.example.test"]
    )
    .await?
    .deltas
    .is_empty());
    let missing = run(
        &pool,
        &engine,
        "r-missing",
        4,
        Complete,
        &["other.example.test"],
    )
    .await?;
    assert_eq!(kinds(&missing), [DeltaKind::AbsentAsset]);
    let seen: (i64, i64) = sqlx::query_as(
        "SELECT first_seen_at, last_seen_at FROM assets WHERE canonical_key = 'web.example.test'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(seen, (2, 2));
    assert_eq!(
        kinds(
            &run(
                &pool,
                &engine,
                "r-return",
                5,
                Partial,
                &["web.example.test"]
            )
            .await?
        ),
        [DeltaKind::ReactivatedAsset]
    );
    let seen: (i64, i64) = sqlx::query_as(
        "SELECT first_seen_at, last_seen_at FROM assets WHERE canonical_key = 'web.example.test'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(seen, (2, 5));
    let observations: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT o.observed_at, o.status, o.exact_hash FROM observations o
         JOIN assets a ON a.id = o.asset_id JOIN tool_runs t ON o.tool_run_id = t.id
         WHERE a.canonical_key = 'web.example.test' ORDER BY o.observed_at",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        observations
            .iter()
            .map(|(time, status, _)| (*time, status.as_str()))
            .collect::<Vec<_>>(),
        [(2, "present"), (4, "absent"), (5, "present")]
    );
    assert!(observations.iter().all(|(_, _, hash)| hash.len() == 64));
    assert_eq!(observations[0].2, observations[2].2);
    assert_ne!(observations[0].2, observations[1].2);
    let run_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tool_runs")
        .fetch_one(&pool)
        .await?;
    assert_eq!(run_count, 4);
    let delta_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE event_type <> 'passive_ingest_gate'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(delta_count, 5);
    Ok(())
}

#[tokio::test]
async fn rejected_domains_are_never_stored_and_new_scope_constrains_absence() -> anyhow::Result<()>
{
    let pool = open_in_memory().await?;
    let first = scope("r1", None, "deny.example.test")?;
    publish_reviewed_scope(&pool, &first, || Ok(1)).await?;
    for bad in [
        "deny.example.test",
        "unlisted.test",
        "http-only.example.org",
        "https://a.example.test",
        "192.0.2.1",
        "-flag.example.test",
        "example.test",
    ] {
        assert!(
            matches!(
                run(
                    &pool,
                    &first,
                    "mixed",
                    2,
                    Complete,
                    &["web.example.test", bad]
                )
                .await,
                Err(StorageError::UnauthorizedDomain)
            ),
            "{bad}"
        );
    }
    let counts: (i64, i64) =
        sqlx::query_as("SELECT (SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM tool_runs)")
            .fetch_one(&pool)
            .await?;
    assert_eq!(counts, (0, 0));
    run(&pool, &first, "mixed", 2, Complete, &["web.example.test"]).await?;
    let second = scope("r2", Some("r1"), "web.example.test")?;
    publish_reviewed_scope(&pool, &second, || Ok(3)).await?;
    let deltas = run(&pool, &second, "new-scope", 4, Complete, &[]).await?;
    assert_eq!(kinds(&deltas), [DeltaKind::ScopeChanged]);
    let observations: Vec<String> = sqlx::query_scalar("SELECT status FROM observations")
        .fetch_all(&pool)
        .await?;
    assert_eq!(observations, ["present"]);
    Ok(())
}

#[tokio::test]
async fn two_concurrent_exact_retries_commit_one_history() -> anyhow::Result<()> {
    let db = tempfile::tempdir()?;
    let pool = open_local(&db.path().join("concurrent.sqlite")).await?;
    let engine = scope("r1", None, "deny.example.test")?;
    publish_reviewed_scope(&pool, &engine, || Ok(1)).await?;
    let (a, b) = tokio::join!(
        run(&pool, &engine, "same", 2, Complete, &["web.example.test"]),
        run(&pool, &engine, "same", 2, Complete, &["web.example.test"]),
    );
    let (a, b) = (a?, b?);
    assert_ne!(a.replayed, b.replayed);
    assert_eq!(a.run_id, b.run_id);
    assert_eq!(a.deltas, b.deltas);
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM observations),
         (SELECT COUNT(*) FROM tool_runs)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (1, 1, 1));
    Ok(())
}
