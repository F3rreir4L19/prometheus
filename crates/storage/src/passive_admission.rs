use std::time::Duration;

use domain::{PassiveRatePolicy, PassiveSource, ToolRunId, PASSIVE_GLOBAL_PER_MINUTE};
use scope_engine::ScopeEngine;
use sqlx::{SqliteConnection, SqlitePool};

use crate::{
    passive::{ensure_published_head, run_id, validate_run_key, ToolProvenance},
    stable_id, LiveTool, StorageError,
};

const MAX_ADMISSION_WAIT_MS: u64 = 120_000;
const MAX_PROVIDER_BACKOFF_MS: u64 = MAX_ADMISSION_WAIT_MS;
type AdmissionLanes = [(String, u64); 6];

struct Capture<'a> {
    tool: LiveTool<'a>,
    id: String,
}

enum Reservation {
    Admitted(ToolRunId),
    Wait(Duration),
}

#[derive(Clone, Copy)]
pub struct PassiveRateTime<'a> {
    pub boot_id: &'a str,
    pub elapsed_ms: u64,
    pub unix_ms: u64,
}

/// Mirror the burst-one GCRA spacing across worker invocations on the same local WAL. A
/// reservation spends all policy lanes together and checks the current policy after any wait.
pub async fn admit_passive_collection<'a>(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    seed: &str,
    tool: LiveTool<'_>,
    run_key: &str,
    clock: impl Fn() -> Result<PassiveRateTime<'a>, StorageError>,
) -> Result<ToolRunId, StorageError> {
    validate_run_key(run_key)?;
    tool.validate()?;
    let source = tool.source();
    let capture = Capture {
        tool,
        id: run_id(engine, source.as_str(), run_key),
    };
    let policy = engine
        .snapshot()
        .passive_live
        .ok_or(StorageError::InactiveScope)?;
    let lanes = admission_lanes(engine, seed, source, policy)?;
    let wait = match reserve(pool, engine, seed, &capture, &lanes, &clock).await? {
        Reservation::Admitted(id) => return Ok(id),
        Reservation::Wait(wait) => wait,
    };
    if wait.as_millis() > u128::from(MAX_ADMISSION_WAIT_MS) {
        return Err(StorageError::PassiveRateLimited);
    }
    tokio::time::sleep(wait).await;
    match reserve(pool, engine, seed, &capture, &lanes, &clock).await? {
        Reservation::Admitted(id) => Ok(id),
        Reservation::Wait(_) => Err(StorageError::PassiveRateLimited),
    }
}

/// Complete a previously admitted operation even if its snapshot has since been revoked.
/// This records operational timing and outcome only.
pub async fn finish_passive_dispatch(
    pool: &SqlitePool,
    id: &ToolRunId,
    success: bool,
    now: u64,
) -> Result<(), StorageError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let (snapshot, finished_at): (String, i64) = sqlx::query_as(
        "UPDATE tool_runs SET finished_at = MAX(?, started_at)
         WHERE id = ? AND finished_at IS NULL AND json_extract(exit_metadata_json, '$.kind') = 'dispatch'
         RETURNING scope_snapshot_id, finished_at",
    )
    .bind(i64::try_from(now)?)
    .bind(&id.0)
    .fetch_one(&mut *tx)
    .await?;
    let status = if success { "collected" } else { "failed" };
    sqlx::query(
        "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision, details_json)
         VALUES (?, ?, ?, 'passive_dispatch_finished', 'ALLOW', json_object('tool_run_id', ?, 'status', ?))",
    )
    .bind(stable_id("passive-dispatch-finished", &[&id.0]))
    .bind(snapshot)
    .bind(finished_at)
    .bind(&id.0)
    .bind(status)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Extend the existing provider gate without shortening a policy interval or earlier cooldown.
pub async fn defer_passive_provider<'a>(
    pool: &SqlitePool,
    source: PassiveSource,
    delay: Duration,
    clock: impl Fn() -> Result<PassiveRateTime<'a>, StorageError>,
) -> Result<(), StorageError> {
    let lane = provider_cooldown_lane(source)?;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let delay_ms = delay.as_millis().min(u128::from(MAX_PROVIDER_BACKOFF_MS));
    let now = clock()?;
    let available = i64::try_from(u128::from(now.elapsed_ms) + delay_ms)?;
    sqlx::query(
        "INSERT INTO passive_admission (lane, boot_id, available_at_ms) VALUES (?, ?, ?)
         ON CONFLICT(lane) DO UPDATE SET available_at_ms = CASE WHEN boot_id = excluded.boot_id
            THEN MAX(available_at_ms, excluded.available_at_ms) ELSE excluded.available_at_ms END,
            last_admission_at_ms = CASE WHEN boot_id = excluded.boot_id THEN last_admission_at_ms END,
            boot_id = excluded.boot_id",
    )
    .bind(lane)
    .bind(now.boot_id)
    .bind(available)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

fn provider_cooldown_lane(source: PassiveSource) -> Result<String, StorageError> {
    Ok(stable_id(
        "passive-provider-cooldown",
        &[live_source(source)?],
    ))
}

fn live_source(source: PassiveSource) -> Result<&'static str, StorageError> {
    if source == PassiveSource::Fixture {
        return Err(StorageError::InvalidCollector);
    }
    Ok(source.as_str())
}

fn admission_lanes(
    engine: &ScopeEngine,
    seed: &str,
    source: PassiveSource,
    policy: PassiveRatePolicy,
) -> Result<AdmissionLanes, StorageError> {
    let program = &engine.snapshot().program_id.0;
    let interval = |per_minute| 60_000_u64.div_ceil(u64::from(per_minute));
    Ok([
        ("global".to_owned(), interval(PASSIVE_GLOBAL_PER_MINUTE)),
        (
            stable_id("passive-program", &[program]),
            interval(policy.program_per_minute.get()),
        ),
        (
            stable_id("passive-action", &[program, "passive"]),
            interval(policy.action_per_minute.get()),
        ),
        (
            stable_id("passive-host", &[program, seed]),
            interval(policy.host_per_minute.get()),
        ),
        (
            stable_id("passive-provider", &[program, live_source(source)?]),
            interval(policy.provider_per_minute.get()),
        ),
        (provider_cooldown_lane(source)?, 0),
    ])
}

async fn reserve<'a>(
    pool: &SqlitePool,
    engine: &ScopeEngine,
    seed: &str,
    capture: &Capture<'_>,
    lanes: &AdmissionLanes,
    clock: &impl Fn() -> Result<PassiveRateTime<'a>, StorageError>,
) -> Result<Reservation, StorageError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let now = clock()?;
    ensure_published_head(&mut tx, engine, now.unix_ms / 1000).await?;
    if !engine.is_passive_collection_seed(engine.snapshot_id(), now.unix_ms / 1000, seed) {
        return Err(StorageError::UnauthorizedDomain);
    }
    let mut unavailable_until = now.elapsed_ms;
    for (lane, interval) in lanes {
        let state: Option<(String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT boot_id, available_at_ms, last_admission_at_ms FROM passive_admission WHERE lane = ?",
        )
        .bind(lane)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((boot_id, available, last_admission)) = state {
            if boot_id != now.boot_id {
                // The previous boot could have ended during a provider cooldown.
                unavailable_until = unavailable_until.max(MAX_PROVIDER_BACKOFF_MS);
                continue;
            }
            unavailable_until = unavailable_until.max(u64::try_from(available)?);
            if let Some(last_admission) = last_admission {
                unavailable_until =
                    unavailable_until.max(u64::try_from(last_admission)?.saturating_add(*interval));
            }
        }
    }
    if unavailable_until > now.elapsed_ms {
        tx.commit().await?;
        return Ok(Reservation::Wait(Duration::from_millis(
            unavailable_until - now.elapsed_ms,
        )));
    }
    let initial_time = now;
    let now = clock()?;
    if now.boot_id != initial_time.boot_id || now.elapsed_ms < unavailable_until {
        return Err(StorageError::PassiveRateLimited);
    }
    for (lane, interval) in lanes {
        let available = i64::try_from(u128::from(now.elapsed_ms) + u128::from(*interval))?;
        sqlx::query(
            "INSERT INTO passive_admission (lane, boot_id, available_at_ms, last_admission_at_ms) VALUES (?, ?, ?, ?)
             ON CONFLICT(lane) DO UPDATE SET boot_id = excluded.boot_id, available_at_ms = excluded.available_at_ms,
                last_admission_at_ms = excluded.last_admission_at_ms",
        )
        .bind(lane)
        .bind(now.boot_id)
        .bind(available)
        .bind(i64::try_from(now.elapsed_ms)?)
        .execute(&mut *tx)
        .await?;
    }
    let attempt = write_dispatch(&mut tx, engine, seed, capture, now).await?;
    let final_now = clock()?;
    let policy = engine.snapshot();
    let validity = policy.valid_from..policy.expires_at;
    if final_now.boot_id != now.boot_id
        || final_now.elapsed_ms < now.elapsed_ms
        || !validity.contains(&(now.unix_ms / 1000))
        || !validity.contains(&(final_now.unix_ms / 1000))
    {
        return Err(StorageError::InactiveScope);
    }
    tx.commit().await?;
    Ok(Reservation::Admitted(attempt))
}

async fn write_dispatch(
    connection: &mut SqliteConnection,
    engine: &ScopeEngine,
    seed: &str,
    capture: &Capture<'_>,
    now: PassiveRateTime<'_>,
) -> Result<ToolRunId, StorageError> {
    let snapshot = engine.snapshot_id();
    let program = &engine.snapshot().program_id.0;
    let seed_id = stable_id("passive-seed", &[program, seed]);
    let attempt = stable_id(
        "passive-dispatch",
        &[
            &capture.id,
            &snapshot.0,
            &seed_id,
            now.boot_id,
            &now.elapsed_ms.to_string(),
        ],
    );
    let decision_id = stable_id("passive-dispatch-allow", &[&attempt]);
    let job_id = stable_id("passive-dispatch-job", &[&attempt]);
    let started_at = i64::try_from(now.unix_ms / 1000)?;
    let source = capture.tool.source().as_str();
    let provenance = ToolProvenance::from_tool(Some(capture.tool));
    sqlx::query(
        "INSERT INTO audit_events (id, scope_snapshot_id, occurred_at, event_type, decision, details_json)
         VALUES (?, ?, ?, 'passive_dispatch_gate', 'ALLOW', json_object('source', ?, 'tool_run_id', ?))",
    )
    .bind(&decision_id)
    .bind(&snapshot.0)
    .bind(started_at)
    .bind(source)
    .bind(&attempt)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO jobs (id, scope_snapshot_id, action, policy_decision_id) VALUES (?, ?, 'passive', ?)",
    )
    .bind(&job_id)
    .bind(&snapshot.0)
    .bind(&decision_id)
    .execute(&mut *connection)
    .await?;
    let metadata = serde_json::json!({
        "kind": "dispatch", "capture_tool_run_id": capture.id,
        "seed_id": seed_id, "sha256_subject": provenance.sha256_subject,
    });
    sqlx::query(
        "INSERT INTO tool_runs (id, job_id, tool, tool_version, tool_sha256, scope_snapshot_id,
             policy_decision_id, started_at, exit_metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&attempt)
    .bind(job_id)
    .bind(source)
    .bind(provenance.version)
    .bind(provenance.sha256)
    .bind(&snapshot.0)
    .bind(decision_id)
    .bind(started_at)
    .bind(metadata.to_string())
    .execute(connection)
    .await?;
    Ok(ToolRunId(attempt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_in_memory, publish_reviewed_scope};

    const POLICY: &[u8] = br#"
version: 1
snapshot:
  id: test-scope
  program_id: test-program
  source: manual_reviewed
  valid_from: 0
  expires_at: 200
  passive_live:
    program_per_minute: 60
    action_per_minute: 60
    host_per_minute: 60
    provider_per_minute: 60
  rules:
    - {id: root, effect: allow, kind: domain, target: example.test, actions: [passive]}
    - {id: child, effect: allow, kind: wildcard, target: '*.example.test', actions: [passive]}
"#;

    fn tick(ms: u64) -> PassiveRateTime<'static> {
        PassiveRateTime {
            boot_id: "boot-1",
            elapsed_ms: ms,
            unix_ms: ms,
        }
    }

    #[tokio::test]
    async fn durable_spacing_and_backoff_survive_new_invocations() -> anyhow::Result<()> {
        let engine = ScopeEngine::from_yaml(POLICY)?;
        let policy = engine
            .snapshot()
            .passive_live
            .ok_or(StorageError::InactiveScope)?;
        let pool = open_in_memory().await?;
        publish_reviewed_scope(&pool, &engine, || Ok(100)).await?;
        let ct = Capture {
            tool: LiveTool::Crtsh,
            id: "ct-capture".to_owned(),
        };
        let subfinder = Capture {
            tool: LiveTool::Subfinder {
                version: "synthetic",
                sha256: concat!(
                    "00000000000000000000000000000000",
                    "00000000000000000000000000000000"
                ),
            },
            id: "subfinder-capture".to_owned(),
        };
        let seed = "example.test";
        let first =
            admit_passive_collection(&pool, &engine, seed, ct.tool, "first", || Ok(tick(100_000)))
                .await?;
        finish_passive_dispatch(&pool, &first, true, 100).await?;

        let subfinder_lanes = admission_lanes(&engine, seed, subfinder.tool.source(), policy)?;
        assert!(matches!(
            reserve(&pool, &engine, seed, &subfinder, &subfinder_lanes, &|| Ok(tick(100_010))).await?,
            Reservation::Wait(wait) if wait == Duration::from_millis(990)
        ));
        assert!(matches!(
            reserve(&pool, &engine, seed, &subfinder, &subfinder_lanes, &|| Ok(PassiveRateTime {
                unix_ms: 110_000,
                ..tick(100_010)
            })).await?,
            Reservation::Wait(wait) if wait == Duration::from_millis(990)
        ));
        assert!(matches!(
            reserve(&pool, &engine, seed, &subfinder, &subfinder_lanes, &|| Ok(PassiveRateTime {
                boot_id: "boot-2", elapsed_ms: 1_000, unix_ms: 111_000,
            })).await?,
            Reservation::Wait(wait) if wait == Duration::from_secs(119)
        ));

        defer_passive_provider(&pool, ct.tool.source(), Duration::from_secs(5), || {
            Ok(tick(100_010))
        })
        .await?;
        assert!(matches!(
            reserve(&pool, &engine, seed, &subfinder, &subfinder_lanes, &|| Ok(
                tick(101_000)
            ))
            .await?,
            Reservation::Admitted(_)
        ));
        let ct_lanes = admission_lanes(&engine, seed, ct.tool.source(), policy)?;
        assert!(matches!(
            reserve(&pool, &engine, seed, &ct, &ct_lanes, &|| Ok(tick(102_000))).await?,
            Reservation::Wait(wait) if wait == Duration::from_millis(3_010)
        ));
        assert!(matches!(
            reserve(&pool, &engine, seed, &ct, &ct_lanes, &|| Ok(tick(105_010))).await?,
            Reservation::Admitted(_)
        ));
        let reserved: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = 'passive_dispatch_gate'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(reserved, 3);
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_rejects_wildcard_seeds_expiration_and_document_collisions(
    ) -> anyhow::Result<()> {
        let engine = ScopeEngine::from_yaml(POLICY)?;
        let pool = open_in_memory().await?;
        let tool = LiveTool::Crtsh;
        publish_reviewed_scope(&pool, &engine, || Ok(100)).await?;
        assert!(matches!(
            admit_passive_collection(&pool, &engine, "child.example.test", tool, "test", || Ok(
                tick(100_000)
            ))
            .await,
            Err(StorageError::UnauthorizedDomain)
        ));
        assert!(matches!(
            admit_passive_collection(&pool, &engine, "example.test", tool, "test", || Ok(tick(
                200_000
            )))
            .await,
            Err(StorageError::InactiveScope)
        ));
        let modified = ScopeEngine::from_yaml(&[POLICY, b"# different digest\n"].concat())?;
        assert!(matches!(
            admit_passive_collection(&pool, &modified, "example.test", tool, "test", || Ok(tick(
                100_000
            )))
            .await,
            Err(StorageError::InactiveScope)
        ));
        Ok(())
    }
}
