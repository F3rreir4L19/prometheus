#![cfg(target_os = "linux")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command as CompileCommand, Output},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use axum::{
    extract::State,
    http::{StatusCode, Uri},
    routing::{get, post},
    Json, Router,
};
use control_protocol::{ControlEvent, SignedEnvelope};
use domain::CollectionCompleteness;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, process::Command, sync::Notify};

const SIGNING_KEY: &str = "synthetic-control-test-key-000001";
const SCOPE_ID: &str = "lab-passive-live-v1";
const ROOT: &str = "inventory.example.test";
const DENIED: &str = "denied.inventory.example.test";
const OUTSIDE: &str = "outside.example.test";
const STUB_VERSION: &str = "2.17.0-prometheus-passive.1";

#[derive(Default)]
struct LocalServices {
    ct_requests: AtomicUsize,
    summaries: Mutex<Vec<SignedEnvelope>>,
}

async fn crtsh(State(state): State<Arc<LocalServices>>, uri: Uri) -> (StatusCode, Json<Value>) {
    state.ct_requests.fetch_add(1, Ordering::Relaxed);
    let mut query = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes());
    if !query.any(|(key, value)| key == "q" && value.ends_with(ROOT)) {
        return (StatusCode::BAD_REQUEST, Json(Value::Null));
    }
    (
        StatusCode::OK,
        Json(json!([
            { "name_value": format!("*.CRT.{ROOT}\ncrt.{ROOT}\n{DENIED}\n{OUTSIDE}") }
        ])),
    )
}

async fn receive_summary(
    State(state): State<Arc<LocalServices>>,
    Json(envelope): Json<SignedEnvelope>,
) -> StatusCode {
    if envelope.verify(SIGNING_KEY.as_bytes()).is_err() || envelope.key_id != "integration-key" {
        return StatusCode::UNAUTHORIZED;
    }
    let Ok(mut summaries) = state.summaries.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    summaries.push(envelope);
    StatusCode::NO_CONTENT
}

fn scope() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/lab-passive-live-scope.yaml")
}

fn worker() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_prometheus-worker"));
    command.kill_on_drop(true);
    command
}

#[tokio::test]
async fn loopback_fixture_cannot_use_a_non_test_scope() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let policy = temp.path().join("scope.yaml");
    fs::write(
        &policy,
        fs::read_to_string(scope())?.replace("inventory.example.test", "inventory.example.invalid"),
    )?;
    let db = temp.path().join("inventory.sqlite");
    let published = output(
        worker()
            .args(["publish-scope", "--scope"])
            .arg(&policy)
            .arg("--db")
            .arg(&db),
    )
    .await?;
    assert!(published.status.success());
    let collected = output(
        worker()
            .args(["passive-sync", "--scope"])
            .arg(&policy)
            .arg("--db")
            .arg(&db)
            .args([
                "--source",
                "crtsh",
                "--run-key",
                "mock-scope",
                "--crtsh-loopback-origin",
                "http://127.0.0.1:9",
            ]),
    )
    .await?;
    assert!(!collected.status.success());
    assert!(String::from_utf8_lossy(&collected.stderr).contains("synthetic .test scope"));
    let pool = storage::open_local(&db).await?;
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM tool_runs")
        .fetch_one(&pool)
        .await?;
    assert_eq!(runs, 0);
    Ok(())
}

async fn output(command: &mut Command) -> Result<Output> {
    Ok(tokio::time::timeout(Duration::from_secs(20), command.output()).await??)
}

async fn publish(db: &Path) -> Result<()> {
    let result = output(
        worker()
            .args(["publish-scope", "--scope"])
            .arg(scope())
            .arg("--db")
            .arg(db),
    )
    .await?;
    ensure!(
        result.status.success(),
        "publish failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

fn make_stub(directory: &Path) -> Result<PathBuf> {
    let source = directory.join("mock-subfinder.c");
    let executable = directory.join("mock-subfinder");
    fs::write(
        &source,
        r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 6 || strcmp(argv[1], "-d") || strcmp(argv[2], "inventory.example.test")
        || getenv("PROMETHEUS_CONTROL_KEY")) return 17;
    puts("{\"host\":\"sub.inventory.example.test\",\"input\":\"inventory.example.test\"}");
    puts("{\"host\":\"denied.inventory.example.test\",\"input\":\"inventory.example.test\"}");
    puts("{\"host\":\"outside.example.test\",\"input\":\"inventory.example.test\"}");
    puts("untrusted stdout must be counted and dropped");
    return 0;
}
"#,
    )?;
    let result = CompileCommand::new("cc")
        .arg(source)
        .arg("-o")
        .arg(&executable)
        .output()?;
    ensure!(
        result.status.success(),
        "ELF stub build failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(executable)
}

fn manifest(directory: &Path, executable: &Path, digest: &str) -> Result<PathBuf> {
    let manifest = directory.join("tools.yaml");
    let tool_config = json!({
        "version": 1,
        "subfinder": { "path": executable, "version": STUB_VERSION, "sha256": digest, "intrusiveness": "passive" },
    });
    fs::write(&manifest, serde_json::to_vec(&tool_config)?)?;
    Ok(manifest)
}

fn report_lines(result: &Output) -> Result<Vec<Value>> {
    let stdout = std::str::from_utf8(&result.stdout)?;
    let stderr = std::str::from_utf8(&result.stderr)?;
    for private in [ROOT, OUTSIDE, SIGNING_KEY, "untrusted stdout"] {
        assert!(!stdout.contains(private));
        assert!(!stderr.contains(private));
    }
    stdout
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[tokio::test]
async fn collects_filters_audits_signs_and_replays_each_live_source() -> Result<()> {
    let state = Arc::new(LocalServices::default());
    let services = Router::new()
        .route("/", get(crtsh))
        .route("/v1/worker-events", post(receive_summary))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async { axum::serve(listener, services).await });
    let temp = tempfile::tempdir()?;
    let db = temp.path().join("inventory.sqlite");
    publish(&db).await?;
    let stub = make_stub(temp.path())?;
    let digest = format!("{:x}", Sha256::digest(fs::read(&stub)?));
    let manifest = manifest(temp.path(), &stub, &digest)?;

    let collect = || {
        let mut command = worker();
        command
            .args(["passive-sync", "--scope"])
            .arg(scope())
            .arg("--db")
            .arg(&db)
            .args([
                "--source",
                "all",
                "--run-key",
                "capture-1",
                "--crtsh-loopback-origin",
                &origin,
                "--control-url",
                &origin,
                "--tools-manifest",
            ])
            .arg(&manifest)
            .env("PROMETHEUS_WORKER_ID", "integration-worker")
            .env("PROMETHEUS_CONTROL_KEY_ID", "integration-key")
            .env("PROMETHEUS_CONTROL_KEY", SIGNING_KEY);
        command
    };
    let first = output(&mut collect()).await?;
    ensure!(
        first.status.success(),
        "collect failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let reports = report_lines(&first)?;
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0]["source"], "crtsh_loopback");
    assert_eq!(reports[0]["inventory"]["duplicates"], 1);
    assert_eq!(reports[1]["source"], "subfinder");
    assert_eq!(reports[1]["inventory"]["malformed"], 1);
    for report in &reports {
        assert_eq!(report["completeness"], "partial");
        assert_eq!(report["inventory"]["allowed"], 1);
        assert_eq!(report["inventory"]["denied"], 1);
        assert_eq!(report["inventory"]["unknown"], 1);
        assert_eq!(report["deltas"]["new_assets"], 1);
        assert_eq!(report["replayed"], false);
    }

    // A completed tool run can replay after the executable and its manifest are removed.
    fs::remove_file(&manifest)?;
    fs::remove_file(&stub)?;
    let replay = output(&mut collect()).await?;
    ensure!(
        replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replays = report_lines(&replay)?;
    assert_eq!(replays.len(), 2);
    assert!(replays.iter().all(|report| report["replayed"] == true));

    let non_monotonic = output(
        worker()
            .args(["passive-sync", "--scope"])
            .arg(scope())
            .arg("--db")
            .arg(&db)
            .args([
                "--source",
                "crtsh",
                "--run-key",
                "non-monotonic-capture",
                "--observed-at",
                "0",
                "--crtsh-loopback-origin",
                &origin,
            ]),
    )
    .await?;
    assert!(!non_monotonic.status.success());
    assert!(String::from_utf8_lossy(&non_monotonic.stderr)
        .contains("observation time must increase for each collector"));
    assert_eq!(state.ct_requests.load(Ordering::Relaxed), 1);

    let pool = storage::open_local(&db).await?;
    let observed: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT o.collector, a.canonical_key, o.scope_snapshot_id FROM observations o
         JOIN assets a ON a.id = o.asset_id ORDER BY o.collector",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        observed,
        [
            (
                "crtsh_loopback".to_owned(),
                format!("crt.{ROOT}"),
                SCOPE_ID.to_owned()
            ),
            (
                "subfinder".to_owned(),
                format!("sub.{ROOT}"),
                SCOPE_ID.to_owned()
            ),
        ]
    );
    let audit: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT t.tool, a.decision, json_extract(a.details_json, '$.count') FROM audit_events a
         JOIN tool_runs t ON t.id = json_extract(a.details_json, '$.tool_run_id')
         WHERE a.event_type = 'passive_candidate_gate' ORDER BY t.tool, a.decision",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        audit,
        [
            ("crtsh_loopback".to_owned(), "DENY".to_owned(), 1),
            ("crtsh_loopback".to_owned(), "UNKNOWN".to_owned(), 1),
            ("subfinder".to_owned(), "DENY".to_owned(), 1),
            ("subfinder".to_owned(), "UNKNOWN".to_owned(), 1),
        ]
    );
    let runs: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT t.id, t.tool, t.tool_version, t.tool_sha256 FROM tool_runs t
                        JOIN passive_runs r ON r.id = t.id ORDER BY t.tool",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[1].2, STUB_VERSION);
    assert_eq!(runs[1].3, digest);
    let finished_dispatches: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tool_runs t
         JOIN passive_runs r ON r.id = json_extract(t.exit_metadata_json, '$.capture_tool_run_id')
         WHERE t.finished_at IS NOT NULL AND t.tool = r.collector",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(finished_dispatches, 2);

    {
        let envelopes = state
            .summaries
            .lock()
            .map_err(|_| anyhow::anyhow!("control state unavailable"))?;
        assert_eq!(envelopes.len(), 4);
        for (index, envelope) in envelopes.iter().enumerate() {
            let ControlEvent::PassiveRunSummary(summary) = &envelope.payload else {
                anyhow::bail!("expected a signed run summary");
            };
            assert_eq!(summary.worker_id, "integration-worker");
            assert_eq!(summary.scope_snapshot_id.0, SCOPE_ID);
            assert_eq!(summary.run_id.0, runs[index % 2].0);
            assert_eq!(summary.completeness, CollectionCompleteness::Partial);
            assert_eq!(summary.deltas.new_assets, 1);
        }
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn live_dry_run_does_not_open_the_database() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let db = temp.path().join("inventory.sqlite");
    let result = output(
        worker()
            .args(["passive-sync", "--scope"])
            .arg(scope())
            .args(["--source", "crtsh", "--dry-run", "--db"])
            .arg(&db),
    )
    .await?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("--dry-run only accepts the fixture source"));
    assert!(!db.exists());
    Ok(())
}

#[tokio::test]
async fn wrong_subfinder_hash_records_a_partial_failure_without_observations() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let db = temp.path().join("inventory.sqlite");
    publish(&db).await?;
    let stub = make_stub(temp.path())?;
    let tools = manifest(temp.path(), &stub, &"0".repeat(64))?;
    let result = output(
        worker()
            .args(["passive-sync", "--scope"])
            .arg(scope())
            .arg("--db")
            .arg(&db)
            .args([
                "--source",
                "subfinder",
                "--run-key",
                "pin-mismatch",
                "--tools-manifest",
            ])
            .arg(&tools),
    )
    .await?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("invalid_manifest"));
    let reports = report_lines(&result)?;
    let report = reports.first().context("missing contained-run report")?;
    assert_eq!(report["failed_collections"], 1);
    assert_eq!(report["inventory"]["allowed"], 0);
    let pool = storage::open_local(&db).await?;
    let (runs, observations): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM tool_runs WHERE tool = 'subfinder'), (SELECT count(*) FROM observations)",
    ).fetch_one(&pool).await?;
    assert_eq!((runs, observations), (1, 0));
    Ok(())
}

#[derive(Default)]
struct PausedProvider {
    received: Notify,
    reply: Notify,
}

async fn paused_response(State(state): State<Arc<PausedProvider>>) -> Json<Value> {
    state.received.notify_one();
    state.reply.notified().await;
    Json(json!([{ "name_value": format!("stale.{ROOT}") }]))
}

#[tokio::test]
async fn a_revoked_snapshot_cannot_persist_a_response_in_flight() -> Result<()> {
    let state = Arc::new(PausedProvider::default());
    let provider = Router::new()
        .route("/", get(paused_response))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async { axum::serve(listener, provider).await });

    let temp = tempfile::tempdir()?;
    let db = temp.path().join("inventory.sqlite");
    publish(&db).await?;
    let mut command = worker();
    command
        .args(["passive-sync", "--scope"])
        .arg(scope())
        .arg("--db")
        .arg(&db)
        .args([
            "--source",
            "crtsh",
            "--run-key",
            "stale-capture",
            "--crtsh-loopback-origin",
        ])
        .arg(origin);
    let running = tokio::spawn(async move { output(&mut command).await });
    tokio::time::timeout(Duration::from_secs(5), state.received.notified()).await?;

    let replacement = temp.path().join("replacement.yaml");
    fs::write(
        &replacement,
        fs::read_to_string(scope())?.replace(
            &format!("id: {SCOPE_ID}"),
            &format!("id: lab-passive-live-v2\n  supersedes_id: {SCOPE_ID}"),
        ),
    )?;
    let publish = output(
        worker()
            .args(["publish-scope", "--scope"])
            .arg(&replacement)
            .arg("--db")
            .arg(&db),
    )
    .await?;
    assert!(publish.status.success());
    state.reply.notify_one();

    let result = running.await??;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("scope revision is inactive"));
    assert!(report_lines(&result)?.is_empty());
    let pool = storage::open_local(&db).await?;
    let (dispatches, captures, observations): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit_events a JOIN tool_runs t
                 ON t.id = json_extract(a.details_json, '$.tool_run_id')
                 WHERE a.event_type = 'passive_dispatch_gate' AND t.finished_at IS NOT NULL),
                (SELECT count(*) FROM passive_runs), (SELECT count(*) FROM observations)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!((dispatches, captures, observations), (1, 0, 0));
    server.abort();
    Ok(())
}
