use std::{cell::RefCell, collections::BTreeSet, fs::File, path::Path, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use domain::{
    Action, CollectionCompleteness, DeltaCounts, Effect, PassiveSource, ScopeSnapshotId,
    TargetKind, ToolRunId,
};
use intel::passive::{filter_live_candidates, SelectionCounts};
use runner::{
    CollectionError, CollectionGate, CrtshCollector, PassiveCollector, PassiveRateLimiter,
    PassiveRequest, SubfinderCollector, ToolManifest,
};
use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
use rustix::time::{clock_gettime, ClockId};
use scope_engine::{canonicalize_domain, ScopeEngine};
use serde::Serialize;
use sqlx::SqlitePool;
use storage::{
    admit_passive_collection, defer_passive_provider, finish_passive_dispatch,
    last_collector_observed_at, open_local, record_collector_run, replay_collector_run,
    unix_time_millis, unix_time_seconds, LiveRunAudit, LiveRunProvenance, LiveTool,
    PassiveRateTime, PassiveRunInput, PassiveRunResult, StorageError, MAX_INVENTORY_DOMAINS,
};

use super::{
    active_snapshot_at, database_path, read_bounded, read_discovery, read_scope, sync_fixture,
    SyncArgs, SyncSource,
};
use crate::control::ControlSender;

const MAX_TOOL_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_SEEDS: usize = 32;
const MAX_CONSECUTIVE_FAILURES: usize = 3;
const COMPLETENESS: CollectionCompleteness = CollectionCompleteness::Partial;

#[derive(Serialize)]
struct LiveReport<'a> {
    scope_snapshot_id: &'a str,
    scope_blake3: &'a str,
    source: &'static str,
    dry_run: bool,
    inventory: SelectionCounts,
    discovery: &'a Option<SelectionCounts>,
    completeness: CollectionCompleteness,
    deltas: DeltaCounts,
    replayed: bool,
    failed_collections: usize,
}

pub(super) async fn sync(args: &SyncArgs) -> Result<()> {
    ensure!(
        args.inventory.is_none() || args.source == SyncSource::All,
        "--inventory requires the fixture or all source"
    );
    let run_key = args
        .run_key
        .as_deref()
        .context("--run-key is required for persistence")?;
    let engine = read_scope(&args.scope)?;
    let db = database_path(args)?;
    let _live_lock = lock_database(db)?;
    let pool = open_local(db).await?;
    let now = unix_time_seconds()?;
    let snapshot = active_snapshot_at(&pool, &engine, now).await?;
    ensure!(
        engine.snapshot().passive_live.is_some(),
        "live collection requires passive_live in the published scope"
    );
    let requests = reviewed_seeds(&engine, &snapshot, now)?;
    let loopback = args.crtsh_loopback_origin.is_some();
    if loopback {
        ensure_synthetic_scope(&engine)?;
    }
    let discovery = read_discovery(args, &engine, &snapshot, now)?;
    let sender = args
        .control_url
        .as_deref()
        .map(ControlSender::new)
        .transpose()?;
    ensure!(
        !loopback || sender.as_ref().is_none_or(ControlSender::is_local),
        "crt.sh loopback requires a local control service"
    );
    let limiter = Arc::new(PassiveRateLimiter::new());
    let context = LiveSync {
        args,
        snapshot: &snapshot,
        run_key,
        gate: PublishedScope {
            pool: &pool,
            engine: &engine,
            boot_id: boot_id()?,
        },
        requests,
        discovery,
        sender,
        limiter,
    };

    let mut failed_sources = 0;
    if args.source == SyncSource::All && args.inventory.is_some() {
        failed_sources += report_failure("fixture", sync_fixture(args).await);
    }
    for &source in selected_sources(args.source, loopback) {
        failed_sources += report_failure(source.as_str(), context.run(source).await);
    }
    ensure!(
        failed_sources == 0,
        "{failed_sources} passive source(s) failed"
    );
    Ok(())
}

fn selected_sources(source: SyncSource, loopback: bool) -> &'static [PassiveSource] {
    match (source, loopback) {
        (SyncSource::Fixture, _) => &[],
        (SyncSource::Subfinder, _) => &[PassiveSource::Subfinder],
        (SyncSource::Crtsh, false) => &[PassiveSource::Crtsh],
        (SyncSource::Crtsh, true) => &[PassiveSource::CrtshLoopback],
        (SyncSource::All, false) => &[PassiveSource::Crtsh, PassiveSource::Subfinder],
        (SyncSource::All, true) => &[PassiveSource::CrtshLoopback, PassiveSource::Subfinder],
    }
}

fn ensure_synthetic_scope(engine: &ScopeEngine) -> Result<()> {
    for rule in &engine.snapshot().rules {
        if rule.effect != Effect::Allow || !rule.actions.contains(&Action::Passive) {
            continue;
        }
        let raw = match rule.kind {
            TargetKind::Domain => rule.target.as_str(),
            TargetKind::Wildcard => rule.target.strip_prefix("*.").unwrap_or(&rule.target),
            _ => continue,
        };
        ensure!(
            canonicalize_domain(raw).is_some_and(|domain| domain.ends_with(".test")),
            "crt.sh loopback requires a synthetic .test scope"
        );
    }
    Ok(())
}

fn report_failure(source: &str, result: Result<()>) -> usize {
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{source}: {error}");
            1
        }
    }
}

fn lock_database(path: &Path) -> Result<File> {
    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("could not open the existing local database for collection")?,
    );
    ensure!(
        file.metadata().is_ok_and(|metadata| metadata.is_file()),
        "collection requires a local regular database file"
    );
    // SQLite uses fcntl byte-range locks on Linux. This flock serializes live CLI invocations
    // across processes without blocking SQLite writers such as publish-scope.
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .context("could not obtain the live collection lock for the local database")?;
    Ok(file)
}

fn reviewed_seeds<'a>(
    engine: &'a ScopeEngine,
    snapshot: &'a ScopeSnapshotId,
    now: u64,
) -> Result<Vec<PassiveRequest<'a>>> {
    let domains = engine
        .snapshot()
        .rules
        .iter()
        .filter(|rule| {
            rule.effect == Effect::Allow
                && rule.kind == TargetKind::Domain
                && rule.actions.contains(&Action::Passive)
        })
        .filter_map(|rule| canonicalize_domain(&rule.target))
        .collect::<BTreeSet<_>>();
    let requests: Vec<_> = domains
        .iter()
        .filter_map(|domain| PassiveRequest::new(engine, snapshot, now, domain).ok())
        .take(MAX_SEEDS + 1)
        .collect();
    ensure!(
        !requests.is_empty(),
        "live collection requires an allowed exact passive domain"
    );
    ensure!(
        requests.len() <= MAX_SEEDS,
        "live collection exceeds the reviewed domain limit"
    );
    Ok(requests)
}

struct PublishedScope<'a> {
    pool: &'a SqlitePool,
    engine: &'a ScopeEngine,
    boot_id: String,
}

impl PublishedScope<'_> {
    fn rate_time(&self) -> Result<PassiveRateTime<'_>, StorageError> {
        let uptime = clock_gettime(ClockId::Boottime);
        let seconds = u64::try_from(uptime.tv_sec)?;
        let nanos = u64::try_from(uptime.tv_nsec)?;
        Ok(PassiveRateTime {
            boot_id: &self.boot_id,
            elapsed_ms: seconds
                .saturating_mul(1_000)
                .saturating_add(nanos / 1_000_000),
            unix_ms: unix_time_millis()?,
        })
    }
}

fn boot_id() -> Result<String> {
    let bytes = read_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 64)
        .context("could not read the kernel boot identity for rate limiting")?;
    let id = std::str::from_utf8(&bytes)?.trim_ascii();
    ensure!(
        id.len() == 36
            && id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "invalid kernel boot identity"
    );
    Ok(id.to_owned())
}

struct DispatchGate<'a> {
    scope: &'a PublishedScope<'a>,
    source: PassiveSource,
    tool: LiveTool<'a>,
    run_key: &'a str,
    attempt: RefCell<Option<ToolRunId>>,
}

impl CollectionGate for DispatchGate<'_> {
    async fn check(
        &self,
        request: &PassiveRequest<'_>,
        source: PassiveSource,
    ) -> Result<(), CollectionError> {
        if source != self.source || self.attempt.borrow().is_some() {
            return Err(CollectionError::PolicyHold);
        }
        let attempt = admit_passive_collection(
            self.scope.pool,
            self.scope.engine,
            request.seed(),
            self.tool,
            self.run_key,
            || self.scope.rate_time(),
        )
        .await
        .map_err(gate_error)?;
        self.attempt.replace(Some(attempt));
        Ok(())
    }

    async fn defer_provider(
        &self,
        _request: &PassiveRequest<'_>,
        source: PassiveSource,
        delay: Duration,
    ) -> Result<(), CollectionError> {
        defer_passive_provider(self.scope.pool, source, delay, || self.scope.rate_time())
            .await
            .map_err(gate_error)
    }
}

fn gate_error(error: StorageError) -> CollectionError {
    match error {
        StorageError::PassiveRateLimited => CollectionError::Admission,
        _ => CollectionError::PolicyHold,
    }
}

struct LiveSync<'a> {
    args: &'a SyncArgs,
    snapshot: &'a ScopeSnapshotId,
    run_key: &'a str,
    gate: PublishedScope<'a>,
    requests: Vec<PassiveRequest<'a>>,
    discovery: Option<SelectionCounts>,
    sender: Option<ControlSender>,
    limiter: Arc<PassiveRateLimiter>,
}

impl LiveSync<'_> {
    async fn run(&self, source: PassiveSource) -> Result<()> {
        if let Some(replay) = replay_collector_run(
            self.gate.pool,
            self.gate.engine,
            source,
            self.run_key,
            unix_time_seconds,
        )
        .await?
        {
            return self
                .finish(source, replay.result, replay.audit, replay.present_count)
                .await;
        }

        let (started_at, observed_at) = self.capture_time(source).await?;
        match source {
            PassiveSource::Crtsh => {
                let collector = CrtshCollector::new(self.limiter.clone());
                self.collect(source, LiveTool::Crtsh, collector, started_at, observed_at)
                    .await
            }
            PassiveSource::CrtshLoopback => {
                let collector = self
                    .args
                    .crtsh_loopback_origin
                    .as_deref()
                    .and_then(|origin| url::Url::parse(origin).ok())
                    .ok_or(CollectionError::Configuration)
                    .and_then(|origin| CrtshCollector::with_loopback(self.limiter.clone(), origin));
                self.collect(
                    source,
                    LiveTool::CrtshLoopback,
                    collector,
                    started_at,
                    observed_at,
                )
                .await
            }
            PassiveSource::Subfinder => {
                let manifest_path = self
                    .args
                    .tools_manifest
                    .as_deref()
                    .context("--tools-manifest is required for the subfinder source")?;
                let content = read_bounded(manifest_path, MAX_TOOL_MANIFEST_BYTES)?;
                let manifest: ToolManifest = serde_yaml::from_slice(&content)
                    .map_err(|_| CollectionError::InvalidManifest)?;
                let pin = manifest.into_subfinder()?;
                let version = pin.version().to_owned();
                let sha256 = pin.sha256_hex();
                let tool = LiveTool::Subfinder {
                    version: &version,
                    sha256: &sha256,
                };
                let collector = SubfinderCollector::new(pin, self.limiter.clone());
                self.collect(source, tool, collector, started_at, observed_at)
                    .await
            }
            PassiveSource::Fixture => anyhow::bail!("fixture collection uses a local input"),
        }
    }

    async fn capture_time(&self, source: PassiveSource) -> Result<(u64, u64)> {
        let previous =
            last_collector_observed_at(self.gate.pool, self.gate.engine, source, unix_time_seconds)
                .await?;
        let mut started_at = unix_time_seconds()?;
        if self.args.observed_at.is_none() && previous == Some(started_at) {
            // Inventory timestamps are whole seconds. Wait through the current second before
            // spending a rate permit for a capture that would collide with the preceding run.
            tokio::time::sleep(Duration::from_secs(1)).await;
            started_at = unix_time_seconds()?;
        }
        let observed_at = self.args.observed_at.unwrap_or(started_at);
        let policy = self.gate.engine.snapshot();
        ensure!(
            (policy.valid_from..policy.expires_at).contains(&started_at)
                && (policy.valid_from..=started_at).contains(&observed_at),
            "observation time is outside the current scope capture window"
        );
        ensure!(
            previous.is_none_or(|previous| observed_at > previous),
            "observation time must increase for each collector"
        );
        Ok((started_at, observed_at))
    }

    async fn collect(
        &self,
        source: PassiveSource,
        tool: LiveTool<'_>,
        collector: Result<impl PassiveCollector, CollectionError>,
        started_at: u64,
        observed_at: u64,
    ) -> Result<()> {
        let mut batch = SourceBatch::default();
        match collector {
            Ok(collector) => {
                let gate = DispatchGate {
                    scope: &self.gate,
                    source,
                    tool,
                    run_key: self.run_key,
                    attempt: RefCell::new(None),
                };
                let mut consecutive_failures = 0;
                for request in &self.requests {
                    let failures_before = batch.audit.failed_collections;
                    let result = collector.collect(request, &gate).await;
                    if let Some(attempt) = gate.attempt.take() {
                        finish_passive_dispatch(
                            self.gate.pool,
                            &attempt,
                            result.is_ok(),
                            unix_time_seconds()?,
                        )
                        .await?;
                    }
                    match result {
                        Ok(output) => {
                            let selection = filter_live_candidates(
                                &output.candidates,
                                output.malformed,
                                self.gate.engine,
                                self.snapshot,
                                unix_time_seconds()?,
                            )?;
                            if batch.add(selection) {
                                batch.failed(source, "inventory_limit");
                            }
                        }
                        Err(error) => {
                            batch.failed(source, error.status());
                            if matches!(
                                error,
                                CollectionError::PolicyHold | CollectionError::InvalidManifest
                            ) {
                                break;
                            }
                        }
                    }
                    if batch.audit.failed_collections == failures_before {
                        consecutive_failures = 0;
                    } else {
                        consecutive_failures += 1;
                        if consecutive_failures == MAX_CONSECUTIVE_FAILURES {
                            break;
                        }
                    }
                }
            }
            Err(error) => batch.failed(source, error.status()),
        }

        let domains: Vec<_> = batch.domains.into_iter().collect();
        let result = record_collector_run(
            self.gate.pool,
            self.gate.engine,
            PassiveRunInput {
                run_key: self.run_key,
                observed_at,
                completeness: COMPLETENESS,
                domains: &domains,
            },
            LiveRunProvenance {
                tool,
                started_at,
                audit: batch.audit,
            },
            unix_time_seconds,
        )
        .await?;
        self.finish(source, result, batch.audit, domains.len())
            .await
    }

    async fn finish(
        &self,
        source: PassiveSource,
        run: PassiveRunResult,
        audit: LiveRunAudit,
        present_count: usize,
    ) -> Result<()> {
        let mut deltas = DeltaCounts::default();
        for event in run.deltas {
            deltas.record(event.kind);
        }
        let digest = self.gate.engine.source_hash().to_hex();
        let inventory = SelectionCounts {
            allowed: present_count,
            denied: audit.denied,
            unknown: audit.unknown,
            duplicates: audit.duplicates,
            malformed: audit.malformed,
        };
        println!(
            "{}",
            serde_json::to_string(&LiveReport {
                scope_snapshot_id: &self.snapshot.0,
                scope_blake3: digest.as_str(),
                source: source.as_str(),
                dry_run: false,
                inventory,
                discovery: &self.discovery,
                completeness: COMPLETENESS,
                deltas,
                replayed: run.replayed,
                failed_collections: audit.failed_collections,
            })?
        );
        if let Some(sender) = &self.sender {
            let snapshot =
                active_snapshot_at(self.gate.pool, self.gate.engine, unix_time_seconds()?).await?;
            sender
                .summary(run.run_id, snapshot, COMPLETENESS, deltas)
                .await?;
        }
        ensure!(
            audit.failed_collections == 0,
            "passive collection recorded partial failures"
        );
        Ok(())
    }
}

#[derive(Default)]
struct SourceBatch {
    domains: BTreeSet<String>,
    audit: LiveRunAudit,
}

impl SourceBatch {
    fn add(&mut self, selection: intel::passive::InventorySelection) -> bool {
        self.audit.denied += selection.counts.denied;
        self.audit.unknown += selection.counts.unknown;
        self.audit.malformed += selection.counts.malformed;
        self.audit.duplicates += selection.counts.duplicates;
        let mut truncated = false;
        for domain in selection.domains {
            if self.domains.len() < MAX_INVENTORY_DOMAINS {
                self.audit.duplicates += usize::from(!self.domains.insert(domain));
            } else if self.domains.contains(&domain) {
                self.audit.duplicates += 1;
            } else {
                truncated = true;
            }
        }
        truncated
    }

    fn failed(&mut self, source: PassiveSource, status: &str) {
        self.audit.failed_collections += 1;
        eprintln!("{} collection: {status}", source.as_str());
    }
}
