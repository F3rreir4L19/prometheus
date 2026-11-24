use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use clap::Args;
use domain::{CollectionCompleteness, DeltaCounts};
use intel::passive::{
    filter_discovery_index, filter_inventory, SelectionCounts, MAX_DISCOVERY_BYTES,
    MAX_INVENTORY_BYTES,
};
use scope_engine::ScopeEngine;
use serde::Serialize;
use storage::{
    active_snapshot_id, open_local, publish_reviewed_scope, record_passive_run, unix_time_seconds,
    PassiveRunInput,
};

use crate::control::ControlSender;

const MAX_SCOPE_BYTES: usize = 1024 * 1024;

#[derive(Args)]
pub struct SyncArgs {
    #[arg(long)]
    scope: PathBuf,
    #[arg(long, visible_alias = "fixture")]
    inventory: Option<PathBuf>,
    #[arg(long)]
    discovery_index: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    db: Option<PathBuf>,
    /// Stable identifier for this inventory capture and its retries.
    #[arg(long)]
    run_key: Option<String>,
    /// UTC Unix seconds when the inventory was captured.
    #[arg(long)]
    observed_at: Option<u64>,
    /// Attest that the input covers the complete local inventory for this revision.
    #[arg(long, requires = "inventory")]
    complete: bool,
    /// Control service origin used to deliver the signed aggregate summary.
    #[arg(long, conflicts_with = "dry_run")]
    control_url: Option<String>,
}

#[derive(Serialize)]
struct SyncReport<'a> {
    scope_snapshot_id: &'a str,
    scope_blake3: &'a str,
    dry_run: bool,
    inventory: SelectionCounts,
    discovery: Option<SelectionCounts>,
    completeness: CollectionCompleteness,
    deltas: DeltaCounts,
    replayed: bool,
}

pub async fn publish_scope(scope: &Path, db: &Path) -> Result<()> {
    let engine = read_scope(scope)?;
    let pool = open_local(db).await?;
    let publication = publish_reviewed_scope(&pool, &engine, unix_time_seconds).await?;
    println!(
        "{}",
        serde_json::json!({
            "scope_snapshot_id": engine.snapshot_id().0,
            "scope_blake3": engine.source_hash().to_hex().as_str(),
            "published": publication.is_some(),
        })
    );
    Ok(())
}

pub async fn sync(args: SyncArgs) -> Result<()> {
    let engine = read_scope(&args.scope)?;
    let now = unix_time_seconds()?;
    let policy = engine.snapshot();
    ensure!(
        (policy.valid_from..policy.expires_at).contains(&now),
        "the scope revision is not currently valid"
    );
    let inventory = args
        .inventory
        .as_deref()
        .map(|path| read_bounded(path, MAX_INVENTORY_BYTES))
        .transpose()?
        .unwrap_or_default();

    let pool = if args.dry_run {
        None
    } else {
        ensure!(
            args.inventory.is_some(),
            "--inventory is required for persistence"
        );
        ensure!(
            args.run_key.is_some(),
            "--run-key is required for persistence"
        );
        ensure!(
            args.observed_at.is_some(),
            "--observed-at is required for persistence"
        );
        let db = args
            .db
            .as_deref()
            .context("--db is required for persistence")?;
        ensure!(
            fs::metadata(db).is_ok_and(|metadata| metadata.is_file()),
            "publish the reviewed scope to the local database first"
        );
        Some(open_local(db).await?)
    };

    let snapshot = match &pool {
        Some(pool) => active_snapshot_id(pool, &policy.program_id, now)
            .await?
            .context("no currently valid scope revision has been published")?,
        None => engine.snapshot_id().clone(),
    };
    ensure!(
        snapshot == *engine.snapshot_id(),
        "the input scope revision is no longer active"
    );
    let selection = filter_inventory(&inventory, &engine, &snapshot, now)?;
    let discovery = args
        .discovery_index
        .as_deref()
        .map(|path| {
            let bytes = read_bounded(path, MAX_DISCOVERY_BYTES)?;
            Ok::<_, anyhow::Error>(filter_discovery_index(&bytes, &engine, &snapshot, now)?.counts)
        })
        .transpose()?;
    let completeness = if args.complete && selection.counts.malformed == 0 {
        CollectionCompleteness::Complete
    } else {
        CollectionCompleteness::Partial
    };

    let mut deltas = DeltaCounts::default();
    let mut replayed = false;
    let mut run_id = None;
    let sender = args
        .control_url
        .as_deref()
        .map(ControlSender::new)
        .transpose()?;
    if let Some(pool) = &pool {
        let run = record_passive_run(
            pool,
            &engine,
            PassiveRunInput {
                run_key: args.run_key.as_deref().context("missing run key")?,
                observed_at: args.observed_at.context("missing observation time")?,
                completeness,
                domains: &selection.domains,
            },
            unix_time_seconds,
        )
        .await?;
        replayed = run.replayed;
        run_id = Some(run.run_id);
        for event in run.deltas {
            deltas.record(event.kind);
        }
    }

    let digest = engine.source_hash().to_hex();
    println!(
        "{}",
        serde_json::to_string(&SyncReport {
            scope_snapshot_id: &snapshot.0,
            scope_blake3: digest.as_str(),
            dry_run: args.dry_run,
            inventory: selection.counts,
            discovery,
            completeness,
            deltas,
            replayed,
        })?
    );
    if let Some(sender) = sender {
        sender
            .summary(
                run_id.context("missing persisted run ID")?,
                snapshot,
                completeness,
                deltas,
            )
            .await?;
    }
    Ok(())
}

fn read_scope(path: &Path) -> Result<ScopeEngine> {
    let document = read_bounded(path, MAX_SCOPE_BYTES)?;
    Ok(ScopeEngine::from_yaml(&document)?)
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{open, Mode, OFlags};
        File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .context("could not open local input")?,
        )
    };
    #[cfg(not(unix))]
    let file = File::open(path).context("could not open local input")?;
    ensure!(
        file.metadata().is_ok_and(|metadata| metadata.is_file()),
        "input must be a readable local regular file"
    );
    let mut bytes = Vec::new();
    file.take(u64::try_from(max_bytes)? + 1)
        .read_to_end(&mut bytes)
        .context("could not read local input")?;
    ensure!(
        bytes.len() <= max_bytes,
        "local input exceeds its size limit"
    );
    Ok(bytes)
}
