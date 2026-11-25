use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use domain::{Action, Decision};
use scope_engine::{ScopeEngine, Verdict};
use serde::Serialize;

mod control;
mod passive;

#[derive(Parser)]
#[command(about = "Prometheus scope audit and local asset inventory")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(long_flag = "shadow-mode")]
    ShadowMode {
        #[arg(long)]
        scope: PathBuf,
        #[arg(long)]
        targets: PathBuf,
        #[arg(long, value_enum)]
        action: CliAction,
    },
    /// Publish a reviewed YAML revision as the active policy for its program.
    PublishScope {
        #[arg(long)]
        scope: PathBuf,
        #[arg(long)]
        db: PathBuf,
    },
    /// Synchronize a local or passive provider inventory and calculate deltas.
    PassiveSync(passive::SyncArgs),
    /// Send periodic signed heartbeats to the control plane.
    Heartbeat(control::HeartbeatArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum CliAction {
    Passive,
    Dns,
    Http,
    Crawl,
    SafeScan,
    Oob,
}

impl From<CliAction> for Action {
    fn from(action: CliAction) -> Self {
        match action {
            CliAction::Passive => Self::Passive,
            CliAction::Dns => Self::Dns,
            CliAction::Http => Self::Http,
            CliAction::Crawl => Self::Crawl,
            CliAction::SafeScan => Self::SafeScan,
            CliAction::Oob => Self::Oob,
        }
    }
}

#[derive(Serialize)]
struct AuditRow<'a> {
    scope_snapshot_id: &'a str,
    scope_blake3: &'a str,
    evaluated_at: u64,
    action: Action,
    line: usize,
    hop: usize,
    #[serde(flatten)]
    verdict: Verdict<'a>,
}

#[derive(Default, Serialize)]
struct Summary {
    allow: usize,
    deny: usize,
    unknown: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let Cli { command } = Cli::parse();
    match command {
        Command::ShadowMode {
            scope,
            targets,
            action,
        } => shadow(&scope, &targets, action.into()),
        Command::PublishScope { scope, db } => passive::publish_scope(&scope, &db).await,
        Command::PassiveSync(args) => passive::sync(args).await,
        Command::Heartbeat(args) => control::heartbeat(args).await,
    }
}

fn shadow(scope: &Path, targets: &Path, action: Action) -> Result<()> {
    let document = fs::read(scope).context("could not read the scope document")?;
    let engine = ScopeEngine::from_yaml(&document)?;
    let hash = engine.source_hash().to_hex();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let targets = BufReader::new(File::open(targets).context("could not open target input")?);
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut summary = Summary::default();

    for (index, raw) in targets.split(b'\n').enumerate() {
        let raw = raw.context("could not read target input")?;
        let parsed = std::str::from_utf8(&raw).ok().map(str::trim);
        if parsed.is_some_and(|line| line.is_empty() || line.starts_with('#')) {
            continue;
        }
        let legs = parsed.unwrap_or("").split(" -> ");
        for (hop, target) in legs.enumerate() {
            let verdict = if hop == 0 {
                engine.evaluate(engine.snapshot_id(), now, action, target)
            } else {
                engine.evaluate_redirect_hop(engine.snapshot_id(), now, action, target)
            };
            let allowed = verdict.is_allowed();
            match verdict.decision {
                Decision::Allow => summary.allow += 1,
                Decision::Deny => summary.deny += 1,
                Decision::Unknown => summary.unknown += 1,
            }
            serde_json::to_writer(
                &mut out,
                &AuditRow {
                    scope_snapshot_id: &engine.snapshot_id().0,
                    scope_blake3: hash.as_str(),
                    evaluated_at: now,
                    action,
                    line: index + 1,
                    hop,
                    verdict,
                },
            )?;
            writeln!(out)?;
            if !allowed {
                break;
            }
        }
    }
    writeln!(out, "{{\"summary\":{}}}", serde_json::to_string(&summary)?)?;
    out.flush()?;
    Ok(())
}
