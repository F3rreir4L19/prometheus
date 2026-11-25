use std::{env, future, net::SocketAddr};

use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, Subcommand};
use prometheus_control::{drain_notifications, ControlPlane, Telegram};

#[derive(Parser)]
#[command(about = "Prometheus read-only control plane")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the local control API and monitor worker liveness.
    Serve {
        /// Bind the control API to a loopback address.
        #[arg(long, default_value = "127.0.0.1:8765")]
        listen: SocketAddr,
        #[arg(long, default_value_t = 45, value_parser = clap::value_parser!(u64).range(2..=3600))]
        ttl_secs: u64,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Some(Command::Serve { listen, ttl_secs }) => serve(listen, ttl_secs).await,
        None => {
            println!("prometheus-control: offline bootstrap");
            Ok(())
        }
    }
}

async fn serve(listen: SocketAddr, ttl_secs: u64) -> Result<()> {
    ensure!(
        listen.ip().is_loopback(),
        "control API requires a loopback listener"
    );
    let worker =
        env::var("PROMETHEUS_WORKER_ID").map_err(|_| anyhow!("missing worker identity"))?;
    let key_id =
        env::var("PROMETHEUS_CONTROL_KEY_ID").map_err(|_| anyhow!("missing control key ID"))?;
    let key =
        env::var("PROMETHEUS_CONTROL_KEY").map_err(|_| anyhow!("missing control signing key"))?;
    let (plane, notices) = ControlPlane::new(worker, key_id, key.into_bytes(), ttl_secs)?;
    let telegram = Telegram::from_environment()?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("could not bind control listener")?;
    let poll = async {
        match telegram.as_ref() {
            Some(telegram) => telegram.poll().await,
            None => future::pending().await,
        }
    };
    tokio::select! {
        result = axum::serve(listener, plane.router()) => result.context("control listener failed"),
        _ = plane.watchdog() => Ok(()),
        _ = drain_notifications(notices, telegram.as_ref()) => Ok(()),
        _ = poll => Ok(()),
    }
}
