use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, ensure, Result};
use clap::Args;
use control_protocol::{
    valid_identifier, ControlEvent, PassiveRunSummary, SignedEnvelope, WorkerHeartbeat,
    MIN_KEY_BYTES,
};
use domain::{CollectionCompleteness, DeltaCounts, ScopeSnapshotId, ToolRunId};
use reqwest::{Client, StatusCode, Url};

#[derive(Args)]
pub struct HeartbeatArgs {
    #[arg(long)]
    control_url: String,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=3600))]
    interval_secs: u64,
    /// Send one heartbeat and exit.
    #[arg(long)]
    once: bool,
}

pub struct ControlSender {
    client: Client,
    endpoint: Url,
    worker_id: String,
    key_id: String,
    key: Vec<u8>,
}

impl ControlSender {
    #[cfg(target_os = "linux")]
    pub(crate) fn is_local(&self) -> bool {
        self.endpoint.scheme() == "http"
    }

    pub fn new(origin: &str) -> Result<Self> {
        let endpoint = event_endpoint(origin)?;
        let worker_id =
            env::var("PROMETHEUS_WORKER_ID").map_err(|_| anyhow!("missing worker identity"))?;
        let key_id =
            env::var("PROMETHEUS_CONTROL_KEY_ID").map_err(|_| anyhow!("missing control key ID"))?;
        let key = env::var("PROMETHEUS_CONTROL_KEY")
            .map_err(|_| anyhow!("missing control signing key"))?
            .into_bytes();
        ensure!(
            valid_identifier(&key_id) && valid_identifier(&worker_id),
            "invalid worker or control key ID"
        );
        ensure!(
            key.len() >= MIN_KEY_BYTES,
            "control signing key is too short"
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| anyhow!("could not configure control transport"))?;
        Ok(Self {
            client,
            endpoint,
            worker_id,
            key_id,
            key,
        })
    }

    async fn heartbeat(&self) -> Result<()> {
        let (issued_at, sequence) = event_time()?;
        self.post(ControlEvent::Heartbeat(WorkerHeartbeat {
            worker_id: self.worker_id.clone(),
            issued_at,
            sequence,
        }))
        .await
    }

    pub async fn summary(
        &self,
        run_id: ToolRunId,
        scope_snapshot_id: ScopeSnapshotId,
        completeness: CollectionCompleteness,
        deltas: DeltaCounts,
    ) -> Result<()> {
        let (issued_at, sequence) = event_time()?;
        self.post(ControlEvent::PassiveRunSummary(PassiveRunSummary {
            worker_id: self.worker_id.clone(),
            issued_at,
            sequence,
            run_id,
            scope_snapshot_id,
            completeness,
            deltas,
        }))
        .await
    }

    async fn post(&self, event: ControlEvent) -> Result<()> {
        let envelope = SignedEnvelope::sign(self.key_id.clone(), event, &self.key)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&envelope)
            .send()
            .await
            .map_err(|_| anyhow!("control service could not be reached"))?;
        ensure!(
            response.status() == StatusCode::NO_CONTENT,
            "control service rejected the signed event ({})",
            response.status().as_u16()
        );
        Ok(())
    }
}

pub async fn heartbeat(args: HeartbeatArgs) -> Result<()> {
    let sender = ControlSender::new(&args.control_url)?;
    if args.once {
        return sender.heartbeat().await;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(args.interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if sender.heartbeat().await.is_err() {
            eprintln!("heartbeat delivery failed");
        }
    }
}

fn event_time() -> Result<(u64, u64)> {
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok((epoch.as_secs(), u64::try_from(epoch.as_micros())?))
}

fn event_endpoint(origin: &str) -> Result<Url> {
    let mut url = Url::parse(origin).map_err(|_| anyhow!("invalid control service origin"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    ensure!(
        (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "control service must be an HTTPS origin or numeric HTTP loopback origin without credentials"
    );
    url.set_path("/v1/worker-events");
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_eligible_control_origins_are_accepted() -> Result<()> {
        assert_eq!(
            event_endpoint("http://127.0.0.1:8000")?.path(),
            "/v1/worker-events"
        );
        assert!(event_endpoint("http://[::1]:8000").is_ok());
        assert!(event_endpoint("https://control.example.test").is_ok());
        for origin in [
            "http://control.example.test",
            "https://user:sample@control.example.test",
            "https://control.example.test/?sample=1",
            "https://control.example.test/alternate",
        ] {
            assert!(event_endpoint(origin).is_err());
        }
        Ok(())
    }
}
