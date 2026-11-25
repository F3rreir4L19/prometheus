use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use control_protocol::{
    valid_identifier, ControlEvent, PassiveRunSummary, SignedEnvelope, MIN_KEY_BYTES,
};
use thiserror::Error;
use tokio::{sync::mpsc, time::Instant};

use crate::{health_router, Notice, NoticeReceivers};

const MAX_EVENT_BYTES: usize = 4096;
const SUMMARY_CAPACITY: usize = 32;
const WATCHDOG_CAPACITY: usize = 4;
const RUN_DEDUP_LIMIT: usize = 1024;
const RUN_DEDUP_WINDOW: Duration = Duration::from_secs(3600);

#[derive(Debug, Error)]
pub enum ControlSettingsError {
    #[error("invalid worker or control key ID")]
    Identity,
    #[error("control signing key is too short")]
    Key,
    #[error("heartbeat TTL must be between 2 and 3600 seconds")]
    Ttl,
    #[error("clock is outside the supported Unix range")]
    Clock,
}

#[derive(Clone)]
pub struct ControlPlane(Arc<ControlState>);

struct ControlState {
    worker_id: String,
    key_id: String,
    key: Vec<u8>,
    ttl_secs: u64,
    started_at: u64,
    status: Mutex<WorkerStatus>,
    summaries: mpsc::Sender<Notice>,
    watchdog_notices: mpsc::Sender<Notice>,
}

struct WorkerStatus {
    heartbeat_order: Option<(u64, u64)>,
    heartbeat_deadline: Instant,
    reported_missing: bool,
    seen_runs: VecDeque<(Instant, PassiveRunSummary)>,
}

impl ControlPlane {
    pub fn new(
        worker_id: String,
        key_id: String,
        key: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<(Self, NoticeReceivers), ControlSettingsError> {
        Self::at(
            worker_id,
            key_id,
            key,
            ttl_secs,
            unix_now()?,
            Instant::now(),
        )
    }

    fn at(
        worker_id: String,
        key_id: String,
        key: Vec<u8>,
        ttl_secs: u64,
        started_at: u64,
        started_instant: Instant,
    ) -> Result<(Self, NoticeReceivers), ControlSettingsError> {
        if !valid_identifier(&worker_id) || !valid_identifier(&key_id) {
            return Err(ControlSettingsError::Identity);
        }
        if key.len() < MIN_KEY_BYTES {
            return Err(ControlSettingsError::Key);
        }
        if !(2..=3600).contains(&ttl_secs) {
            return Err(ControlSettingsError::Ttl);
        }
        let (summaries, summary_receiver) = mpsc::channel(SUMMARY_CAPACITY);
        let (watchdog_notices, watchdog_receiver) = mpsc::channel(WATCHDOG_CAPACITY);
        let status = WorkerStatus {
            heartbeat_order: None,
            heartbeat_deadline: started_instant + Duration::from_secs(ttl_secs),
            reported_missing: false,
            seen_runs: VecDeque::new(),
        };
        Ok((
            Self(Arc::new(ControlState {
                worker_id,
                key_id,
                key,
                ttl_secs,
                started_at,
                status: Mutex::new(status),
                summaries,
                watchdog_notices,
            })),
            NoticeReceivers {
                summaries: summary_receiver,
                watchdog: watchdog_receiver,
            },
        ))
    }

    pub fn router(&self) -> Router {
        health_router().merge(
            Router::new()
                .route("/v1/worker-events", post(ingest))
                .layer(DefaultBodyLimit::max(MAX_EVENT_BYTES))
                .with_state(self.clone()),
        )
    }

    pub async fn watchdog(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Ok(mut status) = self.0.status.lock() {
                self.check_deadline(&mut status, Instant::now());
            }
        }
    }

    fn receive_at(&self, envelope: SignedEnvelope, now: u64, instant: Instant) -> StatusCode {
        let state = &self.0;
        if envelope.key_id != state.key_id || envelope.verify(&state.key).is_err() {
            return StatusCode::UNAUTHORIZED;
        }
        let (worker_id, issued_at, sequence) = match &envelope.payload {
            ControlEvent::Heartbeat(event) => (&event.worker_id, event.issued_at, event.sequence),
            ControlEvent::PassiveRunSummary(event) => {
                if !valid_identifier(&event.scope_snapshot_id.0)
                    || !valid_identifier(&event.run_id.0)
                {
                    return StatusCode::BAD_REQUEST;
                }
                (&event.worker_id, event.issued_at, event.sequence)
            }
            ControlEvent::ReviewRequested(_) => return StatusCode::FORBIDDEN,
        };
        if worker_id != &state.worker_id {
            return StatusCode::FORBIDDEN;
        }
        let Some(age_secs) = now.checked_sub(issued_at) else {
            return StatusCode::CONFLICT;
        };
        // Events from the startup second are fenced off with past sessions. This
        // avoids accepting a captured message again after a control restart.
        if issued_at <= state.started_at || age_secs >= state.ttl_secs || sequence == 0 {
            return StatusCode::CONFLICT;
        }
        let order = (issued_at, sequence);
        let Ok(mut status) = state.status.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE;
        };
        match envelope.payload {
            ControlEvent::Heartbeat(_) => {
                if status
                    .heartbeat_order
                    .is_some_and(|current| order <= current)
                {
                    return StatusCode::CONFLICT;
                }
                self.check_deadline(&mut status, instant);
                status.heartbeat_order = Some(order);
                status.heartbeat_deadline =
                    instant + Duration::from_secs(state.ttl_secs - age_secs);
                self.check_deadline(&mut status, instant);
            }
            ControlEvent::PassiveRunSummary(event) => {
                return self.receive_summary(&mut status, event, order, instant);
            }
            ControlEvent::ReviewRequested(_) => return StatusCode::FORBIDDEN,
        }
        StatusCode::NO_CONTENT
    }

    fn receive_summary(
        &self,
        status: &mut WorkerStatus,
        event: PassiveRunSummary,
        order: (u64, u64),
        now: Instant,
    ) -> StatusCode {
        while status
            .seen_runs
            .front()
            .is_some_and(|(expires, _)| *expires <= now)
        {
            status.seen_runs.pop_front();
        }
        if let Some((index, (_, previous))) = status
            .seen_runs
            .iter()
            .enumerate()
            .find(|(_, (_, previous))| previous.run_id == event.run_id)
        {
            if order <= (previous.issued_at, previous.sequence)
                || previous.scope_snapshot_id != event.scope_snapshot_id
                || previous.completeness != event.completeness
                || previous.deltas != event.deltas
            {
                return StatusCode::CONFLICT;
            }
            status.seen_runs.remove(index);
        } else if status.seen_runs.len() == RUN_DEDUP_LIMIT
            || self
                .0
                .summaries
                .try_send(Notice::PassiveDeltas(event.completeness, event.deltas))
                .is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        status.seen_runs.push_back((now + RUN_DEDUP_WINDOW, event));
        StatusCode::NO_CONTENT
    }

    fn check_deadline(&self, status: &mut WorkerStatus, now: Instant) {
        let missing = now >= status.heartbeat_deadline;
        if status.reported_missing == missing {
            return;
        }
        let notice = if missing {
            Notice::WorkerUnavailable
        } else {
            Notice::WorkerRecovered
        };
        if self.0.watchdog_notices.try_send(notice).is_ok() {
            status.reported_missing = missing;
        }
    }
}

async fn ingest(State(plane): State<ControlPlane>, request: Request) -> StatusCode {
    let json = tokio::time::timeout(
        Duration::from_secs(5),
        Json::<SignedEnvelope>::from_request(request, &plane),
    )
    .await;
    let envelope = match json {
        Ok(Ok(Json(envelope))) => envelope,
        Ok(Err(error)) => return error.status(),
        Err(_) => return StatusCode::REQUEST_TIMEOUT,
    };
    match unix_now() {
        Ok(now) => plane.receive_at(envelope, now, Instant::now()),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn unix_now() -> Result<u64, ControlSettingsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .map_err(|_| ControlSettingsError::Clock)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use axum::{body::Body, http::Request};
    use control_protocol::{ApprovalPayload, PassiveRunSummary, WorkerHeartbeat};
    use domain::{ApprovalId, CollectionCompleteness, DeltaCounts, ScopeSnapshotId, ToolRunId};
    use tower::ServiceExt;

    use super::*;

    const TEST_KEY: [u8; MIN_KEY_BYTES] = [49; MIN_KEY_BYTES];
    const TTL: u64 = 10;

    fn plane(at: u64, instant: Instant) -> Result<(ControlPlane, NoticeReceivers)> {
        Ok(ControlPlane::at(
            "worker".into(),
            "key".into(),
            TEST_KEY.to_vec(),
            TTL,
            at,
            instant,
        )?)
    }

    fn heartbeat(worker_id: &str, issued_at: u64, sequence: u64) -> ControlEvent {
        ControlEvent::Heartbeat(WorkerHeartbeat {
            worker_id: worker_id.into(),
            issued_at,
            sequence,
        })
    }

    fn summary(issued_at: u64, sequence: u64) -> ControlEvent {
        ControlEvent::PassiveRunSummary(PassiveRunSummary {
            worker_id: "worker".into(),
            issued_at,
            sequence,
            run_id: ToolRunId(format!("run-{sequence}")),
            scope_snapshot_id: ScopeSnapshotId("scope".into()),
            completeness: CollectionCompleteness::Partial,
            deltas: DeltaCounts {
                new_assets: 3,
                ..DeltaCounts::default()
            },
        })
    }

    #[test]
    fn retried_run_does_not_duplicate_notifications() -> Result<()> {
        let instant = Instant::now();
        let (plane, mut notices) = plane(100, instant)?;
        let event = summary(110, 1);
        assert_eq!(
            plane.receive_at(sign(event.clone())?, 110, instant),
            StatusCode::NO_CONTENT
        );
        assert!(matches!(
            notices.summaries.try_recv()?,
            Notice::PassiveDeltas(..)
        ));
        let ControlEvent::PassiveRunSummary(mut event) = event else {
            anyhow::bail!("expected summary");
        };
        event.issued_at = 111;
        event.sequence = 2;
        let retry = ControlEvent::PassiveRunSummary(event.clone());
        assert_eq!(
            plane.receive_at(sign(retry)?, 111, instant),
            StatusCode::NO_CONTENT
        );
        event.sequence = 3;
        event.deltas.new_assets += 1;
        assert_eq!(
            plane.receive_at(sign(ControlEvent::PassiveRunSummary(event))?, 111, instant),
            StatusCode::CONFLICT
        );
        assert!(notices.summaries.try_recv().is_err());
        assert_eq!(
            plane.receive_at(sign(summary(109, 4))?, 111, instant),
            StatusCode::NO_CONTENT
        );
        assert!(matches!(
            notices.summaries.try_recv()?,
            Notice::PassiveDeltas(..)
        ));
        Ok(())
    }

    fn sign(event: ControlEvent) -> Result<SignedEnvelope> {
        Ok(SignedEnvelope::sign("key".into(), event, &TEST_KEY)?)
    }

    #[tokio::test]
    async fn ingress_accepts_authenticated_events_and_rejects_replay() -> Result<()> {
        let now = unix_now()?;
        let (plane, mut notices) = plane(now - 1, Instant::now())?;
        let valid = sign(summary(now, 1))?;
        let mut tampered = valid.clone();
        tampered.signature.replace_range(..2, "gg");
        let mut wrong_key = valid.clone();
        wrong_key.key_id = "other-key".to_owned();
        let review = sign(ControlEvent::ReviewRequested(ApprovalPayload {
            approval_id: ApprovalId("review".into()),
            scope_snapshot_id: ScopeSnapshotId("scope".into()),
            nonce: "sample".into(),
            operation_hash: "sample".into(),
            issued_at: now,
            ttl_seconds: 1,
        }))?;
        for (message, status) in [
            (tampered, StatusCode::UNAUTHORIZED),
            (wrong_key, StatusCode::UNAUTHORIZED),
            (sign(heartbeat("other", now, 1))?, StatusCode::FORBIDDEN),
            (sign(heartbeat("worker", now - 1, 1))?, StatusCode::CONFLICT),
            (review, StatusCode::FORBIDDEN),
            (valid.clone(), StatusCode::NO_CONTENT),
            (valid, StatusCode::CONFLICT),
        ] {
            let request = Request::post("/v1/worker-events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&message)?))?;
            assert_eq!(plane.router().oneshot(request).await?.status(), status);
        }
        assert_eq!(
            notices.summaries.try_recv()?,
            Notice::PassiveDeltas(
                CollectionCompleteness::Partial,
                DeltaCounts {
                    new_assets: 3,
                    ..DeltaCounts::default()
                },
            )
        );
        assert!(notices.summaries.try_recv().is_err());

        let oversized = Request::post("/v1/worker-events")
            .header("content-type", "application/json")
            .body(Body::from(vec![b' '; MAX_EVENT_BYTES + 1]))?;
        assert_eq!(
            plane.router().oneshot(oversized).await?.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        Ok(())
    }

    #[test]
    fn watchdog_detects_missing_and_recovered_using_heartbeat_time_only() -> Result<()> {
        let instant = Instant::now();
        let (plane, mut notices) = plane(100, instant)?;
        let after = |seconds| instant + Duration::from_secs(seconds);
        let check = |seconds| -> Result<()> {
            let mut status = plane
                .0
                .status
                .lock()
                .map_err(|_| anyhow::anyhow!("state"))?;
            plane.check_deadline(&mut status, after(seconds));
            Ok(())
        };
        assert_eq!(
            plane.receive_at(sign(summary(106, 90))?, 106, after(6)),
            StatusCode::NO_CONTENT
        );
        assert!(matches!(
            notices.summaries.try_recv()?,
            Notice::PassiveDeltas(..)
        ));
        check(10)?;
        check(11)?;
        assert_eq!(notices.watchdog.try_recv()?, Notice::WorkerUnavailable);
        assert!(notices.watchdog.try_recv().is_err());

        let pulse = sign(heartbeat("worker", 108, 1))?;
        assert_eq!(
            plane.receive_at(pulse.clone(), 112, after(12)),
            StatusCode::NO_CONTENT
        );
        assert_eq!(notices.watchdog.try_recv()?, Notice::WorkerRecovered);
        assert_eq!(
            plane.receive_at(pulse, 113, after(13)),
            StatusCode::CONFLICT
        );
        assert_eq!(
            plane.receive_at(sign(heartbeat("worker", 117, 2))?, 116, after(16)),
            StatusCode::CONFLICT
        );
        check(17)?;
        assert!(notices.watchdog.try_recv().is_err());
        check(18)?;
        assert_eq!(notices.watchdog.try_recv()?, Notice::WorkerUnavailable);
        assert_eq!(
            plane.receive_at(sign(heartbeat("worker", 108, 2))?, 118, after(18)),
            StatusCode::CONFLICT
        );
        Ok(())
    }

    #[test]
    fn full_summary_queue_does_not_delay_watchdog() -> Result<()> {
        let instant = Instant::now();
        let (plane, mut notices) = plane(100, instant)?;
        let after = |seconds| instant + Duration::from_secs(seconds);
        let slots = u64::try_from(SUMMARY_CAPACITY)?;
        for sequence in 1..=slots {
            assert_eq!(
                plane.receive_at(sign(summary(101, sequence))?, 101, after(1)),
                StatusCode::NO_CONTENT
            );
        }
        let pending = sign(summary(110, slots + 1))?;
        assert_eq!(
            plane.receive_at(pending.clone(), 110, after(10)),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            plane.receive_at(sign(heartbeat("worker", 110, 1))?, 110, after(10)),
            StatusCode::NO_CONTENT
        );
        assert_eq!(notices.watchdog.try_recv()?, Notice::WorkerUnavailable);
        assert_eq!(notices.watchdog.try_recv()?, Notice::WorkerRecovered);
        for _ in 0..slots {
            assert!(matches!(
                notices.summaries.try_recv()?,
                Notice::PassiveDeltas(..)
            ));
        }
        assert_eq!(
            plane.receive_at(pending, 110, after(10)),
            StatusCode::NO_CONTENT
        );
        Ok(())
    }
}
