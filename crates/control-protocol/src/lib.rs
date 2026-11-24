//! Wire DTOs. A decoded envelope is untrusted until validated by an authenticated control service.

use domain::{ApprovalId, ScopeSnapshotId};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub version: u16,
    pub key_id: String,
    pub payload: ControlEvent,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", content = "payload", rename_all = "snake_case")]
pub enum ControlEvent {
    Heartbeat(Heartbeat),
    ReviewRequested(ApprovalPayload),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub worker_id: String,
    pub issued_at: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPayload {
    pub approval_id: ApprovalId,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub nonce: String,
    pub operation_hash: String,
    pub issued_at: u64,
    pub ttl_seconds: u32,
}
