//! Wire DTOs. A decoded envelope is untrusted until validated by an authenticated control service.

use domain::{ApprovalId, CollectionCompleteness, DeltaCounts, ScopeSnapshotId, ToolRunId};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MIN_KEY_BYTES: usize = 32;
const SIGNATURE_CONTEXT: &[u8] = b"prometheus-control-envelope\0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub version: u16,
    pub key_id: String,
    pub payload: ControlEvent,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "event",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ControlEvent {
    Heartbeat(Heartbeat),
    ReviewRequested(ApprovalPayload),
    PassiveRunSummary(PassiveRunSummary),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub worker_id: String,
    pub issued_at: u64,
    pub sequence: u64,
}

pub type WorkerHeartbeat = Heartbeat;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveRunSummary {
    pub worker_id: String,
    pub issued_at: u64,
    pub sequence: u64,
    pub run_id: ToolRunId,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub completeness: CollectionCompleteness,
    pub deltas: DeltaCounts,
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

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("unsupported control protocol version")]
    Version,
    #[error("invalid control identifier")]
    Identifier,
    #[error("control signing key must contain at least 32 bytes")]
    Key,
    #[error("could not encode control signing input")]
    Encoding(#[from] serde_json::Error),
    #[error("invalid control signature")]
    Signature,
}

pub fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

impl SignedEnvelope {
    pub fn sign(key_id: String, payload: ControlEvent, key: &[u8]) -> Result<Self, EnvelopeError> {
        let mut envelope = Self {
            version: PROTOCOL_VERSION,
            key_id,
            payload,
            signature: String::new(),
        };
        use std::fmt::Write;
        let tag = envelope.mac(key)?.finalize().into_bytes();
        for byte in tag {
            write!(envelope.signature, "{byte:02x}").map_err(|_| EnvelopeError::Signature)?;
        }
        Ok(envelope)
    }

    pub fn verify(&self, key: &[u8]) -> Result<(), EnvelopeError> {
        let mac = self.mac(key)?;
        let tag = decode_tag(&self.signature).ok_or(EnvelopeError::Signature)?;
        mac.verify_slice(&tag).map_err(|_| EnvelopeError::Signature)
    }

    fn mac(&self, key: &[u8]) -> Result<Hmac<Sha256>, EnvelopeError> {
        if self.version != PROTOCOL_VERSION {
            return Err(EnvelopeError::Version);
        }
        if !valid_identifier(&self.key_id) {
            return Err(EnvelopeError::Identifier);
        }
        if key.len() < MIN_KEY_BYTES {
            return Err(EnvelopeError::Key);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| EnvelopeError::Key)?;
        mac.update(SIGNATURE_CONTEXT);
        mac.update(&serde_json::to_vec(&(
            self.version,
            &self.key_id,
            &self.payload,
        ))?);
        Ok(mac)
    }
}

fn decode_tag(signature: &str) -> Option<[u8; 32]> {
    if signature.len() != 64 {
        return None;
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let mut output = [0; 32];
    let (pairs, _) = signature.as_bytes().as_chunks::<2>();
    for (byte, [high, low]) in output.iter_mut().zip(pairs) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(output)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn legacy_heartbeat_retains_its_wire_shape() {
        let json = r#"{"version":1,"key_id":"k","payload":{"event":"heartbeat","payload":{"worker_id":"w","issued_at":12,"sequence":1}},"signature":""}"#;
        let legacy: SignedEnvelope = serde_json::from_str(json).expect("decode legacy heartbeat");
        assert_eq!(serde_json::to_string(&legacy).expect("encode"), json);
    }

    #[test]
    fn signature_binds_version_key_id_and_full_payload() {
        let key = [23; MIN_KEY_BYTES];
        let mut envelope = SignedEnvelope::sign(
            "lab-key".to_owned(),
            ControlEvent::PassiveRunSummary(PassiveRunSummary {
                worker_id: "lab-worker".to_owned(),
                issued_at: 10,
                sequence: 1,
                run_id: ToolRunId("synthetic-run".to_owned()),
                scope_snapshot_id: ScopeSnapshotId("lab-v1".to_owned()),
                completeness: CollectionCompleteness::Complete,
                deltas: DeltaCounts::default(),
            }),
            &key,
        )
        .expect("sign summary");
        assert!(envelope.verify(&key).is_ok());
        assert!(envelope.verify(&[42; MIN_KEY_BYTES]).is_err());
        envelope.key_id = "another-key".to_owned();
        assert!(envelope.verify(&key).is_err());
        envelope.key_id = "lab-key".to_owned();
        if let ControlEvent::PassiveRunSummary(summary) = &mut envelope.payload {
            summary.deltas.new_assets = 1;
        }
        assert!(envelope.verify(&key).is_err());
        envelope.version = 0;
        assert!(matches!(envelope.verify(&key), Err(EnvelopeError::Version)));
    }
}
