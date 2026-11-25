use std::{future::Future, path::PathBuf, time::Duration};

use domain::{PassiveRatePolicy, PassiveSource, ProgramId, ScopeSnapshotId};
use intel::passive::{PassiveInputError, ProviderCandidates};
use scope_engine::{canonicalize_domain, ScopeEngine};
use serde::Deserialize;
use thiserror::Error;

pub const SUBFINDER_CONTRACT_VERSION: &str = "2.17.0-prometheus-passive.1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    version: u32,
    subfinder: SubfinderPin,
}

impl ToolManifest {
    pub fn into_subfinder(self) -> Result<SubfinderPin, CollectionError> {
        if self.version != 1
            || !self.subfinder.path.is_absolute()
            || self.subfinder.version != SUBFINDER_CONTRACT_VERSION
        {
            return Err(CollectionError::InvalidManifest);
        }
        Ok(self.subfinder)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubfinderPin {
    pub(crate) path: PathBuf,
    pub(crate) version: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub(crate) sha256: [u8; 32],
    #[serde(rename = "intrusiveness")]
    _intrusiveness: Intrusiveness,
}

impl SubfinderPin {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Intrusiveness {
    Passive,
}

fn deserialize_sha256<'de, D: serde::Deserializer<'de>>(input: D) -> Result<[u8; 32], D::Error> {
    let text = String::deserialize(input)?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(serde::de::Error::custom(
            "expected 64 hexadecimal SHA-256 digits",
        ));
    }
    let mut bytes = [0; 32];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (byte, pair) in bytes.iter_mut().zip(pairs) {
        let digits = std::str::from_utf8(pair).map_err(serde::de::Error::custom)?;
        *byte = u8::from_str_radix(digits, 16).map_err(serde::de::Error::custom)?;
    }
    Ok(bytes)
}

/// A concrete seed explicitly reviewed for passive collection. Descendant wildcard rules
/// authorize candidate decisions but cannot independently authorize a collector invocation.
pub struct PassiveRequest<'a> {
    program_id: &'a ProgramId,
    snapshot_id: &'a ScopeSnapshotId,
    seed: String,
    policy: PassiveRatePolicy,
}

impl<'a> PassiveRequest<'a> {
    pub fn new(
        engine: &'a ScopeEngine,
        active_snapshot: &'a ScopeSnapshotId,
        now: u64,
        seed: &str,
    ) -> Result<Self, CollectionError> {
        let seed = canonicalize_domain(seed).ok_or(CollectionError::PolicyHold)?;
        let snapshot = engine.snapshot();
        let policy = snapshot.passive_live.ok_or(CollectionError::PolicyHold)?;
        if !engine.is_passive_collection_seed(active_snapshot, now, &seed) {
            return Err(CollectionError::PolicyHold);
        }
        Ok(Self {
            program_id: &snapshot.program_id,
            snapshot_id: active_snapshot,
            seed,
            policy,
        })
    }

    pub fn program_id(&self) -> &ProgramId {
        self.program_id
    }

    pub fn snapshot_id(&self) -> &ScopeSnapshotId {
        self.snapshot_id
    }

    pub fn seed(&self) -> &str {
        &self.seed
    }

    pub fn rate_policy(&self) -> PassiveRatePolicy {
        self.policy
    }
}

pub trait CollectionGate {
    /// Revalidate the active policy immediately before the request or subprocess starts.
    fn check(
        &self,
        request: &PassiveRequest<'_>,
        source: PassiveSource,
    ) -> impl Future<Output = Result<(), CollectionError>>;

    /// A deployment can persist provider cooldown across collector invocations.
    fn defer_provider(
        &self,
        _request: &PassiveRequest<'_>,
        _source: PassiveSource,
        _delay: Duration,
    ) -> impl Future<Output = Result<(), CollectionError>> {
        async { Ok(()) }
    }
}

pub trait PassiveCollector {
    fn collect(
        &self,
        request: &PassiveRequest<'_>,
        gate: &impl CollectionGate,
    ) -> impl Future<Output = Result<CollectedCandidates, CollectionError>>;
}

/// Provider output is untrusted and still requires selection against the active snapshot.
#[derive(Debug, Default)]
pub struct CollectedCandidates {
    pub candidates: Vec<String>,
    pub malformed: usize,
}

impl From<ProviderCandidates> for CollectedCandidates {
    fn from(batch: ProviderCandidates) -> Self {
        Self {
            candidates: batch.candidates,
            malformed: batch.malformed,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CollectionError {
    #[error("passive collection blocked by the active policy")]
    PolicyHold,
    #[error("invalid passive tool manifest or binary digest")]
    InvalidManifest,
    #[error("invalid passive collector configuration")]
    Configuration,
    #[error("passive collector rate or concurrency admission unavailable")]
    Admission,
    #[error("passive provider reported pressure ({0})")]
    ProviderPressure(u16),
    #[error("passive provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("passive collector transport failed")]
    Transport,
    #[error("passive collector input or output was incomplete or malformed")]
    InvalidOutput,
    #[error("passive collector exceeded its wall timeout")]
    WallTimeout,
    #[error("passive collector exceeded its inactivity timeout")]
    IdleTimeout,
    #[error("passive collector exceeded its byte limit")]
    ByteLimit,
    #[error("passive collector process failed")]
    Process,
}

impl From<PassiveInputError> for CollectionError {
    fn from(error: PassiveInputError) -> Self {
        match error {
            PassiveInputError::ByteLimit => Self::ByteLimit,
            _ => Self::InvalidOutput,
        }
    }
}

impl CollectionError {
    pub fn status(self) -> &'static str {
        match self {
            Self::PolicyHold => "policy_hold",
            Self::InvalidManifest => "invalid_manifest",
            Self::Configuration => "configuration",
            Self::Admission => "admission",
            Self::ProviderPressure(_) => "provider_pressure",
            Self::HttpStatus(_) => "http_status",
            Self::Transport => "transport",
            Self::InvalidOutput => "invalid_output",
            Self::WallTimeout => "wall_timeout",
            Self::IdleTimeout => "idle_timeout",
            Self::ByteLimit => "byte_limit",
            Self::Process => "process",
        }
    }
}
