//! Resource contracts and supervised replay of recorded fixtures.

mod crtsh;
mod passive;
mod rate;
pub use crtsh::CrtshCollector;
pub use passive::{
    CollectedCandidates, CollectionError, CollectionGate, PassiveCollector, PassiveRequest,
    SubfinderPin, ToolManifest, SUBFINDER_CONTRACT_VERSION,
};
pub use rate::PassiveRateLimiter;

#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod subfinder;
#[cfg(target_os = "linux")]
pub use process::{replay_local_fixture, FixtureManifest, FixtureOutput, FixturePin, ReplayError};
#[cfg(target_os = "linux")]
pub use subfinder::SubfinderCollector;

#[cfg(test)]
mod test_support;

use std::{num::NonZeroUsize, time::Duration};

use domain::{Action, AssetId, JobId, ScopeSnapshotId};

#[derive(Clone, Debug)]
pub struct FixtureJob {
    pub id: JobId,
    pub asset_id: AssetId,
    pub scope_snapshot_id: ScopeSnapshotId,
    pub action: Action,
}

#[derive(Clone, Debug)]
pub struct ResourceLimits {
    pub stdout_bytes: NonZeroUsize,
    pub stderr_bytes: NonZeroUsize,
    pub queue_capacity: NonZeroUsize,
    pub wall_timeout: Duration,
    pub idle_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Containment {
    WallTimeout,
    IdleTimeout,
    OutputLimit,
    Backpressure,
    PolicyHold,
}

pub trait FixtureRunner {
    type Output;

    fn replay(
        &self,
        job: &FixtureJob,
        limits: &ResourceLimits,
    ) -> Result<Self::Output, Containment>;
}
