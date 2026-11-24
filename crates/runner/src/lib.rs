//! Local resource contracts. M0 handles only recorded fixtures.

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
