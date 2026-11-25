use std::{num::NonZeroUsize, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

use domain::PassiveSource;
use intel::passive::{parse_subfinder, MAX_PROVIDER_BYTES};
use tokio::{process::Command, time::Instant};

use crate::{
    process::{stage_binary, supervise, HEAVY_PROCESS_SLOT},
    CollectedCandidates, CollectionError, CollectionGate, Containment, FixturePin,
    PassiveCollector, PassiveRateLimiter, PassiveRequest, ReplayError, ResourceLimits,
    SubfinderPin, SUBFINDER_CONTRACT_VERSION,
};

const MAX_BINARY_BYTES: u64 = 96 * 1024 * 1024;
const SOURCE: PassiveSource = PassiveSource::Subfinder;

pub struct SubfinderCollector {
    pin: SubfinderPin,
    rate: Arc<PassiveRateLimiter>,
    limits: ResourceLimits,
}

impl SubfinderCollector {
    pub fn new(pin: SubfinderPin, rate: Arc<PassiveRateLimiter>) -> Result<Self, CollectionError> {
        if pin.version != SUBFINDER_CONTRACT_VERSION || !pin.path.is_absolute() {
            return Err(CollectionError::InvalidManifest);
        }
        let limits = ResourceLimits {
            stdout_bytes: NonZeroUsize::new(MAX_PROVIDER_BYTES)
                .ok_or(CollectionError::Configuration)?,
            stderr_bytes: NonZeroUsize::new(128 * 1024).ok_or(CollectionError::Configuration)?,
            queue_capacity: NonZeroUsize::new(8).ok_or(CollectionError::Configuration)?,
            wall_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
        };
        Ok(Self { pin, rate, limits })
    }
}

impl PassiveCollector for SubfinderCollector {
    async fn collect(
        &self,
        request: &PassiveRequest<'_>,
        gate: &impl CollectionGate,
    ) -> Result<CollectedCandidates, CollectionError> {
        let _slot = HEAVY_PROCESS_SLOT
            .try_acquire()
            .map_err(|_| CollectionError::Admission)?;
        let directory = tempfile::Builder::new()
            .prefix("prometheus-subfinder-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|_| CollectionError::Process)?;
        let home = directory
            .path()
            .canonicalize()
            .map_err(|_| CollectionError::Process)?;
        let executable = home.join("subfinder");
        stage_binary(
            &self.pin.path,
            &executable,
            &FixturePin {
                version: &self.pin.version,
                sha256: self.pin.sha256,
            },
            MAX_BINARY_BYTES,
        )
        .map_err(|_| CollectionError::InvalidManifest)?;

        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("TMPDIR", &home)
            .env("GOMAXPROCS", "1")
            .env("GOMEMLIMIT", "512MiB")
            .current_dir(home)
            .arg("-d")
            .arg(request.seed())
            .args([
                "-silent",
                "-oJ",
                "-duc",
                "-s",
                "hackertarget",
                "-rsr",
                "4194304",
                "-t",
                "1",
            ]);

        let admission = self.rate.wait(request, SOURCE).await?;
        gate.check(request, SOURCE).await?;
        admission.start()?;
        let started = Instant::now();
        let collected = supervise(command, b"", &self.limits)
            .await
            .map_err(containment_error);
        let pressure = collected
            .as_ref()
            .ok()
            .and_then(|(_, status)| match status.code() {
                Some(29) => Some(429),
                Some(53) => Some(503),
                _ => None,
            });
        if let Some(delay) =
            self.rate
                .feedback(SOURCE, started.elapsed(), pressure.is_some(), None)?
        {
            gate.defer_provider(request, SOURCE, delay).await?;
        }
        if let Some(status) = pressure {
            return Err(CollectionError::ProviderPressure(status));
        }
        let (output, status) = collected?;
        if !status.success() {
            return Err(CollectionError::Process);
        }

        Ok(parse_subfinder(output.stdout())?.into())
    }
}

fn containment_error(error: ReplayError) -> CollectionError {
    match error {
        ReplayError::Contained(Containment::WallTimeout) => CollectionError::WallTimeout,
        ReplayError::Contained(Containment::IdleTimeout) => CollectionError::IdleTimeout,
        ReplayError::Contained(Containment::OutputLimit) => CollectionError::ByteLimit,
        ReplayError::Contained(Containment::Backpressure) => CollectionError::Admission,
        _ => CollectionError::Process,
    }
}

#[cfg(test)]
mod tests;
