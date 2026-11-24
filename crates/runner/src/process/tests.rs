use std::{fs, num::NonZeroUsize};

use super::*;

fn limits() -> Result<ResourceLimits, Box<dyn std::error::Error>> {
    Ok(ResourceLimits {
        stdout_bytes: NonZeroUsize::new(16 * 1024).ok_or("stdout")?,
        stderr_bytes: NonZeroUsize::new(128).ok_or("stderr")?,
        queue_capacity: NonZeroUsize::new(1).ok_or("queue")?,
        wall_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(2),
    })
}

#[tokio::test]
async fn pinned_local_replay_applies_the_stdout_budget() -> Result<(), Box<dyn std::error::Error>> {
    let copy = Sha256::digest(fs::read(COPY_BINARY)?).into();
    let limiter = Sha256::digest(fs::read(LIMIT_BINARY)?).into();
    let mut manifest = FixtureManifest {
        copy: FixturePin {
            version: "fixture",
            sha256: [0; 32],
        },
        limiter: FixturePin {
            version: "fixture",
            sha256: limiter,
        },
    };
    let input = b"test.example.com\n".repeat(470);
    let mut limits = limits()?;

    let occupied = REPLAY_SLOT.try_acquire()?;
    assert!(matches!(
        replay_local_fixture(&manifest, &input, &limits).await,
        Err(ReplayError::Contained(Containment::Backpressure))
    ));
    drop(occupied);
    assert!(matches!(
        replay_local_fixture(&manifest, &input, &limits).await,
        Err(ReplayError::InvalidManifest)
    ));

    manifest.copy.sha256 = copy;
    let result = replay_local_fixture(&manifest, &input, &limits).await?;
    assert_eq!(result.stdout(), input);
    assert_eq!(result.stderr_bytes, 0);

    limits.stdout_bytes = NonZeroUsize::new(input.len() - 1).ok_or("stdout")?;
    assert!(matches!(
        replay_local_fixture(&manifest, &input, &limits).await,
        Err(ReplayError::Contained(Containment::OutputLimit))
    ));
    Ok(())
}

#[tokio::test]
async fn stalled_process_hits_independent_wall_and_idle_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut limits = limits()?;
    limits.wall_timeout = Duration::from_millis(100);
    let mut command = Command::new("/usr/bin/sleep");
    command.arg("1");
    assert!(matches!(
        supervise(command, b"", &limits).await,
        Err(ReplayError::Contained(Containment::WallTimeout))
    ));

    limits.wall_timeout = Duration::from_secs(2);
    limits.idle_timeout = Duration::from_millis(100);
    let mut command = Command::new("/usr/bin/sleep");
    command.arg("1");
    assert!(matches!(
        supervise(command, b"", &limits).await,
        Err(ReplayError::Contained(Containment::IdleTimeout))
    ));
    Ok(())
}

#[tokio::test]
async fn stderr_limit_is_enforced_without_retaining_text() -> Result<(), Box<dyn std::error::Error>>
{
    let mut limits = limits()?;
    limits.stderr_bytes = NonZeroUsize::new(1).ok_or("stderr")?;
    let mut command = Command::new(COPY_BINARY);
    command.arg("--synthetic-invalid-option");
    assert!(matches!(
        supervise(command, b"", &limits).await,
        Err(ReplayError::Contained(Containment::OutputLimit))
    ));
    Ok(())
}

#[test]
fn an_executable_script_is_rejected_even_with_a_matching_digest(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("source");
    let staged = dir.path().join("staged");
    let script = b"#!/bin/sh\nexit 0\n";
    fs::write(&source, script)?;
    assert!(matches!(
        stage_helper(
            &source,
            &staged,
            &FixturePin {
                version: "fixture",
                sha256: Sha256::digest(script).into()
            }
        ),
        Err(ReplayError::InvalidManifest)
    ));
    assert!(!staged.exists());
    Ok(())
}

#[test]
fn opening_a_fifo_does_not_wait_for_a_writer() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("fifo");
    let staged = dir.path().join("staged");
    rustix::fs::mkfifoat(rustix::fs::CWD, &source, Mode::RUSR | Mode::WUSR)?;
    let pin = FixturePin {
        version: "fixture",
        sha256: [0; 32],
    };
    assert!(matches!(
        stage_helper(&source, &staged, &pin),
        Err(ReplayError::InvalidManifest)
    ));
    assert!(!staged.exists());
    Ok(())
}
