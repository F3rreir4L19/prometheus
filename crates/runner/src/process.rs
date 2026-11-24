use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use rustix::fs::{open, Mode, OFlags};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, Command},
    sync::{mpsc, Semaphore},
    time::{self, Instant},
};

use crate::{Containment, ResourceLimits};

const COPY_BINARY: &str = "/usr/bin/cat";
const LIMIT_BINARY: &str = "/usr/bin/prlimit";
const MAX_BINARY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FIXTURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUEUE_CAPACITY: usize = 64;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);
const PIPE_CHUNK_BYTES: usize = 4096;
static REPLAY_SLOT: Semaphore = Semaphore::const_new(1);

/// An operator-reviewed binary version and digest. Both fixed helpers require a pin.
pub struct FixturePin<'a> {
    pub version: &'a str,
    pub sha256: [u8; 32],
}

/// Fixed local `cat` and `prlimit` helpers. Subprocess paths and flags are selected by code.
pub struct FixtureManifest<'a> {
    pub copy: FixturePin<'a>,
    pub limiter: FixturePin<'a>,
}

pub struct FixtureOutput {
    stdout: Vec<u8>,
    pub stderr_bytes: usize,
}

impl FixtureOutput {
    /// Fixture bytes remain untrusted. Interpret and filter them before storing or logging.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("fixture replay contained: {0:?}")]
    Contained(Containment),
    #[error("fixture replay configuration exceeds local resource ceilings")]
    InvalidLimits,
    #[error("fixture input exceeds the replay byte limit")]
    InputLimit,
    #[error("fixture helper manifest does not match the local installation")]
    InvalidManifest,
    #[error("fixture helper I/O failed")]
    Io(#[from] io::Error),
    #[error("fixture helper exited unsuccessfully")]
    UnsuccessfulExit,
    #[error("fixture helper could not be terminated and reaped")]
    Cleanup,
}

/// Copy fixture bytes over stdio under independent process and stream limits. The helper has no
/// input-derived arguments, target access, credentials, or inherited environment.
pub async fn replay_local_fixture(
    manifest: &FixtureManifest<'_>,
    input: &[u8],
    limits: &ResourceLimits,
) -> Result<FixtureOutput, ReplayError> {
    validate_limits(input, limits)?;
    let _slot = REPLAY_SLOT
        .try_acquire()
        .map_err(|_| ReplayError::Contained(Containment::Backpressure))?;
    let directory = tempfile::Builder::new()
        .prefix("prometheus-replay-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let directory_path = directory.path().canonicalize()?;
    let copy = directory_path.join("cat");
    let limiter = directory_path.join("prlimit");
    stage_helper(Path::new(COPY_BINARY), &copy, &manifest.copy)?;
    stage_helper(Path::new(LIMIT_BINARY), &limiter, &manifest.limiter)?;

    // prlimit replaces itself with cat in the same process. The 256 MiB address-space budget
    // also applies to cat. Closing core dumps and regular-file output keeps fixture bytes in pipes.
    let mut command = Command::new(limiter);
    command
        .args(["--as=268435456", "--core=0", "--fsize=0", "--"])
        .arg(copy)
        .current_dir(directory_path);
    supervise(command, input, limits).await
}

fn validate_limits(input: &[u8], limits: &ResourceLimits) -> Result<(), ReplayError> {
    if limits.stdout_bytes.get() > MAX_FIXTURE_BYTES
        || limits.stderr_bytes.get() > MAX_FIXTURE_BYTES
        || limits.queue_capacity.get() > MAX_QUEUE_CAPACITY
        || limits.wall_timeout.is_zero()
        || limits.wall_timeout > MAX_TIMEOUT
        || limits.idle_timeout.is_zero()
        || limits.idle_timeout > MAX_TIMEOUT
    {
        return Err(ReplayError::InvalidLimits);
    }
    if input.len() > MAX_FIXTURE_BYTES {
        return Err(ReplayError::InputLimit);
    }
    Ok(())
}

/// Hash exactly the bytes written to a private, read-only executable. A replaced source path
/// cannot change the staged binary after verification.
fn stage_helper(source: &Path, staged: &Path, pin: &FixturePin<'_>) -> Result<(), ReplayError> {
    if pin.version.is_empty()
        || pin.version.len() > 64
        || !pin
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
    {
        return Err(ReplayError::InvalidManifest);
    }
    let source = File::from(
        open(
            source,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let metadata = source.metadata()?;
    let mut header = [0; 4];
    if !metadata.is_file()
        || metadata.len() < header.len() as u64
        || metadata.len() > MAX_BINARY_BYTES
    {
        return Err(ReplayError::InvalidManifest);
    }
    let mut source = source.take(MAX_BINARY_BYTES + 1);
    source.read_exact(&mut header)?;
    if &header != b"\x7fELF" {
        return Err(ReplayError::InvalidManifest);
    }
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staged)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    let mut length = header.len() as u64;
    digest.update(header);
    destination.write_all(&header)?;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length += read as u64;
        if length > MAX_BINARY_BYTES {
            return Err(ReplayError::InvalidManifest);
        }
        digest.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != pin.sha256 {
        return Err(ReplayError::InvalidManifest);
    }
    destination.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    Ok(())
}

async fn supervise(
    mut command: Command,
    input: &[u8],
    limits: &ResourceLimits,
) -> Result<FixtureOutput, ReplayError> {
    let wall_deadline = Instant::now() + limits.wall_timeout;
    let mut child = command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let result = time::timeout_at(wall_deadline, exchange(&mut child, input, limits))
        .await
        .map_err(|_| ReplayError::Contained(Containment::WallTimeout))
        .and_then(std::convert::identity);
    if result.is_err() {
        child.kill().await.map_err(|_| ReplayError::Cleanup)?;
    }
    result
}

enum Activity {
    Stdout(Vec<u8>),
    Stderr,
}

async fn exchange(
    child: &mut Child,
    input: &[u8],
    limits: &ResourceLimits,
) -> Result<FixtureOutput, ReplayError> {
    let unavailable = || io::Error::other("fixture helper pipe unavailable");
    let stdin = child.stdin.take().ok_or_else(unavailable)?;
    let stdout = child.stdout.take().ok_or_else(unavailable)?;
    let stderr = child.stderr.take().ok_or_else(unavailable)?;
    let (send, receive) = mpsc::channel(limits.queue_capacity.get());
    let (_, stderr_bytes, (), (stdout, status)) = tokio::try_join!(
        drain(stdout, limits.stdout_bytes.get(), send.clone(), |bytes| {
            Activity::Stdout(bytes.to_vec())
        }),
        drain(stderr, limits.stderr_bytes.get(), send, |_| {
            Activity::Stderr
        }),
        feed(stdin, input),
        collect(child, receive, limits.idle_timeout)
    )?;
    if !status.success() {
        return Err(ReplayError::UnsuccessfulExit);
    }
    Ok(FixtureOutput {
        stdout,
        stderr_bytes,
    })
}

async fn feed(mut pipe: impl AsyncWrite + Unpin, input: &[u8]) -> Result<(), ReplayError> {
    pipe.write_all(input).await?;
    pipe.shutdown().await?;
    Ok(())
}

async fn drain(
    mut pipe: impl AsyncRead + Unpin,
    ceiling: usize,
    send: mpsc::Sender<Activity>,
    event: impl Fn(&[u8]) -> Activity,
) -> Result<usize, ReplayError> {
    let mut buffer = [0; PIPE_CHUNK_BYTES];
    let mut total = 0;
    loop {
        let count = pipe.read(&mut buffer).await?;
        if count == 0 {
            return Ok(total);
        }
        total += count;
        if total > ceiling {
            return Err(ReplayError::Contained(Containment::OutputLimit));
        }
        send.send(event(&buffer[..count]))
            .await
            .map_err(|_| ReplayError::Contained(Containment::Backpressure))?;
    }
}

async fn collect(
    child: &mut Child,
    mut receive: mpsc::Receiver<Activity>,
    idle_timeout: Duration,
) -> Result<(Vec<u8>, ExitStatus), ReplayError> {
    let idle = time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut output = Vec::new();
    loop {
        tokio::select! {
            biased;
            () = &mut idle => return Err(ReplayError::Contained(Containment::IdleTimeout)),
            event = receive.recv() => match event {
                Some(event) => {
                    if let Activity::Stdout(bytes) = event {
                        output.extend_from_slice(&bytes);
                    }
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
                None => break,
            }
        }
    }
    let status = time::timeout_at(idle.deadline(), child.wait())
        .await
        .map_err(|_| ReplayError::Contained(Containment::IdleTimeout))??;
    Ok((output, status))
}

#[cfg(test)]
mod tests;
