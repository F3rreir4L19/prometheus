use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Mutex,
    time::Duration,
};

use domain::{PassiveSource, ProgramId, PASSIVE_GLOBAL_PER_MINUTE};
use governor::{
    clock::Clock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use tokio::{
    sync::{Semaphore, SemaphorePermit},
    time::{self, Instant},
};

use crate::{CollectionError, PassiveRequest};

const MAX_BUCKETS: usize = 4096;
const MAX_COOLDOWN: Duration = Duration::from_secs(120);
const MAX_WAIT: Duration = MAX_COOLDOWN;
const BASE_COOLDOWN: Duration = Duration::from_secs(5);
const MIN_LATENCY_JUMP: Duration = Duration::from_millis(250);

/// Shared GCRA limits for collector starts within a worker. A single outstanding admission
/// lets provider feedback take effect before the next start and bounds concurrent waiting.
pub struct PassiveRateLimiter {
    state: Mutex<RateState>,
    slot: Semaphore,
}

impl Default for PassiveRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRateLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RateState::default()),
            slot: Semaphore::new(1),
        }
    }

    pub(crate) async fn wait(
        &self,
        request: &PassiveRequest<'_>,
        source: PassiveSource,
    ) -> Result<Admission<'_>, CollectionError> {
        let permit = self
            .slot
            .try_acquire()
            .map_err(|_| CollectionError::Admission)?;
        let policy = request.rate_policy();
        let program = request.program_id();
        let source = source.as_str();
        let limits = [
            (BucketKey::Global, PASSIVE_GLOBAL_PER_MINUTE),
            (
                BucketKey::Program(program.clone()),
                policy.program_per_minute.get(),
            ),
            (
                BucketKey::PassiveAction(program.clone()),
                policy.action_per_minute.get(),
            ),
            (
                BucketKey::Host(program.clone(), request.seed().to_owned()),
                policy.host_per_minute.get(),
            ),
            (
                BucketKey::Provider(program.clone(), source),
                policy.provider_per_minute.get(),
            ),
        ];
        let admission = Admission {
            limiter: self,
            limits,
            _permit: permit,
        };
        let now = Instant::now();
        let ready = admission.ready_at(now, source)?;
        if ready.saturating_duration_since(now) > MAX_WAIT {
            return Err(CollectionError::Admission);
        }
        if ready > now {
            time::sleep_until(ready).await;
        }
        Ok(admission)
    }

    pub(crate) fn feedback(
        &self,
        source: PassiveSource,
        elapsed: Duration,
        pressured: bool,
        retry_after: Option<Duration>,
    ) -> Result<Option<Duration>, CollectionError> {
        let mut state = self.state.lock().map_err(|_| CollectionError::Admission)?;
        Ok(state.feedback.entry(source.as_str()).or_default().record(
            Instant::now(),
            elapsed,
            pressured,
            retry_after,
        ))
    }
}

#[derive(Default)]
struct RateState {
    buckets: HashMap<BucketKey, Bucket>,
    feedback: HashMap<&'static str, ProviderFeedback>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum BucketKey {
    Global,
    Program(ProgramId),
    PassiveAction(ProgramId),
    Host(ProgramId, String),
    Provider(ProgramId, &'static str),
}

pub(crate) struct Admission<'a> {
    limiter: &'a PassiveRateLimiter,
    limits: [(BucketKey, u32); 5],
    _permit: SemaphorePermit<'a>,
}

impl Admission<'_> {
    fn ready_at(&self, now: Instant, source: &str) -> Result<Instant, CollectionError> {
        let mut state = self
            .limiter
            .state
            .lock()
            .map_err(|_| CollectionError::Admission)?;
        let mut ready = state
            .feedback
            .get(source)
            .and_then(|feedback| feedback.until)
            .unwrap_or(now);
        if state.buckets.len() > MAX_BUCKETS - self.limits.len() {
            state.buckets.retain(|_, bucket| {
                bucket
                    .last
                    .is_some_and(|last| now.saturating_duration_since(last) < MAX_WAIT)
            });
            if state.buckets.len() > MAX_BUCKETS - self.limits.len() {
                return Err(CollectionError::Admission);
            }
        }
        for (key, rate) in &self.limits {
            let rate = (*rate).min(PASSIVE_GLOBAL_PER_MINUTE);
            if let Some(bucket) = state.buckets.get(key) {
                if let Some(last) = bucket.last {
                    ready = ready.max(last + bucket.period.max(period(rate)));
                }
            }
        }
        Ok(ready.max(now))
    }

    /// Charge the quotas immediately before dispatch, after the caller's policy callback.
    pub(crate) fn start(&self) -> Result<(), CollectionError> {
        let mut state = self
            .limiter
            .state
            .lock()
            .map_err(|_| CollectionError::Admission)?;
        for (key, rate) in &self.limits {
            let rate = (*rate).min(PASSIVE_GLOBAL_PER_MINUTE);
            let bucket = match state.buckets.entry(key.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(Bucket::new(rate, None)?),
            };
            if bucket.period != period(rate) {
                *bucket = Bucket::new(rate, bucket.last)?;
            }
            bucket
                .limiter
                .check()
                .map_err(|_| CollectionError::Admission)?;
            bucket.last = Some(Instant::now());
        }
        Ok(())
    }
}

// Both async waits and GCRA use the same monotonic clock, including tests with virtual time.
#[derive(Clone, Copy)]
struct RunnerClock;

impl Clock for RunnerClock {
    type Instant = std::time::Instant;

    fn now(&self) -> Self::Instant {
        Instant::now().into_std()
    }
}

struct Bucket {
    limiter: RateLimiter<NotKeyed, InMemoryState, RunnerClock>,
    period: Duration,
    last: Option<Instant>,
}

impl Bucket {
    fn new(rate: u32, last: Option<Instant>) -> Result<Self, CollectionError> {
        let period = period(rate);
        let quota = Quota::with_period(period).ok_or(CollectionError::Configuration)?;
        Ok(Self {
            limiter: RateLimiter::direct_with_clock(quota, RunnerClock),
            period,
            last,
        })
    }
}

fn period(rate: u32) -> Duration {
    Duration::from_nanos(60_000_000_000_u64.div_ceil(u64::from(rate)))
}

#[derive(Default)]
struct ProviderFeedback {
    baseline: Option<Duration>,
    strikes: u32,
    until: Option<Instant>,
}

impl ProviderFeedback {
    fn record(
        &mut self,
        now: Instant,
        elapsed: Duration,
        pressured: bool,
        retry_after: Option<Duration>,
    ) -> Option<Duration> {
        let jump = self.baseline.is_some_and(|baseline| {
            elapsed > baseline.saturating_mul(2)
                && elapsed.saturating_sub(baseline) >= MIN_LATENCY_JUMP
        });
        if pressured || jump {
            self.strikes = (self.strikes + 1).min(6);
            let calculated = BASE_COOLDOWN * (1 << (self.strikes - 1));
            let delay = calculated
                .max(retry_after.unwrap_or_default())
                .min(MAX_COOLDOWN);
            let until = now + delay;
            self.until = Some(self.until.map_or(until, |previous| previous.max(until)));
            return Some(delay);
        }
        self.baseline = Some(
            self.baseline
                .map_or(elapsed, |baseline| baseline - baseline / 4 + elapsed / 4),
        );
        self.strikes = self.strikes.saturating_sub(1);
        None
    }
}

#[cfg(test)]
mod tests;
