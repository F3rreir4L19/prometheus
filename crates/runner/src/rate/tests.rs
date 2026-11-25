use super::*;
use crate::test_support::reviewed_scope;
use domain::ScopeSnapshotId;

#[tokio::test(start_paused = true)]
async fn all_rate_dimensions_use_one_cell_and_bound_starts(
) -> Result<(), Box<dyn std::error::Error>> {
    for (rates, host, source, expected_seconds) in [
        (
            [60, 60, 60, 60],
            "other.example",
            PassiveSource::Subfinder,
            1,
        ),
        (
            [15, 60, 60, 60],
            "other.example",
            PassiveSource::Subfinder,
            4,
        ),
        (
            [60, 12, 60, 60],
            "other.example",
            PassiveSource::Subfinder,
            5,
        ),
        (
            [60, 60, 10, 60],
            "example.test",
            PassiveSource::Subfinder,
            6,
        ),
        ([60, 60, 60, 20], "other.example", PassiveSource::Crtsh, 3),
    ] {
        let engine = reviewed_scope("example", rates)?;
        let rate = PassiveRateLimiter::new();
        let first = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "EXAMPLE.test.")?;
        let second = PassiveRequest::new(&engine, engine.snapshot_id(), 15, host)?;
        let original = Instant::now();
        rate.wait(&first, PassiveSource::Crtsh).await?.start()?;
        rate.wait(&second, source).await?.start()?;
        let expected = Duration::from_secs(expected_seconds);
        assert!(original.elapsed() >= expected);
        assert!(original.elapsed() < expected + Duration::from_millis(10));
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn backoff_discourages_one_provider_and_reacts_to_a_latency_jump(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = reviewed_scope("example", [60; 4])?;
    let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "example.test")?;
    let rate = PassiveRateLimiter::new();
    let admitted = rate.wait(&request, PassiveSource::Crtsh).await?;
    admitted.start()?;
    assert!(matches!(
        rate.wait(&request, PassiveSource::Subfinder).await,
        Err(CollectionError::Admission)
    ));
    drop(admitted);

    assert_eq!(
        rate.feedback(PassiveSource::Crtsh, Duration::from_millis(10), false, None)?,
        None
    );
    assert_eq!(
        rate.feedback(
            PassiveSource::Crtsh,
            Duration::from_millis(500),
            false,
            None
        )?,
        Some(BASE_COOLDOWN)
    );
    assert_eq!(
        rate.feedback(
            PassiveSource::Crtsh,
            Duration::ZERO,
            true,
            Some(Duration::from_secs(12))
        )?,
        Some(Duration::from_secs(12))
    );
    let measured_from = Instant::now();
    rate.wait(&request, PassiveSource::Subfinder)
        .await?
        .start()?;
    assert!(measured_from.elapsed() < BASE_COOLDOWN);
    rate.wait(&request, PassiveSource::Crtsh).await?.start()?;
    assert!(measured_from.elapsed() >= Duration::from_secs(12));
    assert_eq!(
        rate.feedback(
            PassiveSource::Crtsh,
            Duration::ZERO,
            true,
            Some(Duration::from_secs(400))
        )?,
        Some(MAX_COOLDOWN)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn program_limits_are_separate_and_quota_changes_preserve_spacing(
) -> Result<(), Box<dyn std::error::Error>> {
    let first = reviewed_scope("first", [60; 4])?;
    let tighter = reviewed_scope("first", [15, 60, 60, 60])?;
    let second = reviewed_scope("second", [60; 4])?;
    let first = PassiveRequest::new(&first, first.snapshot_id(), 15, "example.test")?;
    let tighter = PassiveRequest::new(&tighter, tighter.snapshot_id(), 15, "example.test")?;
    let second = PassiveRequest::new(&second, second.snapshot_id(), 15, "example.test")?;
    let rate = PassiveRateLimiter::new();
    let original = Instant::now();

    rate.wait(&first, PassiveSource::Crtsh).await?.start()?;
    rate.wait(&second, PassiveSource::Crtsh).await?.start()?;
    assert!(original.elapsed() < Duration::from_secs(2));
    rate.wait(&tighter, PassiveSource::Crtsh).await?.start()?;
    assert!(original.elapsed() >= Duration::from_secs(4));
    Ok(())
}

#[test]
fn collection_requests_reject_unreviewed_seeds_and_stale_snapshots(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = reviewed_scope("example", [60; 4])?;
    assert!(PassiveRequest::new(&engine, engine.snapshot_id(), 15, "www.example.test").is_err());
    assert!(PassiveRequest::new(&engine, engine.snapshot_id(), 20, "example.test").is_err());
    assert!(PassiveRequest::new(
        &engine,
        &ScopeSnapshotId("obsolete".into()),
        15,
        "example.test"
    )
    .is_err());
    assert_eq!(
        PassiveRequest::new(&engine, engine.snapshot_id(), 15, "EXAMPLE.test.")?.seed(),
        "example.test"
    );
    Ok(())
}
