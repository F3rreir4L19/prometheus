use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    http::{StatusCode, Uri},
    response::IntoResponse,
    routing::get,
    Router,
};
use tokio::{net::TcpListener, task::JoinHandle};

use super::*;
use crate::test_support::{reviewed_scope, TestGate};

async fn loopback(router: Router) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("http://{}/", listener.local_addr()?))?;
    let server = tokio::spawn(async move {
        assert!(axum::serve(listener, router).await.is_ok());
    });
    Ok((url, server))
}

#[tokio::test]
async fn requests_only_the_active_seed_and_consumes_bounded_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = Router::new().route("/", get(|uri: Uri| async move {
        assert_eq!(uri.query(), Some("q=%25.example.test&output=json"));
        r#"[{"name_value":"*.App.example.test\nexample.test","common_name":"ignored.example.test"}]"#
    }));
    let (url, _server) = loopback(router).await?;
    let engine = reviewed_scope("crtsh", [60; 4])?;
    let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "Example.test.")?;
    let gate = TestGate::default();
    let collector = CrtshCollector::with_loopback(Arc::new(PassiveRateLimiter::new()), url)?;
    let batch = collector.collect(&request, &gate).await?;
    assert_eq!(batch.candidates, ["app.example.test", "example.test"]);
    assert_eq!(batch.malformed, 0);
    assert_eq!(*gate.checks.borrow(), [PassiveSource::CrtshLoopback]);
    Ok(())
}

#[tokio::test]
async fn provider_pressure_registers_cooldown_without_retries(
) -> Result<(), Box<dyn std::error::Error>> {
    for (status, cooldown) in [
        (StatusCode::TOO_MANY_REQUESTS, 11),
        (StatusCode::SERVICE_UNAVAILABLE, 120),
    ] {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let router = Router::new().route(
            "/",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    (
                        status,
                        [(
                            header::RETRY_AFTER,
                            if cooldown == 11 { "11" } else { "600" },
                        )],
                        "ignored",
                    )
                }
            }),
        );
        let (url, _server) = loopback(router).await?;
        let engine = reviewed_scope("crtsh", [60; 4])?;
        let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "example.test")?;
        let gate = TestGate::default();
        let collector = CrtshCollector::with_loopback(Arc::new(PassiveRateLimiter::new()), url)?;
        assert_eq!(
            collector.collect(&request, &gate).await.err(),
            Some(CollectionError::ProviderPressure(status.as_u16()))
        );
        assert_eq!(
            *gate.deferred.borrow(),
            [(PassiveSource::CrtshLoopback, Duration::from_secs(cooldown))]
        );
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }
    Ok(())
}

#[tokio::test]
async fn header_inactivity_backs_off_after_a_faster_sample(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = Router::new().route("/", get(std::future::pending::<&'static str>));
    let (url, _server) = loopback(router).await?;
    let engine = reviewed_scope("crtsh", [60; 4])?;
    let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "example.test")?;
    let gate = TestGate::default();
    let rate = Arc::new(PassiveRateLimiter::new());
    assert_eq!(
        rate.feedback(
            PassiveSource::CrtshLoopback,
            Duration::from_millis(10),
            false,
            None
        )?,
        None
    );
    let mut collector = CrtshCollector::with_loopback(rate, url)?;
    collector.client = Client::builder()
        .no_proxy()
        .read_timeout(Duration::from_millis(350))
        .build()?;

    assert_eq!(
        collector.collect(&request, &gate).await.err(),
        Some(CollectionError::IdleTimeout)
    );
    assert_eq!(
        *gate.deferred.borrow(),
        [(PassiveSource::CrtshLoopback, Duration::from_secs(5))]
    );
    Ok(())
}

#[tokio::test]
async fn rejects_truncation_overflow_and_redirects() -> Result<(), Box<dyn std::error::Error>> {
    let forbidden_redirect_hits = Arc::new(AtomicUsize::new(0));
    let too_large = vec![b' '; MAX_PROVIDER_BYTES + 1];
    for (response, expected) in [
        (
            r#"[{"name_value":"example.test"}"#.into_response(),
            CollectionError::InvalidOutput,
        ),
        (too_large.into_response(), CollectionError::ByteLimit),
        (
            (StatusCode::PARTIAL_CONTENT, "[]").into_response(),
            CollectionError::HttpStatus(206),
        ),
        (
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "/other")],
                "[]",
            )
                .into_response(),
            CollectionError::HttpStatus(307),
        ),
    ] {
        let response = Arc::new(std::sync::Mutex::new(Some(response)));
        let hit = forbidden_redirect_hits.clone();
        let router = Router::new()
            .route(
                "/",
                get(move || {
                    let response = response.clone();
                    async move {
                        response
                            .lock()
                            .ok()
                            .and_then(|mut response| response.take())
                            .unwrap_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                }),
            )
            .route(
                "/other",
                get(move || {
                    let hit = hit.clone();
                    async move {
                        hit.fetch_add(1, Ordering::Relaxed);
                        "[]"
                    }
                }),
            );
        let (url, _server) = loopback(router).await?;
        let engine = reviewed_scope("crtsh", [60; 4])?;
        let request = PassiveRequest::new(&engine, engine.snapshot_id(), 15, "example.test")?;
        let collector = CrtshCollector::with_loopback(Arc::new(PassiveRateLimiter::new()), url)?;
        let blocked = TestGate {
            blocked: true,
            ..TestGate::default()
        };
        assert_eq!(
            collector.collect(&request, &blocked).await.err(),
            Some(CollectionError::PolicyHold)
        );
        assert_eq!(
            collector
                .collect(&request, &TestGate::default())
                .await
                .err(),
            Some(expected)
        );
    }
    assert_eq!(forbidden_redirect_hits.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn alternate_origins_are_limited_to_numeric_loopback() -> Result<(), Box<dyn std::error::Error>> {
    let rate = Arc::new(PassiveRateLimiter::new());
    for address in [
        "http://localhost:8000/",
        "http://192.0.2.1/",
        "https://127.0.0.1/",
        "http://example.test/",
        "http://user@127.0.0.1/",
        "http://127.0.0.1/a",
        "http://127.0.0.1/?q=example.test",
    ] {
        assert!(CrtshCollector::with_loopback(rate.clone(), Url::parse(address)?).is_err());
    }
    Ok(())
}
