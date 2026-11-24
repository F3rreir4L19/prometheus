//! Read-only worker health and aggregate notifications.

mod control;
mod notifications;

use axum::{http::StatusCode, routing::get, Router};

pub use control::{ControlPlane, ControlSettingsError};
pub use notifications::{drain_notifications, Notice, NoticeReceivers, Telegram};

pub fn health_router() -> Router {
    Router::new().route("/healthz", get(|| async { StatusCode::OK }))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn health_only() {
        for (path, status) in [("/healthz", StatusCode::OK), ("/", StatusCode::NOT_FOUND)] {
            let request = Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = health_router()
                .oneshot(request)
                .await
                .expect("router response");
            assert_eq!(response.status(), status);
        }
    }
}
