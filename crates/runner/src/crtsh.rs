use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use domain::PassiveSource;
use intel::passive::{parse_crtsh, MAX_PROVIDER_BYTES};
use reqwest::{header, Client, Response, StatusCode};
use tokio::time::{self, Instant};
use url::{Host, Url};

use crate::{
    CollectedCandidates, CollectionError, CollectionGate, PassiveCollector, PassiveRateLimiter,
    PassiveRequest,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(8);
const WALL_TIMEOUT: Duration = Duration::from_secs(20);
pub struct CrtshCollector {
    endpoint: Url,
    client: Client,
    rate: Arc<PassiveRateLimiter>,
    source: PassiveSource,
}

impl CrtshCollector {
    pub fn new(rate: Arc<PassiveRateLimiter>) -> Result<Self, CollectionError> {
        let endpoint = Url::parse("https://crt.sh/").map_err(|_| CollectionError::Configuration)?;
        Self::build(rate, endpoint, true)
    }

    /// An in-process test provider may use a numeric HTTP loopback origin.
    pub fn with_loopback(
        rate: Arc<PassiveRateLimiter>,
        endpoint: Url,
    ) -> Result<Self, CollectionError> {
        let numeric_loopback = match endpoint.host() {
            Some(Host::Ipv4(addr)) => addr.is_loopback(),
            Some(Host::Ipv6(addr)) => addr.is_loopback(),
            _ => false,
        };
        if endpoint.scheme() != "http"
            || !numeric_loopback
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(CollectionError::Configuration);
        }
        Self::build(rate, endpoint, false)
    }

    fn build(
        rate: Arc<PassiveRateLimiter>,
        endpoint: Url,
        https_only: bool,
    ) -> Result<Self, CollectionError> {
        let client = Client::builder()
            .use_rustls_tls()
            .https_only(https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(|_| CollectionError::Configuration)?;
        Ok(Self {
            endpoint,
            client,
            rate,
            source: if https_only {
                PassiveSource::Crtsh
            } else {
                PassiveSource::CrtshLoopback
            },
        })
    }
}

impl PassiveCollector for CrtshCollector {
    async fn collect(
        &self,
        request: &PassiveRequest<'_>,
        gate: &impl CollectionGate,
    ) -> Result<CollectedCandidates, CollectionError> {
        let mut query = self.endpoint.clone();
        query
            .query_pairs_mut()
            .append_pair("q", &format!("%.{}", request.seed()))
            .append_pair("output", "json");
        let outbound = self
            .client
            .get(query)
            .header(header::ACCEPT, "application/json")
            .build()
            .map_err(|_| CollectionError::Configuration)?;

        let admission = self.rate.wait(request, self.source).await?;
        gate.check(request, self.source).await?;
        admission.start()?;
        let started = Instant::now();
        let deadline = started + WALL_TIMEOUT;
        let response = time::timeout_at(deadline, self.client.execute(outbound))
            .await
            .map_err(|_| CollectionError::WallTimeout)
            .and_then(|response| response.map_err(transport_error));

        let mut pressure_delay = None;
        let result = match response {
            Ok(response) if response.status() == StatusCode::OK => {
                time::timeout_at(deadline, read_body(response))
                    .await
                    .map_err(|_| CollectionError::WallTimeout)
                    .and_then(std::convert::identity)
            }
            Ok(response) => {
                let status = response.status().as_u16();
                if matches!(status, 429 | 503) {
                    pressure_delay = retry_after(&response);
                    Err(CollectionError::ProviderPressure(status))
                } else {
                    Err(CollectionError::HttpStatus(status))
                }
            }
            Err(error) => Err(error),
        };
        let pressured = matches!(result, Err(CollectionError::ProviderPressure(_)));
        if let Some(delay) =
            self.rate
                .feedback(self.source, started.elapsed(), pressured, pressure_delay)?
        {
            gate.defer_provider(request, self.source, delay).await?;
        }

        Ok(parse_crtsh(&result?)?.into())
    }
}

async fn read_body(mut response: Response) -> Result<Vec<u8>, CollectionError> {
    if response
        .content_length()
        .is_some_and(|bytes| bytes > MAX_PROVIDER_BYTES as u64)
    {
        return Err(CollectionError::ByteLimit);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if chunk.len() > MAX_PROVIDER_BYTES - body.len() {
            return Err(CollectionError::ByteLimit);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers().get(header::RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse() {
        return Some(Duration::from_secs(seconds));
    }
    httpdate::parse_http_date(value)
        .ok()?
        .duration_since(SystemTime::now())
        .ok()
}

fn transport_error(error: reqwest::Error) -> CollectionError {
    if error.is_timeout() {
        CollectionError::IdleTimeout
    } else {
        CollectionError::Transport
    }
}

#[cfg(test)]
mod tests;
