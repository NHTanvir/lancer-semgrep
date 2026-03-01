//! HTTP client for the Semgrep Registry.
//!
//! Fetches a pack / rule YAML from `https://semgrep.dev/c/p/<slug>` (or
//! `…/c/r/<rule-id>`) with exponential-backoff retries on HTTP 429 and 5xx.
//!
//! Mirrors the upstream Semgrep CLI's retry policy (Feb 2026 release notes
//! extended retry to 429 + 5xx — see plan §"Research note → CLI retry logic
//! now extends to HTTP 429 + 5xx").

use std::time::Duration;

use crate::error::LoadError;
use crate::registry::{RulePack, Slug};

/// Default base URL for the Semgrep Registry.
pub const DEFAULT_BASE_URL: &str = "https://semgrep.dev";

/// Total request timeout (per attempt) in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Number of additional retry attempts on a retriable error (429 / 5xx /
/// network error). Total attempts = 1 + this number.
const DEFAULT_RETRIES: usize = 3;

/// Client for fetching Semgrep Registry rule packs.
///
/// The underlying `reqwest::Client` is built once at construction and reused
/// for every fetch — TLS handshakes, DNS lookups, and HTTP/2 connections are
/// pooled per host.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    /// e.g. `"https://semgrep.dev"`. Override for staging or tests.
    pub base_url: String,
    /// Per-attempt request timeout.
    pub timeout: Duration,
    /// Number of additional retry attempts on retriable errors.
    pub retries: usize,
    client: reqwest::Client,
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClient {
    /// New client with default base URL and retry policy.
    pub fn new() -> Self {
        let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
        let client = reqwest::Client::builder()
            .user_agent(concat!("lancer-semgrep/", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            .build()
            .expect("reqwest client builder");
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout,
            retries: DEFAULT_RETRIES,
            client,
        }
    }

    /// Override the base URL — useful for tests against a `mockito` server.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Override the retry count.
    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// Fetch a [`RulePack`] for the given slug.
    pub async fn fetch_pack(&self, slug: &Slug) -> Result<RulePack, LoadError> {
        let url = match slug {
            Slug::Pack(name) => format!("{}/c/p/{}", self.base_url, name),
            Slug::Rule(id) => format!("{}/c/r/{}", self.base_url, id),
        };
        let yaml = self.fetch_with_retry(&url).await?;
        Ok(RulePack {
            id: slug.to_string(),
            source_url: url,
            yaml,
            version: None,
        })
    }

    /// Fetch an arbitrary URL (used by `ConfigSource::Url`).
    pub async fn fetch_url(&self, url: &str) -> Result<String, LoadError> {
        self.fetch_with_retry(url).await
    }

    /// GET `url` with exponential-backoff retry on 429 + 5xx + transport errors.
    ///
    /// Backoff schedule: 250 ms, 500 ms, 1 s, 2 s, … (capped at `self.retries`).
    async fn fetch_with_retry(&self, url: &str) -> Result<String, LoadError> {
        let mut last_err: Option<String> = None;
        for attempt in 0..=self.retries {
            match self.client.get(url).send().await {
                Ok(r) if r.status().is_success() => {
                    return r
                        .text()
                        .await
                        .map_err(|e| LoadError::Network(e.to_string()));
                }
                Ok(r)
                    if r.status().as_u16() == 429 || r.status().is_server_error() =>
                {
                    last_err = Some(format!("{} for {}", r.status(), url));
                    if attempt < self.retries {
                        backoff(attempt).await;
                    }
                }
                Ok(r) => {
                    // 4xx other than 429 — not retriable.
                    return Err(LoadError::Network(format!(
                        "{} for {}",
                        r.status(),
                        url
                    )));
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    if attempt < self.retries {
                        backoff(attempt).await;
                    }
                }
            }
        }
        Err(LoadError::Network(
            last_err.unwrap_or_else(|| format!("retries exhausted for {}", url)),
        ))
    }
}

async fn backoff(attempt: usize) {
    // 250 ms × 2^attempt → 0.25s, 0.5s, 1s, 2s, ...
    let delay = Duration::from_millis(250u64.saturating_mul(1u64 << attempt));
    tokio::time::sleep(delay).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_constructs() {
        let c = RegistryClient::new();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
        assert_eq!(c.retries, DEFAULT_RETRIES);
    }

    #[test]
    fn with_base_url_overrides() {
        let c = RegistryClient::new().with_base_url("http://localhost:9000");
        assert_eq!(c.base_url, "http://localhost:9000");
    }
}
