//! Semgrep AppSec platform REST API client (stub).
//!
//! Per plan §"Semgrep AppSec platform (commercial cloud — REST-API surface
//! to mirror)": the upstream cloud exposes endpoints for uploading findings,
//! listing projects, managing policies, AI auto-triage, network broker,
//! Semgrep Guardian, Autofix, Bedrock BYOK, Jira integration, etc.
//!
//! Every endpoint here is **stubbed** — calling any of them returns
//! `AppSecError::OssOnly` so the caller can fall back to a local-only path.
//! The shape is intentionally complete so that wiring real network I/O in a
//! follow-up doesn't ripple through the type system.

pub mod ai_detection;
pub mod autofix_pr;
pub mod autotriage;
pub mod bedrock;
pub mod findings_upload;
pub mod guardian;
pub mod jira;
pub mod managed_scans;
pub mod multi_policy_secrets;
pub mod network_broker;
pub mod plugin_bundle;
pub mod policies;
pub mod project_tags;
pub mod projects;

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum AppSecError {
    #[error("OSS-only mode: Semgrep AppSec endpoint `{0}` is not available in this build")]
    OssOnly(&'static str),
    #[error("network error: {0}")]
    Network(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("serialisation error: {0}")]
    Serde(String),
}

pub type Result<T> = std::result::Result<T, AppSecError>;

/// Minimal client struct — when wired against a real backend, holds the
/// base URL, bearer token, and a `reqwest::Client`. For now it carries just
/// enough to look real at the call site.
#[derive(Debug, Clone)]
pub struct AppSecClient {
    pub base_url: String,
    pub token: Option<String>,
    pub timeout: Duration,
}

impl Default for AppSecClient {
    fn default() -> Self {
        Self {
            base_url: "https://semgrep.dev".into(),
            token: None,
            timeout: Duration::from_secs(30),
        }
    }
}

impl AppSecClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }
}
