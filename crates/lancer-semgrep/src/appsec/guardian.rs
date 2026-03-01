//! Semgrep Guardian — PR-merge gate. Decides whether a PR is mergeable
//! based on scan findings + policies. Apr 2026 added Supply-Chain hook
//! support.
//!
//! Stub.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct GuardianVerdict {
    pub pr_id: String,
    pub allow_merge: bool,
    pub blocking_findings: Vec<String>,
}

impl AppSecClient {
    pub async fn guardian_verdict(&self, _pr_id: &str) -> Result<GuardianVerdict> {
        Err(AppSecError::OssOnly("GET /api/v1/guardian/verdict"))
    }
}
