//! `POST /api/v1/findings/upload` — upload CLI scan results to AppSec.
//!
//! Stub: returns `OssOnly` so callers can fall back to local-only emission.

use semgrep_output::ScanReport;

use crate::appsec::{AppSecClient, AppSecError, Result};

impl AppSecClient {
    /// Upload a `ScanReport` to AppSec. Stubbed.
    pub async fn upload_findings(&self, _report: &ScanReport) -> Result<UploadAck> {
        Err(AppSecError::OssOnly("POST /api/v1/findings/upload"))
    }
}

#[derive(Debug, Clone)]
pub struct UploadAck {
    pub project_id: String,
    pub finding_count: usize,
}
