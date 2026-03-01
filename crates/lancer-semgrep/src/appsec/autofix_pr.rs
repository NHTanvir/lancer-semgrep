//! Cloud-side Autofix (renamed from "Click to Fix" in Mar 2026) — generate
//! a fix PR for a finding. Distinct from the local CLI `--autofix` flow
//! which applies the rule's static `fix:` template.
//!
//! Per plan §"AppSec / Multimodal → Autofix (Mar 2026)". Stub.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct AutofixPr {
    pub pr_url: String,
    pub branch_name: String,
    pub diff: String,
}

impl AppSecClient {
    /// Request the cloud to author an Autofix PR for a finding.
    pub async fn request_autofix_pr(&self, _finding_id: &str) -> Result<AutofixPr> {
        Err(AppSecError::OssOnly("POST /api/v1/autofix"))
    }
}
