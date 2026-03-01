//! AI Auto-Triage ("Semgrep Multimodal" / "Assistant").
//!
//! Per plan §"AppSec / Multimodal (rebrand of Assistant, Mar 2026)": LLM
//! rates each finding TP/FP/Severity. We mirror the request/response shape
//! for forward compatibility. Stubbed.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct AutoTriageVerdict {
    pub finding_id: String,
    pub label: TriageLabel,
    pub confidence: f32,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageLabel {
    TruePositive,
    FalsePositive,
    NotApplicable,
    NeedsReview,
}

impl AppSecClient {
    pub async fn autotriage(&self, _finding_ids: &[&str]) -> Result<Vec<AutoTriageVerdict>> {
        Err(AppSecError::OssOnly("POST /api/v1/autotriage"))
    }
}
