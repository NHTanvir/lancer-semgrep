//! Plan §"AI augmentation ideas → Rule mining from historical audits".
//!
//! Feed past pentest reports' findings + the matching code; LLM extracts
//! the underlying pattern as a Semgrep rule.

use crate::ai::{AiError, Result};
use semgrep_core::Rule;

pub struct AuditReport {
    pub markdown: String,
    pub anchor_files: Vec<std::path::PathBuf>,
}

pub async fn mine_rules(_report: &AuditReport) -> Result<Vec<Rule>> {
    Err(AiError::NotConfigured)
}
