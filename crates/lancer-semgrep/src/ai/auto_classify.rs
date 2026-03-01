//! Plan §"AI augmentation ideas → Auto-classify findings (TP vs FP)".
//!
//! Each finding plus surrounding context goes to an LLM judge; LLM rates
//! likely real-vuln 0–100 with a one-sentence justification. We expose a
//! local typed verdict so emitters can show / threshold it.

use semgrep_core::Finding;

use crate::ai::{AiError, Result};

#[derive(Debug, Clone)]
pub struct Verdict {
    pub finding_index: usize,
    pub score: u8, // 0–100
    pub justification: String,
}

pub async fn classify(_findings: &[Finding]) -> Result<Vec<Verdict>> {
    Err(AiError::NotConfigured)
}
