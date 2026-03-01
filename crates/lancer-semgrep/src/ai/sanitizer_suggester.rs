//! Plan §"AI augmentation ideas → Suggest sanitizer patterns".
//!
//! Given a taint finding and an in-house sanitizer (`safe_html(x)`) that the
//! rule didn't know about, propose adding it to `pattern-sanitizers`.

use crate::ai::{AiError, Result};

#[derive(Debug, Clone)]
pub struct SanitizerProposal {
    pub pattern_text: String,
    pub justification: String,
}

pub async fn propose_sanitizers(
    _finding: &semgrep_core::Finding,
    _corpus_root: &std::path::Path,
) -> Result<Vec<SanitizerProposal>> {
    Err(AiError::NotConfigured)
}
