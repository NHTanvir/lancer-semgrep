//! Plan §"AI augmentation ideas → Auto-fix synthesis".
//!
//! Given a finding + AST snippet, LLM proposes a patch as a unified diff.

use crate::ai::{AiError, Result};

#[derive(Debug, Clone)]
pub struct LlmFix {
    pub diff: String,
    pub explanation: String,
}

pub async fn synthesise_fix(
    _finding: &semgrep_core::Finding,
    _file_content: &str,
) -> Result<LlmFix> {
    Err(AiError::NotConfigured)
}
