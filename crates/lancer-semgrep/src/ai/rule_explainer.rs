//! Plan §"AI augmentation ideas → Rule explanation in plain language".
//!
//! LLM rewrites a finding's terse message with actual variable / function
//! names from the codebase ("In views/user.py, line 47, cursor.execute(sql)
//! builds sql from request.GET['q']…").

use crate::ai::{AiError, Result};

pub async fn explain_finding(
    _finding: &semgrep_core::Finding,
    _file_content: &str,
) -> Result<String> {
    Err(AiError::NotConfigured)
}
