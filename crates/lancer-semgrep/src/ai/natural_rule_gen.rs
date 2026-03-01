//! Plan §"AI augmentation ideas → LLM-generated rules from natural language".
//!
//! "Find SSRF in this code." → LLM reads a few sample files, drafts a
//! Semgrep rule, tests it on the corpus, refines until matches look right.
//! Saved as a custom rule for reuse.
//!
//! Stub: returns `AiError::NotConfigured` until a backend is wired.

use crate::ai::{AiError, Result};

pub struct RuleGenRequest {
    pub prompt: String,
    pub sample_paths: Vec<std::path::PathBuf>,
    pub target_language: semgrep_core::Language,
}

pub async fn generate_rule_from_nl(_req: &RuleGenRequest) -> Result<String> {
    Err(AiError::NotConfigured)
}
