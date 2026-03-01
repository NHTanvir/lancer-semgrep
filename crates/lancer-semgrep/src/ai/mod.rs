//! AI augmentation hooks (plan §"AI augmentation ideas").
//!
//! Plan §"What is allowed to diverge → AI augmentation — net-new"
//! explicitly marks this surface as new vs upstream Semgrep. Every module
//! here exposes the **shape** of one idea so callers can plug an LLM
//! backend later without re-plumbing types. All public entry points
//! default to `Result::Err(AiError::NotConfigured)` so a missing key /
//! offline environment is fail-open: no AI features fire, the rest of the
//! scan still runs.

pub mod auto_classify;
pub mod cluster_summary;
pub mod conversational_triage;
pub mod fix_synthesis;
pub mod natural_rule_gen;
pub mod per_language_variants;
pub mod rule_explainer;
pub mod rule_mining;
pub mod sanitizer_suggester;

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("no AI backend configured (set ANTHROPIC_API_KEY or LANCER_AI_BACKEND)")]
    NotConfigured,
    #[error("AI backend error: {0}")]
    Backend(String),
    #[error("serialisation error: {0}")]
    Serde(String),
}

pub type Result<T> = std::result::Result<T, AiError>;

/// Generic LLM-backend abstraction. Concrete implementations live in
/// follow-up patches (Anthropic, OpenAI, Bedrock, etc.).
pub trait LlmBackend: Send + Sync {
    fn name(&self) -> &'static str;
}

/// No-op backend used in tests / offline runs.
#[derive(Default)]
pub struct NoBackend;
impl LlmBackend for NoBackend {
    fn name(&self) -> &'static str {
        "none"
    }
}
