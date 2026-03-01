//! Error types for semgrep-core.
//!
//! Centralised `SemgrepError` enum + `Result` alias. Every public fallible
//! function in the crate returns `Result<T>` so the engine can compose errors
//! across modules (parsing, schema validation, IO, regex compile, taint
//! analysis, etc.). See plan.md §"Internal architecture".

use std::time::Duration;

/// All error kinds the semgrep-core engine may surface.
///
/// New variants should be additive — downstream code matches on this enum and
/// non-exhaustive growth would require recompilation regardless.
#[derive(thiserror::Error, Debug)]
pub enum SemgrepError {
    /// Underlying filesystem / OS error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML rule or config could not be parsed.
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// JSON rule or config could not be parsed.
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// Rule passed YAML deserialisation but violated semantic schema.
    #[error("rule schema violation in {rule_id}: {reason}")]
    Schema { rule_id: String, reason: String },

    /// Same metavariable bound to structurally different nodes within a
    /// single match attempt.
    #[error("metavariable bind clash for {name}")]
    MetavarClash { name: String },

    /// Pattern string failed to parse with the language grammar.
    #[error("pattern parse error: {0}")]
    PatternParse(String),

    /// `requires:` boolean-expression DSL failed to parse.
    #[error("requires-expr parse error: {0}")]
    RequiresParse(String),

    /// `regex` crate could not compile a `metavariable-regex` /
    /// `pattern-regex` / etc. value.
    #[error("regex compile error: {0}")]
    Regex(#[from] regex::Error),

    /// Rule declared a language that the engine has no grammar for.
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),

    /// Git operation (baseline-commit, blame, etc.) failed.
    #[error("git error: {0}")]
    Git(#[from] git2::Error),

    /// `redb` rule cache / target cache error.
    #[error("redb error: {0}")]
    Redb(String),

    /// Network failure during registry fetch or Secrets validator call.
    #[error("network error: {0}")]
    Network(String),

    /// Per-rule or global scan timeout hit.
    #[error("scan timeout after {0:?}")]
    Timeout(Duration),

    /// Catch-all for messages not covered by another variant. Prefer adding a
    /// new variant over reaching for this.
    #[error("{0}")]
    Other(String),
}

/// Convenient alias used throughout semgrep-core.
pub type Result<T> = std::result::Result<T, SemgrepError>;
