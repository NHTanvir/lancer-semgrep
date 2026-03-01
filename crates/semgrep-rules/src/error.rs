//! Error types for `semgrep-rules`.
//!
//! Two enums:
//!
//! - [`LoadError`] — anything that can go wrong while loading rules (YAML
//!   parse, IO, schema, network, cache).
//! - [`SchemaError`] — semantic / structural errors found after deserialisation
//!   succeeded. Wrapped inside `LoadError::Schema` for callers that just want
//!   one error type.
//!
//! `LoadError` deliberately does not `#[from]`-impl `SemgrepError` directly;
//! the upstream-style behaviour is for the caller (the CLI / engine) to map
//! between them. We keep the loader-layer error tight on its specific
//! variants.

use std::path::PathBuf;

use semgrep_core::RuleId;

/// Anything that can go wrong while loading rules.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// Top-level YAML parse error (e.g. malformed indentation).
    #[error("yaml parse error in {source}: {error}")]
    Yaml {
        source: String,
        #[source]
        error: serde_yaml::Error,
    },

    /// Per-rule deserialisation error (one rule out of N failed to parse into a `Rule`).
    #[error("rule parse error in {source} (rule #{index}): {error}")]
    RuleParse {
        source: String,
        index: usize,
        #[source]
        error: serde_yaml::Error,
    },

    /// Filesystem read error.
    #[error("io error reading {path}: {error}")]
    Io {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },

    /// Schema validation failed for a rule that otherwise parsed.
    #[error("schema error: {0}")]
    Schema(#[from] SchemaError),

    /// Registry / HTTP failure (404, 429 after retries, TLS error, etc.).
    #[error("network error: {0}")]
    Network(String),

    /// `redb` cache failure (open, read, write, commit).
    #[error("cache error: {0}")]
    Cache(String),

    /// Free-form catch-all (unsupported config kind, etc.).
    #[error("{0}")]
    Other(String),
}

/// Semantic errors in a deserialised rule.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// A required field was empty or missing.
    #[error("rule {rule} missing required field: {field}")]
    MissingField { rule: RuleId, field: String },

    /// The declared `mode:` requires a sub-block / field that wasn't present.
    #[error("rule {rule} mode {mode} requires {field}")]
    ModeRequires {
        rule: RuleId,
        mode: String,
        field: String,
    },

    /// A metavariable name that does not start with `$` (or `$$`).
    #[error("rule {rule} has invalid metavariable name {name}")]
    InvalidMetavarName { rule: RuleId, name: String },
}
