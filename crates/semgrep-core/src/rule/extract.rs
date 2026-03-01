//! `mode: extract` rule configuration.
//!
//! Extract a sub-snippet from a host language and rescan it with rules for an
//! inner language — e.g. pull SQL strings out of Python and run SQL rules over
//! them, or pull embedded shell out of Dockerfile `RUN` lines. Either
//! `pattern:` (AST-driven) or `regex:` (text-driven) must be set. See plan.md
//! §"Newer rule-format features (2025–2026) — `mode: extract`".

use serde::{Deserialize, Serialize};

use crate::lang::Language;
use crate::rule::pattern::PatternOp;

/// `extract:` block of an extract-mode rule.
///
/// `dest_language` is the sub-language to scan the extracted snippet with.
/// Optional `transform` names a pre-scan transformation pass (e.g.
/// `"concat"` joins string fragments, `"unescape-string"` undoes `\\n` →
/// `\n`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExtractRuleConfig {
    /// AST-pattern extractor: bind a metavariable that captures the inner
    /// snippet (e.g. `cursor.execute($SQL)` with `extract: $SQL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<PatternOp>,

    /// Text-regex extractor. Group 1 (or `(?P<extract>...)`) is the captured
    /// snippet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,

    /// Language to scan the extracted snippet with.
    pub dest_language: Language,

    /// Optional pre-scan transform name. Built-ins: `"concat"`,
    /// `"unescape-string"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
}
