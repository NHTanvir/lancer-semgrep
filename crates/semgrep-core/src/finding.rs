//! Owned, serde-friendly finding types emitted by the engine.
//!
//! `Match<'a>` (in `match_/`) borrows from the source buffer and is the
//! transient "we just unified" handle. `Finding` (this module) is the owned
//! result emitted to the output formatter — every field is owned, serde-
//! enabled, and round-trips through JSON / SARIF / GitLab SAST.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::node::{Range, Span};
use crate::rule::RuleId;
use crate::severity::Severity;

/// One emitted finding. The `metavars` map carries the bindings that were
/// substituted into `message`; downstream formatters re-use them for autofix
/// preview, dataflow trace expansion, etc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    /// Final message after `$X` metavariable interpolation.
    pub message: String,
    pub file: PathBuf,
    pub range: Range,
    #[serde(default)]
    pub metavars: BTreeMap<String, MetavarBindingSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<FixSuggestion>,
    /// Secrets-mode validation state. `None` for non-secrets rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_state: Option<ValidationState>,
    /// Taint-mode dataflow trace (source → propagators → sink). `None` for
    /// search-mode findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataflow_trace: Option<DataflowTrace>,
    /// Pattern-matching explanation (driven by `--matching-explanations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<MatchExplanation>,
    /// Rule's `metadata:` block, carried through verbatim.
    #[serde(default, skip_serializing_if = "is_null_value")]
    pub metadata: serde_json::Value,
}

fn is_null_value(v: &serde_json::Value) -> bool {
    v.is_null()
}

/// Outcome of running a Secrets-mode rule's `validators:` block against the
/// candidate credential. See plan §"Semgrep Secrets" and §"Newer rule-format
/// features (2025–2026) — Per-rule `validators:`".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationState {
    Valid,
    Invalid,
    NoValidator,
    ValidationError,
}

/// Source → propagators → sink trace for a taint-mode finding.
///
/// `propagators` is in dataflow order — first the source, then each
/// intermediate assignment / function call, then the sink.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataflowTrace {
    pub source: Span,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub propagators: Vec<Span>,
    pub sink: Span,
    /// Label carried by the source. None for legacy (unlabelled) sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint_label: Option<String>,
}

/// Match-explanation tree (owned).
///
/// Each node names the pattern operator (e.g. `"pattern-either"`,
/// `"metavariable-regex on $X"`), records whether it matched, and contains
/// nested children in source order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchExplanation {
    pub op: String,
    pub matched: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<MatchExplanation>,
}

/// Result of applying a rule's `fix:` template (or `fix-regex:`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixSuggestion {
    /// Unified-diff text (suitable for `--diff` output).
    pub diff: String,
    /// The matched source slice, pre-fix.
    pub before: String,
    /// The post-fix slice.
    pub after: String,
}

/// Snapshot of a single metavariable binding, with the source slice it
/// covered. Embedded in `Finding::metavars`.
///
/// `propagated_value` is `Some(...)` when the engine resolved the metavariable
/// to a constant via symbolic propagation (e.g. `x = "foo"; bar(x)` →
/// `propagated_value = Some("foo")`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetavarBindingSnapshot {
    /// Raw textual content of the metavariable binding.
    pub abstract_content: String,
    /// Propagated constant value, if symbolic propagation resolved one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagated_value: Option<String>,
    pub range: Range,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Position, Range};

    #[test]
    fn validation_state_yaml_screaming_snake_case() {
        let s = serde_yaml::to_string(&ValidationState::NoValidator).unwrap();
        assert!(s.contains("NO_VALIDATOR"), "yaml = {s:?}");
        let v: ValidationState = serde_yaml::from_str("VALIDATION_ERROR\n").unwrap();
        assert_eq!(v, ValidationState::ValidationError);
    }

    #[test]
    fn finding_round_trip_json() {
        let r = Range::new(Position::new(3, 5, 42), Position::new(3, 12, 49));
        let f = Finding {
            rule_id: RuleId::from("python.sqli"),
            severity: Severity::Error,
            message: "SQL injection".into(),
            file: PathBuf::from("views.py"),
            range: r,
            metavars: BTreeMap::new(),
            fix: None,
            validation_state: None,
            dataflow_trace: None,
            explanation: None,
            metadata: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}
