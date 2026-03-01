//! Rule data types — `Rule`, `RuleId`, `Options`, `PathFilter`, plus all the
//! per-mode configuration sub-types. This is the in-memory representation of
//! a YAML rule after deserialisation (and before the patterns are AST-
//! compiled).
//!
//! See plan.md §"Granular feature catalog — Rule format".

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod extract;
pub mod fix;
pub mod join;
pub mod metavar_comp;
pub mod mode;
pub mod pattern;
pub mod secrets;
pub mod taint;

pub use extract::ExtractRuleConfig;
pub use fix::{FixRegex, FixTemplate};
pub use join::{JoinKey, JoinRef, JoinRuleConfig, JoinSubRule};
pub use metavar_comp::{ComparisonAst, MetavariableComparison};
pub use mode::RuleMode;
pub use pattern::{
    DependsOnConstraint, MetavariablePatternBody, MetavariableTypeBody, PatternOp,
    ProjectDependsOnBody,
};
pub use secrets::{
    SecretValidator, SecretsRuleConfig, ValidatorHttp, ValidatorMatch,
    DEFAULT_VALIDATOR_TIMEOUT_SECS,
};
pub use taint::{TaintPropagator, TaintRuleConfig, TaintSanitizer, TaintSink, TaintSource};

use crate::lang::Language;
use crate::severity::Severity;

/// A rule identifier (`python.lang.security.audit.dangerous-subprocess-use`).
///
/// Newtype around `String` so we don't accidentally pass a path or arbitrary
/// label where an ID is expected. Strings round-trip transparently through
/// serde, so YAML still emits the plain ID.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
)]
#[serde(transparent)]
pub struct RuleId(pub String);

impl RuleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for RuleId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Per-rule engine knobs (`options:` block).
///
/// Defaults match upstream Semgrep behaviour as of v1.164 — i.e. symbolic
/// propagation off, field-tracking limit unset (engine default applies),
/// interfile off, matching explanations off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct Options {
    /// When true, the engine tracks value-equivalence: `y = x; sink(y)` will
    /// resolve `y == x` for matching purposes. See plan §"Symbolic
    /// propagation".
    #[serde(default)]
    pub symbolic_propagation: bool,

    /// Per-object field-tracking cap for the taint engine. `None` => engine
    /// default. Mirrors the Feb 2026 upstream improvement (`--max-fields-
    /// tracked-per-object`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fields_tracked_per_object: Option<usize>,

    /// Enable inter-file taint analysis (Pro). Stub at the OSS layer.
    #[serde(default)]
    pub interfile: bool,

    /// Emit per-finding match-tree explanation (drives `--matching-
    /// explanations`).
    #[serde(default)]
    pub matching_explanations: bool,
}

/// Rule-scoped path filter. Globs are absolute or repo-relative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct PathFilter {
    /// Only run on paths matching at least one of these globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// Skip paths matching any of these globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

/// Free-form metadata helper. The canonical home for metadata is the
/// `metadata: serde_json::Value` field on `Rule` itself; this struct is kept
/// as a forward-compat extension point where future strongly-typed metadata
/// fields can live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuleMetadata {
    // intentionally empty — see plan §"Granular feature catalog → metadata".
}

/// One Semgrep rule, fully deserialised from YAML.
///
/// Patterns / sub-rule blocks are kept in their parsed-form-but-uncompiled
/// state; the rule loader in `semgrep-rules` is responsible for further
/// validation, and the matcher in `match_/` compiles patterns lazily.
///
/// `mode` defaults to `RuleMode::Search`. Whichever mode is set, the
/// corresponding sub-config (`taint`, `join`, `extract`, `secrets`) **may**
/// be set. The rule validator in `semgrep-rules` enforces that the right sub-
/// config is non-`None` for the declared mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Rule {
    /// Unique rule identifier.
    pub id: RuleId,

    /// Mode tag. Defaults to `Search` when absent in YAML.
    #[serde(default)]
    pub mode: RuleMode,

    /// Languages this rule applies to.
    #[serde(default)]
    pub languages: Vec<Language>,

    /// Severity of any finding the rule produces.
    pub severity: Severity,

    /// Human-readable message template. Supports `$X`-style metavariable
    /// interpolation at emit time.
    pub message: String,

    /// Free-form metadata (CWE, OWASP, references, confidence, likelihood,
    /// impact, ...).
    #[serde(default, skip_serializing_if = "is_null_value")]
    pub metadata: serde_json::Value,

    /// Engine knobs (`options:` block).
    #[serde(default)]
    pub options: Options,

    /// Optional per-rule path include/exclude filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<PathFilter>,

    /// Search-mode pattern tree. Present for `mode: search` (and historically
    /// for plain `pattern:` / `patterns:` rules without an explicit mode).
    #[serde(default, skip_serializing_if = "Option::is_none", flatten)]
    pub pattern: Option<PatternOp>,

    /// `fix:` template (auto-apply via `--autofix`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<FixTemplate>,

    /// `fix-regex:` template (alternative regex-based fix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_regex: Option<FixRegex>,

    /// `mode: taint` configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint: Option<TaintRuleConfig>,

    /// `mode: join` configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinRuleConfig>,

    /// `mode: extract` configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract: Option<ExtractRuleConfig>,

    /// `mode: secrets` configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsRuleConfig>,
}

fn is_null_value(v: &serde_json::Value) -> bool {
    v.is_null()
}

impl Rule {
    /// Construct a minimal search-mode rule for tests / builders.
    pub fn search(
        id: impl Into<RuleId>,
        languages: impl IntoIterator<Item = Language>,
        severity: Severity,
        message: impl Into<String>,
        pattern: PatternOp,
    ) -> Self {
        Self {
            id: id.into(),
            mode: RuleMode::Search,
            languages: languages.into_iter().collect(),
            severity,
            message: message.into(),
            metadata: serde_json::Value::Null,
            options: Options::default(),
            paths: None,
            pattern: Some(pattern),
            fix: None,
            fix_regex: None,
            taint: None,
            join: None,
            extract: None,
            secrets: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Language;
    use crate::severity::Severity;

    #[test]
    fn rule_id_display_and_from() {
        let id = RuleId::from("foo.bar");
        assert_eq!(id.to_string(), "foo.bar");
        let id2: RuleId = String::from("baz").into();
        assert_eq!(id2.as_str(), "baz");
    }

    #[test]
    fn search_rule_minimal_round_trip() {
        let r = Rule::search(
            "test.search",
            [Language::Python],
            Severity::Error,
            "boom".into(),
            PatternOp::Pattern("foo($X)".into()),
        );
        let yaml = serde_yaml::to_string(&r).unwrap();
        let back: Rule = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn taint_rule_round_trip() {
        let yaml = "
id: tainted-sql-from-request
mode: taint
languages: [python]
severity: ERROR
message: 'SQL query built from user input'
taint:
  pattern-sources:
    - pattern: 'request.GET.get(...)'
      label: user-input
  pattern-sinks:
    - pattern: 'cursor.execute($SQL, ...)'
      requires: 'user-input and not admin-only'
  pattern-sanitizers:
    - pattern: 'bleach.clean(...)'
      by-side-effect: true
  pattern-propagators:
    - pattern: '$X = $Y'
      from: $Y
      to: $X
";
        let r: Rule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(r.mode, RuleMode::Taint);
        assert_eq!(r.languages, vec![Language::Python]);
        assert_eq!(r.severity, Severity::Error);
        let t = r.taint.as_ref().expect("taint config");
        assert_eq!(t.sources.len(), 1);
        assert_eq!(t.sources[0].label.as_deref(), Some("user-input"));
    }
}
