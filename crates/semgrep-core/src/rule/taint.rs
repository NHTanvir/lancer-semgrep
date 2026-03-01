//! `mode: taint` rule configuration.
//!
//! Mirrors the upstream taint rule block:
//!
//! ```yaml
//! - id: tainted-sql-from-request
//!   mode: taint
//!   languages: [python]
//!   pattern-sources:
//!     - pattern: request.GET.get(...)
//!       label: user-input
//!   pattern-sinks:
//!     - pattern: cursor.execute($SQL, ...)
//!       requires: user-input and not admin-only
//!   pattern-sanitizers:
//!     - pattern: bleach.clean(...)
//!       by-side-effect: true
//!   pattern-propagators:
//!     - pattern: $X = f"... {$Y} ..."
//!       from: $Y
//!       to: $X
//! ```
//!
//! Modern (2025–2026) extensions: per-source `label:`, per-sink `requires:`
//! boolean expression, per-sanitizer `by-side-effect:` boolean. See plan.md
//! §"Newer rule-format features to support (2025–2026)".

use serde::{Deserialize, Serialize};

use crate::rule::pattern::PatternOp;
use crate::taint_types::TaintLabel;

/// Top-level taint rule configuration. Stored on `Rule::taint`.
///
/// Field order matches the upstream YAML key order so emit looks "right".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct TaintRuleConfig {
    #[serde(default, rename = "pattern-sources", skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<TaintSource>,

    #[serde(default, rename = "pattern-sinks", skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<TaintSink>,

    #[serde(
        default,
        rename = "pattern-sanitizers",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub sanitizers: Vec<TaintSanitizer>,

    #[serde(
        default,
        rename = "pattern-propagators",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub propagators: Vec<TaintPropagator>,
}

/// A taint source: any expression matching `pattern` is the start of taint
/// flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TaintSource {
    #[serde(flatten)]
    pub pattern: PatternOp,
    /// Optional label (2025+). When `None` the source has the empty label set
    /// (legacy single-source semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<TaintLabel>,
}

/// A taint sink: any expression matching `pattern` is the end of taint flow.
///
/// `requires:` is stored as the raw expression string; the parsed
/// `RequiresExpr` lives in `taint_types::RequiresExpr` and is built lazily by
/// the rule loader after deserialisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TaintSink {
    #[serde(flatten)]
    pub pattern: PatternOp,
    /// Raw boolean expression over source labels. Parsed by
    /// `RequiresExpr::parse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<String>,
}

/// A taint sanitizer: when matched, the engine clears taint on the
/// (`by_side_effect: false`) returned value, or (`by_side_effect: true`) the
/// argument variable in place. See plan §"Newer rule-format features —
/// taint by side-effect".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TaintSanitizer {
    #[serde(flatten)]
    pub pattern: PatternOp,
    /// `by-side-effect: true` means calling the sanitizer mutates the
    /// argument to untainted (e.g., `validate_in_place(buf)`).
    #[serde(default)]
    pub by_side_effect: bool,
}

/// A taint propagator: a custom flow rule transmitting taint from one
/// metavariable binding to another within a matched site (e.g., f-string
/// interpolation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TaintPropagator {
    #[serde(flatten)]
    pub pattern: PatternOp,
    /// Source metavariable for taint flow (e.g. `$Y`).
    pub from: String,
    /// Destination metavariable for taint flow (e.g. `$X`).
    pub to: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_taint_rule_config() {
        let yaml = "
pattern-sources:
  - pattern: request.GET.get(...)
    label: user-input
pattern-sinks:
  - pattern: cursor.execute($SQL, ...)
    requires: 'user-input and not admin-only'
pattern-sanitizers:
  - pattern: bleach.clean(...)
    by-side-effect: true
pattern-propagators:
  - pattern: '$X = $Y'
    from: $Y
    to: $X
";
        let cfg: TaintRuleConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.sources.len(), 1);
        assert_eq!(cfg.sources[0].label.as_deref(), Some("user-input"));
        assert_eq!(
            cfg.sinks[0].requires.as_deref(),
            Some("user-input and not admin-only")
        );
        assert!(cfg.sanitizers[0].by_side_effect);
        assert_eq!(cfg.propagators[0].from, "$Y");
        assert_eq!(cfg.propagators[0].to, "$X");
    }
}
