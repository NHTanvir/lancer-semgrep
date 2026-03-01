//! Parsed form of `metavariable-comparison:` blocks.
//!
//! The comparison string is a tiny Python-like expression DSL evaluated
//! against bound metavariables. The full evaluator lives in `match_/` (Task
//! 5); this file only stores the deserialised AST + a future-facing stub for
//! a parsed `ComparisonAst`. Built-in helpers `lower()`, `upper()`, `int()`,
//! and numeric comparisons over `base`-coerced literals are noted here for
//! future implementers — see plan §"Newer rule-format features (2025–2026)".

use serde::{Deserialize, Serialize};

/// One `metavariable-comparison:` block in a rule.
///
/// YAML shape:
/// ```yaml
/// - metavariable-comparison:
///     metavariable: $N
///     comparison: "$N > 100"
///     base: 10
///     strip: true
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct MetavariableComparison {
    /// Optional — the comparison string can reference multiple metavars; when
    /// `metavariable` is set the engine pre-filters matches where that one is
    /// bound.
    pub metavariable: Option<String>,

    /// Raw comparison DSL string, e.g.
    /// `"$N > 100"`, `"lower($X) == 'foo'"`, `"int($N, base=16) < 0x100"`.
    pub comparison: String,

    /// Optional numeric base for integer-coerced metavariables (`base: 16`
    /// makes `$N` a hex literal).
    pub base: Option<u32>,

    /// If true, surrounding quote characters of a string-typed metavariable
    /// are stripped before substitution into the comparison expression.
    #[serde(default)]
    pub strip: bool,
}

impl MetavariableComparison {
    pub fn new(comparison: impl Into<String>) -> Self {
        Self {
            metavariable: None,
            comparison: comparison.into(),
            base: None,
            strip: false,
        }
    }
}

/// Parsed comparison AST — placeholder for Task 5's evaluator.
///
/// The evaluator will hold a recursive-descent parser over the same Python-
/// like expression DSL Semgrep accepts: arithmetic, string ops, `==`, `!=`,
/// `<`, `<=`, `>`, `>=`, `in`, `not in`, `and`, `or`, `not`, and a small set
/// of builtins (`int`, `str`, `len`, `lower`, `upper`). We declare the enum
/// shape here so other crates can refer to `ComparisonAst` symbolically; the
/// full set of variants will be filled in alongside the evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ComparisonAst {
    /// Reserved — the parser is not implemented in Task 2.
    Unparsed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_round_trip_minimal() {
        let yaml = "metavariable: $N\ncomparison: '$N > 100'\n";
        let mc: MetavariableComparison = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(mc.metavariable.as_deref(), Some("$N"));
        assert_eq!(mc.comparison, "$N > 100");
        assert!(mc.base.is_none());
        assert!(!mc.strip);
    }

    #[test]
    fn yaml_round_trip_with_base_and_strip() {
        let yaml = "metavariable: $N\ncomparison: '$N < 256'\nbase: 16\nstrip: true\n";
        let mc: MetavariableComparison = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(mc.base, Some(16));
        assert!(mc.strip);
    }
}
