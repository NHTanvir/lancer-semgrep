//! Pattern AST — boolean tree of pattern operators from a rule's `patterns:`
//! field.
//!
//! Each operator has its YAML key spelt **kebab-case** (e.g.
//! `pattern-not-inside`, `metavariable-regex`); the `serde(rename_all =
//! "kebab-case")` directive on the enum derives the kebab spelling from each
//! variant's PascalCase name. Variants with `metavariable-` prefixes keep
//! redundant explicit `#[serde(rename = "...")]` attributes as
//! self-documenting reminders of upstream's wire format.
//!
//! See plan.md §"Granular feature catalog — Rule format".
//!
//! ### Bare-string shorthand
//!
//! Upstream Semgrep accepts a *bare-string* shorthand for the nested
//! operators `pattern-not`, `pattern-inside`, `pattern-not-inside`:
//!
//! ```yaml
//! - pattern-not: foo($X)        # shorthand for {pattern: foo($X)}
//! ```
//!
//! Our deserialiser does **not** rewrite this at the type level — the loader
//! in `semgrep-rules` (Task 5) is responsible for canonicalising bare strings
//! into the equivalent `pattern: ...` form before constructing the `Rule`.
//! That keeps `PatternOp` strictly typed and avoids ambiguity in the
//! round-trip.

use serde::{Deserialize, Serialize};

use crate::lang::Language;
use crate::rule::metavar_comp::MetavariableComparison;

/// One node of a pattern boolean tree.
///
/// YAML examples for each variant are sketched alongside the enum in case of
/// future schema drift.
///
/// ```yaml
/// # Pattern("foo($X)")
/// pattern: foo($X)
///
/// # Patterns([... AND ...])
/// patterns:
///   - pattern: foo($X)
///   - metavariable-regex: { metavariable: $X, regex: ^db_ }
///
/// # PatternEither([... OR ...])
/// pattern-either:
///   - pattern: foo($X)
///   - pattern: bar($X)
///
/// # MetavariableRegex { metavariable: $X, regex: ... }
/// metavariable-regex:
///   metavariable: $X
///   regex: '^[A-Z_]+$'
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatternOp {
    /// Raw pattern source. Becomes a parsed AST in Task 5 — for now we keep
    /// the original text so the engine can lazy-compile.
    Pattern(String),

    /// AND of nested operators (all must match).
    Patterns(Vec<PatternOp>),

    /// OR of nested operators (at least one must match).
    PatternEither(Vec<PatternOp>),

    /// Negation: matches in `inner` are subtracted from the parent's matches.
    PatternNot(Box<PatternOp>),

    /// The match must be lexically nested inside something matching `inner`.
    PatternInside(Box<PatternOp>),

    /// The match must NOT be lexically nested inside something matching
    /// `inner`.
    PatternNotInside(Box<PatternOp>),

    /// Fall-back regex over the source text — escape hatch for unparseable
    /// input.
    PatternRegex(String),

    /// Negative regex pre-filter.
    PatternNotRegex(String),

    /// Constrain a bound metavariable by a regex over its source text.
    #[serde(rename = "metavariable-regex")]
    MetavariableRegex {
        metavariable: String,
        regex: String,
    },

    /// Python-like expression DSL over metavariable bindings. See
    /// `metavar_comp.rs`.
    #[serde(rename = "metavariable-comparison")]
    MetavariableComparison(MetavariableComparison),

    /// Re-run a pattern over a metavariable's bound subtree. Supports
    /// language switching for embedded-DSL use cases.
    ///
    /// The inner block carries its own pattern operators (just like a top-
    /// level rule); see [`MetavariablePatternBody`].
    #[serde(rename = "metavariable-pattern")]
    MetavariablePattern(MetavariablePatternBody),

    /// Constrain a metavariable by inferred type. Pro engine feature.
    #[serde(rename = "metavariable-type")]
    MetavariableType(MetavariableTypeBody),

    /// Supply-Chain matcher: rule triggers only when the target project
    /// depends on a listed package within the given version range. Each
    /// list entry is one (`namespace`, `package`, `version`) constraint;
    /// the rule fires when *any* entry matches. See plan.md §"Newer rule-
    /// format features → r2c-internal-project-depends-on".
    #[serde(rename = "r2c-internal-project-depends-on")]
    ProjectDependsOn(ProjectDependsOnBody),
}

/// Inner block of `ProjectDependsOn`.
///
/// ```yaml
/// r2c-internal-project-depends-on:
///   depends-on-either:
///     - namespace: pypi
///       package: requests
///       version: "< 2.20.0"
///     - namespace: npm
///       package: lodash.template
///       version: "<= 4.5.0"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDependsOnBody {
    /// OR-list of package/version constraints. The upstream YAML key is
    /// `depends-on-either`.
    #[serde(rename = "depends-on-either", default)]
    pub depends_on_either: Vec<DependsOnConstraint>,
}

/// One package + version-range constraint used by `ProjectDependsOnBody`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependsOnConstraint {
    /// Ecosystem: `pypi`, `npm`, `gem`, `maven`, `gradle`, `cargo`,
    /// `composer`, `nuget`, `go`, `hex`, `pub`, `swiftpm`.
    pub namespace: String,
    pub package: String,
    /// Version range string (e.g. `"< 2.20.0"`, `">= 1.0, < 2.0"`, `"*"`).
    pub version: String,
}

/// Inner block of `MetavariablePattern`. The `pattern` field is `#[flatten]`-
/// inlined so the YAML can read like:
///
/// ```yaml
/// metavariable-pattern:
///   metavariable: $X
///   pattern: foo($Y)
///   language: python
/// ```
///
/// We use a tuple-style enum variant + inner struct because serde does not
/// currently support `#[serde(flatten)]` on a struct-variant's field directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetavariablePatternBody {
    pub metavariable: String,
    /// Inner pattern operator. Flattened so the variant keys
    /// (`pattern:` / `patterns:` / etc.) appear at the same level as
    /// `metavariable:` and `language:`.
    #[serde(flatten)]
    pub pattern: Box<PatternOp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
}

/// Inner block of `MetavariableType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetavariableTypeBody {
    pub metavariable: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
}

impl PatternOp {
    /// Construct a leaf `pattern: ...` operator.
    pub fn pattern(src: impl Into<String>) -> Self {
        PatternOp::Pattern(src.into())
    }

    /// True when this is a "leaf" operator (no nested `PatternOp` children).
    pub fn is_leaf(&self) -> bool {
        matches!(
            self,
            PatternOp::Pattern(_)
                | PatternOp::PatternRegex(_)
                | PatternOp::PatternNotRegex(_)
                | PatternOp::MetavariableRegex { .. }
                | PatternOp::MetavariableComparison(_)
                | PatternOp::MetavariableType(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pattern_leaf() {
        let yaml = "pattern: foo($X)\n";
        let p: PatternOp = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(p, PatternOp::Pattern("foo($X)".into()));
    }

    #[test]
    fn parse_pattern_either() {
        let yaml = "
pattern-either:
  - pattern: foo($X)
  - pattern: bar($X)
";
        let p: PatternOp = serde_yaml::from_str(yaml).unwrap();
        match p {
            PatternOp::PatternEither(v) => assert_eq!(v.len(), 2),
            _ => panic!("expected PatternEither"),
        }
    }

    #[test]
    fn parse_metavariable_regex() {
        let yaml = "
metavariable-regex:
  metavariable: $X
  regex: '^db_'
";
        let p: PatternOp = serde_yaml::from_str(yaml).unwrap();
        match p {
            PatternOp::MetavariableRegex { metavariable, regex } => {
                assert_eq!(metavariable, "$X");
                assert_eq!(regex, "^db_");
            }
            other => panic!("expected MetavariableRegex, got {other:?}"),
        }
    }

    #[test]
    fn parse_patterns_and() {
        let yaml = "
patterns:
  - pattern: foo($X)
  - pattern-not:
      pattern: bar()
";
        let p: PatternOp = serde_yaml::from_str(yaml).unwrap();
        match p {
            PatternOp::Patterns(v) => {
                assert_eq!(v.len(), 2);
                assert!(matches!(v[0], PatternOp::Pattern(_)));
                assert!(matches!(v[1], PatternOp::PatternNot(_)));
            }
            _ => panic!("expected Patterns"),
        }
    }

    #[test]
    fn parse_metavariable_pattern() {
        let yaml = "
metavariable-pattern:
  metavariable: $X
  pattern: foo($Y)
  language: python
";
        let p: PatternOp = serde_yaml::from_str(yaml).unwrap();
        match p {
            PatternOp::MetavariablePattern(body) => {
                assert_eq!(body.metavariable, "$X");
                assert_eq!(body.language, Some(Language::Python));
                assert!(matches!(*body.pattern, PatternOp::Pattern(_)));
            }
            other => panic!("expected MetavariablePattern, got {other:?}"),
        }
    }
}
