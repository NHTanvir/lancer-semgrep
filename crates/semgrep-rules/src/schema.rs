//! Semantic validation of a deserialised [`Rule`].
//!
//! After `serde_yaml::from_value` succeeds we still need to enforce
//! mode-specific invariants — the type system can't express "if `mode: taint`
//! then `taint` is `Some` AND `taint.sources` is non-empty". This module
//! pulls those checks out into [`validate_rule`].
//!
//! Errors are [`SchemaError`]s, wrapped into [`LoadError::Schema`] by the
//! caller in `load.rs`.

use semgrep_core::{Rule, RuleMode};

use crate::error::SchemaError;

/// Validate a single deserialised rule.
///
/// Checks:
/// - `id`, `message`, `languages` are non-empty.
/// - Mode-specific sub-block presence + minimum content.
pub fn validate_rule(rule: &Rule) -> Result<(), SchemaError> {
    // required top-level fields
    if rule.id.as_str().is_empty() {
        return Err(SchemaError::MissingField {
            rule: rule.id.clone(),
            field: "id".into(),
        });
    }
    if rule.message.is_empty() {
        return Err(SchemaError::MissingField {
            rule: rule.id.clone(),
            field: "message".into(),
        });
    }
    if rule.languages.is_empty() {
        return Err(SchemaError::MissingField {
            rule: rule.id.clone(),
            field: "languages".into(),
        });
    }

    // mode-specific checks
    match rule.mode {
        RuleMode::Search => {
            if rule.pattern.is_none() {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "search".into(),
                    field: "pattern / patterns / pattern-either".into(),
                });
            }
        }
        RuleMode::Taint => {
            let t = rule.taint.as_ref().ok_or_else(|| SchemaError::ModeRequires {
                rule: rule.id.clone(),
                mode: "taint".into(),
                field: "pattern-sources + pattern-sinks".into(),
            })?;
            if t.sources.is_empty() {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "taint".into(),
                    field: "pattern-sources".into(),
                });
            }
            if t.sinks.is_empty() {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "taint".into(),
                    field: "pattern-sinks".into(),
                });
            }
        }
        RuleMode::Join => {
            let j = rule.join.as_ref().ok_or_else(|| SchemaError::ModeRequires {
                rule: rule.id.clone(),
                mode: "join".into(),
                field: "rules + on".into(),
            })?;
            if j.rules.len() < 2 {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "join".into(),
                    field: "at least 2 sub-rules".into(),
                });
            }
            if j.on.is_empty() {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "join".into(),
                    field: "on (join conditions)".into(),
                });
            }
        }
        RuleMode::Extract => {
            let e = rule.extract.as_ref().ok_or_else(|| SchemaError::ModeRequires {
                rule: rule.id.clone(),
                mode: "extract".into(),
                field: "extract block".into(),
            })?;
            if e.pattern.is_none() && e.regex.is_none() {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "extract".into(),
                    field: "pattern or regex".into(),
                });
            }
        }
        RuleMode::Secrets => {
            let s = rule.secrets.as_ref().ok_or_else(|| SchemaError::ModeRequires {
                rule: rule.id.clone(),
                mode: "secrets".into(),
                field: "secrets block".into(),
            })?;
            if s.patterns.is_empty() {
                return Err(SchemaError::ModeRequires {
                    rule: rule.id.clone(),
                    mode: "secrets".into(),
                    field: "pattern".into(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::{Language, PatternOp, Rule, RuleId, Severity};

    fn base_search() -> Rule {
        Rule::search(
            "test.id",
            [Language::Python],
            Severity::Error,
            "msg",
            PatternOp::Pattern("foo()".into()),
        )
    }

    #[test]
    fn ok_search_rule() {
        assert!(validate_rule(&base_search()).is_ok());
    }

    #[test]
    fn rejects_empty_id() {
        let mut r = base_search();
        r.id = RuleId::from("");
        assert!(matches!(
            validate_rule(&r),
            Err(SchemaError::MissingField { field, .. }) if field == "id"
        ));
    }

    #[test]
    fn rejects_empty_message() {
        let mut r = base_search();
        r.message.clear();
        assert!(matches!(
            validate_rule(&r),
            Err(SchemaError::MissingField { field, .. }) if field == "message"
        ));
    }

    #[test]
    fn rejects_empty_languages() {
        let mut r = base_search();
        r.languages.clear();
        assert!(matches!(
            validate_rule(&r),
            Err(SchemaError::MissingField { field, .. }) if field == "languages"
        ));
    }

    #[test]
    fn rejects_search_without_pattern() {
        let mut r = base_search();
        r.pattern = None;
        assert!(matches!(
            validate_rule(&r),
            Err(SchemaError::ModeRequires { mode, .. }) if mode == "search"
        ));
    }
}
