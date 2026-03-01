//! YAML value canonicalisation.
//!
//! Walk a `serde_yaml::Value` tree and rewrite **bare-string shorthand** into
//! the structured form `PatternOp` expects.
//!
//! ### Why we do this here, not in serde
//!
//! Upstream Semgrep accepts both:
//!
//! ```yaml
//! pattern-not: foo($X)                    # bare string
//! pattern-not: { pattern: foo($X) }       # structured map
//! ```
//!
//! The `PatternOp` enum in `semgrep-core` (see `rule/pattern.rs`) does not have
//! a bare-string variant for `pattern-not`; serde would fail on the first
//! form. Rather than complicate `PatternOp` with manual `Deserialize` (which
//! defeats `#[serde(rename_all = "kebab-case")]` and breaks the strict round-
//! trip), we **canonicalise** at the YAML `Value` level before deserialising.
//!
//! See plan.md §"Granular feature catalog → Rule format" and Task 2 concern #3.
//!
//! ### Operators we expand
//!
//! - **String-shorthand**: `pattern-not`, `pattern-inside`, `pattern-not-inside`
//!   may carry a bare string. We wrap as `{ pattern: <str> }`.
//! - **List-shorthand**: inside `pattern-either:` and `patterns:` (which take a
//!   *list* of operators), each list entry may itself be a bare string — we
//!   wrap each such entry as `{ pattern: <str> }`.
//!
//! Other places that accept a `PatternOp` as a flattened *value* (top-level
//! `pattern:` / `patterns:` / `pattern-either:` keys on a rule, the
//! `extract:` block, `taint.pattern-sources[*]`, etc.) are already in the
//! structured form by virtue of using the `pattern:` key; bare-string is only
//! a concern at the three nested-negation/inside operator positions and inside
//! list-shorthand entries.

use serde_yaml::Value;

/// Operators whose value can be a bare string OR a structured map containing `pattern:`.
/// When we see a bare string, wrap it as `{ pattern: <str> }`.
const STRING_SHORTHAND_OPS: &[&str] = &[
    "pattern-not",
    "pattern-inside",
    "pattern-not-inside",
];

/// Operators that take a *list* of pattern operators where each list entry
/// may itself be a bare string shorthand for `{ pattern: <str> }`.
const LIST_OPS: &[&str] = &[
    "pattern-either",
    "patterns",
];

/// Walk `value` in place and canonicalise bare-string shorthand throughout.
///
/// Safe to call on any YAML value (top-level rule, taint config, extract
/// block, …) — operators that don't carry pattern children are walked but not
/// modified.
pub fn canonicalise_yaml(value: &mut Value) {
    canonicalise_value(value);
}

fn wrap_pattern(s: String) -> Value {
    let mut m = serde_yaml::Mapping::new();
    m.insert(Value::String("pattern".into()), Value::String(s));
    Value::Mapping(m)
}

fn canonicalise_value(value: &mut Value) {
    match value {
        Value::Mapping(map) => {
            // Each (key, child) pair: if the key is a known operator and the
            // child is a bare string / a list of bare strings, rewrite it.
            // Always recurse into the (now possibly rewritten) child.
            for (k, v) in map.iter_mut() {
                let key_str = k.as_str().unwrap_or("");

                // String-shorthand operators: `pattern-not: foo()` →
                // `pattern-not: { pattern: foo() }`.
                if STRING_SHORTHAND_OPS.contains(&key_str) {
                    if let Some(s) = v.as_str() {
                        *v = wrap_pattern(s.to_string());
                        // No deeper bare-string children to expand: the wrap
                        // produces a `{pattern: <str>}` map whose value is a
                        // plain string operand, not a nested operator. Skip
                        // recursion to avoid wasted work.
                        continue;
                    }
                }

                // List-shorthand operators: each item in the list may itself
                // be a bare string standing in for `{pattern: <str>}`.
                if LIST_OPS.contains(&key_str) {
                    if let Value::Sequence(seq) = v {
                        for item in seq.iter_mut() {
                            if let Some(s) = item.as_str() {
                                *item = wrap_pattern(s.to_string());
                            } else {
                                canonicalise_value(item);
                            }
                        }
                        continue;
                    }
                }

                // Default: recurse into the child unchanged.
                canonicalise_value(v);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                canonicalise_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).expect("yaml parse")
    }

    #[test]
    fn bare_string_pattern_not_is_wrapped() {
        let mut v = parse("pattern-not: foo($X)\n");
        canonicalise_yaml(&mut v);
        let m = v.as_mapping().unwrap();
        let inner = m.get(&Value::String("pattern-not".into())).unwrap();
        let inner_map = inner.as_mapping().unwrap();
        assert_eq!(
            inner_map
                .get(&Value::String("pattern".into()))
                .and_then(|x| x.as_str()),
            Some("foo($X)")
        );
    }

    #[test]
    fn structured_pattern_not_left_alone() {
        let yaml = "pattern-not:\n  pattern: bar()\n";
        let mut v = parse(yaml);
        canonicalise_yaml(&mut v);
        // Should still be {pattern-not: {pattern: bar()}}.
        let m = v.as_mapping().unwrap();
        let inner = m.get(&Value::String("pattern-not".into())).unwrap();
        let inner_map = inner.as_mapping().unwrap();
        assert_eq!(
            inner_map
                .get(&Value::String("pattern".into()))
                .and_then(|x| x.as_str()),
            Some("bar()")
        );
    }

    #[test]
    fn list_op_each_entry_wrapped() {
        let yaml = "
pattern-either:
  - 'foo($X)'
  - { pattern: 'bar($X)' }
";
        let mut v = parse(yaml);
        canonicalise_yaml(&mut v);
        let either = v
            .as_mapping()
            .unwrap()
            .get(&Value::String("pattern-either".into()))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(either.len(), 2);
        for item in either {
            let m = item.as_mapping().unwrap();
            assert!(m.get(&Value::String("pattern".into())).is_some());
        }
    }

    #[test]
    fn nested_bare_inside_list_is_wrapped() {
        // `patterns:` is a list; one entry has bare-string `pattern-not`.
        let yaml = "
patterns:
  - pattern: 'bar()'
  - pattern-not: 'foo()'
";
        let mut v = parse(yaml);
        canonicalise_yaml(&mut v);
        let seq = v
            .as_mapping()
            .unwrap()
            .get(&Value::String("patterns".into()))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(seq.len(), 2);
        // Second entry: pattern-not should now have a pattern: child map.
        let pn = seq[1]
            .as_mapping()
            .unwrap()
            .get(&Value::String("pattern-not".into()))
            .unwrap();
        let pn_map = pn.as_mapping().unwrap();
        assert_eq!(
            pn_map
                .get(&Value::String("pattern".into()))
                .and_then(|x| x.as_str()),
            Some("foo()")
        );
    }

    #[test]
    fn deep_nesting_walks_correctly() {
        let yaml = "
patterns:
  - pattern: 'top()'
  - pattern-either:
      - 'leaf-bare()'
      - pattern-not: 'inner-bare()'
";
        let mut v = parse(yaml);
        canonicalise_yaml(&mut v);
        let outer = v
            .as_mapping()
            .unwrap()
            .get(&Value::String("patterns".into()))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(outer.len(), 2);
        let either = outer[1]
            .as_mapping()
            .unwrap()
            .get(&Value::String("pattern-either".into()))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(either.len(), 2);
        // first item: bare string → wrapped
        assert!(either[0]
            .as_mapping()
            .and_then(|m| m.get(&Value::String("pattern".into())))
            .is_some());
        // second item: pattern-not bare string → wrapped
        let pn = either[1]
            .as_mapping()
            .unwrap()
            .get(&Value::String("pattern-not".into()))
            .unwrap();
        assert_eq!(
            pn.as_mapping()
                .unwrap()
                .get(&Value::String("pattern".into()))
                .and_then(|x| x.as_str()),
            Some("inner-bare()")
        );
    }
}
