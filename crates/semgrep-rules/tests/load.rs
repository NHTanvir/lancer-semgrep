//! Integration tests for `semgrep-rules` — exercise the public surface
//! (load_str, ConfigSource, RuleSet, …) end-to-end.

use semgrep_core::{Language, PatternOp, RuleMode, Severity};
use semgrep_rules::{load_str, ConfigSource, RuleSet};

#[test]
fn loads_simple_search_rule() {
    let yaml = r#"
rules:
  - id: python.dangerous-eval
    languages: [python]
    severity: ERROR
    message: dangerous eval call
    pattern: eval($X)
"#;
    let rs: RuleSet = load_str(yaml, "inline").expect("load");
    assert_eq!(rs.len(), 1);
    let r = rs.iter().next().unwrap();
    assert_eq!(r.severity, Severity::Error);
    assert_eq!(r.mode, RuleMode::Search);
    assert_eq!(r.languages, vec![Language::Python]);
    match r.pattern.as_ref().expect("pattern") {
        PatternOp::Pattern(s) => assert_eq!(s, "eval($X)"),
        other => panic!("expected Pattern, got {other:?}"),
    }
}

#[test]
fn loads_patterns_and_rule() {
    let yaml = r#"
rules:
  - id: r1
    languages: [python]
    severity: WARNING
    message: combine
    patterns:
      - pattern: foo($X)
      - pattern-not:
          pattern: bar()
"#;
    let rs = load_str(yaml, "inline").expect("load");
    let r = rs.iter().next().unwrap();
    match r.pattern.as_ref().expect("patterns") {
        PatternOp::Patterns(items) => {
            assert_eq!(items.len(), 2);
            assert!(matches!(items[0], PatternOp::Pattern(_)));
            assert!(matches!(items[1], PatternOp::PatternNot(_)));
        }
        other => panic!("expected Patterns, got {other:?}"),
    }
}

#[test]
fn loads_taint_rule() {
    let yaml = r#"
rules:
  - id: tainted-sql-from-request
    mode: taint
    languages: [python]
    severity: ERROR
    message: SQL query built from user input
    taint:
      pattern-sources:
        - pattern: request.GET.get(...)
        - pattern: request.POST.get(...)
      pattern-sinks:
        - pattern: cursor.execute($SQL, ...)
      pattern-sanitizers:
        - pattern: bleach.clean(...)
"#;
    let rs = load_str(yaml, "inline").expect("load");
    let r = rs.iter().next().unwrap();
    assert_eq!(r.mode, RuleMode::Taint);
    let t = r.taint.as_ref().expect("taint");
    assert_eq!(t.sources.len(), 2);
    assert_eq!(t.sinks.len(), 1);
    assert_eq!(t.sanitizers.len(), 1);
}

#[test]
fn canonicalises_bare_string_shorthand() {
    let yaml = r#"
rules:
  - id: example
    languages: [python]
    severity: WARNING
    message: x
    patterns:
      - pattern: foo()
      - pattern-not: bar()
"#;
    let rs = load_str(yaml, "inline").expect("load");
    assert_eq!(rs.len(), 1);
    let r = rs.iter().next().unwrap();
    match r.pattern.as_ref().expect("patterns") {
        PatternOp::Patterns(items) => {
            assert_eq!(items.len(), 2);
            // Second entry must have become PatternNot(Box<Pattern("bar()")>).
            match &items[1] {
                PatternOp::PatternNot(inner) => match inner.as_ref() {
                    PatternOp::Pattern(s) => assert_eq!(s, "bar()"),
                    other => panic!("expected Pattern inside PatternNot, got {other:?}"),
                },
                other => panic!("expected PatternNot, got {other:?}"),
            }
        }
        other => panic!("expected Patterns, got {other:?}"),
    }
}

#[test]
fn canonicalises_bare_string_pattern_inside() {
    let yaml = r#"
rules:
  - id: example
    languages: [python]
    severity: WARNING
    message: x
    patterns:
      - pattern: foo()
      - pattern-inside: 'def f(): ...'
"#;
    let rs = load_str(yaml, "inline").expect("load");
    let r = rs.iter().next().unwrap();
    match r.pattern.as_ref().expect("patterns") {
        PatternOp::Patterns(items) => match &items[1] {
            PatternOp::PatternInside(inner) => match inner.as_ref() {
                PatternOp::Pattern(s) => assert_eq!(s, "def f(): ..."),
                other => panic!("expected Pattern inside PatternInside, got {other:?}"),
            },
            other => panic!("expected PatternInside, got {other:?}"),
        },
        other => panic!("expected Patterns, got {other:?}"),
    }
}

#[test]
fn canonicalises_pattern_either_bare_strings() {
    let yaml = r#"
rules:
  - id: r1
    languages: [python]
    severity: ERROR
    message: m
    pattern-either:
      - 'foo($X)'
      - { pattern: 'bar($X)' }
"#;
    let rs = load_str(yaml, "inline").expect("load");
    let r = rs.iter().next().unwrap();
    match r.pattern.as_ref().expect("pattern-either") {
        PatternOp::PatternEither(items) => {
            assert_eq!(items.len(), 2);
            assert!(matches!(&items[0], PatternOp::Pattern(s) if s == "foo($X)"));
            assert!(matches!(&items[1], PatternOp::Pattern(s) if s == "bar($X)"));
        }
        other => panic!("expected PatternEither, got {other:?}"),
    }
}

#[test]
fn rejects_search_rule_without_pattern() {
    let yaml = r#"
rules:
  - id: bad
    languages: [python]
    severity: ERROR
    message: oh no
"#;
    let err = load_str(yaml, "inline").expect_err("should fail schema");
    let s = err.to_string();
    assert!(
        s.contains("search") && s.contains("pattern"),
        "unexpected error: {}",
        s
    );
}

#[test]
fn rejects_taint_rule_without_sinks() {
    let yaml = r#"
rules:
  - id: bad-taint
    mode: taint
    languages: [python]
    severity: ERROR
    message: x
    taint:
      pattern-sources:
        - pattern: request.GET.get(...)
"#;
    let err = load_str(yaml, "inline").expect_err("should fail schema");
    let s = err.to_string();
    assert!(
        s.contains("sinks") || s.contains("taint"),
        "unexpected error: {}",
        s
    );
}

#[test]
fn slug_parsing() {
    match ConfigSource::parse("p/python") {
        ConfigSource::Slug(s) => assert_eq!(format!("{s}"), "p/python"),
        other => panic!("expected Slug, got {:?}", other),
    }
    match ConfigSource::parse("r/python.lang.security.dangerous-eval") {
        ConfigSource::Slug(s) => {
            assert_eq!(format!("{s}"), "r/python.lang.security.dangerous-eval")
        }
        other => panic!("expected Slug, got {:?}", other),
    }
    match ConfigSource::parse("auto") {
        ConfigSource::Auto => {}
        other => panic!("expected Auto, got {:?}", other),
    }
    match ConfigSource::parse("-") {
        ConfigSource::Stdin => {}
        other => panic!("expected Stdin, got {:?}", other),
    }
    match ConfigSource::parse("https://example.com/rules.yaml") {
        ConfigSource::Url(u) => assert_eq!(u, "https://example.com/rules.yaml"),
        other => panic!("expected Url, got {:?}", other),
    }
}

#[test]
fn well_known_slugs_contains_python_and_default() {
    let slugs = semgrep_rules::well_known_slugs();
    assert!(slugs.contains(&"p/python"));
    assert!(slugs.contains(&"p/default"));
    assert!(slugs.contains(&"p/owasp-top-ten"));
}

#[test]
fn ruleset_filter_by_language() {
    let yaml = r#"
rules:
  - id: py-rule
    languages: [python]
    severity: WARNING
    message: m
    pattern: foo()
  - id: js-rule
    languages: [javascript]
    severity: WARNING
    message: m
    pattern: bar()
"#;
    let rs = load_str(yaml, "inline").expect("load");
    assert_eq!(rs.filter_by_language(Language::Python).count(), 1);
    assert_eq!(rs.filter_by_language(Language::Javascript).count(), 1);
    assert_eq!(rs.filter_by_language(Language::Go).count(), 0);
}
