//! Integration tests: YAML → `Rule` → YAML round-trip parity.
//!
//! Two reference rules — one search-mode, one taint-mode — to cover the bulk
//! of the type vocabulary defined in semgrep-core.

use semgrep_core::{
    Language, PatternOp, Rule, RuleId, RuleMode, Severity, TaintRuleConfig,
};

/// Helper: deserialise YAML → Rule → reserialise → re-deserialise → compare.
fn assert_yaml_round_trip(yaml: &str) -> Rule {
    let first: Rule = serde_yaml::from_str(yaml).expect("first deserialise failed");
    let emitted = serde_yaml::to_string(&first).expect("serialise failed");
    let second: Rule =
        serde_yaml::from_str(&emitted).expect("re-deserialise failed");
    assert_eq!(
        first, second,
        "Rule failed to round-trip through YAML; emitted form:\n{emitted}"
    );
    first
}

#[test]
fn search_rule_round_trip() {
    // Lifted from plan.md §"Granular feature catalog" — a basic SQLi-ish
    // search rule with `pattern-either`, `pattern-not`, and a fix template.
    let yaml = r#"
id: python.lang.security.audit.dangerous-subprocess-use
mode: search
languages: [python]
severity: ERROR
message: 'Dangerous subprocess call with $CMD'
metadata:
  cwe: 'CWE-78'
  owasp: 'A03:2021'
  confidence: HIGH
options:
  symbolic_propagation: true
paths:
  include: ["src/**"]
  exclude: ["src/test/**"]
patterns:
  - pattern-either:
      - pattern: 'subprocess.call($CMD, shell=True)'
      - pattern: 'subprocess.Popen($CMD, shell=True)'
  - pattern-not:
      pattern: 'subprocess.call(["safe", ...], shell=True)'
  - metavariable-regex:
      metavariable: $CMD
      regex: '.*'
fix: 'subprocess.call($CMD, shell=False)'
"#;

    let r = assert_yaml_round_trip(yaml);

    assert_eq!(
        r.id,
        RuleId::from("python.lang.security.audit.dangerous-subprocess-use")
    );
    assert_eq!(r.mode, RuleMode::Search);
    assert_eq!(r.languages, vec![Language::Python]);
    assert_eq!(r.severity, Severity::Error);
    assert!(r.options.symbolic_propagation);
    assert!(r.paths.is_some());
    assert!(r.fix.is_some());

    let pattern = r.pattern.as_ref().expect("pattern present");
    match pattern {
        PatternOp::Patterns(items) => assert_eq!(items.len(), 3),
        other => panic!("expected Patterns root, got {other:?}"),
    }
}

#[test]
fn taint_rule_round_trip() {
    // Taken from plan.md §"Taint mode rule (`mode: taint`)", extended with
    // the 2025+ extensions (`label:`, `requires:`, `by-side-effect:`).
    let yaml = r#"
id: tainted-sql-from-request
mode: taint
languages: [python]
severity: ERROR
message: 'SQL query built from user input'
metadata:
  cwe: 'CWE-89'
  owasp: 'A03:2021'
options:
  symbolic_propagation: true
  max_fields_tracked_per_object: 32
taint:
  pattern-sources:
    - pattern: 'request.GET.get(...)'
      label: user-input
    - pattern: 'request.POST.get(...)'
      label: user-input
  pattern-sinks:
    - pattern: 'cursor.execute($SQL, ...)'
      requires: 'user-input and not admin-only'
  pattern-sanitizers:
    - pattern: 'bleach.clean(...)'
    - pattern: 'escape($X)'
      by-side-effect: true
  pattern-propagators:
    - pattern: '$X = $Y'
      from: $Y
      to: $X
"#;

    let r = assert_yaml_round_trip(yaml);

    assert_eq!(r.id, RuleId::from("tainted-sql-from-request"));
    assert_eq!(r.mode, RuleMode::Taint);
    assert_eq!(r.options.max_fields_tracked_per_object, Some(32));

    let taint: &TaintRuleConfig = r.taint.as_ref().expect("taint config");
    assert_eq!(taint.sources.len(), 2);
    assert_eq!(taint.sources[0].label.as_deref(), Some("user-input"));
    assert_eq!(taint.sinks.len(), 1);
    assert_eq!(
        taint.sinks[0].requires.as_deref(),
        Some("user-input and not admin-only")
    );
    assert_eq!(taint.sanitizers.len(), 2);
    assert!(!taint.sanitizers[0].by_side_effect);
    assert!(taint.sanitizers[1].by_side_effect);
    assert_eq!(taint.propagators.len(), 1);
    assert_eq!(taint.propagators[0].from, "$Y");
    assert_eq!(taint.propagators[0].to, "$X");
}

#[test]
fn requires_expr_via_rule_loader_parses() {
    // Demonstrate that the engine can take a `requires` string off a taint
    // sink and parse it via `RequiresExpr`.
    use semgrep_core::{RequiresExpr, TaintLabelSet};

    let expr = RequiresExpr::parse("user-input and not admin-only").unwrap();
    let mut labels = TaintLabelSet::new();
    labels.insert("user-input".to_string());
    assert!(expr.eval(&labels));
    labels.insert("admin-only".to_string());
    assert!(!expr.eval(&labels));
}
