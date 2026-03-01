//! Integration tests for the emit dispatch.
//!
//! These tests build a minimal `ScanReport` and assert that each emitter
//! produces output containing the format's identifying landmarks. They do
//! not parse the output back through a schema validator — that would be
//! pulling jsonschema or libxml in just for tests, which the task brief
//! forbids. Instead, we string-match on stable substrings.

use std::collections::BTreeMap;

use semgrep_core::{Position, Range, RuleId, Severity};
use semgrep_output::{advisory_url, emitter, OutputFormat, ScanReport};

/// Single representative finding — error severity, no fix / trace,
/// metadata empty. Each test builds a `ScanReport { findings: vec![...] }`
/// on top of this.
fn dummy_finding() -> semgrep_core::Finding {
    semgrep_core::Finding {
        rule_id: RuleId::from("test.rule"),
        severity: Severity::Error,
        message: "test message".into(),
        file: "test.py".into(),
        // Position::ZERO is (line=1, column=1, offset=0) — see node.rs.
        range: Range::new(Position::ZERO, Position::ZERO),
        metavars: BTreeMap::new(),
        fix: None,
        validation_state: None,
        dataflow_trace: None,
        explanation: None,
        metadata: serde_json::Value::Null,
    }
}

fn one_finding_report() -> ScanReport {
    ScanReport {
        version: "0.1.0".into(),
        findings: vec![dummy_finding()],
        ..Default::default()
    }
}

fn emit(format: OutputFormat) -> String {
    let report = one_finding_report();
    let mut buf = Vec::new();
    emitter(format).emit(&report, &mut buf).unwrap();
    String::from_utf8(buf).expect("emitter wrote non-UTF-8")
}

#[test]
fn emit_json_includes_rule_id_and_results_key() {
    let s = emit(OutputFormat::Json);
    // Semgrep-native key is `results`, not `findings`.
    assert!(s.contains("\"results\""), "json: {s}");
    assert!(s.contains("test.rule"), "json: {s}");
    assert!(s.contains("\"version\""), "json: {s}");
}

#[test]
fn emit_sarif_has_required_top_level_keys() {
    let s = emit(OutputFormat::Sarif);
    assert!(s.contains("\"version\":\"2.1.0\"") || s.contains("\"version\": \"2.1.0\""), "sarif: {s}");
    assert!(s.contains("\"runs\""), "sarif: {s}");
    assert!(s.contains("\"ruleId\""), "sarif: {s}");
    assert!(s.contains("test.rule"), "sarif: {s}");
    assert!(s.contains("\"level\""), "sarif: {s}");
}

#[test]
fn emit_gitlab_sast_has_category_sast() {
    let s = emit(OutputFormat::GitlabSast);
    assert!(s.contains("\"vulnerabilities\""), "gitlab-sast: {s}");
    assert!(s.contains("\"category\":\"sast\""), "gitlab-sast: {s}");
    assert!(s.contains("\"scan\""), "gitlab-sast: {s}");
}

#[test]
fn emit_gitlab_secrets_has_category_secret_detection() {
    let s = emit(OutputFormat::GitlabSecrets);
    assert!(
        s.contains("\"category\":\"secret_detection\""),
        "gitlab-secrets: {s}"
    );
}

#[test]
fn emit_junit_is_xml_with_testsuite() {
    let s = emit(OutputFormat::JunitXml);
    assert!(s.contains("<testsuite"), "junit: {s}");
    assert!(s.contains("test.rule"), "junit: {s}");
}

#[test]
fn emit_emacs_format() {
    // Position::ZERO renders as 1:1.
    let s = emit(OutputFormat::Emacs);
    assert!(s.contains("test.py:1:1:"), "emacs: {s}");
    assert!(s.contains("test message"), "emacs: {s}");
    assert!(s.contains("(test.rule)"), "emacs: {s}");
}

#[test]
fn emit_vim_format() {
    let s = emit(OutputFormat::Vim);
    assert!(s.contains("test.py:1:1:[E]"), "vim: {s}");
    assert!(s.contains("(test.rule)"), "vim: {s}");
}

#[test]
fn emit_github_actions() {
    let s = emit(OutputFormat::GithubActions);
    assert!(s.contains("::group::"), "gh-actions: {s}");
    assert!(s.contains("::error"), "gh-actions: {s}");
    assert!(s.contains("file=test.py"), "gh-actions: {s}");
    assert!(s.contains("test message"), "gh-actions: {s}");
    assert!(s.contains("::endgroup::"), "gh-actions: {s}");
}

#[test]
fn emit_text_groups_by_file() {
    let s = emit(OutputFormat::Text);
    // The file header is printed once.
    assert!(s.contains("test.py"), "text: {s}");
    assert!(s.contains("ERROR"), "text: {s}");
    assert!(s.contains("test.rule"), "text: {s}");
    assert!(s.contains("1 findings"), "text: {s}");
}

#[test]
fn advisory_url_shape() {
    assert_eq!(
        advisory_url("GHSA-xyz"),
        "https://semgrep.dev/advisories/GHSA-xyz"
    );
}
