//! Integration tests for the pattern matcher engine (Task 5).
//!
//! Uses hand-built `SgNode<'a>` trees because the real tree-sitter → SgNode
//! adapter lives in `tree-sitter-langs` (Task 9). The shapes we build mirror
//! what a canonicalised parse would look like for the chosen patterns.

use semgrep_core::match_::{
    metavar_comp_eval, parse_pattern, pre_filter, run_rule_on_node, unify, PatternAst,
    MatchCandidate,
};
use semgrep_core::node::{CanonicalKind, Position, Range, SgNode};
use semgrep_core::rule::pattern::PatternOp;
use semgrep_core::{
    Language, MetavarBindings, Rule, Severity,
};

// ---------------------------------------------------------------------------
// Node builders
// ---------------------------------------------------------------------------

fn r(start: usize, end: usize) -> Range {
    Range::new(
        Position::new(1, start + 1, start),
        Position::new(1, end + 1, end),
    )
}

fn id_node<'a>(text: &'a str, off: usize) -> SgNode<'a> {
    SgNode {
        kind: "identifier",
        canonical_kind: CanonicalKind::Identifier,
        range: r(off, off + text.len()),
        bytes: text.as_bytes(),
        children: Vec::new(),
        field_name: None,
    }
}

fn call_node<'a>(
    callee: SgNode<'a>,
    args: Vec<SgNode<'a>>,
    off: usize,
    end: usize,
) -> SgNode<'a> {
    let mut children = vec![callee];
    children.extend(args);
    SgNode {
        kind: "call_expression",
        canonical_kind: CanonicalKind::Call,
        range: r(off, end),
        bytes: b"",
        children,
        field_name: None,
    }
}

fn block_node<'a>(stmts: Vec<SgNode<'a>>, off: usize, end: usize) -> SgNode<'a> {
    SgNode {
        kind: "block",
        canonical_kind: CanonicalKind::Block,
        range: r(off, end),
        bytes: b"",
        children: stmts,
        field_name: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn identifier_pattern_matches_identifier_node() {
    let pat = parse_pattern("foo").unwrap();
    let node = id_node("foo", 0);
    let mut bindings = MetavarBindings::new();
    let ast = match pat {
        PatternAst::ExprStmt(inner) => *inner,
        other => panic!("expected ExprStmt, got {other:?}"),
    };
    assert!(unify(&ast, &node, &mut bindings));
}

#[test]
fn identifier_pattern_rejects_different_text() {
    let pat = parse_pattern("foo").unwrap();
    let node = id_node("bar", 0);
    let mut bindings = MetavarBindings::new();
    let ast = match pat {
        PatternAst::ExprStmt(inner) => *inner,
        _ => unreachable!(),
    };
    assert!(!unify(&ast, &node, &mut bindings));
}

#[test]
fn metavar_binds_and_clashes() {
    let pat = PatternAst::Metavar { name: "$X".into() };
    let foo = id_node("foo", 0);
    let bar = id_node("bar", 5);

    let mut bindings = MetavarBindings::new();
    // First bind: $X → foo.
    assert!(unify(&pat, &foo, &mut bindings));
    assert_eq!(
        bindings.get("$X").map(|n| n.text()),
        Some("foo")
    );

    // Re-binding $X to bar should fail (clash), and rollback should keep
    // foo intact.
    assert!(!unify(&pat, &bar, &mut bindings));
    assert_eq!(
        bindings.get("$X").map(|n| n.text()),
        Some("foo")
    );
}

#[test]
fn call_pattern_matches_with_metavar_arg() {
    let foo = id_node("foo", 0);
    let arg = id_node("bar", 4);
    let call = call_node(foo, vec![arg], 0, 8);
    let pat = parse_pattern("foo($X)").unwrap();
    let ast = match pat {
        PatternAst::ExprStmt(inner) => *inner,
        _ => unreachable!(),
    };
    let mut bindings = MetavarBindings::new();
    assert!(unify(&ast, &call, &mut bindings));
    assert_eq!(bindings.get("$X").map(|n| n.text()), Some("bar"));
}

#[test]
fn ellipsis_in_call_matches_any_arity() {
    let pat = parse_pattern("foo(...)").unwrap();
    let ast = match pat {
        PatternAst::ExprStmt(inner) => *inner,
        _ => unreachable!(),
    };

    // foo() — zero args.
    let foo = id_node("foo", 0);
    let empty_call = call_node(foo, Vec::new(), 0, 5);
    let mut b1 = MetavarBindings::new();
    assert!(unify(&ast, &empty_call, &mut b1), "should match foo()");

    // foo(a, b, c) — three args.
    let foo2 = id_node("foo", 0);
    let a = id_node("a", 4);
    let b = id_node("b", 7);
    let c = id_node("c", 10);
    let multi_call = call_node(foo2, vec![a, b, c], 0, 11);
    let mut b2 = MetavarBindings::new();
    assert!(
        unify(&ast, &multi_call, &mut b2),
        "should match foo(a, b, c)"
    );
}

#[test]
fn pre_filter_rejects_when_required_strings_absent() {
    let ast = parse_pattern("subprocess.call($CMD)").unwrap();
    // Source bytes that contain none of the required identifiers.
    let source = b"completely unrelated content";
    let required = semgrep_core::match_::required_strings(&ast);
    // Should include "subprocess" and "call".
    assert!(required.iter().any(|s| s == "subprocess"));
    assert!(required.iter().any(|s| s == "call"));
    assert!(!pre_filter(source, &required));
}

#[test]
fn pre_filter_accepts_when_required_string_present() {
    let ast = parse_pattern("subprocess.call($CMD)").unwrap();
    let source = b"import subprocess; subprocess.call(['rm', '-rf', '/'])";
    let required = semgrep_core::match_::required_strings(&ast);
    assert!(pre_filter(source, &required));
}

#[test]
fn metavar_comp_eval_lower_string() {
    let e = metavar_comp_eval::parse("lower($X) == \"abc\"").unwrap();
    let mut bindings = MetavarBindings::new();
    let n = SgNode {
        kind: "string",
        canonical_kind: CanonicalKind::String,
        range: r(0, 5),
        bytes: b"\"ABC\"",
        children: Vec::new(),
        field_name: None,
    };
    bindings.try_bind("$X", n).unwrap();
    assert!(metavar_comp_eval::evaluate(&e, &bindings, None, true).unwrap());
}

#[test]
fn metavar_comp_eval_numeric_gt() {
    let e = metavar_comp_eval::parse("$N > 100").unwrap();
    let mut bindings = MetavarBindings::new();
    let n = SgNode {
        kind: "number",
        canonical_kind: CanonicalKind::Number,
        range: r(0, 3),
        bytes: b"200",
        children: Vec::new(),
        field_name: None,
    };
    bindings.try_bind("$N", n).unwrap();
    assert!(metavar_comp_eval::evaluate(&e, &bindings, None, false).unwrap());
}

#[test]
fn run_rule_on_node_returns_dedup_matches() {
    let foo = id_node("foo", 0);
    let x = id_node("x", 4);
    let call = call_node(foo, vec![x], 0, 6);
    let rule = Rule::search(
        "test.matches",
        [Language::Python],
        Severity::Warning,
        "matched",
        PatternOp::Pattern("foo($X)".into()),
    );
    let source = b"foo(x)";
    let matches = run_rule_on_node(&rule, source, &call);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id.as_str(), "test.matches");
    assert_eq!(
        matches[0].bindings.get("$X").map(|n| n.text()),
        Some("x")
    );
}

#[test]
fn pattern_not_filters_out_negated_node() {
    // patterns: [ pattern: foo($X), pattern-not: pattern: foo(bar) ]
    let foo = id_node("foo", 0);
    let bar = id_node("bar", 4);
    let call = call_node(foo, vec![bar], 0, 8);

    let positive = PatternOp::Pattern("foo($X)".into());
    let negative = PatternOp::PatternNot(Box::new(PatternOp::Pattern("foo(bar)".into())));
    let combined = PatternOp::Patterns(vec![positive, negative]);
    let rule = Rule::search(
        "test.not",
        [Language::Python],
        Severity::Warning,
        "matched",
        combined,
    );
    let source = b"foo(bar)";
    let matches = run_rule_on_node(&rule, source, &call);
    assert!(matches.is_empty(), "pattern-not should drop foo(bar)");
}

#[test]
fn pattern_inside_requires_containment() {
    // Build a block containing one call. Pattern: `$X` inside `foo(...)`.
    let foo = id_node("foo", 0);
    let inner_id = id_node("a", 4);
    let call = call_node(foo, vec![inner_id], 0, 6);
    let block = block_node(vec![call], 0, 8);

    let inner = PatternOp::Pattern("$Y".into());
    let inside = PatternOp::PatternInside(Box::new(PatternOp::Pattern("foo(...)".into())));
    let combined = PatternOp::Patterns(vec![inner, inside]);
    let rule = Rule::search(
        "test.inside",
        [Language::Python],
        Severity::Warning,
        "matched",
        combined,
    );
    let source = b"foo(a)";
    let matches = run_rule_on_node(&rule, source, &block);
    assert!(
        !matches.is_empty(),
        "pattern-inside should keep nodes inside foo(...)"
    );
}

#[test]
fn match_candidate_is_constructible() {
    // Sanity check the public re-export shape.
    let node = id_node("foo", 0);
    let candidate = MatchCandidate {
        node: node.clone(),
        bindings: MetavarBindings::new(),
    };
    assert_eq!(candidate.node.range, node.range);
}
