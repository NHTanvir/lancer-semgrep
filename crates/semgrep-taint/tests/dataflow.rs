//! Integration tests for `semgrep-taint`.
//!
//! These exercise the public API surface: CFG construction, the worklist
//! dataflow, `requires:` evaluation, and the runner that glues everything
//! into `Finding`s.

use std::path::PathBuf;

use semgrep_core::node::{CanonicalKind, Position, Range, SgNode};
use semgrep_core::{
    Language, Options, PatternOp, RequiresExpr, Rule, RuleId, RuleMode, Severity,
    TaintLabelSet, TaintRuleConfig, TaintSink, TaintSource, TaintState,
};

use semgrep_taint::cfg::{build_for_root, CfgBuilder, FunctionScope};
use semgrep_taint::dataflow::{
    run_dataflow, SinkPatternHit, SourceHit, TaintNodeMatches, TaintOptions,
};
use semgrep_taint::lattice::{ProgramPointState, VarTaint};
use semgrep_taint::nodes::CfgNodeKind;
use semgrep_taint::requires::eval_requires;
use semgrep_taint::runner::run_taint_rule;

fn rng() -> Range {
    Range::new(Position::ZERO, Position::ZERO)
}

fn empty_root() -> SgNode<'static> {
    SgNode {
        kind: "program",
        canonical_kind: CanonicalKind::Block,
        range: rng(),
        bytes: b"",
        children: vec![],
        field_name: None,
    }
}

#[test]
fn empty_rule_returns_no_findings() {
    let rule = Rule {
        id: RuleId("noop".into()),
        mode: RuleMode::Taint,
        languages: vec![Language::Python],
        severity: Severity::Error,
        message: "m".into(),
        metadata: serde_json::Value::Null,
        options: Options::default(),
        paths: None,
        pattern: None,
        fix: None,
        fix_regex: None,
        taint: None,
        join: None,
        extract: None,
        secrets: None,
    };
    let root = empty_root();
    let findings = run_taint_rule(&rule, &PathBuf::from("test.py"), b"", &root);
    assert!(findings.is_empty());
}

#[test]
fn search_mode_rule_skipped_by_taint_runner() {
    let r = Rule::search(
        "test.search",
        [Language::Python],
        Severity::Error,
        "m",
        PatternOp::Pattern("foo()".into()),
    );
    let root = empty_root();
    let f = run_taint_rule(&r, &PathBuf::from("x.py"), b"", &root);
    assert!(f.is_empty());
}

#[test]
fn lattice_join_lubs_correctly() {
    // Untainted ⊑ Tainted ⊑ Top
    let a = TaintState::Untainted;
    let b = TaintState::Tainted(TaintLabelSet::singleton("user-input"));
    let c = TaintState::Top;
    assert!(matches!(a.join(&b), TaintState::Tainted(_)));
    assert!(matches!(b.join(&c), TaintState::Top));
    assert!(matches!(a.join(&a), TaintState::Untainted));

    // VarTaint LUB
    let mut va = VarTaint::new();
    va.set("x".into(), b.clone());
    let mut vb = VarTaint::new();
    vb.set(
        "x".into(),
        TaintState::Tainted(TaintLabelSet::singleton("other")),
    );
    let changed = va.lub_into(&vb);
    assert!(changed);
    match va.get("x") {
        TaintState::Tainted(s) => {
            assert!(s.contains("user-input"));
            assert!(s.contains("other"));
        }
        _ => panic!("expected tainted"),
    }

    // ProgramPointState LUB
    let mut p = ProgramPointState::default();
    let mut q = ProgramPointState::default();
    q.vars.set(
        "y".into(),
        TaintState::Tainted(TaintLabelSet::singleton("y")),
    );
    assert!(p.lub_into(&q));
    assert!(matches!(p.vars.get("y"), TaintState::Tainted(_)));
}

#[test]
fn eval_requires_user_input_and_not_admin_only() {
    let e = RequiresExpr::parse("user-input and not admin-only").unwrap();
    let mut s = TaintLabelSet::new();
    s.insert("user-input".into());
    assert!(eval_requires(&e, &s));
    s.insert("admin-only".into());
    assert!(!eval_requires(&e, &s));
}

#[test]
fn cfg_builder_handles_function_with_assign_and_call() {
    // Function ( Block ( Assign x, Call sink(x) ) )
    let target_x = SgNode {
        kind: "identifier",
        canonical_kind: CanonicalKind::Identifier,
        range: rng(),
        bytes: b"x",
        children: vec![],
        field_name: None,
    };
    let assign = SgNode {
        kind: "assignment",
        canonical_kind: CanonicalKind::Assign,
        range: rng(),
        bytes: b"x = src()",
        children: vec![target_x.clone()],
        field_name: None,
    };
    let sink_callee = SgNode {
        kind: "identifier",
        canonical_kind: CanonicalKind::Identifier,
        range: rng(),
        bytes: b"sink",
        children: vec![],
        field_name: None,
    };
    let call = SgNode {
        kind: "call_expression",
        canonical_kind: CanonicalKind::Call,
        range: rng(),
        bytes: b"sink(x)",
        children: vec![sink_callee, target_x],
        field_name: None,
    };
    let body = SgNode {
        kind: "block",
        canonical_kind: CanonicalKind::Block,
        range: rng(),
        bytes: b"",
        children: vec![assign, call],
        field_name: None,
    };
    let func = SgNode {
        kind: "function_definition",
        canonical_kind: CanonicalKind::Function,
        range: rng(),
        bytes: b"",
        children: vec![body],
        field_name: None,
    };

    let cfgs = build_for_root(&func);
    assert_eq!(cfgs.len(), 1);
    let cfg = &cfgs[0];

    // Should contain at least one Assign and one Call CFG node.
    let mut has_assign = false;
    let mut has_call = false;
    for w in cfg.node_weights() {
        match &w.kind {
            CfgNodeKind::Assign { target } => {
                has_assign = true;
                assert_eq!(target, "x");
            }
            CfgNodeKind::Call { callee, .. } => {
                has_call = true;
                assert_eq!(callee, "sink");
            }
            _ => {}
        }
    }
    assert!(has_assign);
    assert!(has_call);
}

#[test]
fn end_to_end_source_through_assign_to_sink() {
    // We bypass the matcher: feed a hand-built CFG with a hand-built
    // TaintNodeMatches, then run the dataflow directly. The point is
    // to verify the algorithm threads taint from source -> assign -> sink.
    let assign = SgNode {
        kind: "assignment",
        canonical_kind: CanonicalKind::Assign,
        range: rng(),
        bytes: b"x = src()",
        children: vec![SgNode {
            kind: "identifier",
            canonical_kind: CanonicalKind::Identifier,
            range: rng(),
            bytes: b"x",
            children: vec![],
            field_name: None,
        }],
        field_name: None,
    };
    let call = SgNode {
        kind: "call_expression",
        canonical_kind: CanonicalKind::Call,
        range: rng(),
        bytes: b"sink(x)",
        children: vec![
            SgNode {
                kind: "identifier",
                canonical_kind: CanonicalKind::Identifier,
                range: rng(),
                bytes: b"sink",
                children: vec![],
                field_name: None,
            },
            SgNode {
                kind: "identifier",
                canonical_kind: CanonicalKind::Identifier,
                range: rng(),
                bytes: b"x",
                children: vec![],
                field_name: None,
            },
        ],
        field_name: None,
    };
    let block = SgNode {
        kind: "block",
        canonical_kind: CanonicalKind::Block,
        range: rng(),
        bytes: b"",
        children: vec![assign, call],
        field_name: None,
    };
    let scope = FunctionScope {
        name: None,
        root: &block,
        params: Vec::new(),
    };
    let cfg = CfgBuilder::build(&scope);
    let mut assign_id = None;
    let mut call_id = None;
    for w in cfg.node_weights() {
        match &w.kind {
            CfgNodeKind::Assign { .. } if assign_id.is_none() => assign_id = Some(w.id),
            CfgNodeKind::Call { .. } if call_id.is_none() => call_id = Some(w.id),
            _ => {}
        }
    }
    let assign_id = assign_id.unwrap();
    let call_id = call_id.unwrap();

    let matches = TaintNodeMatches {
        sources: vec![SourceHit {
            cfg_node_id: assign_id,
            bound_var: Some("x".into()),
            label: Some("user-input".into()),
        }],
        sinks: vec![SinkPatternHit {
            cfg_node_id: call_id,
            bound_var: Some("x".into()),
            requires: None,
        }],
        ..Default::default()
    };
    let r = run_dataflow(&cfg, &matches, &TaintOptions::default());
    assert_eq!(r.sinks.len(), 1);
    assert_eq!(r.sinks[0].node_id, call_id);
    assert!(r.sinks[0].labels.contains("user-input"));
}

#[test]
fn taint_rule_skeleton_runs_without_panic() {
    // Drive the full runner with a real (empty) taint config on a
    // synthetic root. We expect no findings but no panic.
    let r = Rule {
        id: RuleId("smoke".into()),
        mode: RuleMode::Taint,
        languages: vec![Language::Python],
        severity: Severity::Warning,
        message: "smoke".into(),
        metadata: serde_json::Value::Null,
        options: Options::default(),
        paths: None,
        pattern: None,
        fix: None,
        fix_regex: None,
        taint: Some(TaintRuleConfig {
            sources: vec![TaintSource {
                pattern: PatternOp::Pattern("get_input()".into()),
                label: Some("user".into()),
            }],
            sinks: vec![TaintSink {
                pattern: PatternOp::Pattern("dangerous($X)".into()),
                requires: None,
            }],
            sanitizers: vec![],
            propagators: vec![],
        }),
        join: None,
        extract: None,
        secrets: None,
    };
    let root = empty_root();
    let f = run_taint_rule(&r, &PathBuf::from("x.py"), b"", &root);
    assert!(f.is_empty());
}
