//! Public orchestrator: glue CFG → matching → dataflow → findings.

use std::collections::BTreeMap;
use std::path::PathBuf;

use petgraph::graph::NodeIndex;

use semgrep_core::node::{Range, SgNode};
use semgrep_core::{Finding, Rule, RuleMode};

use crate::cfg::build_for_root;
use crate::dataflow::{run_dataflow, TaintOptions};
use crate::matching::collect_taint_matches;
use crate::traces::build_trace;

/// Run a single taint-mode rule over an already-parsed AST and return
/// the emitted findings.
///
/// Non-taint rules return `Vec::new()` — the search-mode engine in
/// `semgrep_core::match_::run_rule_on_node` handles those.
pub fn run_taint_rule<'a>(
    rule: &Rule,
    file: &PathBuf,
    source: &[u8],
    root: &SgNode<'a>,
) -> Vec<Finding> {
    if rule.mode != RuleMode::Taint {
        return Vec::new();
    }
    let Some(config) = rule.taint.as_ref() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let opts = TaintOptions {
        max_iterations: 10_000,
        max_fields_tracked_per_object: rule.options.max_fields_tracked_per_object,
        symbolic_propagation: rule.options.symbolic_propagation,
    };

    for cfg in build_for_root(root) {
        let matches = collect_taint_matches(config, &cfg, root, source);
        let result = run_dataflow(&cfg, &matches, &opts);
        for hit in &result.sinks {
            let trace_rec = result.traces.iter().find(|t| t.sink_node_id == hit.node_id);
            let trace = trace_rec.and_then(|r| build_trace(r, file.as_path(), &cfg));
            let range = cfg
                .node_weight(NodeIndex::new(hit.node_id))
                .map(|n| n.range)
                .unwrap_or_else(default_range);
            findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                message: rule.message.clone(),
                file: file.clone(),
                range,
                metavars: BTreeMap::new(),
                fix: None,
                validation_state: None,
                dataflow_trace: trace,
                explanation: None,
                metadata: rule.metadata.clone(),
            });
        }
    }
    findings
}

fn default_range() -> Range {
    Range::new(
        semgrep_core::node::Position::ZERO,
        semgrep_core::node::Position::ZERO,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::node::{CanonicalKind, Position, Range, SgNode};
    use semgrep_core::{Language, Options, PatternOp, RuleId, Severity, TaintRuleConfig};

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
    fn search_mode_rule_returns_empty() {
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
    fn taint_mode_without_config_returns_empty() {
        let r = Rule {
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
        let f = run_taint_rule(&r, &PathBuf::from("x.py"), b"", &root);
        assert!(f.is_empty());
    }

    #[test]
    fn empty_taint_config_returns_empty() {
        let r = Rule {
            id: RuleId("noop2".into()),
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
            taint: Some(TaintRuleConfig::default()),
            join: None,
            extract: None,
            secrets: None,
        };
        let root = empty_root();
        let f = run_taint_rule(&r, &PathBuf::from("x.py"), b"", &root);
        assert!(f.is_empty());
    }
}
