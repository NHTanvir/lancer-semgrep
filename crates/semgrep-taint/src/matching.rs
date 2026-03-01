//! Glue between [`semgrep_core::match_`] and the CFG.
//!
//! For each CFG node we look up the `SgNode` subtree at its range and run
//! every `pattern-sources` / `pattern-sinks` / `pattern-sanitizers` /
//! `pattern-propagators` pattern over it. Hits are converted into the
//! dataflow's [`SourceHit`], [`SinkPatternHit`], [`SanitizerHit`] and
//! [`PropagatorHit`] records.
//!
//! The lookup `range -> SgNode` is O(N) per query — a simple recursive
//! contains-check that returns the smallest enclosing node. For taint
//! workloads this is fine; the matcher itself dominates cost.

use semgrep_core::match_::{
    evaluate_pattern_op, CompiledPatternCache, Match, MatchCandidate,
};
use semgrep_core::node::{Range, SgNode};
use semgrep_core::rule::PatternOp;
use semgrep_core::{
    RequiresExpr, TaintPropagator, TaintRuleConfig, TaintSanitizer, TaintSink, TaintSource,
};

use crate::cfg::Cfg;
use crate::dataflow::{
    PropagatorHit, SanitizerHit, SinkPatternHit, SourceHit, TaintNodeMatches,
};

/// Walk every CFG node and collect taint-pattern hits.
///
/// `root` is the AST root for the entire file. `source` is the raw file
/// bytes (passed through to the matcher's pre-filter).
pub fn collect_taint_matches<'a>(
    config: &TaintRuleConfig,
    cfg: &Cfg,
    root: &SgNode<'a>,
    source: &[u8],
) -> TaintNodeMatches {
    let _ = source; // pre-filter at the matcher layer uses node bytes
    let compiled = CompiledPatternCache::new();
    let mut out = TaintNodeMatches::default();

    for nw in cfg.node_weights() {
        let Some(sub) = find_sgnode_at(root, nw.range) else {
            continue;
        };
        let id = nw.id;

        for src in &config.sources {
            for m in run_pattern(&src.pattern, sub, &compiled) {
                let bound_var = pick_bound_var(&m, sub);
                out.sources.push(SourceHit {
                    cfg_node_id: id,
                    bound_var,
                    label: src.label.clone(),
                });
            }
        }

        for sink in &config.sinks {
            for m in run_pattern(&sink.pattern, sub, &compiled) {
                let bound_var = pick_bound_var(&m, sub);
                let requires = sink
                    .requires
                    .as_deref()
                    .and_then(|s| RequiresExpr::parse(s).ok());
                out.sinks.push(SinkPatternHit {
                    cfg_node_id: id,
                    bound_var,
                    requires,
                });
            }
        }

        for san in &config.sanitizers {
            for m in run_pattern(&san.pattern, sub, &compiled) {
                let bound_var = pick_bound_var(&m, sub);
                out.sanitizers.push(SanitizerHit {
                    cfg_node_id: id,
                    bound_var,
                    by_side_effect: san.by_side_effect,
                });
            }
        }

        for prop in &config.propagators {
            for m in run_pattern(&prop.pattern, sub, &compiled) {
                if let (Some(from), Some(to)) =
                    (binding_text(&m, &prop.from), binding_text(&m, &prop.to))
                {
                    out.propagators.push(PropagatorHit {
                        cfg_node_id: id,
                        from_var: from,
                        to_var: to,
                    });
                }
            }
        }
    }

    out
}

/// Find the *smallest* `SgNode` whose range encloses `range`. Returns
/// `None` if no node contains the range (which should never happen for a
/// CFG node derived from the same tree, but the search is defensive).
fn find_sgnode_at<'a, 'b>(root: &'b SgNode<'a>, range: Range) -> Option<&'b SgNode<'a>> {
    if !root.range.contains(&range) {
        return None;
    }
    // Look in children for a tighter container.
    for c in &root.children {
        if let Some(found) = find_sgnode_at(c, range) {
            return Some(found);
        }
    }
    Some(root)
}

/// Run a [`PatternOp`] against `node`, returning successful matches.
///
/// We reuse the existing `evaluate_pattern_op` from `semgrep_core::match_`
/// to avoid reimplementing the matcher.
fn run_pattern<'a>(
    op: &PatternOp,
    node: &SgNode<'a>,
    compiled: &CompiledPatternCache,
) -> Vec<Match<'a>> {
    let candidates: Vec<MatchCandidate<'a>> = evaluate_pattern_op(op, node, compiled);
    candidates
        .into_iter()
        .map(|c| Match {
            rule_id: semgrep_core::RuleId::default(),
            root: c.node,
            bindings: c.bindings,
            explanation: None,
        })
        .collect()
}

/// Pick the "interesting" variable name for a source / sink / sanitizer.
///
/// Heuristic: if the match bound any metavariable, take the first
/// binding's text. Otherwise fall back to the matched root node's text
/// (which is what we'd want for a bare identifier pattern like
/// `request.GET.get(...)`).
fn pick_bound_var<'a>(m: &Match<'a>, container: &SgNode<'a>) -> Option<String> {
    let _ = container; // available for richer heuristics in future
    if let Some((_, n)) = m.bindings.iter().next() {
        return Some(n.text().to_string());
    }
    // Fall back to the matched root text.
    let t = m.root.text();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Return the textual content of the binding for `name`. `name` must
/// include the `$` sigil if the pattern uses one.
fn binding_text<'a>(m: &Match<'a>, name: &str) -> Option<String> {
    m.bindings.get(name).map(|n| n.text().to_string())
}

// ---------------------------------------------------------------------------
// Public helpers reused by `lib.rs` re-exports.
// ---------------------------------------------------------------------------

/// Run a source pattern over `root` and return raw matches.
pub fn find_source_matches<'a>(
    p: &TaintSource,
    root: &SgNode<'a>,
    _source: &[u8],
) -> Vec<Match<'a>> {
    let compiled = CompiledPatternCache::new();
    run_pattern(&p.pattern, root, &compiled)
}

/// Run a sink pattern over `root` and return raw matches.
pub fn find_sink_matches<'a>(
    p: &TaintSink,
    root: &SgNode<'a>,
    _source: &[u8],
) -> Vec<Match<'a>> {
    let compiled = CompiledPatternCache::new();
    run_pattern(&p.pattern, root, &compiled)
}

/// Run a sanitizer pattern over `root` and return raw matches.
pub fn find_sanitizer_matches<'a>(
    p: &TaintSanitizer,
    root: &SgNode<'a>,
    _source: &[u8],
) -> Vec<Match<'a>> {
    let compiled = CompiledPatternCache::new();
    run_pattern(&p.pattern, root, &compiled)
}

/// Run a propagator pattern over `root` and return raw matches.
pub fn find_propagator_matches<'a>(
    p: &TaintPropagator,
    root: &SgNode<'a>,
    _source: &[u8],
) -> Vec<Match<'a>> {
    let compiled = CompiledPatternCache::new();
    run_pattern(&p.pattern, root, &compiled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::node::{CanonicalKind, Position, Range, SgNode};

    fn rng() -> Range {
        Range::new(Position::ZERO, Position::ZERO)
    }

    #[test]
    fn collect_with_empty_config_returns_empty() {
        let root = SgNode {
            kind: "block",
            canonical_kind: CanonicalKind::Block,
            range: rng(),
            bytes: b"",
            children: vec![],
            field_name: None,
        };
        let scope = crate::cfg::FunctionScope {
            name: None,
            root: &root,
            params: Vec::new(),
        };
        let cfg = crate::cfg::CfgBuilder::build(&scope);
        let cfg_taint = TaintRuleConfig::default();
        let m = collect_taint_matches(&cfg_taint, &cfg, &root, b"");
        assert!(m.sources.is_empty());
        assert!(m.sinks.is_empty());
        assert!(m.sanitizers.is_empty());
        assert!(m.propagators.is_empty());
    }

    #[test]
    fn find_sgnode_at_returns_smallest() {
        let inner = SgNode {
            kind: "ident",
            canonical_kind: CanonicalKind::Identifier,
            range: Range::new(Position::new(1, 1, 0), Position::new(1, 4, 3)),
            bytes: b"abc",
            children: vec![],
            field_name: None,
        };
        let outer_range = Range::new(Position::new(1, 1, 0), Position::new(1, 10, 9));
        let outer = SgNode {
            kind: "stmt",
            canonical_kind: CanonicalKind::Statement,
            range: outer_range,
            bytes: b"abc + def",
            children: vec![inner.clone()],
            field_name: None,
        };
        // Looking up the inner range should pick the inner node.
        let got = find_sgnode_at(&outer, inner.range).unwrap();
        assert_eq!(got.kind, "ident");
    }
}
