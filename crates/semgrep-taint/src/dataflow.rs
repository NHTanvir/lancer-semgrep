//! Forward worklist dataflow over the CFG.
//!
//! For each CFG node we compute a [`ProgramPointState`] = LUB of the states
//! at the ends of every incoming edge, then apply a transfer function
//! driven by the node's `CfgNodeKind` and the [`TaintNodeMatches`]
//! collected by [`crate::matching`].
//!
//! Semantics implemented today (deliberately minimal — see plan.md
//! §"When you're in over your head"):
//!
//! - Sources attached to a CFG node mark a target variable as
//!   `Tainted(label)` after the node.
//! - Assignments propagate taint from the RHS variable (heuristic: first
//!   textual argument / second child) to the LHS target.
//! - Sanitizers clear the bound variable (in place) when
//!   `by-side-effect`, or the call's result otherwise (handled at the
//!   bound variable for simplicity).
//! - Propagators flow taint from `from_var` to `to_var`.
//! - Sinks record any tainted state for the bound variable and check the
//!   `requires:` expression.
//!
//! More elaborate semantics (field tracking, closure capture, inter-
//! procedural calls) are left as `todo!()`-equivalent comments / stubs.

use std::collections::VecDeque;

use petgraph::Direction;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use semgrep_core::{RequiresExpr, TaintLabel, TaintLabelSet, TaintState};

use crate::cfg::Cfg;
use crate::lattice::{ProgramPointState, TaintLattice};
use crate::nodes::CfgNodeKind;
use crate::requires::eval_requires;
use crate::traces::TraceRecord;

/// Knobs from the per-rule `options:` block plus engine-wide bounds.
#[derive(Debug, Clone)]
pub struct TaintOptions {
    /// Safety bound on the worklist loop. Guards against any accidental
    /// non-monotonic transfer or pathological CFG.
    pub max_iterations: usize,
    /// Field-tracking cap (`--max-fields-tracked-per-object`).
    pub max_fields_tracked_per_object: Option<usize>,
    /// Whether the rule asks for symbolic propagation. Hooked but not
    /// fully implemented at this layer — see plan §"Symbolic propagation".
    pub symbolic_propagation: bool,
}

impl Default for TaintOptions {
    fn default() -> Self {
        Self {
            max_iterations: 10_000,
            max_fields_tracked_per_object: None,
            symbolic_propagation: false,
        }
    }
}

/// Match-collection product: where each pattern (source / sink /
/// sanitizer / propagator) hit which CFG node, along with the metavariable
/// binding the pattern picked out as the "interesting" variable.
#[derive(Debug, Clone, Default)]
pub struct TaintNodeMatches {
    pub sources: Vec<SourceHit>,
    pub sinks: Vec<SinkPatternHit>,
    pub sanitizers: Vec<SanitizerHit>,
    pub propagators: Vec<PropagatorHit>,
}

/// One source match. `bound_var` is the variable that becomes tainted as
/// a result (often the LHS of the assignment containing the source).
#[derive(Debug, Clone)]
pub struct SourceHit {
    pub cfg_node_id: usize,
    pub bound_var: Option<String>,
    pub label: Option<TaintLabel>,
}

/// One sink-pattern match.
#[derive(Debug, Clone)]
pub struct SinkPatternHit {
    pub cfg_node_id: usize,
    pub bound_var: Option<String>,
    pub requires: Option<RequiresExpr>,
}

/// One sanitizer-pattern match.
#[derive(Debug, Clone)]
pub struct SanitizerHit {
    pub cfg_node_id: usize,
    pub bound_var: Option<String>,
    pub by_side_effect: bool,
}

/// One propagator-pattern match.
#[derive(Debug, Clone)]
pub struct PropagatorHit {
    pub cfg_node_id: usize,
    pub from_var: String,
    pub to_var: String,
}

/// One sink hit emitted by the dataflow: the CFG node where the sink
/// matched and which labels the sink-variable carried.
#[derive(Debug, Clone)]
pub struct SinkHit {
    pub node_id: usize,
    pub labels: TaintLabelSet,
    pub source_node_ids: Vec<usize>,
}

/// Full dataflow output for one CFG.
#[derive(Debug, Clone)]
pub struct DataflowResult {
    pub lattice: TaintLattice,
    pub sources: Vec<usize>,
    pub sinks: Vec<SinkHit>,
    pub traces: Vec<TraceRecord>,
}

/// Run the worklist fixed-point algorithm. Returns the final lattice plus
/// the sink hits.
pub fn run_dataflow(
    cfg: &Cfg,
    matches: &TaintNodeMatches,
    options: &TaintOptions,
) -> DataflowResult {
    let n = cfg.node_count();
    let mut lattice = TaintLattice::new(n);
    let mut sources_seen: Vec<usize> = matches.sources.iter().map(|s| s.cfg_node_id).collect();
    sources_seen.sort();
    sources_seen.dedup();

    // Seed worklist with every node so the transfer function runs at
    // least once everywhere. Subsequent iterations only re-fire when an
    // incoming edge's state actually changes.
    let mut worklist: VecDeque<NodeIndex> = cfg.node_indices().collect();

    // Track per-variable provenance: which source-node ids contributed to
    // a variable's current taint state. This is approximate — we union it
    // along with the labels.
    //
    // Stored alongside the lattice rather than inside `TaintState` because
    // semgrep_core's lattice is label-only.
    let mut provenance: Vec<std::collections::BTreeMap<String, Vec<usize>>> =
        vec![std::collections::BTreeMap::new(); n];

    let mut iter = 0usize;
    while let Some(idx) = worklist.pop_front() {
        iter += 1;
        if iter > options.max_iterations {
            tracing::warn!(
                target = "semgrep_taint::dataflow",
                "exceeded max_iterations={}, bailing out",
                options.max_iterations
            );
            break;
        }

        // 1) Predecessor state = LUB of out-states at all in-edges.
        let mut pred_state = ProgramPointState::default();
        let mut pred_prov: std::collections::BTreeMap<String, Vec<usize>> =
            std::collections::BTreeMap::new();
        let in_edges: Vec<NodeIndex> = cfg
            .edges_directed(idx, Direction::Incoming)
            .map(|e| e.source())
            .collect();
        for src in &in_edges {
            pred_state.lub_into(lattice.get(src.index()));
            for (k, v) in &provenance[src.index()] {
                let entry = pred_prov.entry(k.clone()).or_default();
                for id in v {
                    if !entry.contains(id) {
                        entry.push(*id);
                    }
                }
            }
        }

        // 2) Transfer function.
        let mut new_state = pred_state.clone();
        let mut new_prov = pred_prov.clone();
        let node_id = idx.index();
        let _ = options.symbolic_propagation; // hook only

        // 2a) Assignment-driven propagation (run *before* source matches,
        // because a source pattern attached to this node names the RHS
        // expression — the source's effect lands on the LHS afterwards).
        //
        // If this CFG node is an `Assign { target }`, propagate the join
        // of every currently-tainted variable mentioned in the RHS text.
        // The CFG doesn't give us a clean RHS variable list, so we
        // heuristically scan the node's source_text for matches against
        // any variable already in the state map.
        if let Some(w) = cfg.node_weight(idx) {
            if let CfgNodeKind::Assign { target } = &w.kind {
                let rhs_bytes = &w.source_text[..];
                let mut acc = TaintState::Untainted;
                let mut prov_acc: Vec<usize> = Vec::new();
                let known_vars: Vec<String> =
                    new_state.vars.0.keys().cloned().collect();
                for v in &known_vars {
                    if v == target {
                        continue;
                    }
                    if rhs_contains(rhs_bytes, v) {
                        acc = acc.join(&new_state.vars.get(v));
                        if let Some(ids) = new_prov.get(v) {
                            for id in ids {
                                if !prov_acc.contains(id) {
                                    prov_acc.push(*id);
                                }
                            }
                        }
                    }
                }
                if matches!(acc, TaintState::Tainted(_) | TaintState::Top) {
                    new_state.vars.set(target.clone(), acc);
                    let entry = new_prov.entry(target.clone()).or_default();
                    for id in prov_acc {
                        if !entry.contains(&id) {
                            entry.push(id);
                        }
                    }
                } else {
                    // Untainted assignment kills any prior taint on target.
                    new_state.vars.set(target.clone(), TaintState::Untainted);
                    new_prov.remove(target);
                }
            }
        }

        // 2b) Sources. A source pattern attached to this CFG node taints
        // the bound variable. For an assignment-node source like
        // `x = request.GET.get(...)`, the matcher binds `x` (or a
        // metavariable that points at the LHS / RHS site) — see
        // `matching.rs::pick_bound_var`. Source application happens after
        // 2a so it isn't accidentally killed by the assignment's RHS
        // analysis.
        for src in &matches.sources {
            if src.cfg_node_id != node_id {
                continue;
            }
            let Some(var) = src.bound_var.clone() else {
                continue;
            };
            let label = src.label.clone();
            let labels = match label {
                Some(l) => TaintLabelSet::singleton(l),
                None => TaintLabelSet::new(),
            };
            let cur = new_state.vars.get(&var);
            let combined = cur.join(&TaintState::Tainted(labels.clone()));
            new_state.vars.set(var.clone(), combined);
            new_prov.entry(var).or_default().push(node_id);
        }

        // 2c) Propagators (custom $X -> $Y rules).
        for p in &matches.propagators {
            if p.cfg_node_id != node_id {
                continue;
            }
            let from = new_state.vars.get(&p.from_var);
            if !from.is_tainted() {
                continue;
            }
            let cur = new_state.vars.get(&p.to_var);
            let combined = cur.join(&from);
            new_state.vars.set(p.to_var.clone(), combined);
            if let Some(ids) = new_prov.get(&p.from_var).cloned() {
                let entry = new_prov.entry(p.to_var.clone()).or_default();
                for id in ids {
                    if !entry.contains(&id) {
                        entry.push(id);
                    }
                }
            }
        }

        // 2d) Sanitizers.
        for s in &matches.sanitizers {
            if s.cfg_node_id != node_id {
                continue;
            }
            let Some(var) = s.bound_var.clone() else {
                continue;
            };
            if s.by_side_effect {
                new_state.vars.set(var.clone(), TaintState::Untainted);
                new_prov.remove(&var);
            } else {
                // Non-side-effect sanitizers also clean their argument's
                // taint in our simplified model. The "result" goes to a
                // synthetic variable we don't track.
                new_state.vars.set(var.clone(), TaintState::Untainted);
                new_prov.remove(&var);
            }
        }

        // 3) Commit lattice changes; if something changed, enqueue
        //    out-neighbours.
        let prev = lattice.get(node_id).clone();
        let prev_prov = provenance[node_id].clone();
        let changed = prev != new_state || prev_prov != new_prov;
        if changed {
            lattice.set(node_id, new_state.clone());
            provenance[node_id] = new_prov.clone();
            for edge in cfg.edges_directed(idx, Direction::Outgoing) {
                worklist.push_back(edge.target());
            }
        }
    }

    // 4) Sink evaluation pass: walk every sink hit and inspect the
    //    just-converged lattice.
    let mut sinks_out: Vec<SinkHit> = Vec::new();
    let mut traces_out: Vec<TraceRecord> = Vec::new();
    for sink in &matches.sinks {
        let st = lattice.get(sink.cfg_node_id);
        let Some(var) = &sink.bound_var else {
            continue;
        };
        let v_state = st.vars.get(var);
        let label_set = match &v_state {
            TaintState::Tainted(ls) => ls.clone(),
            TaintState::Top => TaintLabelSet::new(),
            TaintState::Untainted => continue,
        };
        // Evaluate requires: if absent, taint is sufficient; if present,
        // require it to match.
        if let Some(req) = &sink.requires {
            if !eval_requires(req, &label_set) {
                continue;
            }
        }
        let source_node_ids = provenance[sink.cfg_node_id]
            .get(var)
            .cloned()
            .unwrap_or_default();
        sinks_out.push(SinkHit {
            node_id: sink.cfg_node_id,
            labels: label_set.clone(),
            source_node_ids: source_node_ids.clone(),
        });
        for src_id in &source_node_ids {
            traces_out.push(TraceRecord {
                source_node_id: *src_id,
                propagator_node_ids: Vec::new(),
                sink_node_id: sink.cfg_node_id,
                taint_label: label_set.iter().next().cloned(),
            });
        }
    }
    // De-duplicate sinks_out by node_id (a node can match multiple sink
    // patterns; we collapse).
    sinks_out.sort_by_key(|s| s.node_id);
    sinks_out.dedup_by_key(|s| s.node_id);

    DataflowResult {
        lattice,
        sources: sources_seen,
        sinks: sinks_out,
        traces: traces_out,
    }
}

/// Cheap substring check used by the assignment-propagation heuristic.
fn rhs_contains(bytes: &[u8], name: &str) -> bool {
    let nb = name.as_bytes();
    if nb.is_empty() || bytes.len() < nb.len() {
        return false;
    }
    bytes.windows(nb.len()).any(|w| w == nb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{CfgBuilder, FunctionScope};
    use semgrep_core::node::{CanonicalKind, Position, Range, SgNode};

    fn rng() -> Range {
        Range::new(Position::ZERO, Position::ZERO)
    }

    #[test]
    fn empty_matches_yield_no_sinks() {
        let root = SgNode {
            kind: "block",
            canonical_kind: CanonicalKind::Block,
            range: rng(),
            bytes: b"",
            children: vec![],
            field_name: None,
        };
        let scope = FunctionScope {
            name: None,
            root: &root,
            params: Vec::new(),
        };
        let cfg = CfgBuilder::build(&scope);
        let matches = TaintNodeMatches::default();
        let r = run_dataflow(&cfg, &matches, &TaintOptions::default());
        assert!(r.sinks.is_empty());
        assert!(r.traces.is_empty());
    }

    #[test]
    fn source_propagates_to_sink_through_assign() {
        // Hand-roll a CFG: Entry -> Assign{x} -> Call -> Exit
        // Sources marks Assign{x}; sink marks Call with bound_var=x.
        let root = SgNode {
            kind: "block",
            canonical_kind: CanonicalKind::Block,
            range: rng(),
            bytes: b"",
            children: vec![
                SgNode {
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
                },
                SgNode {
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
                },
            ],
            field_name: None,
        };
        let scope = FunctionScope {
            name: None,
            root: &root,
            params: Vec::new(),
        };
        let cfg = CfgBuilder::build(&scope);

        // Find the Assign and Call CFG node ids by scanning.
        let mut assign_id = None;
        let mut call_id = None;
        for w in cfg.node_weights() {
            match &w.kind {
                CfgNodeKind::Assign { .. } if assign_id.is_none() => assign_id = Some(w.id),
                CfgNodeKind::Call { .. } if call_id.is_none() => call_id = Some(w.id),
                _ => {}
            }
        }
        let assign_id = assign_id.expect("should have an Assign node");
        let call_id = call_id.expect("should have a Call node");

        let matches = TaintNodeMatches {
            sources: vec![SourceHit {
                cfg_node_id: assign_id,
                bound_var: Some("x".into()),
                label: Some("user".into()),
            }],
            sinks: vec![SinkPatternHit {
                cfg_node_id: call_id,
                bound_var: Some("x".into()),
                requires: None,
            }],
            ..Default::default()
        };
        let r = run_dataflow(&cfg, &matches, &TaintOptions::default());
        assert_eq!(r.sinks.len(), 1, "expected exactly one sink hit");
        assert_eq!(r.sinks[0].node_id, call_id);
        assert!(!r.traces.is_empty(), "expected a trace");
    }

    #[test]
    fn requires_expression_filters_sinks() {
        // Same shape as above but the sink has `requires: never`.
        let root = SgNode {
            kind: "block",
            canonical_kind: CanonicalKind::Block,
            range: rng(),
            bytes: b"",
            children: vec![SgNode {
                kind: "call_expression",
                canonical_kind: CanonicalKind::Call,
                range: rng(),
                bytes: b"sink(x)",
                children: vec![SgNode {
                    kind: "identifier",
                    canonical_kind: CanonicalKind::Identifier,
                    range: rng(),
                    bytes: b"sink",
                    children: vec![],
                    field_name: None,
                }],
                field_name: None,
            }],
            field_name: None,
        };
        let scope = FunctionScope {
            name: None,
            root: &root,
            params: Vec::new(),
        };
        let cfg = CfgBuilder::build(&scope);
        let call_id = cfg
            .node_weights()
            .find_map(|w| match &w.kind {
                CfgNodeKind::Call { .. } => Some(w.id),
                _ => None,
            })
            .unwrap();
        // Manually pre-taint x at the entry by adding a source at the
        // call node itself and a sink with a requires that won't match.
        let matches = TaintNodeMatches {
            sources: vec![SourceHit {
                cfg_node_id: call_id,
                bound_var: Some("x".into()),
                label: Some("user".into()),
            }],
            sinks: vec![SinkPatternHit {
                cfg_node_id: call_id,
                bound_var: Some("x".into()),
                requires: Some(RequiresExpr::Label("admin".into())),
            }],
            ..Default::default()
        };
        let r = run_dataflow(&cfg, &matches, &TaintOptions::default());
        assert!(r.sinks.is_empty(), "requires:admin should suppress");
    }
}
