//! Build [`semgrep_core::DataflowTrace`] records (source → propagators →
//! sink) from the dataflow result.
//!
//! A trace is just three (or more) `Span`s in dataflow order. The
//! dataflow records `TraceRecord`s carrying CFG node ids; this module
//! maps those ids back to source `Range`s via the CFG and stamps the
//! file path.

use std::path::{Path, PathBuf};

use semgrep_core::node::{Range, Span};
use semgrep_core::{DataflowTrace, TaintLabel};

use crate::cfg::Cfg;
use petgraph::graph::NodeIndex;

/// In-engine trace record. CFG-node-id-based; turned into a
/// [`DataflowTrace`] (file/path/range based) by [`build_trace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRecord {
    pub source_node_id: usize,
    pub propagator_node_ids: Vec<usize>,
    pub sink_node_id: usize,
    pub taint_label: Option<TaintLabel>,
}

/// Slow-path builder used when the engine constructs traces lazily. Holds
/// a reference to the CFG and file path so individual `TraceRecord`s can
/// be lifted without re-passing context.
pub struct TraceBuilder<'a> {
    cfg: &'a Cfg,
    file: PathBuf,
}

impl<'a> TraceBuilder<'a> {
    pub fn new(cfg: &'a Cfg, file: impl Into<PathBuf>) -> Self {
        Self {
            cfg,
            file: file.into(),
        }
    }

    pub fn build(&self, record: &TraceRecord) -> Option<DataflowTrace> {
        let source = self.span_for(record.source_node_id)?;
        let sink = self.span_for(record.sink_node_id)?;
        let propagators = record
            .propagator_node_ids
            .iter()
            .filter_map(|&id| self.span_for(id))
            .collect();
        Some(DataflowTrace {
            source,
            propagators,
            sink,
            taint_label: record.taint_label.clone(),
        })
    }

    fn span_for(&self, id: usize) -> Option<Span> {
        let weight = self.cfg.node_weight(NodeIndex::new(id))?;
        Some(Span::new(self.file.clone(), weight.range))
    }
}

/// One-shot facade used by the runner module.
pub fn build_trace(record: &TraceRecord, file: &Path, cfg: &Cfg) -> Option<DataflowTrace> {
    TraceBuilder::new(cfg, file.to_path_buf()).build(record)
}

/// Helper to lift a raw `Range` and file into a `Span`. Re-exported as a
/// convenience for downstream callers.
pub fn span(file: impl Into<PathBuf>, range: Range) -> Span {
    Span::new(file.into(), range)
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
    fn build_trace_yields_three_spans() {
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
        // Entry index = 0, Exit index = 1 (only two nodes for empty block).
        let rec = TraceRecord {
            source_node_id: 0,
            propagator_node_ids: vec![],
            sink_node_id: 1,
            taint_label: Some("user".into()),
        };
        let trace = build_trace(&rec, Path::new("x.py"), &cfg).expect("trace");
        assert_eq!(trace.taint_label.as_deref(), Some("user"));
        assert_eq!(trace.source.file, PathBuf::from("x.py"));
    }
}
