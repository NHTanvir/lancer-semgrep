//! Control-flow graph node types.
//!
//! A `CfgNode` is one program-point in the CFG. Each node carries:
//!
//! - a stable id (matches the `petgraph::graph::NodeIndex.index()`),
//! - a `CfgNodeKind` tag that drives the dataflow transfer function,
//! - the source `Range` it corresponds to (for trace emit),
//! - a small `source_text` snippet so the matching layer can do cheap
//!   range-to-node lookups without re-walking the tree-sitter tree.
//!
//! See plan.md §"Internal architecture → taint/" and §"Engineering hard
//! parts → Taint analysis".

use semgrep_core::node::Range;

/// One program-point. `id` mirrors the index into the `petgraph::DiGraph`
/// underlying [`crate::cfg::Cfg`].
#[derive(Debug, Clone)]
pub struct CfgNode {
    pub id: usize,
    pub kind: CfgNodeKind,
    pub range: Range,
    /// Source bytes for this node. Used by the matcher glue to find the
    /// corresponding `SgNode` subtree at this program-point.
    pub source_text: Vec<u8>,
}

/// Kinds of CFG nodes. The dataflow engine branches on this enum in its
/// transfer function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgNodeKind {
    /// Synthetic entry node, one per function.
    Entry,
    /// Synthetic exit node, one per function.
    Exit,
    /// Generic statement we did not specialise.
    Stmt,
    /// Assignment whose LHS is a (possibly desugared) variable name.
    Assign { target: String },
    /// Function call whose callee is `callee` and whose textual args are
    /// `args` (these are *textual* — not bound metavariables).
    Call { callee: String, args: Vec<String> },
    /// `if` / `while` / `for` head — i.e. a branch point with two arms.
    Branch,
    /// Loop header — back-edge target.
    Loop,
    /// `return` (the expression itself becomes the statement).
    Return,
}

/// Edge classification. Mostly informational — the dataflow ignores
/// classification today, but having labels makes the CFG dump readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Normal sequential flow.
    FallThrough,
    /// Branch-taken arm.
    Branch,
    /// Branch-not-taken arm.
    NotTaken,
    /// Loop back-edge.
    Back,
    /// Call to an external function (placeholder for inter-proc).
    Call,
    /// Return from a callee back to caller.
    Return,
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::node::{Position, Range};

    fn rng() -> Range {
        Range::new(Position::ZERO, Position::ZERO)
    }

    #[test]
    fn cfg_node_construct_and_clone() {
        let n = CfgNode {
            id: 7,
            kind: CfgNodeKind::Assign {
                target: "x".into(),
            },
            range: rng(),
            source_text: b"x = 1".to_vec(),
        };
        let m = n.clone();
        assert_eq!(m.id, 7);
        match m.kind {
            CfgNodeKind::Assign { target } => assert_eq!(target, "x"),
            _ => panic!("expected Assign"),
        }
    }

    #[test]
    fn edge_kind_equality() {
        assert_eq!(EdgeKind::FallThrough, EdgeKind::FallThrough);
        assert_ne!(EdgeKind::Branch, EdgeKind::NotTaken);
    }
}
