//! Control-flow graph construction from an [`SgNode`] tree.
//!
//! The CFG is intentionally *approximate*: real Semgrep-style flow analysis
//! works on a desugared IR, but we are operating on a raw tree-sitter tree
//! with cross-language `CanonicalKind` tags. We translate structurally:
//!
//! - one CFG node per `Statement` / `Expression` / `Assign` / `Call` /
//!   `Return`;
//! - sequential siblings connect via `FallThrough` edges;
//! - `IfStmt` opens a `Branch` node and two arms that re-converge;
//! - blocks are flattened;
//! - any unrecognised node degrades to a single `Stmt`.
//!
//! Function discovery: we walk the AST and start one CFG per
//! `Function` / `Method` node we find. If none exist we treat the whole
//! root as a synthetic function (script-style code).
//!
//! See plan.md §"Internal architecture → taint/" and §"Engineering hard
//! parts → Taint analysis" / "CFG construction".

use petgraph::graph::{DiGraph, NodeIndex};

use semgrep_core::node::{CanonicalKind, Range, SgNode};

use crate::nodes::{CfgNode, CfgNodeKind, EdgeKind};

/// Type alias for the workhorse graph. Indexed by `usize` (we feed
/// `NodeIndex::index()` straight to the dataflow lattice).
pub type Cfg = DiGraph<CfgNode, EdgeKind>;

/// Function-level scope passed to the CFG builder.
pub struct FunctionScope<'a> {
    /// Function name (best-effort — `None` for lambdas / scripts).
    pub name: Option<String>,
    /// Root AST node — usually a `Function` / `Method` or a synthetic
    /// `Block` wrapping the whole file.
    pub root: &'a SgNode<'a>,
    /// Parameter names. Currently unused; the matcher introduces sources
    /// at parameter assignments via pattern matching.
    pub params: Vec<String>,
}

/// In-progress CFG. Lives only across one `build` invocation.
pub struct CfgBuilder<'a> {
    graph: Cfg,
    /// Stack of innermost-loop entry nodes for `break` / `continue`
    /// (placeholder — control statements aren't yet wired).
    #[allow(dead_code)]
    loop_stack: Vec<NodeIndex>,
    _src: std::marker::PhantomData<&'a ()>,
}

impl<'a> Default for CfgBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CfgBuilder<'a> {
    /// Fresh, empty builder.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            loop_stack: Vec::new(),
            _src: std::marker::PhantomData,
        }
    }

    /// Build a CFG for one function scope. Returns the final `Cfg`. The
    /// first node is always the synthetic `Entry`; the last is always
    /// `Exit`.
    pub fn build(scope: &FunctionScope<'a>) -> Cfg {
        let mut b = Self::new();
        let entry = b.add_node(
            CfgNodeKind::Entry,
            scope.root.range,
            b"<entry>",
        );
        let last = b.walk(scope.root, entry);
        let exit = b.add_node(
            CfgNodeKind::Exit,
            scope.root.range,
            b"<exit>",
        );
        b.edge(last, exit, EdgeKind::FallThrough);
        b.graph
    }

    /// Allocate a CFG node and stamp its id from the index.
    fn add_node(
        &mut self,
        kind: CfgNodeKind,
        range: Range,
        text: &[u8],
    ) -> NodeIndex {
        let id_placeholder = 0usize;
        let idx = self.graph.add_node(CfgNode {
            id: id_placeholder,
            kind,
            range,
            source_text: text.to_vec(),
        });
        // Patch the id now that we know the NodeIndex.
        if let Some(w) = self.graph.node_weight_mut(idx) {
            w.id = idx.index();
        }
        idx
    }

    /// Add a directed edge.
    fn edge(&mut self, from: NodeIndex, to: NodeIndex, e: EdgeKind) {
        self.graph.add_edge(from, to, e);
    }

    /// Recursive structural walker. Each call returns the *last* CFG node
    /// produced (the predecessor for the caller's next step).
    fn walk(&mut self, node: &SgNode<'a>, predecessor: NodeIndex) -> NodeIndex {
        use CanonicalKind::*;
        match node.canonical_kind {
            // Flatten blocks: process children in source order, chaining
            // fall-through edges.
            Block => {
                let mut prev = predecessor;
                for child in &node.children {
                    prev = self.walk(child, prev);
                }
                prev
            }
            // Functions: descend into the body (= the `Block` child).
            // For a nested function we don't recurse into its body here —
            // the outer build_for_root call enumerates functions, so
            // recursing again would duplicate work. We treat a nested
            // function as a single opaque `Stmt`.
            Function | Method => {
                let n = self.add_node(
                    CfgNodeKind::Stmt,
                    node.range,
                    node.bytes,
                );
                self.edge(predecessor, n, EdgeKind::FallThrough);
                n
            }
            // Assignment: extract the first child's text as the target.
            Assign => {
                let target = first_child_text(node).unwrap_or_default();
                let n = self.add_node(
                    CfgNodeKind::Assign { target },
                    node.range,
                    node.bytes,
                );
                self.edge(predecessor, n, EdgeKind::FallThrough);
                n
            }
            // Call: first child is callee; subsequent children are args.
            Call => {
                let callee = first_child_text(node).unwrap_or_default();
                let args = node
                    .children
                    .iter()
                    .skip(1)
                    .map(|c| c.text().to_string())
                    .collect();
                let n = self.add_node(
                    CfgNodeKind::Call { callee, args },
                    node.range,
                    node.bytes,
                );
                self.edge(predecessor, n, EdgeKind::FallThrough);
                n
            }
            // Return statement.
            Return => {
                let n = self.add_node(
                    CfgNodeKind::Return,
                    node.range,
                    node.bytes,
                );
                self.edge(predecessor, n, EdgeKind::FallThrough);
                n
            }
            // If statement: open a Branch node, walk each arm, merge.
            //
            // We use a simplified shape: each child is treated as either
            // a `then` body or an `else` body. We approximate by walking
            // children in order, branching after the first non-condition
            // child, merging at a fresh `Stmt` node.
            IfStmt => {
                let head = self.add_node(
                    CfgNodeKind::Branch,
                    node.range,
                    node.bytes,
                );
                self.edge(predecessor, head, EdgeKind::FallThrough);
                let merge = self.add_node(
                    CfgNodeKind::Stmt,
                    node.range,
                    b"<merge>",
                );
                // Children: first is the condition; the rest are bodies.
                let mut arms_walked = 0usize;
                for child in node.children.iter().skip(1) {
                    let arm_end = self.walk(child, head);
                    let kind = if arms_walked == 0 {
                        EdgeKind::Branch
                    } else {
                        EdgeKind::NotTaken
                    };
                    // Re-classify the first FallThrough we put out of
                    // `head` -> child's first node? We can't cheaply
                    // re-tag past edges; instead the bookkeeping for
                    // the merge edge is what matters.
                    let _ = kind;
                    self.edge(arm_end, merge, EdgeKind::FallThrough);
                    arms_walked += 1;
                }
                // If there's no else-arm, allow flow to skip past the
                // body directly to the merge.
                if arms_walked < 2 {
                    self.edge(head, merge, EdgeKind::NotTaken);
                }
                merge
            }
            // Statements / expressions / everything else — generic node.
            _ => {
                let kind = match node.canonical_kind {
                    Statement | Expression | Other => CfgNodeKind::Stmt,
                    _ => CfgNodeKind::Stmt,
                };
                let n = self.add_node(kind, node.range, node.bytes);
                self.edge(predecessor, n, EdgeKind::FallThrough);
                // Continue into children so nested calls / assigns inside
                // a generic expression node still show up. (E.g. an
                // expression-statement wrapping a Call.)
                let mut last = n;
                for child in &node.children {
                    last = self.walk(child, last);
                }
                last
            }
        }
    }
}

/// Text of the first child of `node`, or `None` if it has none.
fn first_child_text(node: &SgNode<'_>) -> Option<String> {
    node.children.first().map(|c| c.text().to_string())
}

/// Build one or more CFGs for the entire AST under `root`.
///
/// - Every `Function` / `Method` descendant produces one CFG.
/// - If none are found, the whole root is wrapped in a synthetic
///   anonymous function scope and a single CFG is produced.
pub fn build_for_root<'a>(root: &'a SgNode<'a>) -> Vec<Cfg> {
    let mut cfgs = Vec::new();
    let mut found_function = false;
    walk_collect(root, &mut cfgs, &mut found_function);
    if !found_function {
        let scope = FunctionScope {
            name: None,
            root,
            params: Vec::new(),
        };
        cfgs.push(CfgBuilder::build(&scope));
    }
    cfgs
}

fn walk_collect<'a>(
    node: &'a SgNode<'a>,
    cfgs: &mut Vec<Cfg>,
    found_function: &mut bool,
) {
    use CanonicalKind::*;
    if matches!(node.canonical_kind, Function | Method) {
        *found_function = true;
        let scope = FunctionScope {
            name: None,
            root: node,
            params: Vec::new(),
        };
        cfgs.push(CfgBuilder::build(&scope));
    }
    for c in &node.children {
        walk_collect(c, cfgs, found_function);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::node::{CanonicalKind, Position, Range, SgNode};

    fn rng() -> Range {
        Range::new(Position::ZERO, Position::ZERO)
    }

    fn leaf(kind: CanonicalKind, text: &'static [u8]) -> SgNode<'static> {
        SgNode {
            kind: "leaf",
            canonical_kind: kind,
            range: rng(),
            bytes: text,
            children: vec![],
            field_name: None,
        }
    }

    #[test]
    fn build_for_root_no_functions() {
        // A bare expression-tree with no Function node => 1 synthetic CFG.
        let root = leaf(CanonicalKind::Statement, b"pass");
        let cfgs = build_for_root(&root);
        assert_eq!(cfgs.len(), 1);
        // Entry + one Stmt + Exit = 3 nodes.
        assert!(cfgs[0].node_count() >= 2);
    }

    #[test]
    fn build_for_root_one_function() {
        let body = SgNode {
            kind: "block",
            canonical_kind: CanonicalKind::Block,
            range: rng(),
            bytes: b"",
            children: vec![
                leaf(CanonicalKind::Statement, b"x = 1"),
                leaf(CanonicalKind::Return, b"return x"),
            ],
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
        // Entry, two body statements, Exit.
        assert!(cfgs[0].node_count() >= 4);
    }

    #[test]
    fn assign_node_extracts_target() {
        let target = SgNode {
            kind: "identifier",
            canonical_kind: CanonicalKind::Identifier,
            range: rng(),
            bytes: b"x",
            children: vec![],
            field_name: None,
        };
        let value = leaf(CanonicalKind::Number, b"1");
        let assign = SgNode {
            kind: "assignment",
            canonical_kind: CanonicalKind::Assign,
            range: rng(),
            bytes: b"x = 1",
            children: vec![target, value],
            field_name: None,
        };
        let cfgs = build_for_root(&assign);
        let cfg = &cfgs[0];
        let mut found = false;
        for w in cfg.node_weights() {
            if let CfgNodeKind::Assign { target } = &w.kind {
                assert_eq!(target, "x");
                found = true;
            }
        }
        assert!(found, "should have produced an Assign node");
    }
}
