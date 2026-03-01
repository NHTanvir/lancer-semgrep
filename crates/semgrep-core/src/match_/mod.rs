//! Matching value types — `Match`, `MetavarBindings`, `MatchScope`,
//! `MatchExplanationNode`.
//!
//! `Match<'a>` is what the engine emits at the end of a successful pattern
//! unification: the bound metavariables, the matched root node, and an
//! optional explanation tree (driven by `--matching-explanations`).
//!
//! These types **borrow source bytes** (`'a` lifetime) and therefore don't
//! implement serde. The "wire" equivalents live in `finding.rs`
//! (`Finding`, `MetavarBindingSnapshot`, `MatchExplanation`), which are owned
//! and serde-friendly.

use std::collections::BTreeMap;

use crate::node::SgNode;
use crate::rule::RuleId;

// ---------------------------------------------------------------------------
// Pattern-matcher engine submodules (Task 5).
// ---------------------------------------------------------------------------

pub mod deduplicate;
pub mod ellipsis;
pub mod engine;
pub mod metavar_comp_eval;
pub mod pattern_ast;
pub mod pattern_parser;
pub mod pre_filter;
pub mod rule_evaluator;
pub mod unifier;

pub use deduplicate::dedup_for_rule;
pub use engine::run_rule_on_node;
pub use metavar_comp_eval::{CompExpr, CompOp, CompValue};
pub use pattern_ast::{AtomKind, LitKind, PatternAst};
pub use pattern_parser::parse_pattern;
pub use pre_filter::{pre_filter, required_strings};
pub use rule_evaluator::{evaluate_pattern_op, CompiledPatternCache, MatchCandidate};
pub use unifier::unify;

/// Error returned by `MetavarBindings::try_bind` when a second binding of the
/// same metavariable disagrees structurally with the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetavarBindClash {
    pub name: String,
}

impl std::fmt::Display for MetavarBindClash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "metavariable bind clash for {}", self.name)
    }
}

impl std::error::Error for MetavarBindClash {}

/// In-progress metavariable binding store used by the unifier.
///
/// Bindings are insertion-ordered via `BTreeMap` so that snapshot order is
/// stable and serialisation looks deterministic in tests.
///
/// The unifier needs cheap "try-and-rollback" semantics for alternative
/// branches (`pattern-either`, ellipsis enumerations, ...). To avoid cloning
/// the whole `BTreeMap<String, SgNode<'a>>` on every backtrack — which would
/// be very expensive for owned-children `SgNode` trees — we keep a small
/// **journal** of mutations alongside the map. A `Checkpoint` records the
/// current journal length; `restore_to` replays journaled changes in reverse
/// to roll the map back to that point.
///
/// This keeps the snapshot/restore cost proportional to the *changes* made
/// within a branch rather than to the total binding count.
#[derive(Debug, Clone, Default)]
pub struct MetavarBindings<'a> {
    inner: BTreeMap<String, SgNode<'a>>,
    /// Undo journal: each entry records the state *before* a write. `None`
    /// means the slot was unbound prior to the write; `Some(node)` means it
    /// held that node. To restore, pop the entry and either re-insert the
    /// `Some(node)` or remove the key.
    journal: Vec<(String, Option<SgNode<'a>>)>,
}

/// Opaque checkpoint token returned by [`MetavarBindings::checkpoint`].
///
/// Pair with [`MetavarBindings::restore_to`] to roll back any bindings made
/// since the checkpoint was taken. Checkpoints are integers — taking one is
/// free. Restoring scales with the number of mutations after the checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint(pub usize);

impl<'a> MetavarBindings<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `name` to `node`. If `name` is already bound, the existing
    /// binding must be **structurally equal** to `node`
    /// (same byte range and same tree-sitter kind); otherwise an `Err` is
    /// returned and no change is made.
    ///
    /// Successful binds are journaled so subsequent [`Self::restore_to`]
    /// rolls them back. Structural-equality re-binds are no-ops (no journal
    /// entry).
    pub fn try_bind(
        &mut self,
        name: &str,
        node: SgNode<'a>,
    ) -> Result<(), MetavarBindClash> {
        if let Some(existing) = self.inner.get(name) {
            if existing.structurally_equal(&node) {
                return Ok(());
            }
            return Err(MetavarBindClash {
                name: name.to_string(),
            });
        }
        // Fresh bind — journal the prior `None` and insert.
        self.journal.push((name.to_string(), None));
        self.inner.insert(name.to_string(), node);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&SgNode<'a>> {
        self.inner.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &SgNode<'a>)> {
        self.inner.iter()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Capture a rollback point. Free.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.journal.len())
    }

    /// Restore the map to the state captured by `cp`, undoing every binding
    /// made since then.
    pub fn restore_to(&mut self, cp: Checkpoint) {
        while self.journal.len() > cp.0 {
            let (name, prev) = self
                .journal
                .pop()
                .expect("journal length checked above");
            match prev {
                Some(node) => {
                    self.inner.insert(name, node);
                }
                None => {
                    self.inner.remove(&name);
                }
            }
        }
    }

    /// Compact the journal — call once a successful match has been committed
    /// so future checkpoints are taken against the new floor. Equivalent to
    /// `self.journal.clear()`.
    pub fn commit(&mut self) {
        self.journal.clear();
    }

    /// Project these in-flight bindings into the owned form embedded in
    /// `Finding`s. Returns a deterministic `BTreeMap` of
    /// `metavar-name → snapshot`.
    pub fn snapshot_for_finding(
        &self,
    ) -> BTreeMap<String, crate::finding::MetavarBindingSnapshot> {
        self.inner
            .iter()
            .map(|(name, node)| {
                let snap = crate::finding::MetavarBindingSnapshot {
                    abstract_content: node.text().to_string(),
                    propagated_value: None,
                    range: node.range,
                };
                (name.clone(), snap)
            })
            .collect()
    }
}

/// What scope a pattern is allowed to span.
///
/// Most patterns are scope-free; some constructs (e.g. `pattern-inside:`,
/// statement-level ellipsis) implicitly constrain the scope. `MatchScope`
/// gives the engine a uniform handle on that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchScope {
    /// Single statement.
    Statement,
    /// Single call-site argument.
    Argument,
    /// Single expression (statement-free).
    Expression,
    /// Block of statements (`{ ... }` or indented body).
    Block,
    /// Whole file.
    File,
}

/// One sub-tree of a match explanation, mirroring the rule's pattern tree.
///
/// `--matching-explanations` walks this tree to render "pattern P matched
/// subtree S, but pattern-not Q matched subtree T, so the finding is
/// suppressed".
#[derive(Debug, Clone)]
pub struct MatchExplanationNode {
    /// Human-readable description (e.g. `"pattern-either"`, `"metavariable-
    /// regex on $X"`).
    pub op: String,
    /// Whether this node's sub-pattern matched.
    pub matched: bool,
    /// Per-child explanations, in source order.
    pub children: Vec<MatchExplanationNode>,
}

/// A single successful match. Borrows the source bytes from the parse buffer.
#[derive(Debug, Clone)]
pub struct Match<'a> {
    /// Rule that produced this match.
    pub rule_id: RuleId,
    /// Root node of the matched subtree.
    pub root: SgNode<'a>,
    /// Metavariable bindings established during unification.
    pub bindings: MetavarBindings<'a>,
    /// Optional explanation tree (set iff `options.matching_explanations`).
    pub explanation: Option<MatchExplanationNode>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{CanonicalKind, Position, Range};

    fn node<'a>(s: &'a str, start: usize, end: usize) -> SgNode<'a> {
        let r = Range::new(
            Position::new(1, start + 1, start),
            Position::new(1, end + 1, end),
        );
        SgNode::leaf("identifier", CanonicalKind::Identifier, r, s.as_bytes())
    }

    #[test]
    fn bind_then_repeat_same_range_ok() {
        let mut b = MetavarBindings::new();
        let n = node("foo", 0, 3);
        b.try_bind("$X", n.clone()).unwrap();
        // Re-binding the same node is fine.
        b.try_bind("$X", n).unwrap();
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn bind_clash_on_different_range() {
        let mut b = MetavarBindings::new();
        b.try_bind("$X", node("foo", 0, 3)).unwrap();
        let err = b.try_bind("$X", node("bar", 4, 7)).unwrap_err();
        assert_eq!(err.name, "$X");
    }

    #[test]
    fn snapshot_iter_deterministic() {
        let mut b = MetavarBindings::new();
        b.try_bind("$B", node("two", 4, 7)).unwrap();
        b.try_bind("$A", node("one", 0, 3)).unwrap();
        let snap = b.snapshot_for_finding();
        let keys: Vec<&String> = snap.keys().collect();
        assert_eq!(keys, vec![&"$A".to_string(), &"$B".to_string()]);
    }

    #[test]
    fn checkpoint_restores_fresh_binding() {
        let mut b = MetavarBindings::new();
        let cp = b.checkpoint();
        b.try_bind("$X", node("foo", 0, 3)).unwrap();
        assert_eq!(b.len(), 1);
        b.restore_to(cp);
        assert!(b.is_empty());
        assert!(b.get("$X").is_none());
    }

    #[test]
    fn checkpoint_keeps_earlier_bindings() {
        let mut b = MetavarBindings::new();
        b.try_bind("$A", node("aaa", 0, 3)).unwrap();
        let cp = b.checkpoint();
        b.try_bind("$B", node("bbb", 4, 7)).unwrap();
        b.restore_to(cp);
        assert_eq!(b.len(), 1);
        assert!(b.get("$A").is_some());
        assert!(b.get("$B").is_none());
    }
}
