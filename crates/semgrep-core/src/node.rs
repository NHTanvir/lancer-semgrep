//! AST node wrapper used across matching, taint, and autofix.
//!
//! `SgNode<'a>` is a thin tree wrapper over the source bytes that the engine
//! produces from a tree-sitter parse. The full tree-sitter wiring lives in
//! `tree-sitter-langs` (Task 3) — here we only define the types so that
//! `match_/`, `taint_types`, and `finding` can refer to them without depending
//! on the grammar bundle.
//!
//! Lifetimes: `SgNode<'a>` borrows from the underlying source bytes and from
//! the tree-sitter parse arena. It is intentionally **not** `Serialize` /
//! `Deserialize`; for emit, we snapshot to owned types (`MetavarBindingSnapshot`
//! etc.) in `finding.rs`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A 1-based line / 1-based column / 0-based byte offset triple.
///
/// Matches Semgrep's text-position convention: rules and CLI output use 1-based
/// line numbers ("line 47, column 12"), but byte offsets remain 0-based for
/// trivial slicing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Position {
    pub line: usize,
    pub column: usize,
    pub offset: usize,
}

impl Position {
    pub const ZERO: Position = Position {
        line: 1,
        column: 1,
        offset: 0,
    };
    pub fn new(line: usize, column: usize, offset: usize) -> Self {
        Self { line, column, offset }
    }
}

/// Inclusive `start` / exclusive `end` byte range plus line/column info.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }
    /// True when this range encloses (or equals) `other`.
    pub fn contains(&self, other: &Range) -> bool {
        self.start.offset <= other.start.offset && other.end.offset <= self.end.offset
    }
    /// Length in bytes.
    pub fn byte_len(&self) -> usize {
        self.end.offset.saturating_sub(self.start.offset)
    }
}

/// File-anchored range. Carried in `Finding` and `DataflowTrace` so callers
/// can render `path/to/file.py:47:12-47:24`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub file: PathBuf,
    pub range: Range,
}

impl Span {
    pub fn new(file: impl Into<PathBuf>, range: Range) -> Self {
        Self {
            file: file.into(),
            range,
        }
    }
}

/// Engine-level node category. Each tree-sitter grammar uses its own kind
/// names (`function_definition` in Python, `function_declaration` in JS,
/// `method_declaration` in Java); the canonicaliser in `tree-sitter-langs`
/// maps each onto one of these variants so patterns and the taint engine can
/// reason uniformly. See plan §"Engineering hard parts — Tree-sitter parsing".
///
/// This is a deliberately small placeholder — Task 3 will likely move the full
/// taxonomy into `tree-sitter-langs` and re-export it. Keeping it here for now
/// avoids circular deps between `semgrep-core` and `tree-sitter-langs`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalKind {
    /// `def`, `function`, `func`, `fn`, ...
    Function,
    /// Method on a class / impl block.
    Method,
    /// Call expression: `foo(a, b)`, `obj.bar()`.
    Call,
    /// Bare identifier reference.
    Identifier,
    /// Literal of any primitive kind. (See `String`, `Number` for refinements.)
    Literal,
    /// Binary operator expression: `a + b`, `x and y`.
    BinaryOp,
    /// Assignment: `x = y`, `x += y`.
    Assign,
    /// `if`/`elif`/`else` statement.
    IfStmt,
    /// Block of statements (`{ ... }`, indented body, ...).
    Block,
    /// `return` statement.
    Return,
    /// Call-site argument.
    Argument,
    /// Function-definition parameter.
    Parameter,
    /// `import`, `use`, `require`, etc.
    Import,
    /// Type annotation / type expression.
    TypeAnnotation,
    /// Statement-level node that doesn't fit a more specific variant.
    Statement,
    /// Expression-level node that doesn't fit a more specific variant.
    Expression,
    /// Source comment.
    Comment,
    /// String literal.
    String,
    /// Numeric literal.
    Number,
    /// Anything else — grammar-specific kinds that haven't been mapped yet.
    Other,
}

/// Engine-side AST node, borrowed from the parse buffer.
///
/// This is **not** the full tree-sitter `Node` — once we wire grammars in
/// Task 3, the `tree-sitter-langs::SgTree` will produce `SgNode`s on demand
/// (likely backed by `tree_sitter::Node<'a>` plus the source slice). For now
/// the simplified shape lets `match_/`, `taint_types`, and `finding` compile
/// against a stable interface.
#[derive(Debug, Clone)]
pub struct SgNode<'a> {
    /// Raw kind name from the underlying tree-sitter grammar
    /// (e.g. `"function_definition"`).
    pub kind: &'a str,
    /// Canonicalised kind for cross-language pattern matching.
    pub canonical_kind: CanonicalKind,
    /// Position range within the source file.
    pub range: Range,
    /// Source bytes for this exact node (used by `metavariable-regex` and
    /// autofix substitution).
    pub bytes: &'a [u8],
    /// Direct children. (Real impl in `tree-sitter-langs` will likely lazy-
    /// walk via `tree_sitter::TreeCursor` rather than materialising a `Vec`,
    /// but the simpler shape suffices for the vocabulary crate.)
    pub children: Vec<SgNode<'a>>,
    /// Tree-sitter field label for this child slot, if any
    /// (e.g. `Some("body")` for a function body).
    pub field_name: Option<&'static str>,
}

impl<'a> SgNode<'a> {
    /// Construct a leaf node (no children).
    pub fn leaf(
        kind: &'a str,
        canonical_kind: CanonicalKind,
        range: Range,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            kind,
            canonical_kind,
            range,
            bytes,
            children: Vec::new(),
            field_name: None,
        }
    }

    /// Structural equality used by `MetavarBindings::try_bind`:
    /// two bindings of the same metavariable agree iff they have the same
    /// byte range **and** the same raw kind.
    pub fn structurally_equal(&self, other: &SgNode<'_>) -> bool {
        self.range == other.range && self.kind == other.kind
    }

    /// Returns the node text as a borrowed `str`, assuming valid UTF-8.
    pub fn text(&self) -> &'a str {
        std::str::from_utf8(self.bytes).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_contains() {
        let outer = Range::new(Position::new(1, 1, 0), Position::new(10, 1, 100));
        let inner = Range::new(Position::new(2, 1, 10), Position::new(5, 1, 50));
        assert!(outer.contains(&inner));
        assert!(!inner.contains(&outer));
    }

    #[test]
    fn structural_equal() {
        let r = Range::new(Position::new(1, 1, 0), Position::new(1, 5, 4));
        let bytes = b"name";
        let a = SgNode::leaf("identifier", CanonicalKind::Identifier, r, bytes);
        let b = SgNode::leaf("identifier", CanonicalKind::Identifier, r, bytes);
        assert!(a.structurally_equal(&b));
        let r2 = Range::new(Position::new(2, 1, 5), Position::new(2, 5, 9));
        let c = SgNode::leaf("identifier", CanonicalKind::Identifier, r2, bytes);
        assert!(!a.structurally_equal(&c));
    }
}
