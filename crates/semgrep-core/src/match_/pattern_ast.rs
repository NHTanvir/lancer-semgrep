//! `PatternAst` — the AST produced by `pattern_parser::parse_pattern`.
//!
//! Patterns are written in a language-agnostic mini-syntax: identifiers,
//! `$METAVARS`, `...` ellipses, literals, calls, attribute access, indexing,
//! arithmetic, assignment, blocks. The matcher in `unifier.rs` walks this AST
//! against the canonical [`SgNode`] tree produced by tree-sitter parses.
//!
//! ### Limitations
//!
//! Upstream Semgrep parses each pattern with the *same* grammar as the
//! target language plus metavariable / ellipsis extensions. Mirroring that
//! across 30+ grammars is out of scope, so we use a lossy, language-agnostic
//! mini-syntax instead. This means:
//!
//! - Patterns are parsed at the syntactic skeleton level (`foo(...)`,
//!   `$X.bar`, `if ... { ... }`). Operator semantics, statement-vs-expression
//!   distinctions, and language-specific keywords are normalised to canonical
//!   forms.
//! - Constructs that have no analogue in this mini-syntax (e.g. Python
//!   decorators, Rust lifetimes, JSX trees) currently fall through as bare
//!   `Atom`s. They may match too liberally — track this in TODO.md.
//! - Trailing semicolons / commas are accepted but not required.

/// One node of a parsed pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternAst {
    /// A bare identifier (`foo`) or keyword (`return`, `if`, ...) used as an
    /// atom rather than a structural form.
    Atom { kind: AtomKind, text: String },

    /// `$X` — binds to the source AST node it matches.
    Metavar { name: String },

    /// `...` — matches any sequence of nodes / sub-expressions / statements.
    /// In an atom position it succeeds trivially against any single node.
    Ellipsis,

    /// `callee(args...)` — call expression.
    Call {
        callee: Box<PatternAst>,
        args: Vec<PatternAst>,
    },

    /// `obj.attr`.
    Attr {
        obj: Box<PatternAst>,
        attr: String,
    },

    /// `obj[idx]`.
    Index {
        obj: Box<PatternAst>,
        idx: Box<PatternAst>,
    },

    /// Binary operator (`x + y`, `x == y`, ...).
    BinOp {
        op: String,
        lhs: Box<PatternAst>,
        rhs: Box<PatternAst>,
    },

    /// Unary operator (`!x`, `-y`).
    UnaryOp {
        op: String,
        operand: Box<PatternAst>,
    },

    /// Assignment (`name = value`).
    Assign {
        target: Box<PatternAst>,
        value: Box<PatternAst>,
    },

    /// Block: `{ stmt; stmt; ... }`.
    Block { stmts: Vec<PatternAst> },

    /// Statement: an expression followed by `;` or newline.
    ExprStmt(Box<PatternAst>),

    /// Literal.
    Lit(LitKind),

    /// A keyword form like `return EXPR` or `if COND { ... }`. The `args`
    /// vector carries trailing payload sub-patterns in source order.
    Keyword { name: String, args: Vec<PatternAst> },

    /// Sequence (statement list / argument list) without an explicit `Block`
    /// wrapper. Used by helpers in `ellipsis.rs`.
    Sequence(Vec<PatternAst>),
}

/// Discriminator for [`PatternAst::Atom`] tokens — keywords behave slightly
/// differently from plain identifiers (they participate in the canonical-kind
/// match against statement / control-flow nodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomKind {
    /// Plain identifier.
    Identifier,
    /// Keyword such as `return`, `if`, `else`, ...
    Keyword,
}

/// Literal kinds the pattern parser recognises.
#[derive(Debug, Clone, PartialEq)]
pub enum LitKind {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl PatternAst {
    /// Convenience: identify ellipses in an argument / statement list.
    pub fn is_ellipsis(&self) -> bool {
        matches!(self, PatternAst::Ellipsis)
    }
}
