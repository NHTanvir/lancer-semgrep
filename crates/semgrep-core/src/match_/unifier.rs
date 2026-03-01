//! Pattern → source-AST unification.
//!
//! `unify` walks a [`PatternAst`] alongside an [`SgNode`] and succeeds iff
//! the AST shapes line up. Metavariables (`$X`) bind to whichever source
//! subtree they encounter first; subsequent occurrences in the same pattern
//! must match the same node structurally — see
//! [`MetavarBindings::try_bind`] for the exact equality semantics.
//!
//! ### Backtracking
//!
//! Ellipsis (`...`) inside argument / statement lists can match
//! zero-or-more source items, so we enumerate split points and ask the rest
//! of the pattern to fit. Whenever we try a branch, we
//! [`MetavarBindings::checkpoint`] before and [`MetavarBindings::restore_to`]
//! on failure to roll back any speculative metavar bindings. See
//! [`super::ellipsis`].

use crate::match_::pattern_ast::{AtomKind, LitKind, PatternAst};
use crate::match_::MetavarBindings;
use crate::node::{CanonicalKind, SgNode};

/// Attempt to unify `pattern` against `node`. On success the bindings are
/// updated in place and `true` is returned. On failure any speculative
/// bindings made during the attempt are rolled back.
pub fn unify<'a>(
    pattern: &PatternAst,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    let cp = bindings.checkpoint();
    let ok = unify_inner(pattern, node, bindings);
    if !ok {
        bindings.restore_to(cp);
    }
    ok
}

/// Inner, non-rolling-back variant. The public [`unify`] wraps it with a
/// checkpoint/restore so partial speculative bindings never leak on failure.
pub(crate) fn unify_inner<'a>(
    pattern: &PatternAst,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    use PatternAst::*;
    match pattern {
        Metavar { name } => bind_metavar(name, node, bindings),
        Ellipsis => true,
        Atom { kind, text } => match_atom(*kind, text, node),
        Lit(lit) => match_literal(lit, node),
        Call { callee, args } => match_call(callee, args, node, bindings),
        Attr { obj, attr } => match_attr(obj, attr, node, bindings),
        Index { obj, idx } => match_index(obj, idx, node, bindings),
        BinOp { op, lhs, rhs } => match_binop(op, lhs, rhs, node, bindings),
        UnaryOp { op, operand } => match_unaryop(op, operand, node, bindings),
        Assign { target, value } => match_assign(target, value, node, bindings),
        Block { stmts } => match_block(stmts, node, bindings),
        Sequence(items) => super::ellipsis::match_sequence_with_ellipsis(items, node, bindings),
        ExprStmt(e) => unify_inner(e, node, bindings),
        Keyword { name, args } => match_keyword(name, args, node, bindings),
    }
}

// ---------------------------------------------------------------------------
// Helpers — node text / structural equality / value extraction.
// ---------------------------------------------------------------------------

fn node_text_eq(node: &SgNode<'_>, b: &[u8]) -> bool {
    node.bytes == b
}

fn node_string_value(node: &SgNode<'_>) -> Option<String> {
    let s = std::str::from_utf8(node.bytes).ok()?;
    // Strip a single layer of surrounding quotes (`"..."`, `'...'`, ``` `...` ```).
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'' || first == b'`') && first == last {
            return Some(unescape(&trimmed[1..trimmed.len() - 1]));
        }
    }
    Some(s.to_string())
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('0') => out.push('\0'),
                Some(other) => out.push(other),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn node_int_value(node: &SgNode<'_>) -> Option<i64> {
    let s = std::str::from_utf8(node.bytes).ok()?.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return i64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        return i64::from_str_radix(rest, 8).ok();
    }
    if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        return i64::from_str_radix(rest, 2).ok();
    }
    s.parse().ok()
}

fn node_float_value(node: &SgNode<'_>) -> Option<f64> {
    std::str::from_utf8(node.bytes).ok()?.trim().parse().ok()
}

// ---------------------------------------------------------------------------
// Per-pattern-kind handlers.
// ---------------------------------------------------------------------------

fn bind_metavar<'a>(
    name: &str,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    // Delegate to `MetavarBindings::try_bind` so the structural-equality
    // semantics stay in one place (range + raw kind, defined on `SgNode`).
    bindings.try_bind(name, node.clone()).is_ok()
}

fn match_atom(_kind: AtomKind, text: &str, node: &SgNode<'_>) -> bool {
    // Identifier-like nodes: compare text directly. We allow the source node
    // to be a more specific canonical-kind because the upstream grammar may
    // tag a function name as Call / Function / Identifier interchangeably.
    matches!(
        node.canonical_kind,
        CanonicalKind::Identifier
            | CanonicalKind::Other
            | CanonicalKind::Expression
            | CanonicalKind::Statement
            | CanonicalKind::TypeAnnotation
    ) && node_text_eq(node, text.as_bytes())
}

fn match_literal(lit: &LitKind, node: &SgNode<'_>) -> bool {
    match lit {
        LitKind::Str(s) => {
            matches!(node.canonical_kind, CanonicalKind::String | CanonicalKind::Literal)
                && node_string_value(node).as_deref() == Some(s.as_str())
        }
        LitKind::Int(i) => {
            matches!(node.canonical_kind, CanonicalKind::Number | CanonicalKind::Literal)
                && node_int_value(node) == Some(*i)
        }
        LitKind::Float(f) => {
            matches!(node.canonical_kind, CanonicalKind::Number | CanonicalKind::Literal)
                && node_float_value(node)
                    .map(|x| (x - *f).abs() < 1e-12)
                    .unwrap_or(false)
        }
        LitKind::Bool(b) => {
            let wanted: &[u8] = if *b { b"true" } else { b"false" };
            node_text_eq(node, wanted)
        }
        LitKind::Null => {
            node_text_eq(node, b"null")
                || node_text_eq(node, b"nil")
                || node_text_eq(node, b"None")
                || node_text_eq(node, b"undefined")
        }
    }
}

fn match_call<'a>(
    callee: &PatternAst,
    pattern_args: &[PatternAst],
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if !matches!(node.canonical_kind, CanonicalKind::Call) {
        return false;
    }
    if node.children.is_empty() {
        return false;
    }
    // First child is the callee.
    let callee_node = &node.children[0];
    if !unify_inner(callee, callee_node, bindings) {
        return false;
    }
    // Remaining children are argument nodes.
    let source_args: Vec<&SgNode<'a>> = node.children.iter().skip(1).collect();
    super::ellipsis::match_argument_list(pattern_args, &source_args, bindings)
}

fn match_attr<'a>(
    obj: &PatternAst,
    attr: &str,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if node.children.len() != 2 {
        return false;
    }
    let obj_node = &node.children[0];
    let attr_node = &node.children[1];
    if !unify_inner(obj, obj_node, bindings) {
        return false;
    }
    node_text_eq(attr_node, attr.as_bytes())
}

fn match_index<'a>(
    obj: &PatternAst,
    idx: &PatternAst,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if node.children.len() != 2 {
        return false;
    }
    let obj_node = &node.children[0];
    let idx_node = &node.children[1];
    unify_inner(obj, obj_node, bindings) && unify_inner(idx, idx_node, bindings)
}

fn match_binop<'a>(
    op: &str,
    lhs: &PatternAst,
    rhs: &PatternAst,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if !matches!(node.canonical_kind, CanonicalKind::BinaryOp) {
        return false;
    }
    // Typical canonical layout: [lhs, op-token, rhs]. Accept either two
    // children (operator implied) or three (with operator token).
    let (lhs_node, op_node, rhs_node) = match node.children.as_slice() {
        [a, b] => (a, None, b),
        [a, op, b] => (a, Some(op), b),
        _ => return false,
    };
    if let Some(op_n) = op_node {
        if !node_text_eq(op_n, op.as_bytes()) {
            return false;
        }
    }
    unify_inner(lhs, lhs_node, bindings) && unify_inner(rhs, rhs_node, bindings)
}

fn match_unaryop<'a>(
    op: &str,
    operand: &PatternAst,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if node.children.is_empty() {
        return false;
    }
    // Layout heuristic: [op, operand] or just [operand]. Accept either.
    let (op_node, operand_node) = match node.children.as_slice() {
        [a] => (None, a),
        [op, operand] => (Some(op), operand),
        _ => return false,
    };
    if let Some(op_n) = op_node {
        if !node_text_eq(op_n, op.as_bytes()) {
            return false;
        }
    }
    unify_inner(operand, operand_node, bindings)
}

fn match_assign<'a>(
    target: &PatternAst,
    value: &PatternAst,
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if !matches!(node.canonical_kind, CanonicalKind::Assign) {
        return false;
    }
    let (target_node, value_node) = match node.children.as_slice() {
        [t, v] => (t, v),
        [t, _op, v] => (t, v),
        _ => return false,
    };
    unify_inner(target, target_node, bindings) && unify_inner(value, value_node, bindings)
}

fn match_block<'a>(
    stmts: &[PatternAst],
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    if !matches!(node.canonical_kind, CanonicalKind::Block) {
        return false;
    }
    super::ellipsis::match_block_with_ellipsis(stmts, node, bindings)
}

fn match_keyword<'a>(
    name: &str,
    args: &[PatternAst],
    node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    // Identify the canonical kind we expect based on the keyword.
    let expected_kind = match name {
        "return" => Some(CanonicalKind::Return),
        "if" | "elif" => Some(CanonicalKind::IfStmt),
        "import" | "use" | "require" => Some(CanonicalKind::Import),
        _ => None,
    };
    if let Some(k) = expected_kind {
        if node.canonical_kind != k {
            return false;
        }
    } else if !matches!(node.canonical_kind, CanonicalKind::Statement | CanonicalKind::Other)
    {
        // Loose match for other keywords.
        return false;
    }

    // Match payload sub-patterns against children, skipping the first child
    // if its text equals the keyword.
    let payload_offset = if node
        .children
        .first()
        .map(|c| node_text_eq(c, name.as_bytes()))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };
    let source_args: Vec<&SgNode<'a>> = node.children.iter().skip(payload_offset).collect();
    super::ellipsis::match_argument_list(args, &source_args, bindings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Position, Range};

    fn r(start: usize, end: usize) -> Range {
        Range::new(Position::new(1, start + 1, start), Position::new(1, end + 1, end))
    }

    fn id_node<'a>(text: &'a str, off: usize) -> SgNode<'a> {
        SgNode {
            kind: "identifier",
            canonical_kind: CanonicalKind::Identifier,
            range: r(off, off + text.len()),
            bytes: text.as_bytes(),
            children: Vec::new(),
            field_name: None,
        }
    }

    fn call_node<'a>(callee: SgNode<'a>, args: Vec<SgNode<'a>>, off: usize, end: usize) -> SgNode<'a> {
        let mut children = vec![callee];
        children.extend(args);
        SgNode {
            kind: "call_expression",
            canonical_kind: CanonicalKind::Call,
            range: r(off, end),
            bytes: b"",
            children,
            field_name: None,
        }
    }

    #[test]
    fn identifier_match() {
        let pat = crate::match_::parse_pattern("foo").unwrap();
        let node = id_node("foo", 0);
        let mut b = MetavarBindings::new();
        if let PatternAst::ExprStmt(inner) = pat {
            assert!(unify(&inner, &node, &mut b));
        }
    }

    #[test]
    fn metavar_binds() {
        let pat = PatternAst::Metavar { name: "$X".into() };
        let node = id_node("x", 0);
        let mut b = MetavarBindings::new();
        assert!(unify(&pat, &node, &mut b));
        assert!(b.get("$X").is_some());
    }

    #[test]
    fn metavar_clash() {
        let mut b = MetavarBindings::new();
        b.try_bind("$X", id_node("foo", 0)).unwrap();
        let pat = PatternAst::Metavar { name: "$X".into() };
        // Trying to bind $X again to a different node should fail.
        let bar = id_node("bar", 5);
        assert!(!unify(&pat, &bar, &mut b));
    }

    #[test]
    fn call_match() {
        let foo = id_node("foo", 0);
        let x = id_node("x", 4);
        let call = call_node(foo, vec![x], 0, 6);
        let pat = crate::match_::parse_pattern("foo($X)").unwrap();
        let mut b = MetavarBindings::new();
        if let PatternAst::ExprStmt(inner) = pat {
            assert!(unify(&inner, &call, &mut b));
            assert_eq!(
                b.get("$X").map(|n| n.text().to_string()),
                Some("x".to_string())
            );
        }
    }
}
