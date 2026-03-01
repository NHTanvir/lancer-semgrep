//! Sequence matching with `...` (ellipsis) as a zero-or-more wildcard.
//!
//! Used inside argument lists, statement blocks, and free-form sequences.
//! The core routine `match_seq` is a two-pointer backtracking matcher
//! parallel to a tiny regex matcher where the pattern alphabet is
//! [`PatternAst`] and the only quantifier is `...` (matching zero or more
//! contiguous source items).

use crate::match_::pattern_ast::PatternAst;
use crate::match_::unifier::unify;
use crate::match_::MetavarBindings;
use crate::node::SgNode;

/// Match a pattern argument list (possibly containing [`PatternAst::Ellipsis`])
/// against a slice of actual argument nodes. Ellipsis matches a contiguous
/// zero-or-more run; the matcher backtracks across split points.
pub fn match_argument_list<'a>(
    pattern_args: &[PatternAst],
    source_args: &[&SgNode<'a>],
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    match_seq(pattern_args, source_args, bindings)
}

/// Match the statements inside `source_block.children` against the pattern
/// statement list with ellipsis support.
pub fn match_block_with_ellipsis<'a>(
    pattern_stmts: &[PatternAst],
    source_block: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    let source: Vec<&SgNode<'a>> = source_block.children.iter().collect();
    match_seq(pattern_stmts, &source, bindings)
}

/// Match an arbitrary sequence pattern against `source_node.children` with
/// ellipsis support.
pub fn match_sequence_with_ellipsis<'a>(
    pattern_items: &[PatternAst],
    source_node: &SgNode<'a>,
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    let source: Vec<&SgNode<'a>> = source_node.children.iter().collect();
    match_seq(pattern_items, &source, bindings)
}

fn match_seq<'a>(
    pattern: &[PatternAst],
    source: &[&SgNode<'a>],
    bindings: &mut MetavarBindings<'a>,
) -> bool {
    fn rec<'a>(
        p: &[PatternAst],
        s: &[&SgNode<'a>],
        bindings: &mut MetavarBindings<'a>,
    ) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        let first = &p[0];
        if matches!(first, PatternAst::Ellipsis) {
            // Ellipsis: try matching zero or more source items, then the
            // rest of the pattern.
            for skip in 0..=s.len() {
                let cp = bindings.checkpoint();
                if rec(&p[1..], &s[skip..], bindings) {
                    return true;
                }
                bindings.restore_to(cp);
            }
            return false;
        }
        if s.is_empty() {
            return false;
        }
        let cp = bindings.checkpoint();
        if unify(first, s[0], bindings) && rec(&p[1..], &s[1..], bindings) {
            return true;
        }
        bindings.restore_to(cp);
        false
    }
    rec(pattern, source, bindings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_::pattern_ast::PatternAst;
    use crate::node::{CanonicalKind, Position, Range};

    fn r(start: usize, end: usize) -> Range {
        Range::new(Position::new(1, start + 1, start), Position::new(1, end + 1, end))
    }

    fn id<'a>(text: &'a str, off: usize) -> SgNode<'a> {
        SgNode {
            kind: "identifier",
            canonical_kind: CanonicalKind::Identifier,
            range: r(off, off + text.len()),
            bytes: text.as_bytes(),
            children: Vec::new(),
            field_name: None,
        }
    }

    #[test]
    fn ellipsis_swallows_zero_or_more() {
        let a = id("a", 0);
        let b = id("b", 2);
        let c = id("c", 4);
        let source = vec![&a, &b, &c];
        // Pattern: [..., metavar $X]
        let pattern = vec![
            PatternAst::Ellipsis,
            PatternAst::Metavar { name: "$X".into() },
        ];
        let mut bindings = MetavarBindings::new();
        assert!(match_seq(&pattern, &source, &mut bindings));
        // $X should bind to the last element `c`.
        assert_eq!(bindings.get("$X").map(|n| n.text()), Some("c"));
    }

    #[test]
    fn ellipsis_matches_empty_args() {
        let pattern = vec![PatternAst::Ellipsis];
        let source: Vec<&SgNode<'_>> = vec![];
        let mut b = MetavarBindings::new();
        assert!(match_seq(&pattern, &source, &mut b));
    }
}
