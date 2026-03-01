//! Deduplicate raw match candidates by `(node-range, rule-id)`.
//!
//! The matcher visits every subtree of every rule, so the same `(rule, node)`
//! pair can arise via multiple boolean-tree paths (e.g. `pattern-either` with
//! overlapping branches). We collapse those down before emitting `Match`es.

use std::collections::HashSet;

use crate::match_::rule_evaluator::MatchCandidate;
use crate::match_::Match;
use crate::rule::Rule;

/// Collapse a candidate list down to unique `(node-range)` entries within
/// `rule`'s scope. The first surviving candidate wins.
pub fn dedup_for_rule<'a>(
    rule: &Rule,
    candidates: Vec<MatchCandidate<'a>>,
) -> Vec<Match<'a>> {
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut out = Vec::new();
    for c in candidates {
        let key = (c.node.range.start.offset, c.node.range.end.offset);
        if seen.insert(key) {
            out.push(Match {
                rule_id: rule.id.clone(),
                root: c.node,
                bindings: c.bindings,
                explanation: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Language;
    use crate::match_::MetavarBindings;
    use crate::node::{CanonicalKind, Position, Range, SgNode};
    use crate::rule::PatternOp;
    use crate::severity::Severity;

    fn r(start: usize, end: usize) -> Range {
        Range::new(Position::new(1, start + 1, start), Position::new(1, end + 1, end))
    }

    #[test]
    fn dedup_collapses_overlaps() {
        let rule = Rule::search(
            "test.dedup",
            [Language::Python],
            Severity::Info,
            "msg",
            PatternOp::Pattern("foo".into()),
        );
        let n = SgNode::leaf("ident", CanonicalKind::Identifier, r(0, 3), b"foo");
        let candidates = vec![
            MatchCandidate {
                node: n.clone(),
                bindings: MetavarBindings::new(),
            },
            MatchCandidate {
                node: n.clone(),
                bindings: MetavarBindings::new(),
            },
        ];
        let out = dedup_for_rule(&rule, candidates);
        assert_eq!(out.len(), 1);
    }
}
