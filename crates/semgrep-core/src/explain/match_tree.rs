//! Build a [`MatchExplanationNode`] tree describing which sub-pattern of a
//! rule matched which subtree. This is the structure the JSON / text
//! emitters render under `extra.matching_explanations`.
//!
//! The builder is *structural*: each [`PatternOp`] variant maps onto one
//! [`MatchExplanationNode`] with a stable `op` label. Negations
//! (`pattern-not`, `pattern-not-inside`) flip the child's `matched` flag so
//! the rendered explanation reads "we wanted a match here and got one" /
//! "we wanted no match and got none".

use crate::match_::MatchExplanationNode;
use crate::PatternOp;

/// Pluggable builder. The matcher accumulates the root via
/// [`set_root`](Self::set_root) and the caller pulls it via
/// [`build`](Self::build).
#[derive(Debug, Clone, Default)]
pub struct MatchTreeBuilder {
    root: Option<MatchExplanationNode>,
}

impl MatchTreeBuilder {
    /// Empty builder; no root attached yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Recursively render `op` into a [`MatchExplanationNode`] tree, threading
    /// the `matched` flag down through negations as appropriate.
    pub fn from_pattern_op(op: &PatternOp, matched: bool) -> MatchExplanationNode {
        match op {
            PatternOp::Pattern(_) => MatchExplanationNode {
                op: "pattern".into(),
                matched,
                children: Vec::new(),
            },
            PatternOp::Patterns(list) => MatchExplanationNode {
                op: "patterns".into(),
                matched,
                children: list
                    .iter()
                    .map(|c| Self::from_pattern_op(c, matched))
                    .collect(),
            },
            PatternOp::PatternEither(list) => MatchExplanationNode {
                op: "pattern-either".into(),
                matched,
                children: list
                    .iter()
                    .map(|c| Self::from_pattern_op(c, matched))
                    .collect(),
            },
            PatternOp::PatternNot(inner) => MatchExplanationNode {
                op: "pattern-not".into(),
                matched,
                children: vec![Self::from_pattern_op(inner, !matched)],
            },
            PatternOp::PatternInside(inner) => MatchExplanationNode {
                op: "pattern-inside".into(),
                matched,
                children: vec![Self::from_pattern_op(inner, matched)],
            },
            PatternOp::PatternNotInside(inner) => MatchExplanationNode {
                op: "pattern-not-inside".into(),
                matched,
                children: vec![Self::from_pattern_op(inner, !matched)],
            },
            PatternOp::PatternRegex(_) => MatchExplanationNode {
                op: "pattern-regex".into(),
                matched,
                children: Vec::new(),
            },
            PatternOp::PatternNotRegex(_) => MatchExplanationNode {
                op: "pattern-not-regex".into(),
                matched,
                children: Vec::new(),
            },
            PatternOp::MetavariableRegex { metavariable, .. } => MatchExplanationNode {
                op: format!("metavariable-regex({metavariable})"),
                matched,
                children: Vec::new(),
            },
            PatternOp::MetavariableComparison(_) => MatchExplanationNode {
                op: "metavariable-comparison".into(),
                matched,
                children: Vec::new(),
            },
            PatternOp::MetavariablePattern(body) => MatchExplanationNode {
                op: format!("metavariable-pattern({})", body.metavariable),
                matched,
                children: vec![Self::from_pattern_op(&body.pattern, matched)],
            },
            PatternOp::MetavariableType(body) => MatchExplanationNode {
                op: format!("metavariable-type({})", body.metavariable),
                matched,
                children: Vec::new(),
            },
            PatternOp::ProjectDependsOn(body) => MatchExplanationNode {
                op: format!(
                    "r2c-internal-project-depends-on({} entries)",
                    body.depends_on_either.len()
                ),
                matched,
                children: Vec::new(),
            },
        }
    }

    /// Attach `node` as the root of the explanation.
    pub fn set_root(&mut self, node: MatchExplanationNode) {
        self.root = Some(node);
    }

    /// Pull the accumulated root, consuming the builder.
    pub fn build(self) -> Option<MatchExplanationNode> {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::MetavariablePatternBody;

    #[test]
    fn pattern_either_includes_each_child() {
        let op = PatternOp::PatternEither(vec![
            PatternOp::Pattern("foo()".into()),
            PatternOp::Pattern("bar()".into()),
        ]);
        let node = MatchTreeBuilder::from_pattern_op(&op, true);
        assert_eq!(node.op, "pattern-either");
        assert_eq!(node.children.len(), 2);
    }

    #[test]
    fn pattern_not_flips_child_match() {
        let op = PatternOp::PatternNot(Box::new(PatternOp::Pattern("foo()".into())));
        let node = MatchTreeBuilder::from_pattern_op(&op, true);
        assert!(!node.children[0].matched);
    }

    #[test]
    fn pattern_not_inside_flips_child_match() {
        let op = PatternOp::PatternNotInside(Box::new(PatternOp::Pattern("foo()".into())));
        let node = MatchTreeBuilder::from_pattern_op(&op, true);
        assert!(!node.children[0].matched);
    }

    #[test]
    fn metavariable_regex_carries_name() {
        let op = PatternOp::MetavariableRegex {
            metavariable: "$X".into(),
            regex: "^foo".into(),
        };
        let node = MatchTreeBuilder::from_pattern_op(&op, true);
        assert_eq!(node.op, "metavariable-regex($X)");
        assert!(node.children.is_empty());
    }

    #[test]
    fn metavariable_pattern_recurses_into_body() {
        let body = MetavariablePatternBody {
            metavariable: "$X".into(),
            pattern: Box::new(PatternOp::Pattern("inner($Y)".into())),
            language: None,
        };
        let op = PatternOp::MetavariablePattern(body);
        let node = MatchTreeBuilder::from_pattern_op(&op, true);
        assert_eq!(node.op, "metavariable-pattern($X)");
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].op, "pattern");
    }

    #[test]
    fn builder_round_trips_root() {
        let op = PatternOp::Pattern("foo()".into());
        let n = MatchTreeBuilder::from_pattern_op(&op, true);
        let mut b = MatchTreeBuilder::new();
        b.set_root(n);
        let root = b.build().expect("root attached");
        assert_eq!(root.op, "pattern");
    }
}
