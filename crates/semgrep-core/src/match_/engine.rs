//! Public entry point: `run_rule_on_node` drives pre-filter → pattern
//! evaluation → dedup for a single search-mode rule.
//!
//! Taint-mode and Join-mode rules are handled in their own crates
//! (`semgrep-taint`, future `semgrep-join`); this engine returns `[]` for
//! them.

use crate::match_::deduplicate::dedup_for_rule;
use crate::match_::pre_filter::pre_filter;
use crate::match_::rule_evaluator::{evaluate_pattern_op, CompiledPatternCache};
use crate::match_::Match;
use crate::node::SgNode;
use crate::rule::Rule;

/// Run a search-mode `rule` against the already-parsed AST `root` and return
/// every dedup'd match. `source` is the raw file bytes (used by the
/// memchr-based pre-filter and any `pattern-regex` operators).
pub fn run_rule_on_node<'a>(
    rule: &Rule,
    source: &[u8],
    root: &SgNode<'a>,
) -> Vec<Match<'a>> {
    let Some(op) = &rule.pattern else {
        return Vec::new();
    };

    let compiled = CompiledPatternCache::new();
    let required = compiled.required_for(op);
    if !pre_filter(source, &required) {
        return Vec::new();
    }

    let candidates = evaluate_pattern_op(op, root, &compiled);
    dedup_for_rule(rule, candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Language;
    use crate::node::{CanonicalKind, Position, Range, SgNode};
    use crate::rule::PatternOp;
    use crate::severity::Severity;

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

    fn call<'a>(callee: SgNode<'a>, args: Vec<SgNode<'a>>, off: usize, end: usize) -> SgNode<'a> {
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
    fn matches_simple_call() {
        let foo = id("foo", 0);
        let x = id("x", 4);
        let call_node = call(foo, vec![x], 0, 6);
        let rule = Rule::search(
            "test.call",
            [Language::Python],
            Severity::Warning,
            "matched",
            PatternOp::Pattern("foo($X)".into()),
        );
        let source = b"foo(x)";
        let matches = run_rule_on_node(&rule, source, &call_node);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].bindings.get("$X").map(|n| n.text()),
            Some("x")
        );
    }

    #[test]
    fn pre_filter_short_circuits() {
        let foo = id("foo", 0);
        let x = id("x", 4);
        let call_node = call(foo, vec![x], 0, 6);
        let rule = Rule::search(
            "test.miss",
            [Language::Python],
            Severity::Warning,
            "matched",
            PatternOp::Pattern("subprocess.call($X)".into()),
        );
        let source = b"nothing relevant";
        let matches = run_rule_on_node(&rule, source, &call_node);
        assert_eq!(matches.len(), 0);
    }
}
