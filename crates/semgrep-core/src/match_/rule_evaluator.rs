//! Pattern-operator dispatcher: walks a [`PatternOp`] boolean tree and
//! computes the set of source-node candidates satisfying it.
//!
//! Boolean semantics follow Semgrep:
//! - `pattern` / `patterns` / `pattern-either` are positive contributions.
//! - `pattern-not` *removes* candidates that ALSO match its inner pattern at
//!   the same node.
//! - `pattern-inside` requires the candidate to be lexically contained inside
//!   a match of its inner pattern.
//! - `pattern-not-inside` requires the candidate to NOT be inside any match
//!   of its inner pattern.
//! - `metavariable-regex`, `metavariable-comparison`, `metavariable-pattern`,
//!   `metavariable-type` are filters that act on a candidate's bindings.
//! - `pattern-regex` / `pattern-not-regex` are byte-level regex filters.
//!
//! The pre-filter (memchr-based) is applied *outside* this module by
//! [`super::engine::run_rule_on_node`].

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;

use crate::error::Result;
use crate::match_::pattern_ast::PatternAst;
use crate::match_::pattern_parser::parse_pattern;
use crate::match_::unifier::unify;
use crate::match_::MetavarBindings;
use crate::node::SgNode;
use crate::rule::pattern::{MetavariablePatternBody, MetavariableTypeBody};
use crate::rule::PatternOp;

/// One candidate emitted by [`evaluate_pattern_op`]. Aggregated and filtered
/// through `pattern-not` / `pattern-inside` / metavariable-* constraints in
/// `evaluate_conjunction` and `evaluate_pattern_op`.
#[derive(Debug, Clone)]
pub struct MatchCandidate<'a> {
    /// Root of the matched subtree.
    pub node: SgNode<'a>,
    /// Bindings made during the unification that produced this candidate.
    pub bindings: MetavarBindings<'a>,
}

/// Memoising parse cache: each distinct `pattern:` string is parsed once
/// during a scan and re-used. Wrapped in `Arc` for cheap sharing across
/// recursion stacks.
#[derive(Default)]
pub struct CompiledPatternCache {
    inner: std::sync::Mutex<HashMap<String, Arc<PatternAst>>>,
}

impl CompiledPatternCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a parsed AST for `src`, parsing+caching on first request.
    pub fn get(&self, src: &str) -> Result<Arc<PatternAst>> {
        if let Some(hit) = self.inner.lock().unwrap().get(src).cloned() {
            return Ok(hit);
        }
        let ast = Arc::new(parse_pattern(src)?);
        self.inner
            .lock()
            .unwrap()
            .insert(src.to_string(), ast.clone());
        Ok(ast)
    }

    /// Collect every distinct required string across all `Pattern` leaves
    /// in the given op tree. Used by the engine pre-filter.
    pub fn required_for(&self, op: &PatternOp) -> Vec<String> {
        let mut acc = Vec::new();
        self.collect_required(op, &mut acc);
        acc.sort();
        acc.dedup();
        acc
    }

    fn collect_required(&self, op: &PatternOp, acc: &mut Vec<String>) {
        match op {
            PatternOp::Pattern(s) => {
                if let Ok(ast) = self.get(s) {
                    acc.extend(super::pre_filter::required_strings(&ast));
                }
            }
            PatternOp::Patterns(v) | PatternOp::PatternEither(v) => {
                for o in v {
                    self.collect_required(o, acc);
                }
            }
            PatternOp::PatternInside(inner) => self.collect_required(inner, acc),
            // `pattern-not` should NOT contribute pre-filter terms because
            // a file is allowed to lack the negated string and still match.
            PatternOp::PatternNot(_)
            | PatternOp::PatternNotInside(_)
            | PatternOp::PatternRegex(_)
            | PatternOp::PatternNotRegex(_)
            | PatternOp::MetavariableRegex { .. }
            | PatternOp::MetavariableComparison(_)
            | PatternOp::MetavariablePattern(_)
            | PatternOp::MetavariableType(_)
            | PatternOp::ProjectDependsOn(_) => {}
        }
    }
}

/// Entry point: produce the set of candidates satisfying `op` against
/// `root`. Compound operators delegate to `evaluate_conjunction` /
/// `evaluate_disjunction`.
pub fn evaluate_pattern_op<'a>(
    op: &PatternOp,
    root: &SgNode<'a>,
    compiled: &CompiledPatternCache,
) -> Vec<MatchCandidate<'a>> {
    match op {
        PatternOp::Pattern(s) => match compiled.get(s) {
            Ok(ast) => find_all(&ast, root),
            Err(_) => Vec::new(),
        },
        PatternOp::Patterns(list) => evaluate_conjunction(list, root, compiled),
        PatternOp::PatternEither(list) => list
            .iter()
            .flat_map(|sub| evaluate_pattern_op(sub, root, compiled))
            .collect(),
        // Standalone negative / regex ops at the top level have no positive
        // contribution; they're only meaningful inside a `patterns:` block.
        PatternOp::PatternNot(_)
        | PatternOp::PatternInside(_)
        | PatternOp::PatternNotInside(_) => Vec::new(),
        PatternOp::PatternRegex(rx) => find_all_regex(rx, root),
        PatternOp::PatternNotRegex(_) => Vec::new(),
        PatternOp::MetavariableRegex { .. }
        | PatternOp::MetavariableComparison(_)
        | PatternOp::MetavariablePattern(_)
        | PatternOp::MetavariableType(_)
        // Supply-Chain dependency constraint — evaluated against the project's
        // manifest in the supply-chain orchestrator, not against AST candidates.
        | PatternOp::ProjectDependsOn(_) => Vec::new(),
    }
}

/// Walk every subtree of `root`, attempt unification, return the set of
/// successful matches (each with its own bindings).
fn find_all<'a>(
    ast: &PatternAst,
    root: &SgNode<'a>,
) -> Vec<MatchCandidate<'a>> {
    let mut out = Vec::new();
    walk(root, |n| {
        let mut bindings = MetavarBindings::new();
        if unify(ast, n, &mut bindings) {
            out.push(MatchCandidate {
                node: n.clone(),
                bindings,
            });
        }
    });
    out
}

/// Run a regex over `root.bytes` (whole source) and emit one candidate per
/// match. Range information for the candidate currently mirrors the whole
/// `root` because we don't yet have offset mapping; integration with the
/// real parser tree in Task 9 will refine this.
fn find_all_regex<'a>(rx: &str, root: &SgNode<'a>) -> Vec<MatchCandidate<'a>> {
    let re = match Regex::new(rx) {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };
    let text = match std::str::from_utf8(root.bytes) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    if re.is_match(text) {
        vec![MatchCandidate {
            node: root.clone(),
            bindings: MetavarBindings::new(),
        }]
    } else {
        Vec::new()
    }
}

/// Recursively visit `root` and every descendant. `visit` is called on the
/// root first, then on each child in pre-order.
fn walk<'a, F>(node: &SgNode<'a>, mut visit: F)
where
    F: FnMut(&SgNode<'a>),
{
    fn rec<'a, F: FnMut(&SgNode<'a>)>(n: &SgNode<'a>, visit: &mut F) {
        visit(n);
        for c in &n.children {
            rec(c, visit);
        }
    }
    rec(node, &mut visit);
}

/// `patterns:` AND-block. Combine positive sub-results, then apply
/// `pattern-not` / `pattern-inside` / `pattern-not-inside` / metavariable-*
/// constraints.
fn evaluate_conjunction<'a>(
    list: &[PatternOp],
    root: &SgNode<'a>,
    compiled: &CompiledPatternCache,
) -> Vec<MatchCandidate<'a>> {
    // Partition the list into positive vs. constraint ops.
    let mut positives: Vec<&PatternOp> = Vec::new();
    let mut negs: Vec<&PatternOp> = Vec::new();
    let mut insides: Vec<&PatternOp> = Vec::new();
    let mut not_insides: Vec<&PatternOp> = Vec::new();
    let mut metavar_regexes: Vec<(&str, &str)> = Vec::new();
    let mut metavar_comparisons: Vec<&crate::rule::MetavariableComparison> = Vec::new();
    let mut metavar_patterns: Vec<&MetavariablePatternBody> = Vec::new();
    let mut metavar_types: Vec<&MetavariableTypeBody> = Vec::new();
    let mut pattern_regexes: Vec<&str> = Vec::new();
    let mut pattern_not_regexes: Vec<&str> = Vec::new();

    for op in list {
        match op {
            PatternOp::PatternNot(inner) => negs.push(inner),
            PatternOp::PatternInside(inner) => insides.push(inner),
            PatternOp::PatternNotInside(inner) => not_insides.push(inner),
            PatternOp::MetavariableRegex { metavariable, regex } => {
                metavar_regexes.push((metavariable, regex))
            }
            PatternOp::MetavariableComparison(c) => metavar_comparisons.push(c),
            PatternOp::MetavariablePattern(p) => metavar_patterns.push(p),
            PatternOp::MetavariableType(t) => metavar_types.push(t),
            // Supply-Chain dep-on constraints are gated outside the per-AST
            // matcher; here we drop them (the supply-chain orchestrator
            // evaluates them against project manifests).
            PatternOp::ProjectDependsOn(_) => {}
            PatternOp::PatternRegex(rx) => pattern_regexes.push(rx),
            PatternOp::PatternNotRegex(rx) => pattern_not_regexes.push(rx),
            other => positives.push(other),
        }
    }

    // 1. Build initial candidate set as the *intersection* of all positives
    //    over the same node, joining metavar bindings.
    let mut candidates: Vec<MatchCandidate<'a>> = if positives.is_empty() {
        // No positives: every subtree is a degenerate candidate. Limit to
        // root itself so we don't explode.
        vec![MatchCandidate {
            node: root.clone(),
            bindings: MetavarBindings::new(),
        }]
    } else {
        let mut accum = evaluate_pattern_op(positives[0], root, compiled);
        for op in &positives[1..] {
            let next = evaluate_pattern_op(op, root, compiled);
            accum = intersect_candidates(accum, next);
        }
        accum
    };

    // 2. `pattern-regex` — keep candidates iff the regex matches the source
    //    bytes anywhere.
    for rx in &pattern_regexes {
        if !regex_matches_root(rx, root) {
            return Vec::new();
        }
    }
    // 3. `pattern-not-regex` — drop everything if regex matches.
    for rx in &pattern_not_regexes {
        if regex_matches_root(rx, root) {
            return Vec::new();
        }
    }

    // 4. `pattern-inside` — every candidate must be contained in at least one
    //    match of each inside-op.
    for inner in &insides {
        let inside_matches = evaluate_pattern_op(inner, root, compiled);
        candidates.retain(|c| {
            inside_matches.iter().any(|im| im.node.range.contains(&c.node.range))
        });
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    // 5. `pattern-not-inside` — drop candidates contained in any match of
    //    each not-inside-op.
    for inner in &not_insides {
        let inside_matches = evaluate_pattern_op(inner, root, compiled);
        candidates.retain(|c| {
            !inside_matches
                .iter()
                .any(|im| im.node.range.contains(&c.node.range))
        });
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    // 6. `pattern-not` — drop candidates whose node also matches `inner`.
    for inner in &negs {
        let bad = evaluate_pattern_op(inner, root, compiled);
        candidates.retain(|c| {
            !bad.iter().any(|b| b.node.range == c.node.range)
        });
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    // 7. `metavariable-regex` — bound metavar's source text must match regex.
    for (metavar, regex) in &metavar_regexes {
        let re = match Regex::new(regex) {
            Ok(re) => re,
            Err(_) => return Vec::new(),
        };
        candidates.retain(|c| {
            c.bindings
                .get(metavar)
                .map(|n| re.is_match(n.text()))
                .unwrap_or(false)
        });
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    // 8. `metavariable-comparison` — evaluate DSL against bindings.
    for comp in &metavar_comparisons {
        let parsed = match super::metavar_comp_eval::parse(&comp.comparison) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        candidates.retain(|c| {
            super::metavar_comp_eval::evaluate(
                &parsed,
                &c.bindings,
                comp.base,
                comp.strip,
            )
            .unwrap_or(false)
        });
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    // 9. `metavariable-pattern` — re-run a pattern over the metavariable's
    //    bound subtree.
    for body in &metavar_patterns {
        let metavar = &body.metavariable;
        let inner_op = body.pattern.as_ref();
        candidates.retain(|c| {
            match c.bindings.get(metavar) {
                Some(n) => !evaluate_pattern_op(inner_op, n, compiled).is_empty(),
                None => false,
            }
        });
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    // 10. `metavariable-type` — Pro feature. Without a real type-checker we
    //     soft-pass: if a metavariable is bound, accept; otherwise drop.
    for body in &metavar_types {
        let metavar = &body.metavariable;
        candidates.retain(|c| c.bindings.get(metavar).is_some());
        if candidates.is_empty() {
            return Vec::new();
        }
    }

    candidates
}

fn regex_matches_root<'a>(rx: &str, root: &SgNode<'a>) -> bool {
    let re = match Regex::new(rx) {
        Ok(re) => re,
        Err(_) => return false,
    };
    let text = std::str::from_utf8(root.bytes).unwrap_or("");
    re.is_match(text)
}

/// Intersect two candidate lists by node range, joining the bindings of each
/// pair. Candidates whose bindings conflict are dropped.
fn intersect_candidates<'a>(
    left: Vec<MatchCandidate<'a>>,
    right: Vec<MatchCandidate<'a>>,
) -> Vec<MatchCandidate<'a>> {
    let mut out = Vec::new();
    for l in &left {
        for r in &right {
            if l.node.range != r.node.range {
                continue;
            }
            if let Some(joined) = join_bindings(&l.bindings, &r.bindings) {
                out.push(MatchCandidate {
                    node: l.node.clone(),
                    bindings: joined,
                });
            }
        }
    }
    out
}

fn join_bindings<'a>(
    a: &MetavarBindings<'a>,
    b: &MetavarBindings<'a>,
) -> Option<MetavarBindings<'a>> {
    let mut out = a.clone();
    for (name, node) in b.iter() {
        if let Some(existing) = out.get(name) {
            if !existing.structurally_equal(node) {
                return None;
            }
        } else if out.try_bind(name, node.clone()).is_err() {
            return None;
        }
    }
    Some(out)
}

