//! Pro-mode inter-procedural taint stub.
//!
//! The real engine builds a per-function `FunctionSummary` (which inputs
//! flow to which outputs, which inputs are sanitized), then runs a
//! fixed-point over the call graph. We expose the *shape* here so the
//! rest of the workspace can already depend on the type vocabulary, and
//! parallel summary compilation via `rayon::par_iter` per plan.md
//! §"Research note → Interfile engine redesigned (Apr 2026)".
//!
//! The body is a placeholder until Task 8 (interprocedural pass) wires
//! the real algorithm.

use rayon::prelude::*;
use semgrep_core::Rule;
use std::collections::BTreeMap;

/// Symbolic description of a function's input-to-output taint behaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionSummary {
    pub function_name: String,
    /// Map: parameter name → list of return / mutated-global names that
    /// become tainted when the parameter is tainted.
    pub input_to_output: BTreeMap<String, Vec<String>>,
    /// Parameter names whose taint is consumed by a sanitizer inside the
    /// function body.
    pub sanitised_inputs: Vec<String>,
    /// Captured variables that flow into inner-function closures
    /// (Pro feature, Feb 2026: "Taint through nested functions improved
    /// — closure capture now tracks taint through inner functions").
    pub closure_captures: Vec<String>,
}

/// Scala-specific desugaring marker for `for ... yield ...` blocks. The
/// Scala for-yield desugars to `flatMap`/`map` chains that must propagate
/// taint correctly; without explicit modelling the upstream engine
/// previously dropped taint at the block boundary.
///
/// Per plan §"Research note 2026-05-31 → Scala for-yield taint (Feb 2026)".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScalaForYieldDesugaring {
    /// Synthetic continuation-style identifier introduced by the desugarer.
    pub bound_var: String,
    /// Original outer iterable expression text.
    pub iterable_text: String,
}

/// Engine-wide summary table. Keys are function names; values are the
/// summaries built by [`build_summaries`].
#[derive(Debug, Clone, Default)]
pub struct SummaryTable {
    pub summaries: BTreeMap<String, FunctionSummary>,
}

impl SummaryTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, name: String, s: FunctionSummary) {
        self.summaries.insert(name, s);
    }
}

/// Build summaries from a slice of rules. Parallel via `rayon::par_iter`.
///
/// This is a Pro-mode stub: today it iterates the rules in parallel but
/// produces an empty `SummaryTable`. The structure is here so the public
/// API doesn't move when the algorithm is filled in.
pub fn build_summaries(rules: &[Rule]) -> SummaryTable {
    // Run the parallel pass for its side effect (warming the rayon
    // thread pool + exercising the path).
    let _processed: usize = rules
        .par_iter()
        .map(|_r| {
            // Real implementation: build a CFG per function, run intra-
            // procedural taint with abstract parameter values, then read
            // off the summary.
            0usize
        })
        .sum();
    SummaryTable::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::{Language, PatternOp, Rule, Severity};

    #[test]
    fn empty_rules_yields_empty_table() {
        let table = build_summaries(&[]);
        assert!(table.summaries.is_empty());
    }

    #[test]
    fn handles_one_rule_without_panic() {
        let r = Rule::search(
            "x",
            [Language::Python],
            Severity::Warning,
            "m",
            PatternOp::Pattern("foo($X)".into()),
        );
        let table = build_summaries(std::slice::from_ref(&r));
        assert!(table.summaries.is_empty());
    }

    #[test]
    fn summary_round_trip() {
        let mut t = SummaryTable::new();
        t.insert(
            "foo".into(),
            FunctionSummary {
                function_name: "foo".into(),
                input_to_output: BTreeMap::new(),
                sanitised_inputs: vec!["x".into()],
            },
        );
        assert_eq!(t.summaries.len(), 1);
        assert_eq!(t.summaries["foo"].sanitised_inputs, vec!["x".to_string()]);
    }
}
