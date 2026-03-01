//! Match-tree explanations: per-finding "which sub-pattern matched which
//! subtree" tree, surfaced when `options.matching_explanations` is true.
//!
//! See plan.md §"CLI flags newly important → `--matching-explanations`".

pub mod match_tree;

pub use match_tree::MatchTreeBuilder;
