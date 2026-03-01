//! Baseline-diff filtering.
//!
//! `diff_against(<SHA>, repo_root)` shells out to `git diff` to enumerate
//! changed files + hunk line ranges. `finding_in_diff` decides whether a
//! finding falls inside one of those hunks (optionally expanded by
//! `--diff-depth` lines of context). See plan.md §"Baseline diff".

pub mod filter;
pub mod git_diff;

pub use filter::finding_in_diff;
pub use git_diff::{diff_against, BaselineMap, HunkRange};
