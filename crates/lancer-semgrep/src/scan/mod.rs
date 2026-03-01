//! Scan orchestration for the lancer-semgrep binary.
//!
//! This is the bridge layer that crosses the
//! `semgrep-core` ⇕ `tree-sitter-langs` boundary. semgrep-core can't
//! Cargo-depend on tree-sitter-langs (the latter already depends on the
//! former for the `Language` enum + `CanonicalKind`); orchestration that
//! actually parses files therefore lives here, in the binary, which can
//! depend on both crates without cycles.
//!
//! See plan.md §"Internal architecture → semgrep-core" and §"Engineering
//! hard parts → Performance".

pub mod parallel;
pub mod parse;
pub mod pre_filter;
pub mod run;

pub use parse::{build_sgnode, parse_file, ParseError, ParsedDoc};
pub use run::{run_scan, ScanOpts};
