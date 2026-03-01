//! Scan orchestration vocabulary.
//!
//! `enumerate_targets` walks a tree of roots, applies include/exclude globs,
//! honours `.gitignore`/`.semgrepignore`, and emits `TargetFile`s tagged with
//! a `Language`. The actual parsing + matching glue lives in the binary crate
//! (`lancer-semgrep/src/scan/`) because semgrep-core cannot depend on
//! `tree-sitter-langs` (the latter already depends on this crate).
//!
//! See plan.md §"Internal architecture → semgrep-core" and §"How a rule
//! executes" steps 1-2.

pub mod enumerate;
pub mod report;
pub mod target;

pub use enumerate::{detect_lang, enumerate_targets};
pub use report::report_paths_from_enumeration;
pub use target::{EnumerateOpts, TargetFile};
