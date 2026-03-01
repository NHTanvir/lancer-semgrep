//! tree-sitter-langs — bundled language grammar adapters.
//!
//! See plan.md §"Internal architecture → tree-sitter-langs" and
//! §"Engineering hard parts → Tree-sitter parsing across 30+ languages".
//!
//! Public surface:
//! - [`LangAdapter`] trait — every per-language adapter implements this.
//! - [`adapter_for`] / [`enabled_languages`] — registry helpers.
//! - [`detect_language`] / [`detect_language_with_shebang`] — path-based
//!   language detection.
//! - [`Language`] / [`CanonicalKind`] — re-exports from `semgrep-core` so
//!   downstream crates only have to depend on `tree-sitter-langs` for the
//!   language-handling vocabulary.
//!
//! Each `lang-*` Cargo feature gates one tree-sitter grammar crate. The
//! `default` feature enables the six GA-tier languages (Python, JS, TS, Go,
//! Rust, Java); `all-langs` enables every grammar shipped here.

pub mod adapter;
pub mod adapters;
pub mod canonical;
pub mod detect;
pub mod registry;

pub use adapter::{AdapterError, LangAdapter, ParsedTree};
pub use canonical::canonicalise;
pub use detect::{detect_language, detect_language_with_shebang};
pub use registry::{adapter_for, enabled_languages};

// Vocabulary re-exports so callers can `use tree_sitter_langs::{Language,
// CanonicalKind};` without dragging in `semgrep-core` directly.
pub use semgrep_core::node::CanonicalKind;
pub use semgrep_core::Language;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
