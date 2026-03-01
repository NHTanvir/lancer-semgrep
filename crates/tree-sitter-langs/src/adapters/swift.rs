//! Swift adapter.
//!
//! Community `tree-sitter-swift` predates the 0.22 `LANGUAGE` convention; use
//! the legacy function-style API.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct SwiftAdapter;

impl LangAdapter for SwiftAdapter {
    fn language(&self) -> Language {
        Language::Swift
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_swift::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["swift"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["swift"]
    }
}
