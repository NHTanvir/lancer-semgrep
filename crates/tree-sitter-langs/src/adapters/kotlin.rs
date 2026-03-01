//! Kotlin adapter.
//!
//! The community `tree-sitter-kotlin` crate hasn't shipped a `LANGUAGE`
//! constant as of 0.3; use the legacy `language()` function. Upgrade this
//! call site when the crate publishes a 0.22-ABI `LANGUAGE` symbol.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct KotlinAdapter;

impl LangAdapter for KotlinAdapter {
    fn language(&self) -> Language {
        Language::Kotlin
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_kotlin::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["kt", "kts"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
