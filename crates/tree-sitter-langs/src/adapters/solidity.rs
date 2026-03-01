//! Solidity adapter.
//!
//! Community crate; 1.x line. Pre-LANGUAGE.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct SolidityAdapter;

impl LangAdapter for SolidityAdapter {
    fn language(&self) -> Language {
        Language::Solidity
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_solidity::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["sol"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
