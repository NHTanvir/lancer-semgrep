//! Dart adapter.
//!
//! Community crate at 0.0.x; pre-LANGUAGE.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct DartAdapter;

impl LangAdapter for DartAdapter {
    fn language(&self) -> Language {
        Language::Dart
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_dart::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["dart"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
