//! Rust adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct RustAdapter;

impl LangAdapter for RustAdapter {
    fn language(&self) -> Language {
        Language::Rust
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_rust::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
