//! Go adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct GoAdapter;

impl LangAdapter for GoAdapter {
    fn language(&self) -> Language {
        Language::Go
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_go::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["go"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
