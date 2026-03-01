//! C adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct CAdapter;

impl LangAdapter for CAdapter {
    fn language(&self) -> Language {
        Language::C
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_c::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
