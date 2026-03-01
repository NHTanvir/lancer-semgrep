//! Java adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct JavaAdapter;

impl LangAdapter for JavaAdapter {
    fn language(&self) -> Language {
        Language::Java
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_java::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["java"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
