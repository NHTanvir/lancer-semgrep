//! HTML adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct HtmlAdapter;

impl LangAdapter for HtmlAdapter {
    fn language(&self) -> Language {
        Language::Html
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_html::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["html", "htm", "xhtml"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
