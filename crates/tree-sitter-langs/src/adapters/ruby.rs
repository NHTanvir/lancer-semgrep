//! Ruby adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct RubyAdapter;

impl LangAdapter for RubyAdapter {
    fn language(&self) -> Language {
        Language::Ruby
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_ruby::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["rb", "rbw", "rake", "gemspec"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["ruby"]
    }
}
