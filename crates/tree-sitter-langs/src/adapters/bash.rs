//! Bash adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct BashAdapter;

impl LangAdapter for BashAdapter {
    fn language(&self) -> Language {
        Language::Bash
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_bash::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["sh", "bash", "zsh", "ksh"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["bash", "sh", "zsh", "ksh", "dash"]
    }
}
