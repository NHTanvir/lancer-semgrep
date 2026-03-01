//! Scala adapter.
//!
//! Plan calls out a Scala tree-sitter rewrite landing in Apr 2026; we follow
//! the upstream `tree-sitter-scala` 0.22.x crate, which exposes `LANGUAGE`.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct ScalaAdapter;

impl LangAdapter for ScalaAdapter {
    fn language(&self) -> Language {
        Language::Scala
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_scala::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["scala", "sc"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["scala"]
    }
}
