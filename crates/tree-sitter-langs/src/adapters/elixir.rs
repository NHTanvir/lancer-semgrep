//! Elixir adapter.
//!
//! Community crate; uses legacy `language()` function.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct ElixirAdapter;

impl LangAdapter for ElixirAdapter {
    fn language(&self) -> Language {
        Language::Elixir
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_elixir::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ex", "exs"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["elixir"]
    }
}
