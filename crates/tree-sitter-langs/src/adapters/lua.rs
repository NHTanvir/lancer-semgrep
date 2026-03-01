//! Lua adapter.
//!
//! Community `tree-sitter-lua` 0.2.x exposes `LANGUAGE`. If you bump to an
//! older version that still uses `language()`, swap the implementation.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct LuaAdapter;

impl LangAdapter for LuaAdapter {
    fn language(&self) -> Language {
        Language::Lua
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_lua::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["lua"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["lua"]
    }
}
