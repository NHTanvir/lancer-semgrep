//! Clojure adapter.
//!
//! Community crate; 0.0.x predates the LANGUAGE convention.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct ClojureAdapter;

impl LangAdapter for ClojureAdapter {
    fn language(&self) -> Language {
        Language::Clojure
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_clojure::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["clj", "cljs", "cljc", "edn"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["clojure", "clj"]
    }
}
