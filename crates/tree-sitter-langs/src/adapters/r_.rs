//! R adapter.
//!
//! File is named `r_.rs` rather than `r.rs` to keep the path clear of any
//! literal `r"..."` raw-string-prefix parsing fragility in macros and tooling.
//!
//! `tree-sitter-r` 1.x exposes `LANGUAGE`.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct RAdapter;

impl LangAdapter for RAdapter {
    fn language(&self) -> Language {
        Language::R
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_r::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["r"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["rscript", "r"]
    }
}
