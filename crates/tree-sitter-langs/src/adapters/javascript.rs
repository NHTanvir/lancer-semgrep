//! JavaScript + JSX adapter.
//!
//! `tree-sitter-javascript` covers both vanilla JS and JSX from one grammar;
//! the two adapter structs differ only in their `Language` / file-extension
//! reporting so target enumeration can route `.jsx` to `Language::Jsx`.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct JavascriptAdapter;

impl LangAdapter for JavascriptAdapter {
    fn language(&self) -> Language {
        Language::Javascript
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["js", "cjs", "mjs"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["node", "nodejs"]
    }
}

pub struct JsxAdapter;

impl LangAdapter for JsxAdapter {
    fn language(&self) -> Language {
        Language::Jsx
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["jsx"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
