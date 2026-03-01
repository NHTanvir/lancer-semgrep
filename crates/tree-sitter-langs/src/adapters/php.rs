//! PHP adapter.
//!
//! `tree-sitter-php` exposes the source-php grammar via `LANGUAGE_PHP`
//! (alongside `LANGUAGE_PHP_ONLY` for snippet/no-tag parsing). We pick the
//! standard mixed-HTML/PHP entry point that matches what regular `.php` files
//! contain.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct PhpAdapter;

impl LangAdapter for PhpAdapter {
    fn language(&self) -> Language {
        Language::Php
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["php", "phtml", "php4", "php5", "php7", "phps"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["php"]
    }
}
