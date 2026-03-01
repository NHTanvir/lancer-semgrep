//! YAML adapter.
//!
//! Community `tree-sitter-yaml` crate; sits on the older API.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct YamlAdapter;

impl LangAdapter for YamlAdapter {
    fn language(&self) -> Language {
        Language::Yaml
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_yaml::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["yaml", "yml"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
