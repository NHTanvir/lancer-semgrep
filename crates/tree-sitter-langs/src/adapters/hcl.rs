//! HCL / Terraform adapter.
//!
//! `tree-sitter-hcl` 1.x covers Terraform's HCL syntax. Pre-LANGUAGE.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct HclAdapter;

impl LangAdapter for HclAdapter {
    fn language(&self) -> Language {
        Language::Terraform
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_hcl::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["tf", "tfvars", "hcl"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
