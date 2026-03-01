//! Dockerfile adapter.
//!
//! `tree-sitter-dockerfile` is community-maintained on 0.2.x; pre-LANGUAGE
//! constant.
// fallback to function-style API; upgrade if crate ships LANGUAGE constant

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct DockerfileAdapter;

impl LangAdapter for DockerfileAdapter {
    fn language(&self) -> Language {
        Language::Dockerfile
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_dockerfile::language()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // Dockerfile detection is by basename (`Dockerfile`, `Dockerfile.prod`)
        // rather than extension. `.dockerfile` is still recognised for
        // completeness.
        &["dockerfile"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
