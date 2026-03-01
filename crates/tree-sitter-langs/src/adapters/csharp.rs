//! C# adapter.
//!
//! Note: crate is named `tree-sitter-c-sharp` (Cargo turns hyphens into
//! underscores in the lib name, so the `use` path is `tree_sitter_c_sharp`).

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct CSharpAdapter;

impl LangAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::Csharp
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_c_sharp::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["cs"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
