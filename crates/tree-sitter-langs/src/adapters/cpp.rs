//! C++ adapter.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct CppAdapter;

impl LangAdapter for CppAdapter {
    fn language(&self) -> Language {
        Language::Cpp
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_cpp::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "ipp"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
