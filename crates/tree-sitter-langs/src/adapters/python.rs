//! Python adapter.
//!
//! `tree-sitter-python` ships the 0.22 `LANGUAGE` constant since the 0.21 →
//! 0.22 ABI bump. We use `.into()` to upcast `LanguageFn` → `Language`.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct PythonAdapter;

impl LangAdapter for PythonAdapter {
    fn language(&self) -> Language {
        Language::Python
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["py", "pyi"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["python", "python2", "python3"]
    }
}
