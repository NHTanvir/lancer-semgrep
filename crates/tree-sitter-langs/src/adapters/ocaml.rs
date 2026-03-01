//! OCaml adapter.
//!
//! `tree-sitter-ocaml` ships several entry points (`LANGUAGE_OCAML` for `.ml`,
//! `LANGUAGE_OCAML_INTERFACE` for `.mli`, `LANGUAGE_OCAML_TYPE` for type
//! expressions). For our purposes we want the implementation parser.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct OcamlAdapter;

impl LangAdapter for OcamlAdapter {
    fn language(&self) -> Language {
        Language::Ocaml
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_ocaml::LANGUAGE_OCAML.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ml", "mli"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &["ocaml", "ocamlrun"]
    }
}
