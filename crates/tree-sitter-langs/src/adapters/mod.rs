//! Per-language `LangAdapter` modules, gated by `lang-*` cargo features.
//!
//! Each module exports one or two zero-sized adapter structs (e.g.
//! `PythonAdapter`, or `TypescriptAdapter` + `TsxAdapter` for the dual-parser
//! crates). The corresponding `cfg`-gated arm in `crate::registry::adapter_for`
//! constructs them.

#[cfg(feature = "lang-python")]
pub mod python;

#[cfg(feature = "lang-javascript")]
pub mod javascript;

#[cfg(feature = "lang-typescript")]
pub mod typescript;

#[cfg(feature = "lang-go")]
pub mod go;

#[cfg(feature = "lang-rust")]
pub mod rust;

#[cfg(feature = "lang-java")]
pub mod java;

#[cfg(feature = "lang-ruby")]
pub mod ruby;

#[cfg(feature = "lang-c")]
pub mod c;

#[cfg(feature = "lang-cpp")]
pub mod cpp;

#[cfg(feature = "lang-csharp")]
pub mod csharp;

#[cfg(feature = "lang-php")]
pub mod php;

#[cfg(feature = "lang-kotlin")]
pub mod kotlin;

#[cfg(feature = "lang-swift")]
pub mod swift;

#[cfg(feature = "lang-scala")]
pub mod scala;

#[cfg(feature = "lang-bash")]
pub mod bash;

#[cfg(feature = "lang-lua")]
pub mod lua;

// `r` collides with Rust's raw-string `r#...` macro prefix in many lints and
// reads awkwardly; the file is `r_.rs` to dodge any future fragility.
#[cfg(feature = "lang-r")]
pub mod r_;

#[cfg(feature = "lang-elixir")]
pub mod elixir;

#[cfg(feature = "lang-clojure")]
pub mod clojure;

#[cfg(feature = "lang-ocaml")]
pub mod ocaml;

#[cfg(feature = "lang-yaml")]
pub mod yaml;

#[cfg(feature = "lang-dockerfile")]
pub mod dockerfile;

#[cfg(feature = "lang-hcl")]
pub mod hcl;

#[cfg(feature = "lang-solidity")]
pub mod solidity;

#[cfg(feature = "lang-dart")]
pub mod dart;

#[cfg(feature = "lang-html")]
pub mod html;
