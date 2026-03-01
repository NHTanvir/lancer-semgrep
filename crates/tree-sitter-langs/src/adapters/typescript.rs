//! TypeScript + TSX adapter.
//!
//! `tree-sitter-typescript` ships two grammar entry points
//! (`LANGUAGE_TYPESCRIPT` for `.ts/.mts/.cts` and `LANGUAGE_TSX` for `.tsx`)
//! because the lexer needs different conflict resolution for JSX content.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

pub struct TypescriptAdapter;

impl LangAdapter for TypescriptAdapter {
    fn language(&self) -> Language {
        Language::Typescript
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ts", "mts", "cts"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        // Deno files sometimes carry a `#!/usr/bin/env deno` shebang.
        &["deno"]
    }
}

pub struct TsxAdapter;

impl LangAdapter for TsxAdapter {
    fn language(&self) -> Language {
        Language::Tsx
    }
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["tsx"]
    }
    fn shebangs(&self) -> &'static [&'static str] {
        &[]
    }
}
