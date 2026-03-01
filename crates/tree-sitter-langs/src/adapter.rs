//! `LangAdapter` trait + supporting types.
//!
//! Every per-language module under `crate::adapters::<lang>` implements
//! `LangAdapter`. The trait is intentionally small: it pins down the
//! `Language` discriminant, the `tree_sitter::Language` grammar handle, file
//! detection metadata (extensions / shebangs), and a hook for canonicalising
//! raw grammar node kinds onto `semgrep_core::CanonicalKind` for cross-language
//! pattern matching.
//!
//! Adapters are zero-sized structs — the only state is the grammar handle they
//! return on demand from `ts_language()`. They are `Send + Sync` so the
//! registry can hand back `Box<dyn LangAdapter>` to thread-parallel matchers
//! (Task 6 `rayon` pipeline).

use semgrep_core::{node::CanonicalKind, Language};

/// Output of a successful parse: the `tree_sitter::Tree`, the source bytes the
/// tree borrows from (held alongside the tree to keep node ranges meaningful),
/// and the `Language` it was parsed under.
///
/// Owning the source as a `Vec<u8>` here keeps the parsed tree self-contained;
/// downstream `SgNode` construction in `semgrep-core::parse` will borrow from
/// the same buffer.
pub struct ParsedTree {
    pub tree: tree_sitter::Tree,
    pub source: Vec<u8>,
    pub language: Language,
}

/// Errors produced by the per-language adapters.
///
/// Variants kept small on purpose — `tree-sitter` itself does not return rich
/// error info from `Parser::parse` (it just returns `None` on hard failure),
/// and `set_language` only fails on ABI version mismatch.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// `tree_sitter::Parser::set_language` rejected the grammar (ABI version
    /// mismatch is the usual cause; rebuild against matching `tree-sitter`
    /// version of the grammar crate).
    #[error("could not set tree-sitter language: {0}")]
    SetLanguage(String),
    /// `tree_sitter::Parser::parse` returned `None`. Generally means the
    /// input was too large or contained a timeout/cancellation token.
    #[error("parse failed")]
    ParseFailed,
    /// The requested language is known to `semgrep_core::Language` but the
    /// corresponding `lang-*` cargo feature is disabled in this build.
    #[error("language not enabled (feature flag off): {0:?}")]
    NotEnabled(Language),
}

/// Trait implemented by each per-language adapter.
///
/// `canonical_kind` and `parse` have default implementations that cover the
/// common case (table lookup in `crate::canonical`, vanilla `tree_sitter::
/// Parser` setup) — override per-adapter only if a grammar needs special
/// handling (e.g. TSX vs TS in the same crate, or post-parse fixups).
pub trait LangAdapter: Send + Sync {
    /// The `semgrep_core::Language` discriminant this adapter handles.
    fn language(&self) -> Language;

    /// Concrete `tree_sitter::Language` (grammar handle).
    fn ts_language(&self) -> tree_sitter::Language;

    /// File extensions (no leading dot, lower-case) associated with this
    /// language. Used by `detect.rs`.
    fn file_extensions(&self) -> &'static [&'static str];

    /// Interpreter stems that appear after `#!` (e.g. `"python"`, `"node"`).
    /// Used by `detect.rs` for shebang sniffing.
    fn shebangs(&self) -> &'static [&'static str];

    /// Map a raw tree-sitter node kind (e.g. `"function_definition"`) to a
    /// canonical kind used by the cross-language pattern matcher.
    ///
    /// Default impl dispatches through `crate::canonical::canonicalise` which
    /// holds the per-language lookup tables; adapters can override for
    /// idiosyncratic kinds.
    fn canonical_kind(&self, raw_kind: &str) -> CanonicalKind {
        crate::canonical::canonicalise(self.language(), raw_kind)
    }

    /// Parse `source` with this adapter's grammar.
    ///
    /// Default impl wraps `tree_sitter::Parser::new` + `set_language` + `parse`;
    /// adapters override only for grammars with special parser configuration
    /// (e.g. injection layers, embedded language handoff).
    fn parse(&self, source: &[u8]) -> Result<ParsedTree, AdapterError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&self.ts_language())
            .map_err(|e| AdapterError::SetLanguage(e.to_string()))?;
        let tree = parser
            .parse(source, None)
            .ok_or(AdapterError::ParseFailed)?;
        Ok(ParsedTree {
            tree,
            source: source.to_vec(),
            language: self.language(),
        })
    }
}
