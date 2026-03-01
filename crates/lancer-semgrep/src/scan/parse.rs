//! Parse a single file into a `ParsedDoc` (owns source bytes + tree-sitter
//! tree) and project the tree into the canonicalised `SgNode<'a>` tree the
//! matcher operates on.
//!
//! ## Node-kind interning
//!
//! `SgNode<'a>` carries the raw tree-sitter `kind: &'static str` field
//! defined in semgrep-core. tree-sitter exposes `Node::kind()` as `&str`
//! (lifetime tied to the grammar), but `SgNode` requires `'static`. We
//! intern each distinct kind exactly once per process so we leak at most
//! O(# grammar node kinds) strings rather than O(# AST nodes).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use semgrep_core::node::{Position, Range, SgNode};
use semgrep_core::Language;
use tree_sitter::Tree;

/// Parsed-document wrapper: owns source bytes + the tree-sitter `Tree`.
///
/// Stored under an `Arc` in `TargetCache<ParsedDoc>` so multiple rules can
/// reuse the same parse on the same file content.
pub struct ParsedDoc {
    pub language: Language,
    pub source: Vec<u8>,
    pub tree: Tree,
}

/// Errors from `parse_file`. The matcher's own errors (parse-error, schema,
/// etc.) live in `semgrep_core::SemgrepError`.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unsupported language: {0:?} (feature flag off?)")]
    UnsupportedLanguage(Language),
    #[error("adapter error: {0}")]
    Adapter(tree_sitter_langs::AdapterError),
}

/// Parse `content` as `language`, returning an owned `ParsedDoc`.
pub fn parse_file(
    _path: &std::path::Path,
    content: &[u8],
    language: Language,
) -> Result<ParsedDoc, ParseError> {
    let adapter = tree_sitter_langs::adapter_for(language)
        .ok_or(ParseError::UnsupportedLanguage(language))?;
    let parsed = adapter.parse(content).map_err(ParseError::Adapter)?;
    Ok(ParsedDoc {
        language,
        source: parsed.source,
        tree: parsed.tree,
    })
}

/// Convert the tree-sitter `Tree` inside `doc` to an owned `SgNode<'a>` tree
/// whose `bytes` slices borrow from `doc.source`.
pub fn build_sgnode<'a>(doc: &'a ParsedDoc) -> SgNode<'a> {
    let root = doc.tree.root_node();
    walk(&root, &doc.source, doc.language)
}

fn walk<'a>(node: &tree_sitter::Node<'_>, source: &'a [u8], lang: Language) -> SgNode<'a> {
    let kind_static = intern_kind(node.kind());
    let canonical = tree_sitter_langs::canonical::canonicalise(lang, node.kind());
    let start = node.start_position();
    let end = node.end_position();
    let byte_start = node.start_byte();
    let byte_end = node.end_byte();

    let mut cursor = node.walk();
    let mut children = Vec::new();
    for child in node.children(&mut cursor) {
        children.push(walk(&child, source, lang));
    }

    let range = Range {
        start: Position {
            line: start.row + 1,
            column: start.column + 1,
            offset: byte_start,
        },
        end: Position {
            line: end.row + 1,
            column: end.column + 1,
            offset: byte_end,
        },
    };

    SgNode {
        kind: kind_static,
        canonical_kind: canonical,
        range,
        bytes: &source[byte_start..byte_end],
        children,
        field_name: None,
    }
}

/// Intern a tree-sitter node kind string into a `&'static str`. Each distinct
/// kind is leaked at most once.
fn intern_kind(kind: &str) -> &'static str {
    static MAP: Lazy<Mutex<HashMap<Arc<str>, &'static str>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));
    let mut m = MAP.lock().unwrap();
    let key: Arc<str> = Arc::from(kind);
    if let Some(s) = m.get(&key) {
        return s;
    }
    let leaked: &'static str = Box::leak(kind.to_string().into_boxed_str());
    m.insert(key, leaked);
    leaked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_returns_same_pointer_for_same_kind() {
        let a = intern_kind("identifier");
        let b = intern_kind("identifier");
        assert_eq!(a.as_ptr(), b.as_ptr());
    }
}
