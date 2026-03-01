//! Apply a rule's `fix:` template — substitute each `$X` metavariable in the
//! template string with the bound text from a `Match`'s `MetavarBindings`.
//!
//! Order of substitution: longest metavariable name first, so `$X` doesn't
//! eat a prefix of `$XY`. Substitution is purely textual — formatting
//! preservation is the caller's responsibility (`apply.rs` handles byte
//! ranges).

use crate::match_::MetavarBindings;

/// Substitute every `$X` placeholder in `template` with the text of the
/// metavariable's binding. Unbound metavariables pass through untouched.
pub fn render_fix_template(template: &str, bindings: &MetavarBindings<'_>) -> String {
    let mut pairs: Vec<(String, String)> = bindings
        .iter()
        .map(|(name, node)| {
            (
                name.clone(),
                std::str::from_utf8(node.bytes).unwrap_or("").to_string(),
            )
        })
        .collect();
    // Longest-name-first so `$X` doesn't substring `$XY`.
    pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    let mut out = template.to_string();
    for (name, value) in pairs {
        out = out.replace(&name, &value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_::MetavarBindings;
    use crate::node::{CanonicalKind, Position, Range, SgNode};

    fn nd(s: &str) -> SgNode<'_> {
        SgNode::leaf(
            "identifier",
            CanonicalKind::Identifier,
            Range::new(
                Position::new(1, 1, 0),
                Position::new(1, 1 + s.len(), s.len()),
            ),
            s.as_bytes(),
        )
    }

    #[test]
    fn substitutes_single_metavar() {
        let mut b = MetavarBindings::new();
        b.try_bind("$X", nd("foo")).unwrap();
        assert_eq!(render_fix_template("call($X)", &b), "call(foo)");
    }

    #[test]
    fn longest_metavar_first() {
        let mut b = MetavarBindings::new();
        b.try_bind("$X", nd("a")).unwrap();
        b.try_bind("$XY", nd("b")).unwrap();
        assert_eq!(render_fix_template("$X + $XY", &b), "a + b");
    }

    #[test]
    fn unbound_passes_through() {
        let b = MetavarBindings::new();
        assert_eq!(render_fix_template("call($X)", &b), "call($X)");
    }
}
