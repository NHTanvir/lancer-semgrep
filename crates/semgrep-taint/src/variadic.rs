//! Variadic-argument detection helpers.
//!
//! Python `*args`, `**kwargs`; JS `...rest`; Ruby `*args`, `**kwargs`. When a
//! call's actual argument is variadic, taint propagation must consider every
//! entry in the variadic bundle. See plan.md §"Newer rule-format features
//! to support (2025–2026)" — variadic functions.
//!
//! The detection here is intentionally syntactic — we look at the textual
//! prefix. The matcher already filters down to "this is an argument", so a
//! lightweight check suffices.

/// Detect a variadic argument pattern from its textual form.
///
/// Returns `true` for: `*args`, `**kwargs`, `...rest`, and the bare names
/// `args` / `kwargs` (which is what tree-sitter leaves you with after
/// stripping the splat).
pub fn is_variadic_arg(text: &[u8]) -> bool {
    let s = std::str::from_utf8(text).unwrap_or("");
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    s.starts_with("**")
        || s.starts_with('*')
        || s.starts_with("...")
        || s == "args"
        || s == "kwargs"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_python_splats() {
        assert!(is_variadic_arg(b"*args"));
        assert!(is_variadic_arg(b"**kwargs"));
    }

    #[test]
    fn detects_js_rest() {
        assert!(is_variadic_arg(b"...rest"));
        assert!(is_variadic_arg(b"...items"));
    }

    #[test]
    fn detects_bare_names() {
        assert!(is_variadic_arg(b"args"));
        assert!(is_variadic_arg(b"kwargs"));
    }

    #[test]
    fn rejects_plain_identifier() {
        assert!(!is_variadic_arg(b"x"));
        assert!(!is_variadic_arg(b"foo"));
        assert!(!is_variadic_arg(b""));
    }
}
