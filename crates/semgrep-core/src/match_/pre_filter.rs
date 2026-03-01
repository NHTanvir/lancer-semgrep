//! Cheap pre-filter that decides whether a pattern *could possibly* match a
//! source file before any AST walking happens.
//!
//! Concretely:
//! 1. Extract the literal "required strings" from a parsed [`PatternAst`] —
//!    identifiers, attribute names, string literals, keyword names.
//! 2. Use `memchr::memmem::find` to do a byte-level scan of the source for
//!    those literals.
//!
//! Semgrep's upstream uses an AND ("every required substring must appear")
//! pre-filter; we start with OR ("any required substring suffices") to
//! minimise false negatives. Tighten to AND once integration tests confirm
//! safety.

use crate::match_::pattern_ast::{LitKind, PatternAst};

/// Walk a [`PatternAst`] and collect literal strings that the pattern
/// requires in order to match. Filters out trivial / short strings and
/// metavariable names.
pub fn required_strings(ast: &PatternAst) -> Vec<String> {
    fn collect(ast: &PatternAst, acc: &mut Vec<String>) {
        use PatternAst::*;
        match ast {
            Atom { text, .. } => acc.push(text.clone()),
            Metavar { .. } | Ellipsis => {}
            Call { callee, args } => {
                collect(callee, acc);
                for a in args {
                    collect(a, acc);
                }
            }
            Attr { obj, attr } => {
                collect(obj, acc);
                acc.push(attr.clone());
            }
            Index { obj, idx } => {
                collect(obj, acc);
                collect(idx, acc);
            }
            BinOp { lhs, rhs, .. } => {
                collect(lhs, acc);
                collect(rhs, acc);
            }
            UnaryOp { operand, .. } => collect(operand, acc),
            Assign { target, value } => {
                collect(target, acc);
                collect(value, acc);
            }
            Block { stmts } | Sequence(stmts) => {
                for s in stmts {
                    collect(s, acc);
                }
            }
            ExprStmt(e) => collect(e, acc),
            Lit(LitKind::Str(s)) => acc.push(s.clone()),
            Lit(_) => {}
            Keyword { name, args } => {
                acc.push(name.clone());
                for a in args {
                    collect(a, acc);
                }
            }
        }
    }
    let mut acc = Vec::new();
    collect(ast, &mut acc);
    acc.sort();
    acc.dedup();
    // Drop trivial / metavar / noise strings.
    acc.retain(|s| s.len() >= 3 && !s.starts_with('$'));
    acc
}

/// Returns true when at least one required string is present in the source
/// bytes (OR semantics). Empty `required` is treated as "no constraint" —
/// always returns true. Memchr-backed.
pub fn pre_filter(source: &[u8], required: &[String]) -> bool {
    if required.is_empty() {
        return true;
    }
    for r in required {
        if memchr::memmem::find(source, r.as_bytes()).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_::pattern_parser::parse_pattern;

    #[test]
    fn extracts_required_strings_from_call() {
        let ast = parse_pattern("subprocess.call($CMD)").unwrap();
        let req = required_strings(&ast);
        assert!(req.contains(&"subprocess".to_string()));
        assert!(req.contains(&"call".to_string()));
        assert!(!req.iter().any(|s| s.starts_with('$')));
    }

    #[test]
    fn pre_filter_accepts_when_any_required_string_present() {
        let req = vec!["foo".to_string(), "bar".to_string()];
        assert!(pre_filter(b"hello bar world", &req));
    }

    #[test]
    fn pre_filter_rejects_when_none_present() {
        let req = vec!["foo".to_string(), "bar".to_string()];
        assert!(!pre_filter(b"nothing relevant here", &req));
    }

    #[test]
    fn pre_filter_passes_when_no_required_strings() {
        assert!(pre_filter(b"anything", &[]));
    }
}
