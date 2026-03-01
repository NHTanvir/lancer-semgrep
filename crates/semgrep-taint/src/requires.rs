//! Evaluate a `requires:` boolean expression against an accumulated
//! [`TaintLabelSet`] at a sink.
//!
//! The parser + evaluator live in `semgrep_core::taint_types::RequiresExpr`;
//! this module is a thin facade so taint code can write
//! `requires::eval_requires(expr, &labels)` without reaching into
//! `semgrep_core` internals.
//!
//! See plan.md §"Newer rule-format features to support (2025–2026)" —
//! taint labels with `requires:`.

use semgrep_core::{RequiresExpr, TaintLabelSet};

/// True iff `expr` evaluates true under the inbound label set at a sink.
///
/// Forwards to [`RequiresExpr::eval`].
pub fn eval_requires(expr: &RequiresExpr, labels: &TaintLabelSet) -> bool {
    expr.eval(labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_input_and_not_admin_only() {
        let e = RequiresExpr::parse("user-input and not admin-only").unwrap();
        let mut s = TaintLabelSet::new();
        s.insert("user-input".into());
        assert!(eval_requires(&e, &s));
        s.insert("admin-only".into());
        assert!(!eval_requires(&e, &s));
    }

    #[test]
    fn true_literal() {
        let e = RequiresExpr::True;
        assert!(eval_requires(&e, &TaintLabelSet::new()));
    }
}
