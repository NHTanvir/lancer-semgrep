//! Sanitizer handling.
//!
//! Two flavours:
//!
//! - `by-side-effect: false` (the default): the sanitizer's *return value*
//!   is untainted. In our simplified, variable-keyed model we don't track
//!   call results, so we clear the bound argument variable's taint and
//!   trust the caller to capture the sanitized value into a new
//!   assignment.
//! - `by-side-effect: true`: the sanitizer mutates its argument in place
//!   (think `validate_in_place(buf)`). We clear the bound argument
//!   variable's taint.
//!
//! See plan.md §"Newer rule-format features to support (2025–2026)" —
//! taint by side-effect sanitizers.

use semgrep_core::TaintState;

use crate::dataflow::SanitizerHit;
use crate::lattice::VarTaint;

/// Apply a sanitizer to the variable map. Returns `true` iff anything
/// changed.
pub fn apply_sanitizer(s: &SanitizerHit, vars: &mut VarTaint) -> bool {
    let Some(name) = s.bound_var.as_deref() else {
        return false;
    };
    let cur = vars.get(name);
    if matches!(cur, TaintState::Untainted) {
        return false;
    }
    // Both flavours clear the bound variable today. The distinction
    // (by-side-effect: true mutates the argument; false untaints the
    // result) is preserved on the SanitizerHit for future when we track
    // call results separately.
    let _ = s.by_side_effect;
    vars.set(name.to_string(), TaintState::Untainted);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::TaintLabelSet;

    #[test]
    fn sanitizes_tainted_var() {
        let mut vars = VarTaint::new();
        vars.set("x".into(), TaintState::Tainted(TaintLabelSet::singleton("u")));
        let s = SanitizerHit {
            cfg_node_id: 0,
            bound_var: Some("x".into()),
            by_side_effect: true,
        };
        assert!(apply_sanitizer(&s, &mut vars));
        assert!(matches!(vars.get("x"), TaintState::Untainted));
    }

    #[test]
    fn noop_on_clean_var() {
        let mut vars = VarTaint::new();
        let s = SanitizerHit {
            cfg_node_id: 0,
            bound_var: Some("x".into()),
            by_side_effect: false,
        };
        assert!(!apply_sanitizer(&s, &mut vars));
    }
}
