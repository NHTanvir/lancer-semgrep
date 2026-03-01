//! Propagator handling.
//!
//! A propagator is a custom flow rule `$X → $Y` declared in a rule's
//! `pattern-propagators:` block. When a propagator pattern matches at a
//! program-point, the engine treats it as: "if `from` var is tainted at
//! this point, `to` var becomes tainted with the same labels".
//!
//! The main worklist loop in [`crate::dataflow`] already applies this
//! semantics inline; this module is a tiny helper kept around for unit
//! testing and for future refactoring (e.g. running propagators in
//! batches via SCC ordering).

use crate::dataflow::PropagatorHit;
use crate::lattice::VarTaint;

/// Apply one propagator hit to a variable map. Returns `true` iff the
/// destination variable's taint state changed.
pub fn apply_propagator(p: &PropagatorHit, vars: &mut VarTaint) -> bool {
    let from = vars.get(&p.from_var);
    if !from.is_tainted() {
        return false;
    }
    let cur = vars.get(&p.to_var);
    let new = cur.join(&from);
    if new != cur {
        vars.set(p.to_var.clone(), new);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::{TaintLabelSet, TaintState};

    #[test]
    fn propagates_when_from_is_tainted() {
        let mut vars = VarTaint::new();
        vars.set("x".into(), TaintState::Tainted(TaintLabelSet::singleton("u")));
        let p = PropagatorHit {
            cfg_node_id: 0,
            from_var: "x".into(),
            to_var: "y".into(),
        };
        assert!(apply_propagator(&p, &mut vars));
        match vars.get("y") {
            TaintState::Tainted(s) => assert!(s.contains("u")),
            _ => panic!("expected tainted"),
        }
    }

    #[test]
    fn noop_when_from_clean() {
        let mut vars = VarTaint::new();
        let p = PropagatorHit {
            cfg_node_id: 0,
            from_var: "x".into(),
            to_var: "y".into(),
        };
        assert!(!apply_propagator(&p, &mut vars));
    }
}
