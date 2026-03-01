//! Per-program-point taint lattice.
//!
//! Each program-point has a [`ProgramPointState`] holding a map
//! `variable name → TaintState`. The lattice LUB is per-variable: missing
//! entries default to `Untainted`.
//!
//! See plan.md §"Internal architecture → taint/" and §"Engineering hard
//! parts → Taint analysis". The lattice itself is in
//! [`semgrep_core::TaintState`] (Top / Tainted(labels) / Untainted) — we
//! wrap it here per-variable, then aggregate per-program-point.

use semgrep_core::TaintState;
use std::collections::BTreeMap;

/// Variable identifier inside a function's CFG. Currently a plain
/// `String` (variable name as it appears in the source). Field tracking
/// is encoded with dotted names (e.g. `obj.field`) — see plan §"Research
/// note 2026-05-31 → field-tracking capacity".
pub type VarName = String;

/// Per-variable taint map. The default for any unmapped variable is
/// `TaintState::Untainted`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VarTaint(pub BTreeMap<VarName, TaintState>);

impl VarTaint {
    /// New empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the state of `name`. Unmapped variables read as `Untainted`.
    pub fn get(&self, name: &str) -> TaintState {
        self.0.get(name).cloned().unwrap_or(TaintState::Untainted)
    }

    /// Set `name = state`. If `state == Untainted`, the entry is removed
    /// so the map stays compact.
    pub fn set(&mut self, name: VarName, state: TaintState) {
        match state {
            TaintState::Untainted => {
                self.0.remove(&name);
            }
            _ => {
                self.0.insert(name, state);
            }
        }
    }

    /// Functional per-variable LUB. Variables present in either side end
    /// up in the result with `join` applied.
    pub fn join(&self, other: &VarTaint) -> VarTaint {
        let mut out = self.clone();
        let _ = out.lub_into(other);
        out
    }

    /// In-place LUB. Returns `true` iff any variable's state changed.
    pub fn lub_into(&mut self, other: &VarTaint) -> bool {
        let mut changed = false;
        for (k, v) in &other.0 {
            let cur = self.get(k);
            let new = cur.join(v);
            if new != cur {
                self.set(k.clone(), new);
                changed = true;
            }
        }
        changed
    }
}

/// State at a single program-point — currently just the variable map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramPointState {
    pub vars: VarTaint,
}

impl ProgramPointState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Functional LUB at this program-point.
    pub fn join(&self, other: &ProgramPointState) -> ProgramPointState {
        let mut out = self.clone();
        let _ = out.lub_into(other);
        out
    }

    /// In-place LUB. Returns `true` iff anything changed.
    pub fn lub_into(&mut self, other: &ProgramPointState) -> bool {
        self.vars.lub_into(&other.vars)
    }
}

/// Per-CFG-node state map. Indexed by `NodeIndex::index()` (i.e. the
/// `usize` id we stash on each [`crate::nodes::CfgNode`]).
#[derive(Debug, Clone)]
pub struct TaintLattice {
    pub per_node: Vec<ProgramPointState>,
}

impl TaintLattice {
    /// Allocate one state slot per CFG node, all initialised to the empty
    /// (everywhere-Untainted) state.
    pub fn new(node_count: usize) -> Self {
        Self {
            per_node: vec![ProgramPointState::default(); node_count],
        }
    }

    /// Read-only access. `id` must be a valid CFG node index.
    pub fn get(&self, id: usize) -> &ProgramPointState {
        &self.per_node[id]
    }

    /// Mutable access. `id` must be a valid CFG node index.
    pub fn get_mut(&mut self, id: usize) -> &mut ProgramPointState {
        &mut self.per_node[id]
    }

    /// Replace the state at `id`.
    pub fn set(&mut self, id: usize, state: ProgramPointState) {
        self.per_node[id] = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::TaintLabelSet;

    #[test]
    fn vartaint_default_untainted() {
        let v = VarTaint::new();
        assert!(matches!(v.get("missing"), TaintState::Untainted));
    }

    #[test]
    fn vartaint_set_and_get() {
        let mut v = VarTaint::new();
        v.set("x".into(), TaintState::Tainted(TaintLabelSet::singleton("user")));
        match v.get("x") {
            TaintState::Tainted(s) => assert!(s.contains("user")),
            _ => panic!("expected tainted"),
        }
    }

    #[test]
    fn vartaint_lub_detects_change() {
        let mut a = VarTaint::new();
        let mut b = VarTaint::new();
        b.set("x".into(), TaintState::Tainted(TaintLabelSet::singleton("u")));
        assert!(a.lub_into(&b));
        // Second time, no change.
        assert!(!a.lub_into(&b));
    }

    #[test]
    fn lattice_new_sized() {
        let l = TaintLattice::new(3);
        assert_eq!(l.per_node.len(), 3);
        assert!(l.get(0).vars.0.is_empty());
    }

    #[test]
    fn program_point_join_unions_labels() {
        let mut a = ProgramPointState::new();
        a.vars.set("x".into(), TaintState::Tainted(TaintLabelSet::singleton("a")));
        let mut b = ProgramPointState::new();
        b.vars.set("x".into(), TaintState::Tainted(TaintLabelSet::singleton("b")));
        let c = a.join(&b);
        match c.vars.get("x") {
            TaintState::Tainted(s) => {
                assert!(s.contains("a"));
                assert!(s.contains("b"));
            }
            _ => panic!("expected tainted"),
        }
    }
}
