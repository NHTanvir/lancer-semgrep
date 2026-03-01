//! Small helpers around [`semgrep_core::TaintLabelSet`].
//!
//! `TaintLabelSet` already has `union` and `contains` methods; this module
//! mirrors them as free functions so the dataflow code can read fluently
//! (`labels::union(&a, &b)`) without dragging method-call boilerplate
//! across every site.

use semgrep_core::TaintLabelSet;

/// Set-theoretic union of two label sets.
pub fn union(a: &TaintLabelSet, b: &TaintLabelSet) -> TaintLabelSet {
    a.union(b)
}

/// True iff `set` contains the textual label `label`.
pub fn contains(set: &TaintLabelSet, label: &str) -> bool {
    set.contains(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_combines() {
        let a = TaintLabelSet::singleton("a");
        let b = TaintLabelSet::singleton("b");
        let c = union(&a, &b);
        assert!(contains(&c, "a"));
        assert!(contains(&c, "b"));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn contains_is_false_when_absent() {
        let a = TaintLabelSet::singleton("x");
        assert!(!contains(&a, "y"));
    }
}
