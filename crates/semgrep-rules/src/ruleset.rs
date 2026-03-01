//! Container for a loaded batch of [`Rule`]s.
//!
//! Owns the rules in the order they were loaded. Provides:
//!
//! - lazy iteration (`iter`)
//! - language filtering (`filter_by_language`)
//! - lookup by ID (`find`)
//! - composition (`extend`, `push`)
//!
//! Internally just a `Vec<Rule>` — no fancy index structures yet. If/when
//! `filter_by_language` becomes hot the engine can build an index from this.

use semgrep_core::{Language, Rule, RuleId};

/// An ordered collection of [`Rule`]s.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Empty rule set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap an existing `Vec<Rule>`.
    pub fn from(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Iterate over rules in load order.
    pub fn iter(&self) -> std::slice::Iter<'_, Rule> {
        self.rules.iter()
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True iff there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Consume another set's rules, appending to `self`.
    pub fn extend(&mut self, other: RuleSet) {
        self.rules.extend(other.rules);
    }

    /// Append a single rule.
    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Lazily yield references to rules that target the given language.
    pub fn filter_by_language(
        &self,
        lang: Language,
    ) -> impl Iterator<Item = &Rule> {
        self.rules
            .iter()
            .filter(move |r| r.languages.contains(&lang))
    }

    /// First rule with the given ID (rule IDs are typically unique per set).
    pub fn find(&self, id: &RuleId) -> Option<&Rule> {
        self.rules.iter().find(|r| &r.id == id)
    }

    /// Borrow the underlying slice — handy for callers that need random access.
    pub fn as_slice(&self) -> &[Rule] {
        &self.rules
    }

    /// Convert into the underlying `Vec<Rule>`, consuming the set.
    pub fn into_inner(self) -> Vec<Rule> {
        self.rules
    }
}

impl IntoIterator for RuleSet {
    type Item = Rule;
    type IntoIter = std::vec::IntoIter<Rule>;
    fn into_iter(self) -> Self::IntoIter {
        self.rules.into_iter()
    }
}

impl<'a> IntoIterator for &'a RuleSet {
    type Item = &'a Rule;
    type IntoIter = std::slice::Iter<'a, Rule>;
    fn into_iter(self) -> Self::IntoIter {
        self.rules.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semgrep_core::{Language, PatternOp, Rule, Severity};

    fn r(id: &str, langs: &[Language]) -> Rule {
        Rule::search(
            id,
            langs.iter().copied(),
            Severity::Warning,
            "m",
            PatternOp::Pattern("x".into()),
        )
    }

    #[test]
    fn filter_by_language_lazy() {
        let mut set = RuleSet::new();
        set.push(r("py-only", &[Language::Python]));
        set.push(r("js-only", &[Language::Javascript]));
        set.push(r("py-js", &[Language::Python, Language::Javascript]));
        let py: Vec<_> = set.filter_by_language(Language::Python).collect();
        assert_eq!(py.len(), 2);
        let go: Vec<_> = set.filter_by_language(Language::Go).collect();
        assert_eq!(go.len(), 0);
    }

    #[test]
    fn find_by_id() {
        let mut set = RuleSet::new();
        set.push(r("a", &[Language::Python]));
        set.push(r("b", &[Language::Python]));
        let id = "b".into();
        assert!(set.find(&id).is_some());
        let id = "c".into();
        assert!(set.find(&id).is_none());
    }
}
