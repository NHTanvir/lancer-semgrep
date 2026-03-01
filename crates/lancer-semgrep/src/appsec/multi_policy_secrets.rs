//! Custom secrets in multi-policy projects (Feb 2026).
//!
//! Per plan §"Research note 2026-05-31 → Custom secrets in multi-policy
//! projects": when a project has multiple Secrets policies active, custom
//! secret patterns can now be attached to any of them — previously only
//! the default policy could carry custom secrets. We mirror the same
//! semantics in the local policy resolver.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSecretBinding {
    pub policy_id: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MultiPolicySecrets {
    pub bindings: Vec<CustomSecretBinding>,
}

impl MultiPolicySecrets {
    /// Attach a custom secret rule to a policy. Accepted regardless of
    /// whether the policy is the project default (the Feb 2026 change).
    pub fn attach(&mut self, policy_id: impl Into<String>, rule_id: impl Into<String>) {
        self.bindings.push(CustomSecretBinding {
            policy_id: policy_id.into(),
            rule_id: rule_id.into(),
        });
    }

    pub fn rules_for_policy(&self, policy_id: &str) -> impl Iterator<Item = &str> {
        self.bindings
            .iter()
            .filter(move |b| b.policy_id == policy_id)
            .map(|b| b.rule_id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_to_non_default_policy() {
        let mut mps = MultiPolicySecrets::default();
        mps.attach("policy-staging", "rule-foo");
        mps.attach("policy-prod", "rule-bar");
        let staging: Vec<_> = mps.rules_for_policy("policy-staging").collect();
        assert_eq!(staging, vec!["rule-foo"]);
    }
}
