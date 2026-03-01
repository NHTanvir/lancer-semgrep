//! Project tags update gating (Feb 2026).
//!
//! Per plan §"Research note 2026-05-31 → Project tags update gating
//! (Feb 2026)": project tags can no longer be modified via
//! `.semgrepconfig.yml` changes in PR scans — only during full scans.
//! Forces an audit trail.
//!
//! `PolicyContext` is the local equivalent: a read-only context refuses
//! tag mutations, a read-write context accepts them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyContext {
    /// Full scan (e.g. on the default branch or a scheduled scan). Tag
    /// mutations from `.semgrepconfig.yml` are accepted.
    ReadWrite,
    /// PR scan. Tag mutations are silently ignored, with a warning.
    ReadOnly,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectTags {
    pub tags: Vec<String>,
}

impl ProjectTags {
    /// Attempt to update tags. Returns `Ok(())` if accepted, `Err(reason)`
    /// if rejected by the policy context.
    pub fn apply_update(
        &mut self,
        context: PolicyContext,
        proposed: Vec<String>,
    ) -> Result<(), &'static str> {
        match context {
            PolicyContext::ReadWrite => {
                self.tags = proposed;
                Ok(())
            }
            PolicyContext::ReadOnly => Err("PR-scan context refuses tag mutations"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_rejects() {
        let mut tags = ProjectTags::default();
        assert!(tags
            .apply_update(PolicyContext::ReadOnly, vec!["a".into()])
            .is_err());
        assert!(tags.tags.is_empty());
    }

    #[test]
    fn read_write_accepts() {
        let mut tags = ProjectTags::default();
        assert!(tags
            .apply_update(PolicyContext::ReadWrite, vec!["a".into(), "b".into()])
            .is_ok());
        assert_eq!(tags.tags.len(), 2);
    }
}
