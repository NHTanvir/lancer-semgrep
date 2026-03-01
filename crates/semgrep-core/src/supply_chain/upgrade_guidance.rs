//! "Upgrade Guidance" — auto-generated PRs to bump vulnerable dependencies
//! to safe versions.
//!
//! Per plan §"Semgrep Supply Chain → Auto-generated PRs to upgrade
//! vulnerable deps to safe versions". The upstream cloud emits a per-vuln
//! suggested-version + a PR template. We mirror the value shape so callers
//! can serialise a guidance record; emitting the PR itself requires a Git
//! provider integration (out of scope here).

use serde::{Deserialize, Serialize};

use crate::supply_chain::manifests::ManifestKind;

/// One upgrade suggestion produced from a Supply-Chain finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeGuidance {
    pub package: String,
    pub namespace: String, // e.g. "pypi", "npm"
    pub current_version: String,
    /// Lowest safe version the cloud / advisory feed recommends.
    pub suggested_version: String,
    pub manifest: ManifestKind,
    pub manifest_path: std::path::PathBuf,
    pub advisory_id: Option<String>,
    pub justification: String,
}

impl UpgradeGuidance {
    /// Render a one-line PR title.
    pub fn pr_title(&self) -> String {
        format!(
            "Bump {} from {} to {} ({})",
            self.package, self.current_version, self.suggested_version, self.namespace
        )
    }

    /// Render a multi-line PR body.
    pub fn pr_body(&self) -> String {
        let mut body = format!(
            "## Upgrade Guidance\n\n\
             - Package: `{}`\n\
             - Ecosystem: `{}`\n\
             - Current: `{}`\n\
             - Suggested: `{}`\n\n\
             {}\n",
            self.package,
            self.namespace,
            self.current_version,
            self.suggested_version,
            self.justification,
        );
        if let Some(adv) = &self.advisory_id {
            body.push_str(&format!(
                "\nAdvisory: https://semgrep.dev/advisories/{adv}\n"
            ));
        }
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pr_title_format() {
        let g = UpgradeGuidance {
            package: "lodash".into(),
            namespace: "npm".into(),
            current_version: "4.17.0".into(),
            suggested_version: "4.17.21".into(),
            manifest: ManifestKind::NpmPackageJson,
            manifest_path: "package.json".into(),
            advisory_id: Some("GHSA-1234".into()),
            justification: "patches prototype pollution".into(),
        };
        assert_eq!(
            g.pr_title(),
            "Bump lodash from 4.17.0 to 4.17.21 (npm)"
        );
        assert!(g.pr_body().contains("GHSA-1234"));
    }
}
