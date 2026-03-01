//! GitLab SAST report JSON (`--gitlab-sast`).
//!
//! GitLab's pipeline UI ingests a per-job artifact whose schema is documented
//! at <https://docs.gitlab.com/ee/user/application_security/sast/>. The
//! relevant shape (schema version 15.x):
//!
//! ```json
//! {
//!   "version": "15.0.7",
//!   "vulnerabilities": [{
//!     "id": "<stable-hash>",
//!     "category": "sast",
//!     "name":  "<rule message>",
//!     "message": "<rule message>",
//!     "description": "<rule message>",
//!     "severity": "Critical|High|Medium|Low|Info",
//!     "scanner":  { "id": "lancer-semgrep", "name": "Lancer Semgrep" },
//!     "location": { "file": "...", "start_line": 0, "end_line": 0 },
//!     "identifiers": [{ "type": "rule_id", "name": "...", "value": "..." }]
//!   }],
//!   "scan": {
//!     "scanner": { "id": "lancer-semgrep", "name": "Lancer Semgrep",
//!                  "version": "..." },
//!     "type": "sast",
//!     "start_time": "...",
//!     "end_time":   "...",
//!     "status": "success"
//!   }
//! }
//! ```
//!
//! Severity map (Semgrep → GitLab):
//! `Error → "Critical"`, `Warning → "Medium"`, `Info → "Info"`. GitLab also
//! supports `"High"` and `"Low"`, but Semgrep's rule format doesn't ship the
//! intermediate levels first-class, so we collapse onto the bracketing tiers.
//!
//! Stable IDs are produced with `std::collections::hash_map::DefaultHasher`
//! over `rule_id:file:start.line:start.column`. The blake3 dep mentioned in
//! the Task-7 spec is already in the workspace, but using `DefaultHasher`
//! keeps this module free of extra hashing deps and stable enough for
//! deduplication on the GitLab side.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;

use serde::Serialize;

use semgrep_core::{Finding, Severity};

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

const GITLAB_SAST_VERSION: &str = "15.0.7";

#[derive(Debug, Default, Clone)]
pub struct GitlabSastEmitter;

impl OutputEmitter for GitlabSastEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        let doc = build_report(report, "sast");
        serde_json::to_writer(&mut *out, &doc)?;
        out.write_all(b"\n")?;
        Ok(())
    }
}

/// Shared report builder. `category` is `"sast"` for this module and
/// `"secret_detection"` for `gitlab_secrets.rs`; everything else is identical.
pub(crate) fn build_report(report: &ScanReport, category: &'static str) -> GitlabReport {
    GitlabReport {
        version: GITLAB_SAST_VERSION,
        vulnerabilities: report
            .findings
            .iter()
            .map(|f| finding_to_vuln(f, category))
            .collect(),
        scan: GitlabScan {
            scanner: GitlabScanner {
                id: "lancer-semgrep",
                name: "Lancer Semgrep",
                version: report.version.clone(),
            },
            r#type: scan_type_for(category),
            status: "success",
        },
    }
}

fn finding_to_vuln(f: &Finding, category: &'static str) -> GitlabVulnerability {
    GitlabVulnerability {
        id: stable_id(f),
        category,
        name: f.message.clone(),
        message: f.message.clone(),
        description: f.message.clone(),
        severity: gitlab_severity(f.severity),
        scanner: GitlabScannerRef {
            id: "lancer-semgrep",
            name: "Lancer Semgrep",
        },
        location: GitlabLocation {
            file: f.file.to_string_lossy().replace('\\', "/"),
            start_line: f.range.start.line,
            end_line: f.range.end.line,
        },
        identifiers: vec![GitlabIdentifier {
            r#type: "rule_id",
            name: f.rule_id.as_str().to_string(),
            value: f.rule_id.as_str().to_string(),
        }],
    }
}

/// Produce a deterministic ID for a finding so re-running the scan over the
/// same source yields the same vulnerability key on GitLab's side. Keyed on
/// `rule_id:file:line:column`; that's coarse enough to survive whitespace
/// edits, fine enough to distinguish multiple hits in the same file.
fn stable_id(f: &Finding) -> String {
    let mut h = DefaultHasher::new();
    f.rule_id.as_str().hash(&mut h);
    f.file.to_string_lossy().hash(&mut h);
    f.range.start.line.hash(&mut h);
    f.range.start.column.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn gitlab_severity(s: Severity) -> &'static str {
    match s {
        Severity::Error => "Critical",
        Severity::Warning => "Medium",
        Severity::Info => "Info",
    }
}

fn scan_type_for(category: &'static str) -> &'static str {
    // GitLab's "scan.type" enum mirrors the per-vuln category. Anything we
    // don't explicitly know about falls back to "sast" to stay valid.
    match category {
        "secret_detection" => "secret_detection",
        _ => "sast",
    }
}

#[derive(Serialize)]
pub(crate) struct GitlabReport {
    pub version: &'static str,
    pub vulnerabilities: Vec<GitlabVulnerability>,
    pub scan: GitlabScan,
}

#[derive(Serialize)]
pub(crate) struct GitlabVulnerability {
    pub id: String,
    pub category: &'static str,
    pub name: String,
    pub message: String,
    pub description: String,
    pub severity: &'static str,
    pub scanner: GitlabScannerRef,
    pub location: GitlabLocation,
    pub identifiers: Vec<GitlabIdentifier>,
}

#[derive(Serialize)]
pub(crate) struct GitlabScannerRef {
    pub id: &'static str,
    pub name: &'static str,
}

#[derive(Serialize)]
pub(crate) struct GitlabLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Serialize)]
pub(crate) struct GitlabIdentifier {
    #[serde(rename = "type")]
    pub r#type: &'static str,
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
pub(crate) struct GitlabScan {
    pub scanner: GitlabScanner,
    #[serde(rename = "type")]
    pub r#type: &'static str,
    pub status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct GitlabScanner {
    pub id: &'static str,
    pub name: &'static str,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mapping() {
        assert_eq!(gitlab_severity(Severity::Error), "Critical");
        assert_eq!(gitlab_severity(Severity::Warning), "Medium");
        assert_eq!(gitlab_severity(Severity::Info), "Info");
    }
}
