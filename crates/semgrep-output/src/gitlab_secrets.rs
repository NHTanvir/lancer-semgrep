//! GitLab Secrets-detection report JSON (`--gitlab-secrets`).
//!
//! Identical wire shape to GitLab SAST (`gitlab_sast.rs`) but with
//! `vulnerabilities[].category = "secret_detection"` and the matching
//! `scan.type`. Sharing the report struct with `gitlab_sast.rs` keeps the
//! two emitters in lock-step on schema upgrades.

use std::io::Write;

use crate::emitter::{OutputEmitter, OutputError};
use crate::gitlab_sast::build_report;
use crate::report::ScanReport;

#[derive(Debug, Default, Clone)]
pub struct GitlabSecretsEmitter;

impl OutputEmitter for GitlabSecretsEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        let doc = build_report(report, "secret_detection");
        serde_json::to_writer(&mut *out, &doc)?;
        out.write_all(b"\n")?;
        Ok(())
    }
}
