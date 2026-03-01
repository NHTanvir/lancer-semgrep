//! The `OutputEmitter` trait + shared error type.
//!
//! Each concrete emitter (text, JSON, SARIF, GitLab, JUnit, emacs, vim,
//! github-actions) implements `OutputEmitter`. The trait deliberately takes
//! `&mut dyn Write` rather than returning a `String` so emitters can stream
//! findings on huge scans without buffering the whole document.

use std::io::Write;

use semgrep_core::Finding;

use crate::report::ScanReport;

/// Common surface across every output format.
///
/// Emitters are `Send` so `lancer-semgrep` can move them across rayon worker
/// boundaries when streaming partial results from a parallel scan.
pub trait OutputEmitter: Send {
    /// Emit a full scan report — findings, run-level errors, paths, timing.
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError>;

    /// Convenience wrapper that wraps a bare `&[Finding]` in a `ScanReport`
    /// with empty metadata. Useful for unit tests and for emitters fed from a
    /// streaming source that hasn't materialised a full report yet.
    fn emit_findings(
        &self,
        findings: &[Finding],
        out: &mut dyn Write,
    ) -> Result<(), OutputError> {
        let r = ScanReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            findings: findings.to_vec(),
            errors: Vec::new(),
            paths: Default::default(),
            time: Default::default(),
        };
        self.emit(&r, out)
    }
}

/// Failure modes that any emitter can hit. `Io` and `Json` are the common
/// ones; `Format` is the catch-all for emitter-specific issues (e.g. JUnit
/// failing to build a `TestCase`).
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("output format error: {0}")]
    Format(String),
}
