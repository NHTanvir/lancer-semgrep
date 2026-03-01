//! Semgrep-native JSON emitter (`--json`).
//!
//! Top-level shape, matching the upstream `semgrep --json` schema:
//!
//! ```json
//! {
//!   "version":  "0.1.0",
//!   "results":  [ ... Finding ... ],
//!   "errors":   [ ... ScanError ... ],
//!   "paths":    { "scanned": [...], "ignored": [...] },
//!   "time":     { "rules": [...], "targets": [...], "total_seconds": 0.0 }
//! }
//! ```
//!
//! `Finding` and `ScanError` already implement `Serialize`, so emit reduces
//! to a single `serde_json::to_writer*` call against a thin reference view.

use std::io::Write;

use serde::Serialize;

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::{Paths, ScanError, ScanReport, ScanTime};

/// Configurable JSON emitter.
///
/// `pretty == true` gives multi-line output (handy from a TTY); the default
/// emits compact JSON, which is what `--json | jq` users expect and what
/// CI integrations parse fastest.
#[derive(Debug, Default, Clone)]
pub struct JsonEmitter {
    pub pretty: bool,
}

impl JsonEmitter {
    pub fn pretty() -> Self {
        Self { pretty: true }
    }
}

impl OutputEmitter for JsonEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        let view = SemgrepJsonView::from_report(report);
        if self.pretty {
            serde_json::to_writer_pretty(&mut *out, &view)?;
        } else {
            serde_json::to_writer(&mut *out, &view)?;
        }
        // Trailing newline so `--output report.json` plays nicely with diff
        // tools and POSIX text-file conventions.
        out.write_all(b"\n")?;
        Ok(())
    }
}

/// Thin borrowing view over `ScanReport` that renames `findings → results`
/// without cloning the underlying vector.
///
/// `results` is the historical Semgrep key for findings, so we keep it on
/// the wire even though the engine-side type is named `Finding`.
#[derive(Serialize)]
struct SemgrepJsonView<'a> {
    version: &'a str,
    results: &'a [semgrep_core::Finding],
    errors: &'a [ScanError],
    paths: &'a Paths,
    time: &'a ScanTime,
}

impl<'a> SemgrepJsonView<'a> {
    fn from_report(r: &'a ScanReport) -> Self {
        Self {
            version: &r.version,
            results: &r.findings,
            errors: &r.errors,
            paths: &r.paths,
            time: &r.time,
        }
    }
}
