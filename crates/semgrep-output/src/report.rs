//! The top-level "scan report" object that emitters consume.
//!
//! A `ScanReport` is the in-memory equivalent of the JSON document Semgrep
//! prints with `--json`: a list of findings, plus run-level metadata
//! (errors, scanned/ignored paths, per-rule + per-target timing). Every
//! emitter is fed one of these; the Text, Emacs, Vim, GitHub-Actions
//! emitters use only the `findings` field, while JSON / SARIF / GitLab /
//! JUnit consume the whole report.
//!
//! All fields are owned + `Serialize` + `Deserialize` so a report can
//! round-trip through cache files (Task 8) and `--from-json` style replay
//! flows.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use semgrep_core::Finding;

/// One scan's worth of output, ready to be handed to an emitter.
///
/// Built by `lancer-semgrep::run::scan()` after collecting findings from the
/// matcher (Task 5) and taint engine (Task 6). Emitters never mutate it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanReport {
    /// Engine version that produced this report. Surfaces in SARIF
    /// `runs[].tool.driver.version` and in the GitLab SAST `scan.scanner`
    /// block.
    pub version: String,
    /// All findings, already de-duplicated and severity-filtered.
    pub findings: Vec<Finding>,
    /// Run-level errors. Parse failures, rule load failures, validator HTTP
    /// errors — anything that didn't stop the scan but should still be
    /// surfaced to the caller.
    pub errors: Vec<ScanError>,
    /// Which files the engine actually opened vs. which it skipped (via
    /// `.gitignore`, size limits, language detection misses, etc.).
    pub paths: Paths,
    /// Optional timing info (filled when `--time` is on).
    pub time: ScanTime,
}

/// Files scanned vs. files ignored during traversal.
///
/// `lancer-semgrep` populates this from the `ignore`/`walkdir` traversal in
/// Task 8. Emitters that don't surface paths (Text, Emacs, Vim) leave it
/// alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Paths {
    pub scanned: Vec<PathBuf>,
    pub ignored: Vec<PathBuf>,
}

/// Per-rule and per-target timing, plus the wall-clock total.
///
/// Filled only when the user passes `--time`. Emitters MUST NOT treat
/// missing timing as an error — `ScanTime::default()` is the normal case.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanTime {
    pub rules: Vec<RuleTime>,
    pub targets: Vec<TargetTime>,
    pub total_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTime {
    pub rule_id: String,
    pub seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTime {
    pub path: PathBuf,
    pub seconds: f64,
}

/// One non-fatal error encountered during the scan.
///
/// Level distinguishes warnings (skipped file, missing language support)
/// from errors (rule didn't compile, validator crashed). Tests and CI
/// integrations key off `level` to decide whether to fail the build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub level: ErrorLevel,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorLevel {
    Warn,
    Error,
}
