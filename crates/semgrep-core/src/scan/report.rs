//! Helpers for assembling the post-scan `ScanReport` from enumeration output.
//!
//! `semgrep-output::ScanReport` owns the schema; we only build the `Paths`
//! sub-record here to keep enumeration-internal types out of the output crate.

use std::path::PathBuf;

use crate::scan::target::TargetFile;

/// Tiny owned `(scanned, ignored)` shape used as a stable hand-off to the
/// emitter layer. Mirrors `semgrep_output::report::Paths` field-for-field; we
/// don't pull in `semgrep-output` as a dep so consumers do the conversion.
#[derive(Debug, Clone, Default)]
pub struct Paths {
    pub scanned: Vec<PathBuf>,
    pub ignored: Vec<PathBuf>,
}

/// Project an `enumerate_targets` result into a flat `Paths` value.
pub fn report_paths_from_enumeration(targets: &[TargetFile], ignored: &[PathBuf]) -> Paths {
    Paths {
        scanned: targets.iter().map(|t| t.path.clone()).collect(),
        ignored: ignored.to_vec(),
    }
}
