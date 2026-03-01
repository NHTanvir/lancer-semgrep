//! SARIF 2.1.0 emitter (`--sarif`).
//!
//! SARIF (Static Analysis Results Interchange Format) is OASIS's
//! XML-flavoured-as-JSON sibling to JUnit; GitHub code-scanning, Azure DevOps
//! Advanced Security, and most enterprise dashboards ingest it natively.
//!
//! Implementation choice: we hand-build the document with `serde_json::json!`
//! rather than the strong types in `serde_sarif::sarif`. Rationale:
//!
//! * The crate's builder API churns across 0.4.x and trying to type every
//!   nested field (`PhysicalLocationBuilder`, `RegionBuilder`, …) bloats the
//!   call site without buying anything we can't get from `json!`.
//! * The plan explicitly OKs this fallback (see plan.md §"Output formats" and
//!   the Task-7 spec — *"build SARIF as a `serde_json::Value` directly — that's
//!   acceptable"*).
//! * The output is still validated against `https://json.schemastore.org/sarif-2.1.0.json`
//!   if the user wants to lint it externally.
//!
//! Required top-level shape we conform to:
//! ```json
//! {
//!   "version": "2.1.0",
//!   "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
//!   "runs": [{
//!     "tool": { "driver": { "name": "lancer-semgrep", "version": "...",
//!                            "rules": [ ... ] } },
//!     "results": [
//!       { "ruleId": "...", "level": "...", "message": { "text": "..." },
//!         "locations": [ ... ], "codeFlows": [ ... ] }
//!     ]
//!   }]
//! }
//! ```
//!
//! Per plan §"Research note → SARIF trace fix (Apr 2026)", taint findings
//! emit `codeFlows[0].threadFlows[0].locations = [source, ...propagators,
//! sink]` so the dataflow is visible in GitHub's code-scanning UI.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

use semgrep_core::{DataflowTrace, Finding, Severity, Span};

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME: &str = "lancer-semgrep";

#[derive(Debug, Default, Clone)]
pub struct SarifEmitter {
    pub pretty: bool,
}

impl SarifEmitter {
    pub fn pretty() -> Self {
        Self { pretty: true }
    }
}

impl OutputEmitter for SarifEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        let doc = build_sarif(report);
        if self.pretty {
            serde_json::to_writer_pretty(&mut *out, &doc)?;
        } else {
            serde_json::to_writer(&mut *out, &doc)?;
        }
        out.write_all(b"\n")?;
        Ok(())
    }
}

/// Build the full SARIF document for a scan report.
///
/// One `Run` per emit call. Each unique `rule_id` in the findings becomes a
/// `tool.driver.rules[]` entry so the consumer can attach metadata back to
/// rule definitions even if `results[].ruleId` is the only field shipped per
/// finding.
fn build_sarif(report: &ScanReport) -> Value {
    // Collect unique rules in deterministic order. SARIF consumers (notably
    // GitHub) tie `result.ruleId` to `tool.driver.rules[].id`, so it's
    // important every distinct rule_id has a corresponding rule object.
    let mut rules: BTreeMap<String, &Finding> = BTreeMap::new();
    for f in &report.findings {
        rules.entry(f.rule_id.as_str().to_string()).or_insert(f);
    }
    let rules_array: Vec<Value> = rules
        .iter()
        .map(|(rid, sample)| {
            json!({
                "id": rid,
                "name": rid,
                "shortDescription": { "text": sample.message },
                "fullDescription":  { "text": sample.message },
                "defaultConfiguration": { "level": sarif_level(sample.severity) },
            })
        })
        .collect();

    let results: Vec<Value> = report.findings.iter().map(finding_to_result).collect();

    json!({
        "version":  SARIF_VERSION,
        "$schema":  SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name":             TOOL_NAME,
                    "informationUri":   "https://github.com/NHTanvir/lancer-semgrep",
                    "version":          report.version,
                    "rules":            rules_array,
                }
            },
            "results": results,
        }],
    })
}

/// Map a `Finding` into a SARIF `result` object.
fn finding_to_result(f: &Finding) -> Value {
    let mut result = json!({
        "ruleId":    f.rule_id.as_str(),
        "level":     sarif_level(f.severity),
        "message":   { "text": f.message },
        "locations": [physical_location_for_file(&f.file, &f.range)],
    });

    // Taint-mode findings carry a `dataflow_trace`. SARIF expresses that as
    // codeFlows[].threadFlows[].locations in source → ... → sink order.
    if let Some(trace) = &f.dataflow_trace {
        result["codeFlows"] = code_flows(trace);
    }

    // Fix suggestions, when present, ride along as a SARIF "fix" object with
    // a single `artifactChange` containing the replacement text and the
    // unified-diff snippet. Consumers that don't know about fixes ignore it.
    if let Some(fix) = &f.fix {
        result["fixes"] = json!([{
            "description": { "text": fix.diff },
            "artifactChanges": [{
                "artifactLocation": { "uri": path_uri(&f.file) },
                "replacements": [{
                    "deletedRegion": region_from_range(&f.range),
                    "insertedContent": { "text": fix.after },
                }]
            }]
        }]);
    }

    result
}

fn code_flows(trace: &DataflowTrace) -> Value {
    let mut locs: Vec<Value> = Vec::with_capacity(2 + trace.propagators.len());
    locs.push(thread_flow_location(&trace.source, "source"));
    for (i, p) in trace.propagators.iter().enumerate() {
        locs.push(thread_flow_location(p, &format!("propagator-{i}")));
    }
    locs.push(thread_flow_location(&trace.sink, "sink"));
    json!([{
        "threadFlows": [{
            "locations": locs,
        }]
    }])
}

fn thread_flow_location(span: &Span, kind: &str) -> Value {
    json!({
        "location": {
            "physicalLocation": physical_location_for_file_inner(&span.file, &span.range),
            "message": { "text": kind },
        }
    })
}

fn physical_location_for_file(file: &Path, range: &semgrep_core::Range) -> Value {
    json!({
        "physicalLocation": physical_location_for_file_inner(file, range)
    })
}

fn physical_location_for_file_inner(file: &Path, range: &semgrep_core::Range) -> Value {
    json!({
        "artifactLocation": { "uri": path_uri(file) },
        "region":           region_from_range(range),
    })
}

fn region_from_range(r: &semgrep_core::Range) -> Value {
    json!({
        "startLine":   r.start.line,
        "startColumn": r.start.column,
        "endLine":     r.end.line,
        "endColumn":   r.end.column,
    })
}

/// Normalise a path into a SARIF `uri`: forward slashes, no leading drive
/// prefix. SARIF spec wants RFC-3986 URIs; absolute Windows paths would
/// otherwise embed backslashes the schema rejects.
fn path_uri(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    // Strip a leading `./` so `./src/foo.rs` and `src/foo.rs` are the same
    // location key in the consumer's UI.
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

/// Severity → SARIF level. SARIF only has `error / warning / note / none`;
/// we collapse `Info` onto `note`, the documented mapping.
fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_mapping() {
        assert_eq!(sarif_level(Severity::Error), "error");
        assert_eq!(sarif_level(Severity::Warning), "warning");
        assert_eq!(sarif_level(Severity::Info), "note");
    }

    #[test]
    fn path_uri_normalises_separators() {
        let p = Path::new("src\\foo.rs");
        assert_eq!(path_uri(p), "src/foo.rs");
    }
}
