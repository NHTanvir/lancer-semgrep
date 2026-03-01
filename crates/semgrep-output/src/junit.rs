//! JUnit XML emitter (`--junit-xml`).
//!
//! Many CI systems (Jenkins, CircleCI, Buildkite, GitLab's "Tests" tab) treat
//! JUnit XML as the canonical "tests ran, here's how they did" format even
//! for non-test workloads. We expose one testsuite (`lancer-semgrep`) with
//! one testcase per finding — failures populate the `<failure>` body with
//! the rule message and `file:line` reference.
//!
//! `junit-report` 0.8 surfaces `Report::new()`, `TestSuite::new(name)`,
//! `TestCase::failure(name, duration, type_, message)`, and
//! `Report::write_xml(&self, sink)`. We use the direct constructors rather
//! than the builders — the spec for this task is "one testsuite, one
//! testcase per finding" and the direct API is the shortest path to that.

use std::io::Write;

use junit_report::{Duration, Report, TestCase, TestSuite};

use semgrep_core::Finding;

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

#[derive(Debug, Default, Clone)]
pub struct JunitEmitter;

impl OutputEmitter for JunitEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        let junit = build_report(report);
        junit
            .write_xml(out)
            .map_err(|e| OutputError::Format(format!("junit write_xml failed: {e}")))?;
        Ok(())
    }
}

/// Build a `junit_report::Report` from a scan report.
///
/// One `<testsuite>` named `lancer-semgrep`, one `<testcase>` per finding.
/// Each testcase carries a `<failure>` element whose:
/// * `type` = the rule ID (so CI can group by rule), and
/// * `message` = the rendered finding message (after metavar interpolation).
fn build_report(report: &ScanReport) -> Report {
    let mut suite = TestSuite::new("lancer-semgrep");
    for f in &report.findings {
        suite.add_testcase(build_testcase(f));
    }
    let mut r = Report::new();
    r.add_testsuite(suite);
    r
}

fn build_testcase(f: &Finding) -> TestCase {
    // CI dashboards group testcases by `name`; `file:line` makes the row
    // clickable / sortable, and disambiguates multiple hits in the same file.
    let name = format!(
        "{}:{}",
        f.file.to_string_lossy(),
        f.range.start.line,
    );
    TestCase::failure(
        &name,
        Duration::ZERO,
        f.rule_id.as_str(),
        &f.message,
    )
}
