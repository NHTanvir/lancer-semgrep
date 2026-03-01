//! GitHub Actions log annotations (`--github-actions`).
//!
//! GitHub Actions parses "workflow commands" out of step logs. The relevant
//! ones for static analysis:
//!
//! * `::error file=...,line=...,col=...,endLine=...,endColumn=...,title=...::message`
//! * `::warning ... ::message`
//! * `::notice ... ::message`
//! * `::group::NAME` ... `::endgroup::` — collapse a set of related
//!    annotations under one header.
//!
//! Reference:
//! <https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions>
//!
//! We wrap each finding in a `::group::<rule-id>` ... `::endgroup::` pair so
//! the Actions UI shows one collapsible block per finding, which is much
//! more navigable on PRs with hundreds of hits.

use std::io::Write;

use semgrep_core::Severity;

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

#[derive(Debug, Default, Clone)]
pub struct GithubActionsEmitter;

impl OutputEmitter for GithubActionsEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        for f in &report.findings {
            let cmd = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "notice",
            };
            // Sanitise the message: GitHub treats `%`, `\r`, `\n` specially
            // and will swallow the rest of the message if it sees a raw
            // newline. Per their docs, we URL-encode those three characters.
            let msg = encode_workflow_data(&f.message);
            let title = encode_workflow_property(f.rule_id.as_str());
            let file = encode_workflow_property(&f.file.to_string_lossy());

            writeln!(out, "::group::{}", f.rule_id.as_str())?;
            writeln!(
                out,
                "::{cmd} file={file},line={line},col={col},endLine={end_line},endColumn={end_col},title={title}::{msg}",
                cmd = cmd,
                file = file,
                line = f.range.start.line,
                col = f.range.start.column,
                end_line = f.range.end.line,
                end_col = f.range.end.column,
                title = title,
                msg = msg,
            )?;
            writeln!(out, "::endgroup::")?;
        }
        Ok(())
    }
}

/// Encode the *data* part of a workflow command (after `::cmd ...::`).
/// Per GitHub's spec, `%`, `\r`, `\n` must be URL-encoded.
fn encode_workflow_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Encode a *property value* (`file=`, `title=` etc.). Adds `:` and `,` to
/// the escape set since commas and colons separate the key/value pairs.
fn encode_workflow_property(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_data_escapes_newlines() {
        assert_eq!(encode_workflow_data("a\nb"), "a%0Ab");
        assert_eq!(encode_workflow_data("100%"), "100%25");
    }

    #[test]
    fn encode_property_escapes_commas() {
        assert_eq!(encode_workflow_property("a,b"), "a%2Cb");
        assert_eq!(encode_workflow_property("a:b"), "a%3Ab");
    }
}
