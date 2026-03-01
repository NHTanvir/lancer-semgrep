//! Vim quickfix line emitter (`--vim`).
//!
//! Vim's quickfix system parses `file:line:col:[E|W|I] message` lines
//! (the `errorformat` setting can be customised, but this is the default
//! shape that `:cnext` works with). We tack on the rule ID at the end so
//! `:copen` shows it inline.
//!
//! ```text
//! src/views.py:47:12:[E] Possible SQL injection (python.sqli)
//! ```

use std::io::Write;

use semgrep_core::Severity;

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

#[derive(Debug, Default, Clone)]
pub struct VimEmitter;

impl OutputEmitter for VimEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        for f in &report.findings {
            let sev = match f.severity {
                Severity::Error => 'E',
                Severity::Warning => 'W',
                Severity::Info => 'I',
            };
            writeln!(
                out,
                "{}:{}:{}:[{}] {} ({})",
                f.file.display(),
                f.range.start.line,
                f.range.start.column,
                sev,
                f.message,
                f.rule_id.as_str(),
            )?;
        }
        Ok(())
    }
}
