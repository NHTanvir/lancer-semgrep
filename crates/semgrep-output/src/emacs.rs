//! Emacs grep-mode line emitter (`--emacs`).
//!
//! `M-x grep` parses lines of the form `file:line:column: message`. We
//! append the rule ID in parentheses so the user can see what fired without
//! having to switch buffers:
//!
//! ```text
//! src/views.py:47:12: Possible SQL injection (python.sqli)
//! ```

use std::io::Write;

use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

#[derive(Debug, Default, Clone)]
pub struct EmacsEmitter;

impl OutputEmitter for EmacsEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        for f in &report.findings {
            writeln!(
                out,
                "{}:{}:{}: {} ({})",
                f.file.display(),
                f.range.start.line,
                f.range.start.column,
                f.message,
                f.rule_id.as_str(),
            )?;
        }
        Ok(())
    }
}
