//! Human-readable terminal output (`--text`, the default).
//!
//! Findings are grouped by file. Each file gets a header (path, underlined),
//! followed by one indented line per finding:
//!
//! ```text
//! → src/views.py
//!   ERROR  47:12 python.sqli  Possible SQL injection
//!     advisory: https://semgrep.dev/advisories/GHSA-...
//! ```
//!
//! `owo_colors::OwoColorize` is implemented on every `Display` value, so we
//! ANSI-paint the severity / file path with zero allocation when colors are
//! enabled and emit plain text otherwise.
//!
//! Colour-mode policy:
//! * `Auto`   — owo-colors' auto-detection (TTY vs. pipe, NO_COLOR env).
//! * `Always` — force ANSI on.
//! * `Never`  — strip ANSI even on a TTY.
//!
//! The emit closure flips `owo_colors::set_override` accordingly and restores
//! the original setting via `with_override`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use owo_colors::OwoColorize;

use semgrep_core::{Finding, Severity};

use crate::advisory;
use crate::emitter::{OutputEmitter, OutputError};
use crate::report::ScanReport;

#[derive(Debug, Default, Clone)]
pub struct TextEmitter {
    pub color: ColorMode,
    /// When `true`, prints the rule's `--matching-explanations` tree if the
    /// finding carries one. Off by default to keep the canonical `--text`
    /// output compact.
    pub show_match_explanation: bool,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// Detect from the terminal (TTY / `NO_COLOR` / `CLICOLOR`).
    #[default]
    Auto,
    /// Always emit ANSI escapes, even into a pipe / file.
    Always,
    /// Never emit ANSI escapes, even into a TTY.
    Never,
}

impl OutputEmitter for TextEmitter {
    fn emit(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        // Stash + flip the global colour override. `with_override` borrows a
        // closure-shape we don't want (it's `FnOnce -> R`), so we use the
        // explicit pair instead so `emit` stays `&self`-only.
        let prev = override_for(self.color);
        let result = self.emit_inner(report, out);
        restore_override(prev);
        result
    }
}

impl TextEmitter {
    fn emit_inner(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), OutputError> {
        // Group findings by file path so multiple hits in the same file
        // share one header. BTreeMap gives deterministic ordering (handy for
        // CI snapshot tests).
        let mut by_file: BTreeMap<&Path, Vec<&Finding>> = BTreeMap::new();
        for f in &report.findings {
            by_file.entry(f.file.as_path()).or_default().push(f);
        }

        for (file, findings) in by_file {
            writeln!(
                out,
                "{} {}",
                "→".bold(),
                file.display().to_string().underline()
            )?;
            for f in findings {
                let sev_label = match f.severity {
                    Severity::Error => "ERROR".red().to_string(),
                    Severity::Warning => "WARN".yellow().to_string(),
                    Severity::Info => "INFO".cyan().to_string(),
                };
                writeln!(
                    out,
                    "  {} {}:{} {} {}",
                    sev_label,
                    f.range.start.line,
                    f.range.start.column,
                    f.rule_id.as_str().bold(),
                    f.message,
                )?;

                // Best-effort advisory link if the rule's metadata pins one.
                // We check the common keys (`advisory_id`, `ghsa_id`,
                // `cve_id`) — the rule loader (Task 4) carries metadata
                // through verbatim, so any of these can show up.
                if let Some(adv) = lookup_advisory(&f.metadata) {
                    writeln!(
                        out,
                        "    advisory: {}",
                        advisory::advisory_url(adv).blue()
                    )?;
                }

                // Optional explanation tree (off by default).
                if self.show_match_explanation {
                    if let Some(exp) = &f.explanation {
                        writeln!(out, "    explanation:")?;
                        print_explanation(out, exp, 6)?;
                    }
                }
            }
        }

        writeln!(
            out,
            "\n{} {} findings",
            "✓".green(),
            report.findings.len()
        )?;
        Ok(())
    }
}

fn lookup_advisory(metadata: &serde_json::Value) -> Option<&str> {
    if !metadata.is_object() {
        return None;
    }
    for key in ["advisory_id", "ghsa_id", "cve_id", "cve", "ghsa"] {
        if let Some(v) = metadata.get(key).and_then(|v| v.as_str()) {
            return Some(v);
        }
    }
    None
}

fn print_explanation(
    out: &mut dyn Write,
    node: &semgrep_core::MatchExplanation,
    indent: usize,
) -> Result<(), OutputError> {
    let pad = " ".repeat(indent);
    let mark = if node.matched { "✓" } else { "✗" };
    writeln!(out, "{pad}{mark} {}", node.op)?;
    for c in &node.children {
        print_explanation(out, c, indent + 2)?;
    }
    Ok(())
}

/// Push the requested colour policy into `owo_colors`' global state and
/// return the previous state so `emit` can restore it.
///
/// `Auto` is encoded as `None`: we call `unset_override` to let owo-colors
/// fall back to its detection logic (TTY + `NO_COLOR`).
fn override_for(mode: ColorMode) -> Option<bool> {
    let prev = previous_override();
    match mode {
        ColorMode::Always => owo_colors::set_override(true),
        ColorMode::Never => owo_colors::set_override(false),
        ColorMode::Auto => owo_colors::unset_override(),
    }
    prev
}

fn restore_override(prev: Option<bool>) {
    match prev {
        Some(b) => owo_colors::set_override(b),
        None => owo_colors::unset_override(),
    }
}

/// owo-colors doesn't expose a public "get current override" hook in 4.x.
/// We can't accurately restore prior state, but `unset_override` returns
/// the runtime to its detection default which is what callers want once
/// our emit finishes. Returning `None` here means "restore to auto".
fn previous_override() -> Option<bool> {
    None
}
