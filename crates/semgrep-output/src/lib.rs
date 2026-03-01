//! semgrep-output — output format emitters for findings.
//!
//! Formatters covered (one per `OutputFormat` variant):
//!   * Text (terminal-coloured via `owo-colors`).
//!   * JSON — Semgrep-native schema.
//!   * SARIF 2.1.0 — built as `serde_json::Value` (see `sarif.rs` for why).
//!   * GitLab SAST + GitLab Secrets — schema 15.x.
//!   * JUnit XML — via the `junit-report` crate.
//!   * Emacs / Vim — line-oriented editor formats.
//!   * GitHub Actions — `::error file=...::msg` workflow commands.
//!
//! Public surface keeps the trait-driven dispatch flat: one
//! `OutputFormat` enum, one `OutputEmitter` trait, one `emitter()` factory.
//! Downstream code (`lancer-semgrep` CLI, Task 8) wires CLI flags to a
//! single `OutputFormat` and asks `emitter()` for the right writer.
//!
//! See plan.md §"Granular feature catalog → Output formats" and
//! §"Internal architecture → semgrep-output".

pub mod advisory;
pub mod emacs;
pub mod emitter;
pub mod format;
pub mod github_actions;
pub mod gitlab_sast;
pub mod gitlab_secrets;
pub mod json;
pub mod junit;
pub mod report;
pub mod sarif;
pub mod text;
pub mod vim;

pub use advisory::advisory_url;
pub use emitter::{OutputEmitter, OutputError};
pub use format::OutputFormat;
pub use report::{
    ErrorLevel, Paths, RuleTime, ScanError, ScanReport, ScanTime, TargetTime,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Factory: pick the right emitter for the requested wire format.
///
/// Returns a boxed trait object so callers don't have to match the format
/// twice (once at parse time, once at emit time). The returned emitter
/// carries its own defaults — text colour mode is `Auto`, JSON is compact.
/// Callers that need to override defaults (e.g. force pretty JSON) should
/// instantiate the concrete emitter directly.
pub fn emitter(format: OutputFormat) -> Box<dyn OutputEmitter> {
    match format {
        OutputFormat::Text => Box::new(text::TextEmitter::default()),
        OutputFormat::Json => Box::new(json::JsonEmitter::default()),
        OutputFormat::Sarif => Box::new(sarif::SarifEmitter::default()),
        OutputFormat::GitlabSast => Box::new(gitlab_sast::GitlabSastEmitter),
        OutputFormat::GitlabSecrets => {
            Box::new(gitlab_secrets::GitlabSecretsEmitter)
        }
        OutputFormat::JunitXml => Box::new(junit::JunitEmitter),
        OutputFormat::Emacs => Box::new(emacs::EmacsEmitter),
        OutputFormat::Vim => Box::new(vim::VimEmitter),
        OutputFormat::GithubActions => {
            Box::new(github_actions::GithubActionsEmitter)
        }
    }
}
