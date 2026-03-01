//! Collapse the raw boolean output-format flags onto a single
//! [`semgrep_output::OutputFormat`] value.
//!
//! Even though clap's `group = "format"` rejects multiple format flags at
//! parse time, we still funnel through `OutputFormat::from_flags` so the
//! upstream-documented priority order (sarif > gitlab-sast > ... > text)
//! kicks in if the constraint is relaxed in the future.

use crate::cli::args::ScanArgs;
use semgrep_output::OutputFormat;

pub fn select_format(a: &ScanArgs) -> OutputFormat {
    OutputFormat::from_flags(
        a.json,
        a.sarif,
        a.gitlab_sast,
        a.gitlab_secrets,
        a.junit_xml,
        a.emacs,
        a.vim,
        a.github_actions,
    )
}
