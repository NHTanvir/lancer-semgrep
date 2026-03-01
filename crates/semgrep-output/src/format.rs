//! Output-format selector.
//!
//! `OutputFormat` enumerates the wire formats the CLI can emit. `from_flags`
//! folds the raw `--json` / `--sarif` / ... booleans coming off Clap into a
//! single enum value with a documented priority order.
//!
//! See plan.md §"Granular feature catalog → Output formats".

/// One of the formats the engine knows how to serialize findings into.
///
/// New variants land here first; the emitter dispatch in `lib::emitter()`
/// must stay exhaustive over this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    /// Default human-readable, terminal-coloured output.
    Text,
    /// Semgrep-native JSON (the `results: [...]` shape).
    Json,
    /// SARIF 2.1.0 — the GitHub code-scanning / Azure DevOps interchange format.
    Sarif,
    /// GitLab SAST report JSON.
    GitlabSast,
    /// GitLab Secrets-detection report JSON (same schema family, different
    /// `category`).
    GitlabSecrets,
    /// JUnit XML — one testsuite, one testcase per finding.
    JunitXml,
    /// `file:line:column: message` lines for emacs `M-x grep` mode.
    Emacs,
    /// `file:line:col:[E|W|I] message` lines for vim's quickfix list.
    Vim,
    /// `::error file=...,line=...::message` workflow commands for GitHub
    /// Actions log annotations.
    GithubActions,
}

impl OutputFormat {
    /// Pick a single format from the parsed CLI boolean flags.
    ///
    /// Priority (first match wins): `sarif > gitlab_sast > gitlab_secrets >
    /// junit_xml > json > emacs > vim > github_actions > text`. The ordering
    /// matches upstream Semgrep so users who pass `--json --sarif` together
    /// (which Clap's `conflicts_with` blocks anyway) get the structured-most
    /// format, not a silent demotion to plain JSON.
    #[allow(clippy::too_many_arguments)]
    pub fn from_flags(
        json: bool,
        sarif: bool,
        gitlab_sast: bool,
        gitlab_secrets: bool,
        junit_xml: bool,
        emacs: bool,
        vim: bool,
        github_actions: bool,
    ) -> Self {
        if sarif {
            return Self::Sarif;
        }
        if gitlab_sast {
            return Self::GitlabSast;
        }
        if gitlab_secrets {
            return Self::GitlabSecrets;
        }
        if junit_xml {
            return Self::JunitXml;
        }
        if json {
            return Self::Json;
        }
        if emacs {
            return Self::Emacs;
        }
        if vim {
            return Self::Vim;
        }
        if github_actions {
            return Self::GithubActions;
        }
        Self::Text
    }
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_text() {
        let f = OutputFormat::from_flags(false, false, false, false, false, false, false, false);
        assert_eq!(f, OutputFormat::Text);
    }

    #[test]
    fn sarif_wins_over_json() {
        let f = OutputFormat::from_flags(true, true, false, false, false, false, false, false);
        assert_eq!(f, OutputFormat::Sarif);
    }

    #[test]
    fn gitlab_sast_wins_over_json() {
        let f = OutputFormat::from_flags(true, false, true, false, false, false, false, false);
        assert_eq!(f, OutputFormat::GitlabSast);
    }

    #[test]
    fn emacs_picked_when_only_flag_set() {
        let f = OutputFormat::from_flags(false, false, false, false, false, true, false, false);
        assert_eq!(f, OutputFormat::Emacs);
    }
}
