//! Target-file vocabulary for the scan orchestrator.
//!
//! `TargetFile` is the per-file unit handed from enumeration into parsing /
//! matching. `EnumerateOpts` collects the filesystem-walk knobs that map onto
//! the CLI flags (`--include`, `--exclude`, `--max-target-bytes`, ...).
//!
//! See plan.md §"Internal architecture → semgrep-core" and §"How a rule
//! executes" step 2.

use std::path::PathBuf;

use crate::Language;

/// One file the engine has been asked to analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetFile {
    pub path: PathBuf,
    pub language: Language,
    pub size_bytes: u64,
}

/// Filesystem-walk knobs for [`crate::scan::enumerate::enumerate_targets`].
///
/// Defaults match upstream Semgrep: 1 MB size cap, .gitignore + .semgrepignore
/// honoured, unknown extensions skipped.
#[derive(Debug, Clone)]
pub struct EnumerateOpts {
    /// Include globs — only files matching at least one are kept (empty ⇒ no
    /// constraint).
    pub include: Vec<String>,
    /// Exclude globs — files matching any are dropped.
    pub exclude: Vec<String>,
    /// Skip files larger than this many bytes.
    pub max_target_bytes: u64,
    /// Honour `.gitignore` (and `.git/info/exclude`).
    pub use_git_ignore: bool,
    /// Honour `.semgrepignore`.
    pub use_semgrep_ignore: bool,
    /// Force every visited file to this language (overrides extension).
    pub force_language: Option<Language>,
    /// When true, files whose extension doesn't map to any language are still
    /// included (under `Language::Generic`).
    pub scan_unknown_extensions: bool,
}

impl Default for EnumerateOpts {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            max_target_bytes: 1_000_000,
            use_git_ignore: true,
            use_semgrep_ignore: true,
            force_language: None,
            scan_unknown_extensions: false,
        }
    }
}
