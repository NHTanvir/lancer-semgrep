//! Clap derive structs for the full Semgrep-compatible CLI surface.
//!
//! Every flag from plan.md §"Granular feature catalog → CLI surface" and
//! §"CLI flags newly important (2025-2026)" lives in this file. Long names are
//! pinned with `#[arg(long = "...")]` where clap's default derived name does
//! not match upstream (e.g. `no-git-ignore`, `gitlab-sast`).

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Top-level CLI
// ---------------------------------------------------------------------------

/// Top-level CLI.
///
/// The default subcommand when none is supplied is `scan`; flags in
/// [`ScanArgs`] are also accepted directly at the top level via the
/// `#[command(flatten)]` below.
#[derive(Parser, Debug)]
#[command(
    name = "lancer-semgrep",
    version,
    about = "Rust clone of semgrep - part of the Lancer bug bounty toolkit",
    arg_required_else_help = false,
    propagate_version = true,
)]
pub struct Cli {
    /// Subcommand. If omitted, runs `scan` with the global flags.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Force CLI mode (suppress GUI launch in GUI-enabled builds).
    #[arg(long, global = true)]
    pub cli: bool,

    /// Launch the native GUI (default in GUI-enabled builds).
    #[arg(long, global = true)]
    pub gui: bool,

    /// Print only critical messages.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Debug output.
    #[arg(long, global = true)]
    pub debug: bool,

    /// Show supported languages and exit.
    #[arg(long, global = true)]
    pub show_supported_languages: bool,

    /// Run the upstream parity matrix and exit (1 = failure).
    #[arg(long, global = true)]
    pub self_test: bool,

    /// Force terminal color.
    #[arg(long, global = true, conflicts_with = "no_color")]
    pub force_color: bool,

    /// Never use terminal color.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// OpenTelemetry trace export.
    #[arg(long, global = true)]
    pub trace: bool,

    /// OpenTelemetry trace endpoint URL (defaults to localhost:4317).
    #[arg(long, global = true)]
    pub trace_endpoint: Option<String>,

    /// Anonymous usage telemetry.
    #[arg(long, global = true, default_value = "auto", value_enum)]
    pub metrics: Metrics,

    /// Global flags that apply when no subcommand is given (== scan).
    #[command(flatten)]
    pub scan_args: ScanArgs,
}

// ---------------------------------------------------------------------------
// Subcommand enum
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Run rules over one or more targets (default subcommand).
    Scan(ScanArgs),
    /// CI orchestration: detect PR base, run baseline diff, post findings.
    Ci(CiArgs),
    /// Semgrep AppSec auth (OSS-only build stubs this out).
    Login(LoginArgs),
    /// Semgrep AppSec logout (stub).
    Logout,
    /// Push private rules to AppSec (stub).
    Publish(PublishArgs),
    /// Run rule unit tests against `.yaml` + sibling-file pairs.
    Test(TestArgs),
    /// Schema-check rule files.
    Validate(ValidateArgs),
    /// "I should have found that" - report a missed finding (Pro stub).
    Shouldafound(ShouldaArgs),
    /// Install the Semgrep Pro engine (stub).
    InstallSemgrepPro(InstallProArgs),
    /// Start the Model Context Protocol server (Task 10).
    Mcp(McpArgs),
}

// ---------------------------------------------------------------------------
// `scan` arguments — also used as the top-level no-subcommand flag set.
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Default, Clone)]
pub struct ScanArgs {
    // === Config ===
    /// Rule config source(s): path, dir, p/<slug>, r/<id>, URL, or `auto`.
    #[arg(short, long = "config", value_name = "CONFIG", num_args = 1..)]
    pub config: Vec<String>,

    /// Semgrep AppSec config policy (Pro only).
    #[arg(long)]
    pub config_policy: Option<String>,

    /// Preserve original rule IDs in output.
    #[arg(long, conflicts_with = "rewrite_rule_ids")]
    pub no_rewrite_rule_ids: bool,

    /// Rewrite path.to.rule.id into rule.id (default upstream behaviour).
    #[arg(long)]
    pub rewrite_rule_ids: bool,

    /// Cache registry rule packs locally.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub registry_caching: bool,

    // === Targets ===
    /// One or more target paths (default: current directory).
    #[arg(value_name = "TARGETS", default_value = ".")]
    pub targets: Vec<PathBuf>,

    /// Force language (for stdin or unrecognised extensions).
    #[arg(long, value_name = "LANG")]
    pub lang: Option<String>,

    /// Only scan files matching these globs.
    #[arg(long, num_args = 1..)]
    pub include: Vec<String>,

    /// Exclude files matching these globs.
    #[arg(long, num_args = 1..)]
    pub exclude: Vec<String>,

    /// Skip specific rule IDs.
    #[arg(long, num_args = 1..)]
    pub exclude_rule: Vec<String>,

    /// Skip files larger than N bytes (default 1 MB).
    #[arg(long, default_value_t = 1_000_000)]
    pub max_target_bytes: u64,

    /// Try to scan files with unknown extensions (uses content sniffing).
    #[arg(long)]
    pub scan_unknown_extensions: bool,

    /// Use .gitignore (default).
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    pub use_git_ignore: bool,

    /// Disable .gitignore (legacy alias for `--use-git-ignore=false`).
    #[arg(long = "no-git-ignore", action = clap::ArgAction::SetTrue)]
    pub no_git_ignore: bool,

    /// Use git-aware target enumeration.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    pub use_git: bool,

    /// Disable git-aware target enumeration.
    #[arg(long = "no-git", action = clap::ArgAction::SetTrue)]
    pub no_git: bool,

    // === Severity / output filtering ===
    /// Only emit findings at or above this severity.
    #[arg(long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Non-zero exit on parse errors.
    #[arg(long)]
    pub strict: bool,

    /// Non-zero exit if any findings.
    #[arg(long)]
    pub error: bool,

    // === Output formats (one wins; default text) ===
    /// Default human-readable, terminal-coloured output.
    #[arg(long, group = "format")]
    pub text: bool,
    /// Semgrep-native JSON.
    #[arg(long, group = "format")]
    pub json: bool,
    /// SARIF 2.1.0.
    #[arg(long, group = "format")]
    pub sarif: bool,
    /// GitLab SAST report JSON.
    #[arg(long, group = "format")]
    pub gitlab_sast: bool,
    /// GitLab Secrets report JSON.
    #[arg(long, group = "format")]
    pub gitlab_secrets: bool,
    /// JUnit XML.
    #[arg(long, group = "format")]
    pub junit_xml: bool,
    /// Emacs line format (`file:line:col: message`).
    #[arg(long, group = "format")]
    pub emacs: bool,
    /// Vim quickfix line format.
    #[arg(long, group = "format")]
    pub vim: bool,
    /// GitHub Actions `::error file=...::` workflow commands.
    #[arg(long, group = "format")]
    pub github_actions: bool,

    /// Write output to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    // === Baseline / diff ===
    /// Only emit findings introduced since this commit.
    #[arg(long, value_name = "SHA")]
    pub baseline_commit: Option<String>,

    /// Lines of context around each diff hunk to consider.
    #[arg(long, default_value_t = 0)]
    pub diff_depth: usize,

    // === Performance ===
    /// Parallelism (default = `available_parallelism()`).
    #[arg(short = 'j', long, default_value_t = num_cpus())]
    pub jobs: usize,
    /// Memory cap per worker (MB).
    #[arg(long)]
    pub max_memory: Option<u64>,
    /// Per-rule timeout in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Kill a rule after N file timeouts.
    #[arg(long)]
    pub timeout_threshold: Option<usize>,
    /// Emit per-rule timing.
    #[arg(long)]
    pub time: bool,
    /// Memory tuning policy (Pro feature; maps to allocator selection here).
    #[arg(long, value_enum)]
    pub x_mem_policy: Option<MemPolicy>,
    /// Cap on fields tracked per object in dataflow.
    #[arg(long)]
    pub max_fields_tracked_per_object: Option<usize>,

    // === Products ===
    /// Enable Semgrep Code (default if no other product flag set).
    #[arg(long)]
    pub code: bool,
    /// Enable Semgrep Secrets scanning.
    #[arg(long)]
    pub secrets: bool,
    /// Enable Semgrep Supply Chain scanning.
    #[arg(long)]
    pub supply_chain: bool,

    // === Pro / Experimental ===
    /// Turn on experimental engine features.
    #[arg(long)]
    pub enable_experimental: bool,
    /// Use the Pro engine (errors out cleanly in OSS clone).
    #[arg(long)]
    pub pro: bool,
    /// Pro intra-file analysis.
    #[arg(long)]
    pub pro_intrafile: bool,
    /// Pro inter-file analysis.
    #[arg(long)]
    pub pro_interfile: bool,
    /// Emit full taint trace in findings.
    #[arg(long)]
    pub dataflow_traces: bool,
    /// Disable Pro features even if logged in.
    #[arg(long)]
    pub oss_only: bool,
    /// Emit per-finding match-tree explanation (for rule debugging).
    #[arg(long)]
    pub matching_explanations: bool,

    /// Apply each rule's `fix:` template to the source file. Mutually exclusive
    /// with `--dryrun` (Task 13).
    #[arg(long)]
    pub autofix: bool,

    /// Print autofix diffs but do not modify files. Implies `--autofix`.
    #[arg(long)]
    pub dryrun: bool,

    /// AI-assisted severity scoring of findings (plan §"Semgrep 1.120+
    /// → AI-assisted rule generation; `--ai-rank` for severity scoring").
    /// Requires an LLM backend configured via `ANTHROPIC_API_KEY` /
    /// `LANCER_AI_BACKEND`; off-line runs silently no-op.
    #[arg(long)]
    pub ai_rank: bool,
}

// ---------------------------------------------------------------------------
// Other subcommand arg structs
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Default, Clone)]
pub struct CiArgs {
    /// All scan args available.
    #[command(flatten)]
    pub scan: ScanArgs,
    /// Auto-detect PR base for baseline diff.
    #[arg(long)]
    pub auto_baseline: bool,
}

#[derive(Args, Debug, Default, Clone)]
pub struct LoginArgs {
    /// Personal access token (alternative to interactive login).
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct PublishArgs {
    /// Visibility (private | org | public).
    #[arg(long, default_value = "private")]
    pub visibility: String,
    /// Rule files to publish.
    pub rule_files: Vec<PathBuf>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct TestArgs {
    /// Target directory or file pair.
    pub target: PathBuf,
    /// Pattern for sibling test file (defaults to `<rule>.<ext>`).
    #[arg(long)]
    pub test_pattern: Option<String>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct ValidateArgs {
    /// Rule files or dirs to validate.
    pub rule_files: Vec<PathBuf>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct ShouldaArgs {
    /// Vuln report.
    pub report: Option<PathBuf>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct InstallProArgs {
    /// Version to install.
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Args, Debug, Default, Clone)]
pub struct McpArgs {
    /// Transport.
    #[arg(long, default_value = "stdio", value_enum)]
    pub transport: McpTransport,
    /// Bind host (default 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Port (auto when 0).
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Enable OAuth 2.1 (required for non-stdio transports).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub oauth: bool,
}

// ---------------------------------------------------------------------------
// Value enums
// ---------------------------------------------------------------------------

#[derive(ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub enum Metrics {
    #[default]
    Auto,
    On,
    Off,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "UPPER")]
pub enum SeverityFilter {
    Info,
    Warning,
    Error,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub enum MemPolicy {
    Aggressive,
    Balanced,
}

#[derive(ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub enum McpTransport {
    #[default]
    Stdio,
    Http,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
