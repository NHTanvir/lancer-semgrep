//! semgrep-core — rule engine vocabulary + matcher + taint orchestration.
//!
//! This crate defines the shared type vocabulary used across the rest of the
//! workspace: languages, AST nodes, severities, rules (search / taint / join /
//! extract / secrets), pattern operators, matches, findings, taint-types, and
//! the central error enum. Subsequent tasks fill in the actual engine modules
//! (`parse/`, `match_/`, `taint/`, `autofix/`, `cache/`, `baseline/`, ...).
//!
//! See plan.md §"Internal architecture" and §"Granular feature catalog".

// ---------------------------------------------------------------------------
// Core type modules
// ---------------------------------------------------------------------------

pub mod autofix;
pub mod baseline;
pub mod cache;
pub mod error;
pub mod explain;
pub mod finding;
pub mod generic;
pub mod lang;
pub mod match_;
pub mod node;
pub mod rule;
pub mod scan;
pub mod secrets;
pub mod severity;
pub mod supply_chain;
pub mod taint_types;

// ---------------------------------------------------------------------------
// Crate version
// ---------------------------------------------------------------------------

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Top-level re-exports
//
// Keep this list curated: anything that downstream crates use *frequently*
// should be at the crate root. Anything mode-specific (e.g. SecretsRuleConfig)
// stays accessible via its sub-module.
// ---------------------------------------------------------------------------

pub use error::{Result, SemgrepError};
pub use lang::Language;
pub use node::{CanonicalKind, Position, Range, SgNode, Span};
pub use severity::{Confidence, Impact, Likelihood, Severity};

pub use finding::{
    DataflowTrace, Finding, FixSuggestion, MatchExplanation, MetavarBindingSnapshot,
    ValidationState,
};

pub use rule::{
    ComparisonAst, DependsOnConstraint, ExtractRuleConfig, FixRegex, FixTemplate,
    JoinKey, JoinRef, JoinRuleConfig, JoinSubRule, MetavariableComparison,
    MetavariablePatternBody, MetavariableTypeBody, Options, PathFilter, PatternOp,
    ProjectDependsOnBody, Rule, RuleId, RuleMode, SecretValidator, SecretsRuleConfig,
    TaintPropagator, TaintRuleConfig, TaintSanitizer, TaintSink, TaintSource,
    ValidatorHttp, ValidatorMatch, DEFAULT_VALIDATOR_TIMEOUT_SECS,
};

pub use match_::{
    Checkpoint, Match, MatchExplanationNode, MatchScope, MetavarBindClash, MetavarBindings,
};

pub use taint_types::{
    RequiresExpr, RequiresParseError, TaintLabel, TaintLabelSet, TaintState,
};

// Orchestration / cache / baseline / supply-chain / secrets (Task 9).
pub use baseline::{diff_against, finding_in_diff, BaselineMap, HunkRange};
pub use cache::{RuleCache, TargetCache};
pub use scan::{detect_lang, enumerate_targets, EnumerateOpts, TargetFile};
pub use secrets::{shannon_entropy, SecretValidatorRunner};
pub use supply_chain::{
    detect_manifest, evaluate_depends_on, export_sbom, lockfile_less_supported,
    parse_manifest, read_local_build_env, reachability_supported,
    reachability_supported_list, supports_lockfile_less, version_matches, DepDecl,
    LocalBuildEnv, ManifestKind, SbomFormat,
};

// Autofix synthesis + match-tree explanations (Task 12).
pub use autofix::{
    apply_regex_fix, apply_template_fix, apply_to_file as apply_autofix,
    ApplyResult as AutofixApplyResult,
};
pub use explain::MatchTreeBuilder;
