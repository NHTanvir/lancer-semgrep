//! Entry-points for loading YAML rule files into a [`RuleSet`].
//!
//! The pipeline is:
//!
//! 1. Parse the top-level YAML into a [`RulesFile`] of `serde_yaml::Value`s
//!    (one Value per rule). This is intentionally untyped so we can rewrite
//!    bare-string shorthand before strict deserialisation.
//! 2. For each rule value:
//!    - Walk it with [`canonicalise_yaml`] to expand bare-string shorthand
//!      for `pattern-not` / `pattern-inside` / `pattern-not-inside`.
//!    - Deserialise into a [`Rule`].
//!    - [`validate_rule`] enforces mode-specific invariants.
//! 3. Push valid rules into the result [`RuleSet`].
//!
//! See plan.md §"How a rule executes" step 1.

use std::io::Read;
use std::path::{Path, PathBuf};

use semgrep_core::Rule;
use serde::Deserialize;

use crate::canonicalise::canonicalise_yaml;
use crate::error::LoadError;
use crate::ruleset::RuleSet;
use crate::schema::validate_rule;

/// Top-level YAML shape: `{ rules: [...] }`.
#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<serde_yaml::Value>,
}

/// Parse a YAML string into a [`RuleSet`].
///
/// `source` is used in error messages to identify which file / blob the
/// error came from. Pass the file path, the URL, or `"inline"` etc.
pub fn load_str(yaml: &str, source: impl Into<String>) -> Result<RuleSet, LoadError> {
    let source: String = source.into();
    let file: RulesFile = serde_yaml::from_str(yaml).map_err(|e| LoadError::Yaml {
        source: source.clone(),
        error: e,
    })?;

    let mut rules = Vec::with_capacity(file.rules.len());
    for (idx, mut value) in file.rules.into_iter().enumerate() {
        canonicalise_yaml(&mut value);
        let rule: Rule = serde_yaml::from_value(value).map_err(|e| LoadError::RuleParse {
            source: source.clone(),
            index: idx,
            error: e,
        })?;
        validate_rule(&rule)?;
        rules.push(rule);
    }

    Ok(RuleSet::from(rules))
}

/// Load a single YAML file from disk.
pub fn load_file(path: impl AsRef<Path>) -> Result<RuleSet, LoadError> {
    let path = path.as_ref();
    let yaml = std::fs::read_to_string(path).map_err(|e| LoadError::Io {
        path: path.to_path_buf(),
        error: e,
    })?;
    load_str(&yaml, path.display().to_string())
}

/// Recursively load every `*.yaml` / `*.yml` file under `dir`.
///
/// Files that fail to load propagate their error and abort the walk. This is
/// the upstream Semgrep behaviour for `--config <dir>` — partial loads are
/// considered a hard error.
pub fn load_dir(dir: impl AsRef<Path>) -> Result<RuleSet, LoadError> {
    let dir = dir.as_ref();
    let mut combined = RuleSet::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(|x| x.to_str());
        if matches!(ext, Some("yaml") | Some("yml")) {
            combined.extend(load_file(p)?);
        }
    }
    Ok(combined)
}

/// Load rules from any `Read` source (stdin, network response, decompressed buffer).
pub fn load_reader<R: Read>(r: &mut R, source: impl Into<String>) -> Result<RuleSet, LoadError> {
    let source: String = source.into();
    let mut s = String::new();
    r.read_to_string(&mut s).map_err(|e| LoadError::Io {
        path: PathBuf::from(&source),
        error: e,
    })?;
    load_str(&s, source)
}
