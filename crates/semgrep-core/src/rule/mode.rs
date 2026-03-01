//! Top-level rule mode tag.
//!
//! Each rule declares one of these via `mode:` in YAML. `search` is the
//! historical default (omitted in older rules); modern rules tend to write it
//! explicitly. See plan.md §"Newer rule-format features to support (2025–2026)".

use serde::{Deserialize, Serialize};

/// What kind of analysis the rule drives.
///
/// - `Search` — classic AST pattern matching (the default).
/// - `Taint`  — forward dataflow taint analysis.
/// - `Join`   — multi-rule cross-file join on shared metavariables.
/// - `Extract` — extract a sub-snippet (e.g. embedded SQL in Python) and rescan
///   it under a different language's rules.
/// - `Secrets` — entropy + regex + optional HTTP validator (Semgrep Secrets
///   product).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Search,
    Taint,
    Join,
    Extract,
    Secrets,
}

impl Default for RuleMode {
    fn default() -> Self {
        RuleMode::Search
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_round_trip() {
        for &m in &[
            RuleMode::Search,
            RuleMode::Taint,
            RuleMode::Join,
            RuleMode::Extract,
            RuleMode::Secrets,
        ] {
            let s = serde_yaml::to_string(&m).unwrap();
            let back: RuleMode = serde_yaml::from_str(&s).unwrap();
            assert_eq!(m, back);
        }
    }

    #[test]
    fn taint_yaml_is_lowercase() {
        let s = serde_yaml::to_string(&RuleMode::Taint).unwrap();
        assert!(s.contains("taint"), "yaml = {s:?}");
    }
}
