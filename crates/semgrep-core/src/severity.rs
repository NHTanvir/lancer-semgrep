//! Severity / confidence / likelihood / impact scoring enums.
//!
//! Semgrep itself ships only `severity:` as a first-class rule field
//! (`INFO` / `WARNING` / `ERROR`). The other three live inside the rule's
//! free-form `metadata:` object (used by AppSec / Multimodal triage and by
//! many community rule packs to express "low/medium/high"). We surface them as
//! typed enums so callers can ergonomically read them out of metadata.
//!
//! See plan.md §"Granular feature catalog — Rule format".

use serde::{Deserialize, Serialize};

/// Rule severity. Round-trips as upper-case YAML / JSON (`INFO`, `WARNING`,
/// `ERROR`) per Semgrep convention.
///
/// Ordering is `Info < Warning < Error`, matching `--severity` threshold
/// semantics: `--severity WARNING` shows `Warning` and `Error` findings.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    /// True iff `self` is at least as severe as `threshold`.
    pub fn meets(self, threshold: Severity) -> bool {
        self >= threshold
    }
}

/// How sure are we this is a real finding (low → high)?
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// How likely is exploitation in practice?
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum Likelihood {
    Low,
    Medium,
    High,
}

/// How bad would exploitation be if it happened?
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    Low,
    Medium,
    High,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert!(Severity::Error.meets(Severity::Info));
        assert!(!Severity::Info.meets(Severity::Error));
    }

    #[test]
    fn severity_serde_uppercase() {
        let yaml = serde_yaml::to_string(&Severity::Warning).unwrap();
        assert!(yaml.contains("WARNING"), "yaml = {yaml:?}");
        let back: Severity = serde_yaml::from_str("ERROR\n").unwrap();
        assert_eq!(back, Severity::Error);
    }

    #[test]
    fn confidence_round_trip() {
        let json = serde_json::to_string(&Confidence::High).unwrap();
        assert_eq!(json, "\"HIGH\"");
        let back: Confidence = serde_json::from_str("\"LOW\"").unwrap();
        assert_eq!(back, Confidence::Low);
    }
}
