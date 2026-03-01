//! Autofix templates.
//!
//! Two flavours, mirroring upstream Semgrep:
//!
//! - **`fix:`** — a code template with `$X` placeholders that are substituted
//!   with the corresponding metavariable bindings from the match. The
//!   resulting text replaces the matched range. Substitution lives in
//!   `autofix/fix.rs` (Task 8).
//! - **`fix-regex:`** — a `regex` + `replacement` pair applied to the matched
//!   slice. Optional `count` caps the number of substitutions. Substitution
//!   lives in `autofix/fix_regex.rs`.

use serde::{Deserialize, Serialize};

/// Code template with `$X` metavariable placeholders.
///
/// Stored as the raw template string; the `autofix` module performs
/// substitution + diff synthesis later. We deliberately avoid pre-parsing the
/// template here because the placeholder syntax overlaps with the language's
/// own `$`-using syntax (e.g. shell, Perl-style variables) and parsing is
/// language-aware in Task 8.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct FixTemplate(pub String);

impl FixTemplate {
    pub fn new(template: impl Into<String>) -> Self {
        Self(template.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for FixTemplate {
    fn from(s: String) -> Self {
        FixTemplate(s)
    }
}

impl From<&str> for FixTemplate {
    fn from(s: &str) -> Self {
        FixTemplate(s.to_string())
    }
}

/// Regex-based fix.
///
/// YAML shape:
/// ```yaml
/// fix-regex:
///   regex: "pickle\\.loads"
///   replacement: "json.loads"
///   count: 1
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FixRegex {
    /// Regex applied to the matched span's bytes.
    pub regex: String,
    /// Replacement template — supports `regex` crate capture-group syntax
    /// (`$1`, `${name}`).
    pub replacement: String,
    /// Cap on number of substitutions per match (`None` = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
}

impl FixRegex {
    pub fn new(regex: impl Into<String>, replacement: impl Into<String>) -> Self {
        Self {
            regex: regex.into(),
            replacement: replacement.into(),
            count: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_template_transparent_yaml() {
        let ft = FixTemplate::new("foo($X)");
        let yaml = serde_yaml::to_string(&ft).unwrap();
        assert!(yaml.contains("foo($X)"), "yaml = {yaml:?}");
        let back: FixTemplate = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(ft, back);
    }

    #[test]
    fn fix_regex_round_trip() {
        let yaml = "regex: 'pickle\\.loads'\nreplacement: 'json.loads'\ncount: 1\n";
        let fr: FixRegex = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(fr.count, Some(1));
        let back = serde_yaml::to_string(&fr).unwrap();
        let again: FixRegex = serde_yaml::from_str(&back).unwrap();
        assert_eq!(fr, again);
    }
}
