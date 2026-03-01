//! A rule pack fetched from the Semgrep Registry.
//!
//! Holds the raw YAML; conversion into a [`crate::RuleSet`] is done by
//! `load_str` on the consumer side. The pack metadata (`id`, `source_url`,
//! `version`) is preserved so callers can attribute findings or display the
//! source in the UI.

/// One Semgrep Registry rule pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePack {
    /// Slug or rule id ("p/python", "r/python.lang.security.dangerous-eval").
    pub id: String,
    /// Original URL the pack was fetched from.
    pub source_url: String,
    /// Raw YAML text. Pass to `load_str` to obtain a `RuleSet`.
    pub yaml: String,
    /// Optional version pin (Semgrep's `version:` header, when present).
    pub version: Option<String>,
}

impl RulePack {
    pub fn new(
        id: impl Into<String>,
        source_url: impl Into<String>,
        yaml: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            source_url: source_url.into(),
            yaml: yaml.into(),
            version: None,
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}
