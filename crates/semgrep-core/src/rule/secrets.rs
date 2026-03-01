//! `mode: secrets` rule configuration.
//!
//! Semgrep Secrets rules combine: (a) high-entropy / regex pattern detection
//! to surface candidate credentials, and (b) optional **validators** that
//! make a live HTTP request against the suspected secret and classify the
//! response as VALID / INVALID. See plan.md §"Semgrep Secrets" and
//! §"Newer rule-format features (2025–2026) — Per-rule validators".
//!
//! Validators time out at 30 seconds by default (down from 15 minutes pre-Mar
//! 2026).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::rule::pattern::PatternOp;

/// Default validator timeout in seconds (Semgrep Mar 2026 change).
pub const DEFAULT_VALIDATOR_TIMEOUT_SECS: u64 = 30;

/// `mode: secrets` rule block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct SecretsRuleConfig {
    /// One or more pattern operators selecting candidate secret tokens. Each
    /// pattern is run independently and its matches funnelled through the
    /// validators (if any).
    pub patterns: Vec<PatternOp>,

    /// Optional minimum Shannon entropy (bits) — candidates below this are
    /// rejected. Reduces FP rate on short matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_entropy: Option<f64>,

    /// Zero or more HTTP validators. A finding gets `ValidationState::Valid`
    /// if any validator's `valid:` block matches the response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validators: Vec<SecretValidator>,
}

/// A single validator entry. Pairs the HTTP request to issue with the
/// response criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecretValidator {
    pub http: ValidatorHttp,
    /// Criteria for marking the secret as VALID.
    pub valid: ValidatorMatch,
    /// Optional criteria for marking the secret as definitely INVALID. If
    /// neither `valid` nor `invalid` match, the state is `ValidationError`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid: Option<ValidatorMatch>,
}

/// HTTP request issued by a validator. The request body and URL may contain
/// `$SECRET` placeholders that the engine substitutes with the matched
/// credential before sending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ValidatorHttp {
    /// HTTP method (`GET`, `POST`, `PUT`, ...).
    pub method: String,
    /// Target URL. May contain `$SECRET` / metavariable placeholders.
    pub url: String,
    /// Request headers. Values may contain placeholders.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Optional request body string. May contain placeholders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Hard timeout for the request. Defaults to
    /// [`DEFAULT_VALIDATOR_TIMEOUT_SECS`] seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    DEFAULT_VALIDATOR_TIMEOUT_SECS
}

impl Default for ValidatorHttp {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            url: String::new(),
            headers: BTreeMap::new(),
            body: None,
            timeout_secs: DEFAULT_VALIDATOR_TIMEOUT_SECS,
        }
    }
}

/// Criteria a validator response must satisfy to be classified as VALID (or
/// explicitly INVALID).
///
/// Any number of criteria may be set; all set criteria must match
/// (logical AND). If none are set, the response is treated as not matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct ValidatorMatch {
    /// Expected HTTP status code (e.g. `200`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Regex applied to the response body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_regex: Option<String>,
    /// `(header-name, regex)` pair applied to a specific response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_regex: Option<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secret_validator_yaml() {
        let yaml = "
patterns:
  - pattern-regex: 'ghp_[A-Za-z0-9]{36}'
min-entropy: 4.0
validators:
  - http:
      method: GET
      url: 'https://api.github.com/user'
      headers:
        Authorization: 'Bearer $SECRET'
    valid:
      status-code: 200
      body-regex: '\"login\"'
";
        let cfg: SecretsRuleConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.min_entropy, Some(4.0));
        assert_eq!(cfg.validators.len(), 1);
        assert_eq!(cfg.validators[0].http.method, "GET");
        assert_eq!(
            cfg.validators[0].http.timeout_secs,
            DEFAULT_VALIDATOR_TIMEOUT_SECS
        );
        assert_eq!(cfg.validators[0].valid.status_code, Some(200));
    }
}
