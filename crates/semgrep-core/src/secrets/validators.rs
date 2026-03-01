//! Live `validators:` HTTP runner for Secrets mode.
//!
//! Per plan §"Research note → Secrets: 30-sec timeout (Mar 2026)" — the
//! upstream brought the validator timeout down from 15 min to 30 s. We use
//! the same 30 s cap. The candidate secret is substituted into the
//! `{secret}` placeholder inside the validator request body / header values.

use std::time::Duration;

use reqwest::Client;

use crate::rule::{SecretValidator, ValidatorMatch};
use crate::ValidationState;

/// Default validator timeout (30 seconds per Mar 2026 upstream change).
pub const DEFAULT_VALIDATOR_TIMEOUT: Duration = Duration::from_secs(30);

/// Issues a single HTTP request per validator, substitutes the candidate
/// secret, and classifies the response.
pub struct SecretValidatorRunner {
    client: Client,
}

impl Default for SecretValidatorRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretValidatorRunner {
    /// Build a runner with the default 30 s timeout.
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(DEFAULT_VALIDATOR_TIMEOUT)
            .user_agent(concat!(
                "lancer-semgrep/",
                env!("CARGO_PKG_VERSION"),
                " (+secrets-validator)"
            ))
            .build()
            .expect("reqwest client should always build with these options");
        Self { client }
    }

    /// Substitute the candidate into the validator request and classify the
    /// response. Returns `NoValidator` for fundamentally un-validatable
    /// configs (no URL), `ValidationError` for transport-level failures, and
    /// `Valid`/`Invalid` based on the configured criteria.
    pub async fn validate(
        &self,
        validator: &SecretValidator,
        candidate: &str,
    ) -> ValidationState {
        if validator.http.url.trim().is_empty() {
            return ValidationState::NoValidator;
        }

        let url = substitute_secret(&validator.http.url, candidate);
        let method = validator.http.method.as_str();
        let body = validator
            .http
            .body
            .as_deref()
            .map(|b| substitute_secret(b, candidate));

        let req = self.client.request(
            reqwest::Method::from_bytes(method.as_bytes())
                .unwrap_or(reqwest::Method::GET),
            url,
        );

        let mut req = req;
        for (k, v) in &validator.http.headers {
            req = req.header(k, substitute_secret(v, candidate));
        }
        if let Some(body) = body {
            req = req.body(body);
        }

        match req.send().await {
            Ok(resp) => classify(&validator.valid, validator.invalid.as_ref(), resp).await,
            Err(_) => ValidationState::ValidationError,
        }
    }
}

fn substitute_secret(template: &str, candidate: &str) -> String {
    template.replace("{secret}", candidate)
}

async fn classify(
    valid: &ValidatorMatch,
    invalid: Option<&ValidatorMatch>,
    resp: reqwest::Response,
) -> ValidationState {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body_text = resp.text().await.unwrap_or_default();

    if matches_criteria(valid, status, &headers, &body_text) {
        return ValidationState::Valid;
    }
    if let Some(invalid) = invalid {
        if matches_criteria(invalid, status, &headers, &body_text) {
            return ValidationState::Invalid;
        }
    }
    // Response didn't fit either bucket — treat as invalid by default.
    ValidationState::Invalid
}

fn matches_criteria(
    crit: &ValidatorMatch,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> bool {
    if let Some(want) = crit.status_code {
        if status != want {
            return false;
        }
    }
    if let Some(re) = &crit.body_regex {
        if let Ok(rx) = regex::Regex::new(re) {
            if !rx.is_match(body) {
                return false;
            }
        } else {
            return false;
        }
    }
    if let Some((name, re)) = &crit.header_regex {
        if let Ok(rx) = regex::Regex::new(re) {
            let v = headers
                .get(name.as_str())
                .and_then(|hv| hv.to_str().ok())
                .unwrap_or("");
            if !rx.is_match(v) {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_replaces_placeholder() {
        assert_eq!(
            substitute_secret("https://api.example.com/v1/me?token={secret}", "abc"),
            "https://api.example.com/v1/me?token=abc"
        );
    }

    #[test]
    fn empty_url_means_no_validator() {
        let runner = SecretValidatorRunner::new();
        let v = SecretValidator {
            http: crate::rule::ValidatorHttp {
                method: "GET".into(),
                url: "".into(),
                headers: Default::default(),
                body: None,
                timeout_secs: 30,
            },
            valid: ValidatorMatch {
                status_code: Some(200),
                body_regex: None,
                header_regex: None,
            },
            invalid: None,
        };
        let fut = runner.validate(&v, "tok");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let state = rt.block_on(fut);
        assert!(matches!(state, ValidationState::NoValidator));
    }
}
