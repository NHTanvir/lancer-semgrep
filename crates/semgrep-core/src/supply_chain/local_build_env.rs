//! `SEMGREP_LOCAL_BUILD_ENV` — JSON env-vars passed to package managers.
//!
//! Per plan §"Research note 2026-05-31 → `SEMGREP_LOCAL_BUILD_ENV` —
//! JSON, not string (Feb 2026)":
//!
//! ```text
//! SEMGREP_LOCAL_BUILD_ENV='{"PIP_INDEX_URL":"https://internal/...","CARGO_NET_GIT_FETCH_WITH_CLI":"true"}'
//! ```
//!
//! These get passed wholesale to each invoked package manager
//! (`pip install`, `cargo metadata`, `npm install`, …) during dep resolution
//! for Supply Chain reachability. The reader here parses the env var; the
//! actual pass-through happens in callers that invoke the package managers.

use std::collections::BTreeMap;

/// Parsed contents of `SEMGREP_LOCAL_BUILD_ENV`.
///
/// Empty when the env var is unset or not valid JSON; callers should still
/// proceed (graceful degradation).
#[derive(Debug, Clone, Default)]
pub struct LocalBuildEnv(pub BTreeMap<String, String>);

/// Read `SEMGREP_LOCAL_BUILD_ENV` from the process environment and parse it.
///
/// Returns an empty `LocalBuildEnv` when:
/// - the var is unset
/// - the value is empty
/// - the value is not valid JSON
/// - the value is not a JSON object of string→string entries
pub fn read_local_build_env() -> LocalBuildEnv {
    read_from(std::env::var("SEMGREP_LOCAL_BUILD_ENV").ok().as_deref())
}

/// Variant of [`read_local_build_env`] that takes the raw string explicitly
/// (handy in tests). `None` ⇒ empty map.
pub fn read_from(raw: Option<&str>) -> LocalBuildEnv {
    let Some(raw) = raw else {
        return LocalBuildEnv::default();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return LocalBuildEnv::default();
    }
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return LocalBuildEnv::default(),
    };
    let Some(obj) = value.as_object() else {
        return LocalBuildEnv::default();
    };
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            out.insert(k.clone(), s.to_string());
        }
    }
    LocalBuildEnv(out)
}

impl LocalBuildEnv {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }

    /// Iterate over (key, value) pairs in deterministic (BTreeMap) order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_when_unset() {
        assert!(read_from(None).is_empty());
    }

    #[test]
    fn parses_valid_json() {
        let env = read_from(Some(
            r#"{"PIP_INDEX_URL":"https://internal/","CARGO_NET_GIT_FETCH_WITH_CLI":"true"}"#,
        ));
        assert_eq!(env.get("PIP_INDEX_URL"), Some("https://internal/"));
        assert_eq!(env.get("CARGO_NET_GIT_FETCH_WITH_CLI"), Some("true"));
    }

    #[test]
    fn empty_on_invalid_json() {
        assert!(read_from(Some("not json")).is_empty());
        assert!(read_from(Some("")).is_empty());
        assert!(read_from(Some("[\"array\"]")).is_empty());
    }

    #[test]
    fn drops_non_string_values() {
        let env = read_from(Some(r#"{"A":"x","B":7,"C":"y"}"#));
        assert_eq!(env.get("A"), Some("x"));
        assert_eq!(env.get("B"), None);
        assert_eq!(env.get("C"), Some("y"));
    }
}
