//! `--config <arg>` resolution.
//!
//! Translates the CLI argument into a fetch plan:
//!
//! | CLI arg              | [`ConfigSource`] variant |
//! |----------------------|--------------------------|
//! | `./rules.yaml`        | `File(...)`              |
//! | `./rules/`            | `Dir(...)`               |
//! | `p/python`            | `Slug(Slug::Pack(...))`  |
//! | `r/rule-id`           | `Slug(Slug::Rule(...))`  |
//! | `https://...yaml`     | `Url(...)`               |
//! | `auto`                | `Auto`                   |
//! | `-`                   | `Stdin`                  |
//! | (inline YAML at API)  | `Inline(...)`            |
//!
//! [`resolve`] reads / fetches each source into a list of `(source-id,
//! yaml-text)` pairs, ready for [`crate::load_str`].

use std::io::Read;
use std::path::PathBuf;

use crate::cache::RuleCache;
use crate::error::LoadError;
use crate::registry::{RegistryClient, Slug};

/// Where a `--config` value points.
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// Single YAML file on disk.
    File(PathBuf),
    /// Directory of YAML files (recursive walk).
    Dir(PathBuf),
    /// Semgrep Registry slug ("p/python" / "r/rule-id").
    Slug(Slug),
    /// Arbitrary URL serving raw YAML.
    Url(String),
    /// `auto` — Semgrep AppSec selects rules in the upstream. OSS clone falls
    /// back to `Slug(Pack("default"))`.
    Auto,
    /// `-` — read YAML from stdin.
    Stdin,
    /// Inline YAML supplied programmatically (no CLI form).
    Inline(String),
}

impl ConfigSource {
    /// Parse a CLI `--config <arg>` value into a `ConfigSource`.
    ///
    /// File / directory detection is best-effort: the argument is treated as
    /// a path only if it doesn't look like a slug / URL / `auto` / `-`.
    /// `is_dir()` then disambiguates `File` vs `Dir`.
    pub fn parse(arg: &str) -> Self {
        if arg == "auto" {
            return ConfigSource::Auto;
        }
        if arg == "-" {
            return ConfigSource::Stdin;
        }
        if arg.starts_with("p/") || arg.starts_with("r/") {
            return ConfigSource::Slug(Slug::parse(arg));
        }
        if arg.starts_with("http://") || arg.starts_with("https://") {
            return ConfigSource::Url(arg.to_string());
        }
        let pb = PathBuf::from(arg);
        if pb.is_dir() {
            ConfigSource::Dir(pb)
        } else {
            ConfigSource::File(pb)
        }
    }
}

/// The resolved YAML content for a `ConfigSource`.
///
/// `rules_yaml` is a list of `(source-id, yaml)` pairs so callers can attribute
/// findings to the original file / URL / slug.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub source: ConfigSource,
    pub rules_yaml: Vec<(String, String)>,
}

/// Resolve a [`ConfigSource`] into its raw YAML.
///
/// - Local file / dir / inline: read straight from disk / memory.
/// - Slug / URL / Auto: hit the registry via `client`, then cache the response
///   in `cache` keyed by `blake3(yaml)`. Subsequent runs short-circuit the
///   network call when the URL's previous fetch is still cache-valid (we
///   currently keep cache entries indefinitely; expiration / `If-None-Match`
///   support is future work).
/// - Stdin: drain `std::io::stdin()` into one entry.
pub async fn resolve(
    source: ConfigSource,
    client: &RegistryClient,
    cache: &RuleCache,
) -> Result<ResolvedConfig, LoadError> {
    let rules_yaml = match &source {
        ConfigSource::File(p) => {
            let s = std::fs::read_to_string(p).map_err(|e| LoadError::Io {
                path: p.clone(),
                error: e,
            })?;
            vec![(p.display().to_string(), s)]
        }
        ConfigSource::Dir(d) => {
            let mut out = Vec::new();
            for entry in walkdir::WalkDir::new(d)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                let ext = p.extension().and_then(|x| x.to_str());
                if matches!(ext, Some("yaml") | Some("yml")) {
                    let s = std::fs::read_to_string(p).map_err(|e| LoadError::Io {
                        path: p.to_path_buf(),
                        error: e,
                    })?;
                    out.push((p.display().to_string(), s));
                }
            }
            out
        }
        ConfigSource::Slug(slug) => {
            let id = slug.to_string();
            let yaml = match cache_get_str(cache, &id)? {
                Some(s) => s,
                None => {
                    let pack = client.fetch_pack(slug).await?;
                    cache_put(cache, &id, &pack.yaml)?;
                    pack.yaml
                }
            };
            vec![(id, yaml)]
        }
        ConfigSource::Url(url) => {
            let yaml = match cache_get_str(cache, url)? {
                Some(s) => s,
                None => {
                    let body = client.fetch_url(url).await?;
                    cache_put(cache, url, &body)?;
                    body
                }
            };
            vec![(url.clone(), yaml)]
        }
        ConfigSource::Auto => {
            // OSS-clone fallback: alias for `p/default`.
            let slug = Slug::Pack("default".into());
            let id = slug.to_string();
            let yaml = match cache_get_str(cache, &id)? {
                Some(s) => s,
                None => {
                    let pack = client.fetch_pack(&slug).await?;
                    cache_put(cache, &id, &pack.yaml)?;
                    pack.yaml
                }
            };
            vec![(id, yaml)]
        }
        ConfigSource::Stdin => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| LoadError::Io {
                    path: PathBuf::from("<stdin>"),
                    error: e,
                })?;
            vec![("<stdin>".to_string(), s)]
        }
        ConfigSource::Inline(s) => vec![("<inline>".to_string(), s.clone())],
    };

    Ok(ResolvedConfig { source, rules_yaml })
}

/// Read a cached UTF-8 entry, swallowing decode failures (the corrupt entry
/// will be re-fetched and overwritten).
fn cache_get_str(cache: &RuleCache, key: &str) -> Result<Option<String>, LoadError> {
    match cache.get(key)? {
        Some(bytes) => Ok(String::from_utf8(bytes).ok()),
        None => Ok(None),
    }
}

/// Cache a fetched body under both the friendly id key and its content hash,
/// so future lookups by either key hit.
fn cache_put(cache: &RuleCache, id: &str, yaml: &str) -> Result<(), LoadError> {
    cache.put(id, yaml.as_bytes())?;
    let content_key = RuleCache::key_for_yaml(yaml);
    cache.put(&content_key, yaml.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_slug() {
        match ConfigSource::parse("p/python") {
            ConfigSource::Slug(s) => assert_eq!(format!("{s}"), "p/python"),
            other => panic!("expected Slug, got {:?}", other),
        }
    }

    #[test]
    fn parses_rule_slug() {
        match ConfigSource::parse("r/foo.bar") {
            ConfigSource::Slug(s) => assert_eq!(format!("{s}"), "r/foo.bar"),
            other => panic!("expected Slug, got {:?}", other),
        }
    }

    #[test]
    fn parses_url() {
        match ConfigSource::parse("https://example.com/rules.yaml") {
            ConfigSource::Url(u) => assert_eq!(u, "https://example.com/rules.yaml"),
            other => panic!("expected Url, got {:?}", other),
        }
    }

    #[test]
    fn parses_auto() {
        assert!(matches!(ConfigSource::parse("auto"), ConfigSource::Auto));
    }

    #[test]
    fn parses_stdin() {
        assert!(matches!(ConfigSource::parse("-"), ConfigSource::Stdin));
    }

    #[test]
    fn parses_file_path() {
        match ConfigSource::parse("./nonexistent.yaml") {
            ConfigSource::File(p) => {
                assert!(p.to_string_lossy().ends_with("nonexistent.yaml"))
            }
            other => panic!("expected File, got {:?}", other),
        }
    }
}
