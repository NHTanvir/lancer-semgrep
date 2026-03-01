//! Slug parsing for Semgrep Registry references.
//!
//! Slug shapes:
//!
//! - `p/<pack-name>` — a curated pack ("p/python", "p/owasp-top-ten").
//! - `r/<rule-id>`   — a single rule by its fully-qualified id
//!   ("r/python.lang.security.dangerous-eval").
//!
//! `auto` is handled at the [`crate::ConfigSource`] level (not here): it expands
//! to `Slug::Pack("default")` in the OSS clone.

/// One Semgrep Registry slug.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Slug {
    /// `p/<name>` — curated rule pack.
    Pack(String),
    /// `r/<id>` — single rule by ID.
    Rule(String),
}

impl Slug {
    /// Parse a slug string. Falls back to `Pack` if neither `p/` nor `r/`
    /// prefix is present.
    pub fn parse(s: &str) -> Self {
        if let Some(rest) = s.strip_prefix("p/") {
            Slug::Pack(rest.to_string())
        } else if let Some(rest) = s.strip_prefix("r/") {
            Slug::Rule(rest.to_string())
        } else {
            Slug::Pack(s.to_string())
        }
    }

    /// True iff this is a single-rule reference.
    pub fn is_rule(&self) -> bool {
        matches!(self, Slug::Rule(_))
    }
}

impl std::fmt::Display for Slug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Slug::Pack(n) => write!(f, "p/{}", n),
            Slug::Rule(i) => write!(f, "r/{}", i),
        }
    }
}

/// Well-known registry slugs surfaced for tab completion / docs.
///
/// Sourced from plan.md §"Registry slugs (popular ones)". Curated rather than
/// exhaustive — for full discovery the user should query the registry directly.
pub fn well_known_slugs() -> &'static [&'static str] {
    &[
        // Cross-language / curated
        "p/default",
        "p/owasp-top-ten",
        "p/cwe-top-25",
        "p/security-audit",
        "p/secrets",
        // Per-language
        "p/javascript",
        "p/python",
        "p/golang",
        "p/java",
        "p/typescript",
        "p/ruby",
        "p/php",
        "p/csharp",
        "p/c",
        "p/cpp",
        "p/rust",
        "p/kotlin",
        "p/swift",
        "p/scala",
        "p/solidity",
        "p/bash",
        "p/dockerfile",
        "p/terraform",
        "p/kubernetes",
        // Per-framework
        "p/react",
        "p/django",
        "p/flask",
        "p/express",
        "p/spring",
        "p/rails",
        "p/nextjs",
        "p/nestjs",
        // 2025-2026 additions
        "p/ai",
        "p/ml-security",
        "p/supply-chain",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pack_slug() {
        assert_eq!(Slug::parse("p/python"), Slug::Pack("python".into()));
    }

    #[test]
    fn parses_rule_slug() {
        assert_eq!(
            Slug::parse("r/python.lang.security.dangerous-eval"),
            Slug::Rule("python.lang.security.dangerous-eval".into())
        );
    }

    #[test]
    fn unprefixed_falls_back_to_pack() {
        assert_eq!(Slug::parse("python"), Slug::Pack("python".into()));
    }

    #[test]
    fn display_round_trips() {
        let s = Slug::parse("p/owasp-top-ten");
        assert_eq!(s.to_string(), "p/owasp-top-ten");
        let s = Slug::parse("r/foo.bar");
        assert_eq!(s.to_string(), "r/foo.bar");
    }
}
