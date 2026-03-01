//! Advisory URL builder.
//!
//! Per plan §"Research note → 2026-05-31": findings carrying an advisory ID
//! (typically pulled out of `rule.metadata.advisory_id`, `cve_id`, or
//! `ghsa_id`) should link to the Semgrep Advisory page rather than the
//! generic NIST CVE listing, because the Semgrep page bundles reachability
//! info and remediation alongside the CVE summary.
//!
//! The function is intentionally stupid — string concat, no validation —
//! because the engine never invents advisory IDs; they come straight from
//! the rule author's `metadata:` block.

/// Build a URL pointing at the Semgrep Advisory page for the given ID.
///
/// `advisory_id` is passed through verbatim (no URL-encoding) since Semgrep's
/// own advisory IDs already use a URL-safe alphabet (`GHSA-...`, `CVE-...`).
///
/// ```
/// assert_eq!(
///     semgrep_output::advisory_url("GHSA-1234-5678-90ab"),
///     "https://semgrep.dev/advisories/GHSA-1234-5678-90ab"
/// );
/// ```
pub fn advisory_url(advisory_id: &str) -> String {
    format!("https://semgrep.dev/advisories/{advisory_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_expected_url() {
        assert_eq!(
            advisory_url("GHSA-xyz"),
            "https://semgrep.dev/advisories/GHSA-xyz"
        );
        assert_eq!(
            advisory_url("CVE-2026-12345"),
            "https://semgrep.dev/advisories/CVE-2026-12345"
        );
    }
}
