//! OAuth 2.1 PKCE token issuer / verifier — current build ships only the
//! verifier shim.
//!
//! Per plan.md §"Research note → MCP OAuth for Streamable HTTP transport
//! (May 2026)": OAuth is required when using `--transport http`. The stdio
//! transport (used by Claude Desktop) remains anonymous. A real issuer
//! lands in a future task; for now we accept any non-empty Bearer token so
//! the HTTP transport still enforces the *shape* of authentication (empty
//! Bearer / missing header / wrong scheme are rejected).

/// Validate an `Authorization:` header value. Returns true iff the header
/// starts with `Bearer ` and a non-empty token follows.
pub fn verify_bearer(authorization_header: &str) -> bool {
    if let Some(token) = authorization_header.strip_prefix("Bearer ") {
        return !token.trim().is_empty();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_bearer() {
        assert!(!verify_bearer(""));
        assert!(!verify_bearer("Bearer "));
        assert!(!verify_bearer("Bearer    "));
        assert!(!verify_bearer("Basic xxx"));
        assert!(!verify_bearer("bearer abc"));
    }

    #[test]
    fn accepts_nonempty_bearer() {
        assert!(verify_bearer("Bearer abc123"));
        assert!(verify_bearer("Bearer x"));
    }
}
