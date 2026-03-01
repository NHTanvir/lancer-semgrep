//! DNS-rebinding protection for the HTTP transport.
//!
//! Per plan.md §"MCP DNS-rebinding protection (Feb 2026)" the HTTP transport
//! must (a) bind to `127.0.0.1` only and (b) reject any `Host:` header whose
//! value does not resolve to a loopback IP. We deliberately refuse to do a
//! live DNS lookup here — that *is* the rebinding attack surface — and
//! instead accept only the canonical loopback aliases.

use std::net::IpAddr;

/// Return true iff `host` is a loopback host that the HTTP transport may
/// legitimately serve. Accepts:
///
/// - "127.0.0.1" (any 127.0.0.0/8 address)
/// - "::1"  (with or without `[]` brackets)
/// - "localhost" (canonical loopback alias)
///
/// Anything else — including non-loopback IPv4, public IPv6, or arbitrary
/// DNS names that *would* resolve to a loopback address if we asked — is
/// rejected.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        return false;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    // Refuse arbitrary hostnames. A live `to_socket_addrs` here would let an
    // attacker-controlled DNS record map to 127.0.0.1, which is exactly the
    // attack we're defending against.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_recognised() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LocalHost"));
        // RFC 1122 loopback covers the whole /8.
        assert!(is_loopback_host("127.5.5.5"));
    }

    #[test]
    fn external_rejected() {
        assert!(!is_loopback_host("evil.example.com"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("8.8.8.8"));
        assert!(!is_loopback_host(""));
        assert!(!is_loopback_host("attacker.example.com"));
    }
}
