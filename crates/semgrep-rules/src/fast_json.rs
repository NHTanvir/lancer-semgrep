//! Fast JSON parsing path for very large rule packs.
//!
//! Per plan §"Research note 2026-05-31 → JSON rule parsing 5× speedup
//! (Apr 2026)": the upstream OCaml engine landed a hand-written RFC 8259
//! parser that takes a 382 MB rule pack from 134 s → 28 s. Our `serde_json`
//! path won't hit that speed; this module exposes a `parse_rule_pack_fast`
//! entry that callers can switch to once they decide the rule-pack is big
//! enough to justify the extra dep.
//!
//! Stub today: routes through `serde_json::from_slice`. A follow-up can
//! drop in `simd-json` (already a sibling crate on crates.io) without
//! changing the public signature.

use serde::de::DeserializeOwned;

/// Parse a Semgrep rule pack (or any JSON value) into a typed struct.
///
/// Currently a thin wrapper over `serde_json::from_slice`. Public so that
/// callers commit to the API; the implementation can swap to `simd-json` or
/// a hand-written RFC 8259 parser later.
pub fn parse_rule_pack_fast<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Pack {
        rules: Vec<RuleStub>,
    }

    #[derive(Debug, Deserialize)]
    struct RuleStub {
        id: String,
    }

    #[test]
    fn parses_rule_pack() {
        let pack: Pack =
            parse_rule_pack_fast(b"{\"rules\":[{\"id\":\"a\"},{\"id\":\"b\"}]}").unwrap();
        assert_eq!(pack.rules.len(), 2);
        assert_eq!(pack.rules[0].id, "a");
    }
}
