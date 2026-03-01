//! Shannon entropy heuristic for the Secrets mode pre-filter.
//!
//! High-entropy strings are likely to be credentials. Combined with regex
//! patterns and (optionally) a live `validators:` HTTP check, this is the
//! core mechanism Semgrep Secrets uses to surface tokens.

/// Shannon entropy in bits/byte of `bytes`. Returns `0.0` for the empty input.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn uniform_is_max() {
        // 256 distinct bytes — max entropy = 8 bits/byte.
        let all: Vec<u8> = (0u32..256).map(|i| i as u8).collect();
        let h = shannon_entropy(&all);
        assert!((h - 8.0).abs() < 1e-9, "expected ~8, got {h}");
    }

    #[test]
    fn single_byte_is_zero() {
        // All same byte → no entropy.
        let buf = vec![b'a'; 64];
        assert_eq!(shannon_entropy(&buf), 0.0);
    }

    #[test]
    fn jwt_like_is_high() {
        // Random-looking base64-style text → ~5-6 bits/byte.
        let s = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let h = shannon_entropy(s);
        assert!(h > 4.0, "expected high entropy, got {h}");
    }
}
