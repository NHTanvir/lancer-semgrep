//! Wrap `similar::TextDiff` to produce a unified-diff string.

use similar::TextDiff;

/// Produce a unified diff of `before` → `after`, labelled with `file` on both
/// header lines (`--- file` / `+++ file`).
pub fn unified_diff(before: &str, after: &str, file: &str) -> String {
    TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(3)
        .header(file, file)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_non_empty_diff() {
        let d = unified_diff("a\n", "b\n", "foo");
        assert!(d.contains("foo"));
        assert!(d.contains("-a"));
        assert!(d.contains("+b"));
    }

    #[test]
    fn identical_text_produces_empty_diff() {
        let d = unified_diff("a\n", "a\n", "foo");
        // No `-` or `+` content lines when there's no change.
        assert!(
            !d.contains("\n-a"),
            "unexpected `-a` in identical diff: {d}"
        );
        assert!(
            !d.contains("\n+a"),
            "unexpected `+a` in identical diff: {d}"
        );
    }
}
