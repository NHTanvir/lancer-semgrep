//! Compute the changed-file + hunk-range map vs a baseline commit.
//!
//! Implemented by shelling out to `git diff` (the user's repo will reliably
//! have it; libgit2 hunk parsing would duplicate the same logic). Hunk
//! headers (`@@ -X,Y +A,B @@`) are parsed line-by-line.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One contiguous range of "introduced/changed" lines in a target file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HunkRange {
    pub start_line: usize,
    pub end_line: usize,
}

/// Per-file list of introduced hunks since the baseline commit.
pub type BaselineMap = HashMap<PathBuf, Vec<HunkRange>>;

/// Run `git diff <SHA>..HEAD` in `repo_root` and return the per-file hunk map.
pub fn diff_against(
    baseline_sha: &str,
    repo_root: &Path,
) -> Result<BaselineMap, crate::SemgrepError> {
    let out = Command::new("git")
        .current_dir(repo_root)
        .args(["diff", "--name-only", &format!("{baseline_sha}..HEAD")])
        .output()
        .map_err(crate::SemgrepError::Io)?;

    if !out.status.success() {
        return Err(crate::SemgrepError::Other(format!(
            "git diff --name-only exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let names = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut map = BaselineMap::new();
    for path_str in names.lines() {
        if path_str.is_empty() {
            continue;
        }
        let full_path = repo_root.join(path_str);

        let out2 = Command::new("git")
            .current_dir(repo_root)
            .args([
                "diff",
                "-U0",
                &format!("{baseline_sha}..HEAD"),
                "--",
                path_str,
            ])
            .output()
            .map_err(crate::SemgrepError::Io)?;
        let body = String::from_utf8_lossy(&out2.stdout);
        let mut ranges = Vec::new();
        for line in body.lines() {
            if let Some(h) = parse_hunk_header(line) {
                ranges.push(h);
            }
        }
        map.insert(full_path, ranges);
    }
    Ok(map)
}

/// Parse a unified-diff hunk header, returning the *new-file* range.
///
/// `@@ -12,5 +14,7 @@ optional-text` ⇒ `HunkRange { start_line: 14, end_line: 20 }`.
/// `@@ -12 +14 @@` ⇒ count defaults to 1 ⇒ `HunkRange { start_line: 14, end_line: 14 }`.
pub fn parse_hunk_header(line: &str) -> Option<HunkRange> {
    let rest = line.strip_prefix("@@ ")?;
    let plus_part = rest.split(' ').find(|tok| tok.starts_with('+'))?;
    let payload = plus_part.trim_start_matches('+');
    let (start_str, count_str) = if let Some((s, c)) = payload.split_once(',') {
        (s, c)
    } else {
        (payload, "1")
    };
    let start: usize = start_str.parse().ok()?;
    let count: usize = count_str.parse().ok()?;
    Some(HunkRange {
        start_line: start,
        end_line: start + count.saturating_sub(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_hunk_header() {
        let h = parse_hunk_header("@@ -12,5 +14,7 @@ func").unwrap();
        assert_eq!(h.start_line, 14);
        assert_eq!(h.end_line, 20);
    }

    #[test]
    fn parses_unit_count_hunk_header() {
        let h = parse_hunk_header("@@ -1 +3 @@").unwrap();
        assert_eq!(h.start_line, 3);
        assert_eq!(h.end_line, 3);
    }

    #[test]
    fn rejects_garbage_lines() {
        assert!(parse_hunk_header("not a hunk").is_none());
        assert!(parse_hunk_header("+++ b/foo").is_none());
    }
}
