//! Decide whether a finding falls inside the baseline-diff hunks.

use crate::baseline::git_diff::BaselineMap;
use crate::Finding;

/// True iff `finding.range` (expanded by `diff_depth` lines on either side)
/// intersects any introduced hunk in `baseline` for the same path.
pub fn finding_in_diff(finding: &Finding, baseline: &BaselineMap, diff_depth: usize) -> bool {
    let Some(ranges) = baseline.get(finding.file.as_path()) else {
        return false;
    };
    let f_start = finding.range.start.line;
    let f_end = finding.range.end.line;
    for r in ranges {
        let s = r.start_line.saturating_sub(diff_depth);
        let e = r.end_line + diff_depth;
        if f_start <= e && f_end >= s {
            return true;
        }
    }
    false
}
