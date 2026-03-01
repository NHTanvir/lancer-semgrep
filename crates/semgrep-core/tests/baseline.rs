//! Integration tests for the baseline-diff filter.

use std::path::PathBuf;

use semgrep_core::baseline::{
    filter::finding_in_diff,
    git_diff::{BaselineMap, HunkRange},
};
use semgrep_core::{Finding, Position, Range, RuleId, Severity};

fn dummy_finding(file: &str, start_line: usize, end_line: usize) -> Finding {
    Finding {
        rule_id: RuleId("r".into()),
        severity: Severity::Error,
        message: "m".into(),
        file: PathBuf::from(file),
        range: Range {
            start: Position {
                line: start_line,
                column: 1,
                offset: 0,
            },
            end: Position {
                line: end_line,
                column: 1,
                offset: 0,
            },
        },
        metavars: Default::default(),
        fix: None,
        validation_state: None,
        dataflow_trace: None,
        explanation: None,
        metadata: serde_json::Value::Null,
    }
}

#[test]
fn finding_inside_hunk_is_kept() {
    let mut map = BaselineMap::new();
    map.insert(
        PathBuf::from("foo.py"),
        vec![HunkRange {
            start_line: 10,
            end_line: 20,
        }],
    );
    assert!(finding_in_diff(&dummy_finding("foo.py", 15, 15), &map, 0));
}

#[test]
fn finding_outside_hunk_is_dropped() {
    let mut map = BaselineMap::new();
    map.insert(
        PathBuf::from("foo.py"),
        vec![HunkRange {
            start_line: 10,
            end_line: 20,
        }],
    );
    assert!(!finding_in_diff(&dummy_finding("foo.py", 5, 5), &map, 0));
}

#[test]
fn diff_depth_expands_intersection() {
    let mut map = BaselineMap::new();
    map.insert(
        PathBuf::from("foo.py"),
        vec![HunkRange {
            start_line: 10,
            end_line: 20,
        }],
    );
    // line 7 with diff_depth=3 → expanded hunk is 7..23 → matches.
    assert!(finding_in_diff(&dummy_finding("foo.py", 7, 7), &map, 3));
    // line 5 with diff_depth=3 → still misses (5..7 vs 7..23).
    assert!(!finding_in_diff(&dummy_finding("foo.py", 5, 5), &map, 3));
}

#[test]
fn unknown_file_is_dropped() {
    let map = BaselineMap::new();
    assert!(!finding_in_diff(&dummy_finding("foo.py", 1, 1), &map, 0));
}
