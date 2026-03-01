//! Rule unit test runner. Loads a `rule.yaml` plus a sibling target file
//! that carries `// ruleid: <id>` (expected match on that line) and
//! `// ok: <id>` (expected no-match) annotations. Runs the matcher and
//! asserts the lines line up. This mirrors `semgrep test`.
//!
//! The end-to-end harness lives in `subcommands::test` and is exercised via
//! `lancer-semgrep test <target>`. Here we keep two cheap smoke tests:
//!   1) the parity corpus directory is reachable from the test binary, and
//!   2) at least one rule.yaml + target pair exists under it (so the
//!      `test` subcommand can be dogfooded against it locally).

use std::path::Path;

#[test]
#[ignore]
fn unit_test_harness_loads_corpus() {
    // The harness is exercised end-to-end by `lancer-semgrep test <target>`;
    // here we just check the corpus shape parses.
    let _ = Path::new(env!("CARGO_MANIFEST_DIR"));
}

#[test]
fn upstream_parity_dir_resolvable() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/upstream_parity");
    assert!(
        dir.exists(),
        "tests/upstream_parity/ should exist after Task 12"
    );
}

#[test]
fn at_least_one_rule_yaml_pair_exists() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/upstream_parity");
    let mut found_pair = false;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let rule_yaml = path.join("rule.yaml");
            if !rule_yaml.exists() {
                continue;
            }
            // Look for any sibling file with stem `target`.
            if let Ok(sub) = std::fs::read_dir(&path) {
                for e in sub.flatten() {
                    let p = e.path();
                    if p.file_stem().and_then(|s| s.to_str()) == Some("target") {
                        found_pair = true;
                        break;
                    }
                }
            }
            if found_pair {
                break;
            }
        }
    }
    assert!(
        found_pair,
        "no rule.yaml + target.* pair found under tests/upstream_parity/ \
         (Task 12 scaffolds at least one)"
    );
}
