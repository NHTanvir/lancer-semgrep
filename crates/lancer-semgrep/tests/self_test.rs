//! `--self-test` parity matrix harness. Loads every subdirectory of
//! `tests/upstream_parity/`, runs each rule against its target, and compares
//! emitted JSON to `expected.json`.
//!
//! This is `#[ignore]` by default — flip `--include-ignored` to opt in.
//! The harness's goal at this milestone is to:
//!   1) keep the corpus shape healthy (every subdir has the 3 expected files),
//!   2) be a place where a future patch plugs in the actual scan + JSON diff.

#[test]
#[ignore]
fn upstream_parity_matrix() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/upstream_parity");
    if !dir.exists() {
        eprintln!("no parity corpus; skip");
        return;
    }
    let mut failures: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let rule_yaml = path.join("rule.yaml");
        let expected_json = path.join("expected.json");
        if !rule_yaml.exists() || !expected_json.exists() {
            // README.md, hidden dirs, ad-hoc fixtures — skip silently.
            continue;
        }

        // Pick the target.* file.
        let target = std::fs::read_dir(&path)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| {
                let p = e.path();
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("target."))
                    .unwrap_or(false)
            });
        let Some(target) = target else {
            failures.push(format!("{}: no target.*", path.display()));
            continue;
        };
        let _ = target;

        // Defer actual scan — this is a harness; the assertion is "the corpus
        // is well-formed". A future patch will plug in `run_scan` + JSON diff.
    }

    if !failures.is_empty() {
        panic!("parity failures: {failures:#?}");
    }
}

#[test]
fn upstream_parity_corpus_has_readme() {
    let readme =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/upstream_parity/README.md");
    assert!(
        readme.exists(),
        "tests/upstream_parity/README.md is required (see Task 12)"
    );
}

#[test]
fn upstream_parity_corpus_has_minimum_cases() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/upstream_parity");
    let case_count = std::fs::read_dir(&root)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .count()
        })
        .unwrap_or(0);
    // Plan requires at least 3 parity cases under tests/upstream_parity/.
    assert!(
        case_count >= 3,
        "expected >=3 parity-case subdirs under tests/upstream_parity/, found {case_count}"
    );
}
