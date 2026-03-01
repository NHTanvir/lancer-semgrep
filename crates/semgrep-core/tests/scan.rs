//! Integration tests for the scan-enumerate path.

use std::path::PathBuf;

use semgrep_core::scan::{enumerate_targets, EnumerateOpts};

#[test]
fn enumerate_skips_files_over_size_limit() {
    let tmpdir = tempfile::tempdir().unwrap();
    std::fs::write(tmpdir.path().join("big.py"), "x".repeat(2_000_000)).unwrap();
    std::fs::write(tmpdir.path().join("small.py"), "x").unwrap();

    let opts = EnumerateOpts {
        max_target_bytes: 1_000_000,
        ..Default::default()
    };
    let roots = vec![tmpdir.path().to_path_buf()];
    let (files, ignored) = enumerate_targets(&roots, &opts, |p| {
        p.extension()
            .and_then(|e| e.to_str())
            .and_then(semgrep_core::Language::from_extension)
    });

    let scanned_names: Vec<_> = files
        .iter()
        .filter_map(|t| t.path.file_name().and_then(|s| s.to_str()).map(str::to_string))
        .collect();
    let ignored_names: Vec<_> = ignored
        .iter()
        .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(str::to_string))
        .collect();

    assert!(scanned_names.contains(&"small.py".to_string()));
    assert!(ignored_names.contains(&"big.py".to_string()));
}

#[test]
fn enumerate_honours_include_glob() {
    let tmpdir = tempfile::tempdir().unwrap();
    std::fs::write(tmpdir.path().join("a.py"), "x").unwrap();
    std::fs::write(tmpdir.path().join("b.js"), "x").unwrap();

    let opts = EnumerateOpts {
        include: vec!["**/*.py".to_string()],
        ..Default::default()
    };
    let roots = vec![tmpdir.path().to_path_buf()];
    let (files, _) = enumerate_targets(&roots, &opts, |p| {
        p.extension()
            .and_then(|e| e.to_str())
            .and_then(semgrep_core::Language::from_extension)
    });
    assert!(files.iter().any(|t| t.path.file_name().unwrap() == "a.py"));
    assert!(!files.iter().any(|t| t.path.file_name().unwrap() == "b.js"));
}

#[test]
fn force_language_overrides_extension_detector() {
    let tmpdir = tempfile::tempdir().unwrap();
    let unusual = tmpdir.path().join("weird.zzz");
    std::fs::write(&unusual, "print('hi')").unwrap();

    let opts = EnumerateOpts {
        force_language: Some(semgrep_core::Language::Python),
        ..Default::default()
    };
    let roots = vec![tmpdir.path().to_path_buf()];
    let (files, _) = enumerate_targets(&roots, &opts, |_| None);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].language, semgrep_core::Language::Python);
    let _ = PathBuf::from(unusual);
}
