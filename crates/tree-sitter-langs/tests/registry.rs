//! Integration tests for the language registry + detector.
//!
//! These tests run against the **default** feature set (Python, JS, TS, Go,
//! Rust, Java). Tests are skipped automatically when a feature is off via the
//! `#[cfg(feature = …)]` attributes inside the helpers.

use std::path::Path;

use tree_sitter_langs::{adapter_for, detect_language, enabled_languages, Language};

#[test]
fn enabled_languages_includes_default_set() {
    let langs = enabled_languages();

    #[cfg(feature = "lang-python")]
    assert!(langs.contains(&Language::Python), "expected Python in {langs:?}");
    #[cfg(feature = "lang-javascript")]
    {
        assert!(langs.contains(&Language::Javascript));
        assert!(langs.contains(&Language::Jsx));
    }
    #[cfg(feature = "lang-typescript")]
    {
        assert!(langs.contains(&Language::Typescript));
        assert!(langs.contains(&Language::Tsx));
    }
    #[cfg(feature = "lang-go")]
    assert!(langs.contains(&Language::Go));
    #[cfg(feature = "lang-rust")]
    assert!(langs.contains(&Language::Rust));
    #[cfg(feature = "lang-java")]
    assert!(langs.contains(&Language::Java));
}

#[test]
fn detect_language_from_path() {
    assert_eq!(detect_language(Path::new("foo.py")), Some(Language::Python));
    assert_eq!(detect_language(Path::new("foo.rs")), Some(Language::Rust));
    assert_eq!(detect_language(Path::new("foo.tsx")), Some(Language::Tsx));
    assert_eq!(detect_language(Path::new("foo.go")), Some(Language::Go));
    assert_eq!(
        detect_language(Path::new("Dockerfile")),
        Some(Language::Dockerfile)
    );
    assert_eq!(
        detect_language(Path::new("Dockerfile.prod")),
        Some(Language::Dockerfile)
    );
    assert_eq!(detect_language(Path::new("nope.unknown")), None);
}

#[test]
fn adapter_lookup_for_default_set() {
    #[cfg(feature = "lang-python")]
    assert!(
        adapter_for(Language::Python).is_some(),
        "missing adapter for Python"
    );
    #[cfg(feature = "lang-javascript")]
    {
        assert!(adapter_for(Language::Javascript).is_some());
        assert!(adapter_for(Language::Jsx).is_some());
    }
    #[cfg(feature = "lang-typescript")]
    {
        assert!(adapter_for(Language::Typescript).is_some());
        assert!(adapter_for(Language::Tsx).is_some());
    }
    #[cfg(feature = "lang-go")]
    assert!(adapter_for(Language::Go).is_some());
    #[cfg(feature = "lang-rust")]
    assert!(adapter_for(Language::Rust).is_some());
    #[cfg(feature = "lang-java")]
    assert!(adapter_for(Language::Java).is_some());
}

#[test]
fn adapter_reports_correct_metadata() {
    // Sanity check that the adapter wires `Language::Python` to the `.py`/
    // `.pyi` extension table.
    #[cfg(feature = "lang-python")]
    {
        let adapter = adapter_for(Language::Python).expect("python adapter");
        assert_eq!(adapter.language(), Language::Python);
        assert!(adapter.file_extensions().contains(&"py"));
        assert!(adapter.shebangs().contains(&"python3"));
    }
}

#[test]
fn unsupported_languages_return_none() {
    // `Generic` has no grammar; should always be None irrespective of features.
    assert!(adapter_for(Language::Generic).is_none());
}
