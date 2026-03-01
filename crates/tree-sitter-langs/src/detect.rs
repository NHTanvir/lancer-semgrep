//! File-path / shebang-driven language detection.
//!
//! Thin wrapper over `semgrep_core::Language::{from_extension, from_shebang}`
//! that also handles the basename special cases (`Dockerfile`, `Dockerfile.prod`,
//! `Makefile`, …) the extension-based table can't express.
//!
//! Called from `semgrep-core`'s target-enumeration pipeline (Task 6) and from
//! the CLI's `--lang` resolver.

use std::path::Path;

use semgrep_core::Language;

/// Detect language for a path using basename + extension only.
///
/// Returns `None` when the path doesn't match any known table; callers wanting
/// shebang fallback should use [`detect_language_with_shebang`].
pub fn detect_language(path: &Path) -> Option<Language> {
    // 1. Basename special cases: `Dockerfile`, `Dockerfile.prod`, etc.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name == "Dockerfile"
            || name == "Containerfile"
            || name.starts_with("Dockerfile.")
            || name.ends_with(".Dockerfile")
            || name.ends_with(".dockerfile")
        {
            return Some(Language::Dockerfile);
        }
    }

    // 2. Extension.
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if let Some(l) = Language::from_extension(ext) {
            return Some(l);
        }
    }

    None
}

/// Detect language using basename + extension; if nothing matches, fall back
/// to interpreting `first_line` as a shebang.
///
/// `first_line` should be the file's first line *including* the leading `#!`
/// (or `None` if the file is empty / binary). The caller owns the file IO so
/// this module stays trivial to test.
pub fn detect_language_with_shebang(
    path: &Path,
    first_line: Option<&str>,
) -> Option<Language> {
    if let Some(l) = detect_language(path) {
        return Some(l);
    }
    if let Some(line) = first_line {
        if line.starts_with("#!") {
            return Language::from_shebang(line);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_by_extension() {
        assert_eq!(detect_language(Path::new("foo.py")), Some(Language::Python));
        assert_eq!(detect_language(Path::new("foo.rs")), Some(Language::Rust));
        assert_eq!(detect_language(Path::new("foo.tsx")), Some(Language::Tsx));
        assert_eq!(detect_language(Path::new("foo.go")), Some(Language::Go));
        assert_eq!(detect_language(Path::new("nope.unknown")), None);
    }

    #[test]
    fn detect_dockerfile_basenames() {
        assert_eq!(
            detect_language(Path::new("Dockerfile")),
            Some(Language::Dockerfile)
        );
        assert_eq!(
            detect_language(Path::new("Dockerfile.prod")),
            Some(Language::Dockerfile)
        );
        assert_eq!(
            detect_language(Path::new("./build/Dockerfile.ci")),
            Some(Language::Dockerfile)
        );
        assert_eq!(
            detect_language(Path::new("Containerfile")),
            Some(Language::Dockerfile)
        );
    }

    #[test]
    fn shebang_fallback() {
        // Extensionless file `foo` with a python shebang.
        assert_eq!(
            detect_language_with_shebang(
                Path::new("foo"),
                Some("#!/usr/bin/env python3"),
            ),
            Some(Language::Python),
        );
        // No shebang, no extension → no detection.
        assert_eq!(
            detect_language_with_shebang(Path::new("foo"), Some("not a shebang")),
            None,
        );
        // Extension wins over shebang.
        assert_eq!(
            detect_language_with_shebang(
                Path::new("foo.py"),
                Some("#!/usr/bin/env node"),
            ),
            Some(Language::Python),
        );
    }
}
