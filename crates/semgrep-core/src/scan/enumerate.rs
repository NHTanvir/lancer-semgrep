//! Filesystem walk + per-file language detection.
//!
//! Honours `.gitignore`, `.semgrepignore`, include/exclude globs, and the
//! `--max-target-bytes` cap. Pluggable language detector — callers in the
//! binary supply a richer detector that also consults shebangs via
//! `tree-sitter-langs`.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::scan::target::{EnumerateOpts, TargetFile};
use crate::Language;

/// Extension/basename-based language detector used by callers that don't want
/// to bring in `tree-sitter-langs`. Recognises `Dockerfile` / `Dockerfile.*`
/// as `Language::Dockerfile` and falls back to `Language::from_extension`.
pub fn detect_lang(path: &Path) -> Option<Language> {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name == "Dockerfile" || name.starts_with("Dockerfile.") {
            return Some(Language::Dockerfile);
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .and_then(Language::from_extension)
}

/// Walk `roots`, applying `opts`, and bucket files into "scan these" vs
/// "ignored". The language for each scanned file is resolved via
/// `custom_lang_detector` (callers typically wire in
/// `tree_sitter_langs::detect_language`).
pub fn enumerate_targets(
    roots: &[PathBuf],
    opts: &EnumerateOpts,
    custom_lang_detector: impl Fn(&Path) -> Option<Language>,
) -> (Vec<TargetFile>, Vec<PathBuf>) {
    let include_set = build_globset(&opts.include);
    let exclude_set = build_globset(&opts.exclude);

    let mut files = Vec::new();
    let mut ignored = Vec::new();

    for root in roots {
        let mut builder = WalkBuilder::new(root);
        builder.git_ignore(opts.use_git_ignore);
        builder.git_exclude(opts.use_git_ignore);
        builder.hidden(false);
        if opts.use_semgrep_ignore {
            builder.add_custom_ignore_filename(".semgrepignore");
        }

        for entry in builder.build().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Some(ref set) = include_set {
                if !set.is_match(path) {
                    continue;
                }
            }
            if let Some(ref set) = exclude_set {
                if set.is_match(path) {
                    ignored.push(path.to_path_buf());
                    continue;
                }
            }

            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if size > opts.max_target_bytes {
                ignored.push(path.to_path_buf());
                continue;
            }

            let lang = opts
                .force_language
                .or_else(|| custom_lang_detector(path));
            let lang = match lang {
                Some(l) => l,
                None => {
                    if opts.scan_unknown_extensions {
                        Language::Generic
                    } else {
                        continue;
                    }
                }
            };

            files.push(TargetFile {
                path: path.to_path_buf(),
                language: lang,
                size_bytes: size,
            });
        }
    }

    (files, ignored)
}

fn build_globset(patterns: &[String]) -> Option<globset::GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut b = globset::GlobSetBuilder::new();
    for p in patterns {
        if let Ok(g) = globset::Glob::new(p) {
            b.add(g);
        }
    }
    b.build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detect_dockerfile_basename() {
        assert_eq!(detect_lang(Path::new("Dockerfile")), Some(Language::Dockerfile));
        assert_eq!(detect_lang(Path::new("Dockerfile.prod")), Some(Language::Dockerfile));
    }

    #[test]
    fn detect_by_extension() {
        assert_eq!(detect_lang(Path::new("foo.py")), Some(Language::Python));
        assert_eq!(detect_lang(Path::new("foo.rs")), Some(Language::Rust));
    }

    #[test]
    fn globset_empty_returns_none() {
        assert!(build_globset(&[]).is_none());
    }
}
