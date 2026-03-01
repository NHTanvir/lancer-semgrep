//! Lockfile-less Java/Kotlin Supply Chain scanning.
//!
//! Per plan §"Research note 2026-05-31 → Java/Kotlin lockfile-less scan
//! (Mar 2026 beta)": when no `*.lock` file exists, synthesise the dep graph
//! by parsing `pom.xml` / `build.gradle[.kts]` directly. Useful for projects
//! that don't commit lockfiles to git.
//!
//! Stub-level today — surfaces the API and the supported languages list so
//! `--supply-chain` callers can branch on it. Full pom.xml / Gradle parsing
//! lands later alongside the per-manifest parsers in `manifests.rs`.

use crate::Language;

/// Languages that support lockfile-less synthesis.
pub fn lockfile_less_supported() -> Vec<Language> {
    vec![Language::Java, Language::Kotlin]
}

/// Returns `true` when synthesising the dep graph from a non-lockfile
/// manifest is supported for `lang`.
pub fn supports_lockfile_less(lang: Language) -> bool {
    matches!(lang, Language::Java | Language::Kotlin)
}

/// Synthesise dependency declarations from a non-lockfile manifest.
///
/// **Stub:** returns an empty `Vec<DepDecl>`. Full parsing pulls in
/// `pom.xml` / `build.gradle` / `build.gradle.kts` and walks them. Tracked
/// alongside the per-manifest parser stubs in `manifests.rs`.
pub fn synth_from_manifest(
    _path: &std::path::Path,
) -> Result<Vec<crate::supply_chain::manifests::DepDecl>, crate::SemgrepError> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_and_kotlin_supported() {
        assert!(supports_lockfile_less(Language::Java));
        assert!(supports_lockfile_less(Language::Kotlin));
        assert!(!supports_lockfile_less(Language::Python));
    }

    #[test]
    fn supported_list_size_two() {
        assert_eq!(lockfile_less_supported().len(), 2);
    }
}
