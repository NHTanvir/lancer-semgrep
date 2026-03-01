//! Integration tests for supply-chain manifest detection + reachability list.

use std::path::Path;

use semgrep_core::supply_chain::{
    detect_manifest, reachability_supported, reachability_supported_list, ManifestKind,
};
use semgrep_core::Language;

#[test]
fn detects_common_manifests() {
    assert_eq!(
        detect_manifest(Path::new("package.json")),
        Some(ManifestKind::NpmPackageJson)
    );
    assert_eq!(
        detect_manifest(Path::new("Cargo.lock")),
        Some(ManifestKind::CargoLock)
    );
    assert_eq!(
        detect_manifest(Path::new("Gemfile.lock")),
        Some(ManifestKind::GemfileLock)
    );
    assert_eq!(
        detect_manifest(Path::new("go.mod")),
        Some(ManifestKind::GoMod)
    );
    assert_eq!(
        detect_manifest(Path::new("App.csproj")),
        Some(ManifestKind::NuGetCsproj)
    );
    assert_eq!(detect_manifest(Path::new("random.txt")), None);
}

#[test]
fn php_is_in_reachability_list() {
    assert!(reachability_supported(Language::Php));
    assert!(reachability_supported_list().contains(&Language::Php));
}

#[test]
fn reachability_list_has_eleven_languages() {
    assert_eq!(reachability_supported_list().len(), 11);
}
