//! Dependency-manifest detection + (stub) parsing for the 15+ package
//! managers the Supply Chain product supports. Actual parsing per manifest
//! type is intentionally left as a stub returning an empty `Vec<DepDecl>` —
//! the detector is enough to drive a Supply Chain workflow skeleton; full
//! parsing lands in a follow-up.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// One declared dependency from a manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepDecl {
    pub name: String,
    pub version: String,
    pub manifest: ManifestKind,
}

/// Which manifest format produced this declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestKind {
    NpmPackageJson,
    NpmLock,
    YarnLock,
    PnpmLock,
    PipRequirements,
    PipPipfileLock,
    PipPoetryLock,
    PipUvLock,
    MavenPom,
    GradleBuild,
    CargoLock,
    ComposerLock,
    GemfileLock,
    GoMod,
    GoSum,
    NuGetCsproj,
    NuGetPackagesConfig,
    HexMixLock,
    PubPubspecLock,
    SwiftPackageResolved,
}

/// Recognise a manifest from its basename. Returns `None` for files we don't
/// know how to interpret.
pub fn detect_manifest(path: &Path) -> Option<ManifestKind> {
    let name = path.file_name().and_then(|n| n.to_str())?;
    Some(match name {
        "package.json" => ManifestKind::NpmPackageJson,
        "package-lock.json" => ManifestKind::NpmLock,
        "yarn.lock" => ManifestKind::YarnLock,
        "pnpm-lock.yaml" => ManifestKind::PnpmLock,
        "requirements.txt" => ManifestKind::PipRequirements,
        "Pipfile.lock" => ManifestKind::PipPipfileLock,
        "poetry.lock" => ManifestKind::PipPoetryLock,
        "uv.lock" => ManifestKind::PipUvLock,
        "pom.xml" => ManifestKind::MavenPom,
        "build.gradle" | "build.gradle.kts" => ManifestKind::GradleBuild,
        "Cargo.lock" => ManifestKind::CargoLock,
        "composer.lock" => ManifestKind::ComposerLock,
        "Gemfile.lock" => ManifestKind::GemfileLock,
        "go.mod" => ManifestKind::GoMod,
        "go.sum" => ManifestKind::GoSum,
        "packages.config" => ManifestKind::NuGetPackagesConfig,
        "mix.lock" => ManifestKind::HexMixLock,
        "pubspec.lock" => ManifestKind::PubPubspecLock,
        "Package.resolved" => ManifestKind::SwiftPackageResolved,
        n if n.ends_with(".csproj") => ManifestKind::NuGetCsproj,
        _ => return None,
    })
}

/// Parse a manifest file into `DepDecl`s.
///
/// **Stub:** returns an empty Vec for every manifest type. The detector + the
/// `ManifestKind` enum are enough to power a Supply Chain workflow skeleton;
/// per-format parsers are deferred.
pub fn parse_manifest(path: &Path) -> Result<Vec<DepDecl>, crate::SemgrepError> {
    let _kind = detect_manifest(path).ok_or_else(|| {
        crate::SemgrepError::Other(format!("unknown manifest: {}", path.display()))
    })?;
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
        assert_eq!(detect_manifest(Path::new("go.mod")), Some(ManifestKind::GoMod));
        assert_eq!(
            detect_manifest(Path::new("App.csproj")),
            Some(ManifestKind::NuGetCsproj)
        );
        assert_eq!(detect_manifest(Path::new("random.txt")), None);
    }
}
