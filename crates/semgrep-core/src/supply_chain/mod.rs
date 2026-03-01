//! Supply-chain mode: manifest detection + dependency parsing + reachability.
//!
//! See plan.md §"Supply chain mode" and §"Research note 2026-05-31" (PHP
//! reachability, lockfile-less Java/Kotlin scan, `SEMGREP_LOCAL_BUILD_ENV`,
//! SBOM dep-path export).

pub mod local_build_env;
pub mod lockfile_less;
pub mod manifests;
pub mod project_depends_on;
pub mod reachability;
pub mod sbom;
pub mod upgrade_guidance;

pub use local_build_env::{read_local_build_env, LocalBuildEnv};
pub use lockfile_less::{lockfile_less_supported, supports_lockfile_less, synth_from_manifest};
pub use manifests::{detect_manifest, parse_manifest, DepDecl, ManifestKind};
pub use project_depends_on::{compare_versions, evaluate_depends_on, version_matches};
pub use reachability::{reachability_supported, reachability_supported_list};
pub use sbom::{export_sbom, SbomFormat};
pub use upgrade_guidance::UpgradeGuidance;
