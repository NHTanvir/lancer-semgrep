//! SBOM (Software Bill of Materials) export stubs.
//!
//! Per plan §"Research note 2026-05-31 → SBOM dep-path export (Apr 2026)".
//! Both formats are stubbed for now; emitters that actually serialise the
//! dep graph will land alongside per-manifest parsers.

use crate::supply_chain::manifests::DepDecl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

/// Render `deps` into a `format`-formatted SBOM document.
///
/// **Stub:** returns an empty document marker (`{}` for CycloneDX,
/// `SPDXVersion: SPDX-2.3\n` for SPDX) so the CLI plumbing can call this
/// without panicking. Actual serialisation lands later.
pub fn export_sbom(_deps: &[DepDecl], format: SbomFormat) -> String {
    match format {
        SbomFormat::CycloneDx => "{}".to_string(),
        SbomFormat::Spdx => "SPDXVersion: SPDX-2.3\n".to_string(),
    }
}
