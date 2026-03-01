//! Evaluate a rule's `r2c-internal-project-depends-on:` block against the
//! project's resolved dependency set.
//!
//! Per plan.md §"Newer rule-format features → r2c-internal-project-depends-on":
//! the rule should only fire if the target project depends on a package
//! within a given version range. The check runs once per scan (gated by the
//! manifest detector); when no constraint matches, all rules with a
//! `r2c-internal-project-depends-on:` block are skipped.

use crate::rule::DependsOnConstraint;
use crate::supply_chain::manifests::DepDecl;

/// Returns `true` iff at least one of `constraints` is satisfied by an entry
/// in `deps`. The version range is interpreted loosely:
///
/// - `"*"` matches any version.
/// - `">= X"` / `"> X"` / `"<= X"` / `"< X"` matches against `dep.version`
///   using simple lexicographic comparison after splitting on `.`. Suitable
///   for SemVer-style strings; not strictly compliant with the full SemVer
///   range grammar.
/// - `"X"` (bare version) matches exact equality.
/// - Comma-separated clauses (`">= 1.0, < 2.0"`) AND-combine.
///
/// Each constraint's `namespace` must equal `dep.namespace` (case-insensitive)
/// and `package` must equal `dep.name` (case-insensitive) for the match to
/// even be considered.
pub fn evaluate_depends_on(constraints: &[DependsOnConstraint], deps: &[DepDecl]) -> bool {
    for c in constraints {
        for d in deps {
            if !c.namespace.eq_ignore_ascii_case(&namespace_of(d)) {
                continue;
            }
            if !c.package.eq_ignore_ascii_case(&d.name) {
                continue;
            }
            if version_matches(&d.version, &c.version) {
                return true;
            }
        }
    }
    false
}

/// Map a `ManifestKind` to a canonical namespace string for matching.
fn namespace_of(d: &DepDecl) -> String {
    use crate::supply_chain::manifests::ManifestKind::*;
    match d.manifest {
        NpmPackageJson | NpmLock | YarnLock | PnpmLock => "npm",
        PipRequirements | PipPipfileLock | PipPoetryLock | PipUvLock => "pypi",
        MavenPom | GradleBuild => "maven",
        CargoLock => "cargo",
        ComposerLock => "composer",
        GemfileLock => "gem",
        GoMod | GoSum => "go",
        NuGetCsproj | NuGetPackagesConfig => "nuget",
        HexMixLock => "hex",
        PubPubspecLock => "pub",
        SwiftPackageResolved => "swiftpm",
    }
    .to_string()
}

/// Check whether `actual` satisfies the comma-AND-combined `range` spec.
pub fn version_matches(actual: &str, range: &str) -> bool {
    let range = range.trim();
    if range == "*" || range.is_empty() {
        return true;
    }
    for clause in range.split(',') {
        if !match_clause(actual, clause.trim()) {
            return false;
        }
    }
    true
}

fn match_clause(actual: &str, clause: &str) -> bool {
    let (op, rhs) = if let Some(rest) = clause.strip_prefix(">=") {
        (">=", rest.trim())
    } else if let Some(rest) = clause.strip_prefix("<=") {
        ("<=", rest.trim())
    } else if let Some(rest) = clause.strip_prefix("==") {
        ("==", rest.trim())
    } else if let Some(rest) = clause.strip_prefix('>') {
        (">", rest.trim())
    } else if let Some(rest) = clause.strip_prefix('<') {
        ("<", rest.trim())
    } else if let Some(rest) = clause.strip_prefix('=') {
        ("==", rest.trim())
    } else {
        ("==", clause)
    };

    let ord = compare_versions(actual, rhs);
    match op {
        "==" => ord == std::cmp::Ordering::Equal,
        ">" => ord == std::cmp::Ordering::Greater,
        ">=" => ord != std::cmp::Ordering::Less,
        "<" => ord == std::cmp::Ordering::Less,
        "<=" => ord != std::cmp::Ordering::Greater,
        _ => false,
    }
}

/// Compare two version strings componentwise. Numeric components are
/// compared numerically; non-numeric components lexicographically.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.split(|c: char| c == '.' || c == '-' || c == '+');
    let mut bi = b.split(|c: char| c == '.' || c == '-' || c == '+');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                let xn = x.parse::<u64>().ok();
                let yn = y.parse::<u64>().ok();
                let ord = match (xn, yn) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    _ => x.cmp(y),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_matches_everything() {
        assert!(version_matches("1.0.0", "*"));
        assert!(version_matches("anything", ""));
    }

    #[test]
    fn lt_clause_works() {
        assert!(version_matches("1.0.0", "< 2.0.0"));
        assert!(!version_matches("2.0.0", "< 2.0.0"));
    }

    #[test]
    fn compound_range_works() {
        assert!(version_matches("1.5.0", ">= 1.0.0, < 2.0.0"));
        assert!(!version_matches("2.0.0", ">= 1.0.0, < 2.0.0"));
        assert!(!version_matches("0.9.0", ">= 1.0.0, < 2.0.0"));
    }

    #[test]
    fn equality_default() {
        assert!(version_matches("1.0.0", "1.0.0"));
        assert!(!version_matches("1.0.1", "1.0.0"));
    }
}
