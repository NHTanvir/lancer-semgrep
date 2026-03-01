//! Plan §"AI augmentation ideas → Per-language rule variants".
//!
//! Given one canonical rule (e.g. Python SSRF), produce variants for JS /
//! Go / Ruby / Java / etc.

use crate::ai::{AiError, Result};
use semgrep_core::{Language, Rule};

pub async fn produce_variants(
    _canonical: &Rule,
    _target_languages: &[Language],
) -> Result<Vec<Rule>> {
    Err(AiError::NotConfigured)
}
