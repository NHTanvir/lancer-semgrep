//! Plan §"AI augmentation ideas → Summarise a finding cluster".
//!
//! Collapse a 200-finding report into ~15 root-cause clusters with a
//! one-line summary each.

use semgrep_core::Finding;

use crate::ai::{AiError, Result};

#[derive(Debug, Clone)]
pub struct Cluster {
    pub summary: String,
    pub member_indices: Vec<usize>,
}

pub async fn summarise(_findings: &[Finding]) -> Result<Vec<Cluster>> {
    Err(AiError::NotConfigured)
}
