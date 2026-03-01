//! Managed Scans — server-side scheduled scans, branch-scoped scanning.
//!
//! Stub.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct ManagedScan {
    pub id: String,
    pub schedule: String,    // e.g. "0 0 * * *"
    pub target_branches: Vec<String>,
}

impl AppSecClient {
    pub async fn list_managed_scans(&self) -> Result<Vec<ManagedScan>> {
        Err(AppSecError::OssOnly("GET /api/v1/managed-scans"))
    }
}
