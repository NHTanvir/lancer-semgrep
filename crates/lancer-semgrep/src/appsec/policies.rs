//! Policies + Managed-Scans server-side configuration endpoints.
//!
//! Stub.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub branch_scoped: bool,
}

impl AppSecClient {
    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        Err(AppSecError::OssOnly("GET /api/v1/policies"))
    }
}
