//! `GET /api/v1/projects` + project metadata endpoints.
//!
//! Stub: returns `OssOnly`.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub default_branch: String,
}

impl AppSecClient {
    pub async fn list_projects(&self) -> Result<Vec<Project>> {
        Err(AppSecError::OssOnly("GET /api/v1/projects"))
    }

    pub async fn project(&self, _id: &str) -> Result<Project> {
        Err(AppSecError::OssOnly("GET /api/v1/projects/{id}"))
    }
}
