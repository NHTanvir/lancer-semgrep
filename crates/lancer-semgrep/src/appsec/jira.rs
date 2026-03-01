//! Jira ticketing integration — file Jira tickets from findings.
//!
//! Stub.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct JiraTicket {
    pub key: String,         // e.g. "SEC-1234"
    pub url: String,
}

impl AppSecClient {
    pub async fn file_jira_ticket(&self, _finding_id: &str) -> Result<JiraTicket> {
        Err(AppSecError::OssOnly("POST /api/v1/integrations/jira"))
    }
}
