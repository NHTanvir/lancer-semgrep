//! Network Broker — on-prem agent for scanning private repos.
//!
//! Per plan §"AppSec / Network Broker (single-pubkey, Feb 2026)": only one
//! pubkey may be registered at a time; rotation goes through revoke→add.
//! Stubbed.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct BrokerRegistration {
    pub pubkey_fingerprint: String,
    pub bound_at: String,
}

impl AppSecClient {
    pub async fn broker_register(&self, _pubkey: &str) -> Result<BrokerRegistration> {
        Err(AppSecError::OssOnly("POST /api/v1/broker/register"))
    }
    pub async fn broker_revoke(&self, _fingerprint: &str) -> Result<()> {
        Err(AppSecError::OssOnly("POST /api/v1/broker/revoke"))
    }
}
