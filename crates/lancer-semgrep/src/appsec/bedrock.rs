//! AWS Bedrock BYOK (Bring Your Own Key) with IAM role-assumption (Apr 2026).
//!
//! Per plan §"AppSec / Multimodal → AWS Bedrock BYOK with IAM role-assumption
//! (Apr 2026)". Customers can run Semgrep's LLM-backed features (AI
//! auto-triage, Autofix, AI-powered detection) against their own Bedrock
//! account, paying their own bill and keeping data inside their AWS org.
//!
//! Stub: shape of the IAM role-assumption config + endpoint.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct BedrockBindings {
    pub account_id: String,
    pub region: String,
    pub assume_role_arn: String,
    pub model_id: String, // e.g. "anthropic.claude-sonnet-4-6"
}

impl AppSecClient {
    /// Configure AWS Bedrock as the LLM backend for this customer's tenant.
    pub async fn configure_bedrock(&self, _b: &BedrockBindings) -> Result<()> {
        Err(AppSecError::OssOnly("PUT /api/v1/bedrock"))
    }
}
