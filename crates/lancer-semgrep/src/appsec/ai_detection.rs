//! AI-powered detection — beta IDOR / broken-authz detector that combines
//! LLM reasoning with Semgrep findings (Mar 2026).
//!
//! Per plan §"AppSec / Multimodal → AI-powered detection (Mar 2026)".
//! Stubbed: a real implementation calls the cloud's `/detect/ai` endpoint
//! and merges the LLM verdict back into findings.

use crate::appsec::{AppSecClient, AppSecError, Result};

#[derive(Debug, Clone)]
pub struct AiFinding {
    pub kind: AiDetectionKind,
    pub file: std::path::PathBuf,
    pub line: usize,
    pub message: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiDetectionKind {
    Idor,
    BrokenAuthz,
}

impl AppSecClient {
    pub async fn ai_detect(&self, _target_dir: &std::path::Path) -> Result<Vec<AiFinding>> {
        Err(AppSecError::OssOnly("POST /api/v1/ai/detect"))
    }
}
