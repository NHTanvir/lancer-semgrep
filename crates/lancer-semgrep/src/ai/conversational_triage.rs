//! Plan §"AI augmentation ideas → Conversational triage".
//!
//! A chat session with the current finding loaded as context. "Is this
//! exploitable given the input is validated upstream?"

use crate::ai::{AiError, Result};

pub struct TriageSession {
    pub finding: semgrep_core::Finding,
    pub transcript: Vec<TriageTurn>,
}

#[derive(Debug, Clone)]
pub struct TriageTurn {
    pub role: TriageRole,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageRole {
    User,
    Assistant,
}

impl TriageSession {
    pub fn new(finding: semgrep_core::Finding) -> Self {
        Self {
            finding,
            transcript: Vec::new(),
        }
    }

    pub async fn ask(&mut self, _question: &str) -> Result<String> {
        Err(AiError::NotConfigured)
    }
}
