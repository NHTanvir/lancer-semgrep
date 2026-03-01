//! Semgrep Plugin install bundle — MCP server + agentic Hooks + Skills
//! shipped together for Claude Code / Cursor / Windsurf.
//!
//! Per plan §"MCP server → Bundled with Hooks + Skills in the Semgrep
//! Plugin install (Mar 2026)" and §"MCP server → Default config runs Code +
//! Supply Chain + Secrets in one MCP server".
//!
//! The plugin bundle is a small JSON manifest declaring (a) the MCP server
//! invocation, (b) the agentic hooks (custom Cursor / Windsurf / Claude Code
//! hooks that pull custom rules from the Registry), and (c) the skills
//! library. We expose helpers to render the manifest for each editor.

use serde::{Deserialize, Serialize};

/// Top-level bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBundle {
    pub mcp_servers: Vec<McpServerEntry>,
    pub hooks: Vec<HookEntry>,
    pub skills: Vec<SkillEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub products: Vec<String>, // ["code", "supply-chain", "secrets"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEntry {
    pub event: String,        // e.g. "pre-commit", "pre-merge"
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillEntry {
    pub name: String,
    pub description: String,
    pub source: String,       // file path or URL
}

impl PluginBundle {
    /// Default bundle: one MCP server running Code + Supply Chain + Secrets,
    /// plus a pre-commit hook and a "scan" skill.
    pub fn default_bundle() -> Self {
        Self {
            mcp_servers: vec![McpServerEntry {
                name: "lancer-semgrep".into(),
                command: "lancer-semgrep".into(),
                args: vec!["mcp".into(), "--transport".into(), "stdio".into()],
                products: vec!["code".into(), "supply-chain".into(), "secrets".into()],
            }],
            hooks: vec![HookEntry {
                event: "pre-commit".into(),
                command: "lancer-semgrep".into(),
                args: vec!["scan".into(), "--baseline-commit".into(), "HEAD".into()],
            }],
            skills: vec![SkillEntry {
                name: "scan".into(),
                description: "Run lancer-semgrep on this folder and surface findings.".into(),
                source: "builtin:semgrep_scan".into(),
            }],
        }
    }

    /// Render to JSON for Claude Code's `.mcp.json` / Cursor's
    /// `mcpServers` config / Windsurf's `mcp_config.json`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_serialises() {
        let b = PluginBundle::default_bundle();
        let json = b.to_json().unwrap();
        assert!(json.contains("lancer-semgrep"));
        assert!(json.contains("supply-chain"));
        assert!(json.contains("pre-commit"));
    }
}
