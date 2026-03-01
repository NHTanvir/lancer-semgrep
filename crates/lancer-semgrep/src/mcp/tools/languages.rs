//! `semgrep_get_supported_languages` MCP tool.

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_get_supported_languages",
        "description": "List the languages this build of lancer-semgrep can parse.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    })
}

pub async fn run(_args: serde_json::Value) -> Result<serde_json::Value> {
    let langs: Vec<String> = tree_sitter_langs::enabled_languages()
        .into_iter()
        .map(|l| l.display_name().to_string())
        .collect();
    Ok(serde_json::json!({ "languages": langs }))
}
