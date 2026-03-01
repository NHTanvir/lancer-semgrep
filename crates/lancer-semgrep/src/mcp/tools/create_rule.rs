//! `semgrep_create_rule` MCP tool — author a minimal rule YAML and write
//! it to a path the caller specifies.

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_create_rule",
        "description": "Author a minimal Semgrep rule (id / pattern / language / \
                        message / severity) and write it to disk as YAML.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":     { "type": "string", "description": "Destination YAML path" },
                "id":       { "type": "string", "description": "Rule id", "default": "custom-rule" },
                "pattern":  { "type": "string", "description": "Semgrep pattern" },
                "language": { "type": "string", "description": "Target language (default python)" },
                "message":  { "type": "string", "description": "Finding message" },
                "severity": { "type": "string", "description": "INFO | WARNING | ERROR" }
            },
            "required": ["path", "pattern"]
        }
    })
}

pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("path required"))?;
    let pattern = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("pattern required"))?;
    let language = args
        .get("language")
        .and_then(|v| v.as_str())
        .unwrap_or("python");
    let id = args
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("custom-rule");
    let message = args
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("custom rule finding");
    let severity = args
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("WARNING");

    let yaml = format!(
        "rules:\n  - id: {id}\n    languages: [{language}]\n    severity: {severity}\n    message: {message}\n    pattern: {pattern}\n"
    );
    std::fs::write(path, &yaml)?;

    Ok(serde_json::json!({
        "written": path,
        "bytes": yaml.len()
    }))
}
