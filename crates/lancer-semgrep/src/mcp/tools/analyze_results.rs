//! `semgrep_analyze_results` MCP tool — re-process a previously emitted
//! Semgrep-JSON result file and return a tiny summary.

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_analyze_results",
        "description": "Load a previously emitted Semgrep JSON results file and \
                        return a finding-count summary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "results_path": {
                    "type": "string",
                    "description": "Path to a JSON file produced by `semgrep --json`."
                }
            },
            "required": ["results_path"]
        }
    })
}

pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    let path = args
        .get("results_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("results_path required"))?;
    let body = std::fs::read_to_string(path)?;
    let parsed: serde_json::Value = serde_json::from_str(&body)?;

    // Either `results` (Semgrep wire format) or `findings` (ScanReport).
    let total = parsed
        .get("results")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .or_else(|| {
            parsed
                .get("findings")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
        })
        .unwrap_or(0);

    Ok(serde_json::json!({
        "total_findings": total,
        "summary": format!("Loaded {total} findings from {path}")
    }))
}
