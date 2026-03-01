//! `semgrep_scan_with_custom_rule` MCP tool — scan with an inline rule YAML.

use eyre::Result;
use semgrep_core::scan::EnumerateOpts;

use crate::scan::run::{run_scan, ScanOpts};

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_scan_with_custom_rule",
        "description": "Scan a path with an ad-hoc rule YAML string supplied inline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory or file to scan"
                },
                "rule_yaml": {
                    "type": "string",
                    "description": "Inline YAML, with `rules:` at the top level"
                }
            },
            "required": ["path", "rule_yaml"]
        }
    })
}

pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("path required"))?;
    let rule_yaml = args
        .get("rule_yaml")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("rule_yaml required"))?;

    let rules = semgrep_rules::load_str(rule_yaml, "<inline>")?;

    let opts = ScanOpts {
        targets: vec![std::path::PathBuf::from(path)],
        enumerate: EnumerateOpts::default(),
        baseline_commit: None,
        diff_depth: 0,
        jobs: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        dataflow_traces: false,
    };
    let report = run_scan(&opts, &rules).await;
    Ok(serde_json::to_value(report)?)
}
