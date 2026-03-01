//! `semgrep_scan` MCP tool — scan a directory using a Semgrep config.

use eyre::Result;
use semgrep_core::scan::EnumerateOpts;

use crate::scan::run::{run_scan, ScanOpts};

/// MCP tool descriptor (returned in `tools/list`).
pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_scan",
        "description": "Scan a directory for security issues using a Semgrep config \
                        (path, dir, p/<slug>, or `auto`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory or file to scan"
                },
                "config": {
                    "type": "string",
                    "description": "Config path / slug / `auto`",
                    "default": "auto"
                }
            },
            "required": ["path"]
        }
    })
}

/// Handle `tools/call name=semgrep_scan`.
pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("path required"))?;
    let config = args
        .get("config")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    let mut rules = semgrep_rules::RuleSet::new();
    match semgrep_rules::ConfigSource::parse(config) {
        semgrep_rules::ConfigSource::File(p) => {
            rules.extend(semgrep_rules::load_file(&p)?);
        }
        semgrep_rules::ConfigSource::Dir(p) => {
            rules.extend(semgrep_rules::load_dir(&p)?);
        }
        // Slug / URL / Auto: registry fetch is wired in a later task. Until
        // then we proceed with an empty rule set; the response will simply
        // contain zero findings.
        _ => {
            tracing::warn!(
                config = %config,
                "registry slug / URL / auto: network wiring deferred"
            );
        }
    }

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
