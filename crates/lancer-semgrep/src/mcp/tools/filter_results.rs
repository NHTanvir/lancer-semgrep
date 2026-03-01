//! `semgrep_filter_results` MCP tool — narrow a `ScanReport`-shaped JSON
//! by rule_id / language / severity / path glob / message substring.

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_filter_results",
        "description": "Filter a Semgrep results / ScanReport JSON by rule_id, \
                        language, severity, path substring, or message substring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "results":  { "type": "object", "description": "ScanReport or wire-format results JSON" },
                "rule_id":  { "type": "string" },
                "language": { "type": "string" },
                "severity": { "type": "string", "description": "INFO | WARNING | ERROR" },
                "path":     { "type": "string", "description": "Substring to match against finding path" },
                "message":  { "type": "string", "description": "Substring to match against finding message" }
            },
            "required": ["results"]
        }
    })
}

pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    let results = args
        .get("results")
        .cloned()
        .ok_or_else(|| eyre::eyre!("results required"))?;

    let rule_id = args.get("rule_id").and_then(|v| v.as_str());
    let language = args.get("language").and_then(|v| v.as_str());
    let severity = args.get("severity").and_then(|v| v.as_str());
    let path_sub = args.get("path").and_then(|v| v.as_str());
    let msg_sub = args.get("message").and_then(|v| v.as_str());

    // `findings` is the ScanReport key; `results` is the legacy wire key.
    // Whichever the caller passed in, we filter the array under it.
    let mut filtered = results.clone();
    for key in ["findings", "results"] {
        if let Some(arr) = filtered
            .get(key)
            .and_then(|v| v.as_array())
            .cloned()
        {
            let new_arr: Vec<serde_json::Value> = arr
                .into_iter()
                .filter(|f| matches_filters(f, rule_id, language, severity, path_sub, msg_sub))
                .collect();
            filtered[key] = serde_json::Value::Array(new_arr);
        }
    }
    Ok(filtered)
}

fn matches_filters(
    finding: &serde_json::Value,
    rule_id: Option<&str>,
    language: Option<&str>,
    severity: Option<&str>,
    path_sub: Option<&str>,
    msg_sub: Option<&str>,
) -> bool {
    if let Some(r) = rule_id {
        let id = finding
            .get("rule_id")
            .or_else(|| finding.get("check_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if id != r {
            return false;
        }
    }
    if let Some(lang) = language {
        // Finding may carry the language via `extra.languages` or
        // top-level `languages`. We accept any presence of `lang` in
        // either array.
        let lang_ok = finding
            .get("languages")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().any(|x| x.as_str() == Some(lang)))
            .unwrap_or(false)
            || finding
                .pointer("/extra/languages")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().any(|x| x.as_str() == Some(lang)))
                .unwrap_or(false);
        if !lang_ok {
            return false;
        }
    }
    if let Some(sev) = severity {
        let sev_ok = finding
            .get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case(sev))
            .unwrap_or(false);
        if !sev_ok {
            return false;
        }
    }
    if let Some(p) = path_sub {
        let path_ok = finding
            .get("file")
            .or_else(|| finding.get("path"))
            .and_then(|v| v.as_str())
            .map(|s| s.contains(p))
            .unwrap_or(false);
        if !path_ok {
            return false;
        }
    }
    if let Some(m) = msg_sub {
        let msg_ok = finding
            .get("message")
            .or_else(|| finding.pointer("/extra/message"))
            .and_then(|v| v.as_str())
            .map(|s| s.contains(m))
            .unwrap_or(false);
        if !msg_ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn filter_by_severity_keeps_only_matching() {
        let payload = serde_json::json!({
            "findings": [
                { "rule_id": "a", "severity": "ERROR",   "file": "x.py", "message": "boom" },
                { "rule_id": "b", "severity": "WARNING", "file": "y.py", "message": "meh" }
            ]
        });
        let out = run(serde_json::json!({
            "results":  payload,
            "severity": "ERROR"
        }))
        .await
        .unwrap();
        let arr = out.get("findings").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["rule_id"], "a");
    }
}
