//! `semgrep_findings` MCP tool — May 2026 spec.
//!
//! Per plan.md §"Research note — 2026-05-31":
//! - `refs`: optional array of branch names; when omitted, defaults to the
//!   primary branch.
//! - `autotriage_verdict`: optional AI verdict filter. Crucially, when the
//!   caller *omits* this filter, findings without a verdict are still
//!   returned. The server must distinguish "filter unset" from
//!   "filter explicitly null".
//!
//! `lancer-semgrep` doesn't yet persist a per-branch report cache, so the
//! response is currently always an empty findings list with `filters_applied`
//! echoed back so MCP clients can confirm the request shape was understood.

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_findings",
        "description": "Fetch findings from the local report cache, filterable by \
                        branch refs and AI auto-triage verdict (May 2026 spec).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "refs": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Branch refs to filter by; defaults to primary branch."
                },
                "autotriage_verdict": {
                    "type": "string",
                    "description": "Optional AI verdict filter (May 2026). When omitted, \
                                    findings without verdicts are still returned."
                }
            }
        }
    })
}

pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    // Preserve `null` vs. absent: an MCP client may explicitly pass
    // `autotriage_verdict: null`, which is different from omitting it.
    let refs = args.get("refs").cloned();
    let verdict = if args.as_object().map(|o| o.contains_key("autotriage_verdict")).unwrap_or(false)
    {
        args.get("autotriage_verdict").cloned()
    } else {
        None
    };

    Ok(serde_json::json!({
        "findings": [],
        "filters_applied": {
            "refs": refs,
            "autotriage_verdict": verdict
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_args_returns_empty_findings_with_no_filters() {
        let out = run(serde_json::json!({})).await.unwrap();
        assert!(out["findings"].as_array().unwrap().is_empty());
        assert!(out["filters_applied"]["refs"].is_null());
        assert!(out["filters_applied"]["autotriage_verdict"].is_null());
    }

    #[tokio::test]
    async fn refs_passed_through() {
        let out = run(serde_json::json!({ "refs": ["main", "release/1.5"] }))
            .await
            .unwrap();
        let refs = out["filters_applied"]["refs"].as_array().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], "main");
    }
}
