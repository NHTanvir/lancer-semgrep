//! MCP tool registry and dispatcher.
//!
//! Each tool is one sub-module with `tool_def()` (the schema descriptor
//! returned in `tools/list`) and `run(args) -> Result<Value>` (the handler
//! invoked by `tools/call`). Adding a new tool means: a new sub-module, an
//! entry in [`list`], and an arm in [`call`].

use crate::mcp::protocol::*;

pub mod analyze_results;
pub mod create_rule;
pub mod filter_results;
pub mod findings;
pub mod languages;
pub mod list_rules;
pub mod rule_schema;
pub mod scan;
pub mod scan_custom;

/// Build the response body for `tools/list` — the array of tool
/// descriptors the MCP client uses to render its tool palette.
pub fn list() -> serde_json::Value {
    serde_json::json!({
        "tools": [
            scan::tool_def(),
            scan_custom::tool_def(),
            list_rules::tool_def(),
            languages::tool_def(),
            rule_schema::tool_def(),
            analyze_results::tool_def(),
            create_rule::tool_def(),
            filter_results::tool_def(),
            findings::tool_def(),
        ]
    })
}

/// Handle a `tools/call` JSON-RPC request. `params` is the raw
/// `{"name": "...", "arguments": {...}}` body from the client.
pub async fn call(
    id: serde_json::Value,
    params: serde_json::Value,
) -> JsonRpcResponse {
    let Some(name) = params
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return crate::mcp::server::error(id, INVALID_PARAMS, "missing tool name");
    };
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let result: eyre::Result<serde_json::Value> = match name.as_str() {
        "semgrep_scan" => scan::run(args).await,
        "semgrep_scan_with_custom_rule" => scan_custom::run(args).await,
        "semgrep_list_rules" => list_rules::run(args).await,
        "semgrep_get_supported_languages" => languages::run(args).await,
        "semgrep_rule_schema" => rule_schema::run(args).await,
        "semgrep_analyze_results" => analyze_results::run(args).await,
        "semgrep_create_rule" => create_rule::run(args).await,
        "semgrep_filter_results" => filter_results::run(args).await,
        "semgrep_findings" => findings::run(args).await,
        _ => {
            return crate::mcp::server::error(
                id,
                METHOD_NOT_FOUND,
                &format!("unknown tool: {name}"),
            );
        }
    };
    match result {
        Ok(v) => crate::mcp::server::respond(id, v),
        Err(e) => crate::mcp::server::error(id, INTERNAL_ERROR, &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_includes_all_nine_tools() {
        let v = list();
        let arr = v.get("tools").unwrap().as_array().unwrap();
        let names: Vec<&str> = arr
            .iter()
            .map(|t| t.get("name").unwrap().as_str().unwrap())
            .collect();
        for expected in [
            "semgrep_scan",
            "semgrep_scan_with_custom_rule",
            "semgrep_list_rules",
            "semgrep_get_supported_languages",
            "semgrep_rule_schema",
            "semgrep_analyze_results",
            "semgrep_create_rule",
            "semgrep_filter_results",
            "semgrep_findings",
        ] {
            assert!(
                names.contains(&expected),
                "tools/list missing {expected}"
            );
        }
    }

    #[tokio::test]
    async fn call_unknown_tool_returns_method_not_found() {
        let resp = call(
            serde_json::Value::Number(1.into()),
            serde_json::json!({ "name": "nope" }),
        )
        .await;
        let err = resp.error.expect("error");
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn call_missing_name_returns_invalid_params() {
        let resp = call(
            serde_json::Value::Number(1.into()),
            serde_json::json!({}),
        )
        .await;
        let err = resp.error.expect("error");
        assert_eq!(err.code, INVALID_PARAMS);
    }
}
