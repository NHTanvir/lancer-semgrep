//! Integration tests for the MCP subcommand surface (Task 10).
//!
//! These exercise the protocol / security / tool-registry surface without
//! touching real networks or stdin — the goal is to lock in the
//! invariants the MCP spec demands (DNS-rebinding refusal, OAuth Bearer
//! enforcement, the nine registered tools).

use lancer_semgrep::mcp::oauth::verify_bearer;
use lancer_semgrep::mcp::protocol::{JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND};
use lancer_semgrep::mcp::security::is_loopback_host;
use lancer_semgrep::mcp::server::handle_request;
use lancer_semgrep::mcp::tools;

#[test]
fn loopback_check_rejects_external() {
    assert!(!is_loopback_host("attacker.example.com"));
    assert!(!is_loopback_host("10.0.0.1"));
    assert!(!is_loopback_host("8.8.8.8"));
    assert!(is_loopback_host("127.0.0.1"));
    assert!(is_loopback_host("::1"));
    assert!(is_loopback_host("[::1]"));
    assert!(is_loopback_host("localhost"));
}

#[test]
fn oauth_rejects_empty_bearer() {
    assert!(!verify_bearer("Bearer "));
    assert!(!verify_bearer(""));
    assert!(!verify_bearer("Basic abc"));
    assert!(verify_bearer("Bearer xyz"));
}

#[test]
fn tools_list_includes_all_required_tools() {
    let v = tools::list();
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
            "tools/list missing {expected}; got {names:?}"
        );
    }
    // Plan-mandated minimum: at least 9 tools registered.
    assert!(arr.len() >= 9, "expected >=9 tools, got {}", arr.len());
}

#[tokio::test]
async fn handle_request_initialize_returns_protocol_version() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(serde_json::Value::Number(1.into())),
        method: "initialize".into(),
        params: serde_json::Value::Null,
    };
    let resp: JsonRpcResponse = handle_request(req).await;
    let r = resp.result.expect("result");
    assert_eq!(r["protocolVersion"], "2025-11-05");
    assert_eq!(r["serverInfo"]["name"], "lancer-semgrep");
}

#[tokio::test]
async fn handle_request_unknown_method_returns_method_not_found() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(serde_json::Value::Number(7.into())),
        method: "no.such.method".into(),
        params: serde_json::Value::Null,
    };
    let resp = handle_request(req).await;
    let err = resp.error.expect("error");
    assert_eq!(err.code, METHOD_NOT_FOUND);
}

#[tokio::test]
async fn tools_list_via_handle_request() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(serde_json::Value::Number(2.into())),
        method: "tools/list".into(),
        params: serde_json::Value::Null,
    };
    let resp = handle_request(req).await;
    let r = resp.result.expect("result");
    let arr = r.get("tools").unwrap().as_array().unwrap();
    assert!(arr.len() >= 9);
}
