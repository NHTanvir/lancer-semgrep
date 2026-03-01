//! MCP dispatch loop: parse JSON-RPC request → route to method/tool → emit
//! the response.
//!
//! The transport layer (stdio / http) is responsible for framing; this
//! module operates strictly on parsed `JsonRpcRequest` values and the
//! `JsonRpcResponse` values it returns.

use crate::mcp::protocol::*;
use crate::mcp::tools;

/// Dispatch a parsed JSON-RPC request to the appropriate handler and return
/// a response. Notifications (no `id`) still get a response built here; the
/// transport layer must drop it before writing to the wire.
pub async fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone().unwrap_or(serde_json::Value::Null);
    match req.method.as_str() {
        "initialize" => match serde_json::to_value(initialize()) {
            Ok(v) => respond(id, v),
            Err(e) => error(id, INTERNAL_ERROR, &e.to_string()),
        },
        // MCP clients often send `notifications/initialized` after `initialize`;
        // we ack with an empty result.
        "notifications/initialized" => respond(id, serde_json::json!({})),
        "tools/list" => respond(id, tools::list()),
        "tools/call" => tools::call(id, req.params).await,
        "ping" => respond(id, serde_json::json!({})),
        _ => error(id, METHOD_NOT_FOUND, "method not found"),
    }
}

/// Build the `initialize` response body. Protocol version pinned to
/// `2025-11-05`; the MCP capabilities object only advertises `tools` for
/// now.
fn initialize() -> InitializeResult {
    InitializeResult {
        protocol_version: "2025-11-05".to_string(),
        capabilities: serde_json::json!({
            "tools": { "listChanged": false }
        }),
        server_info: ServerInfo {
            name: "lancer-semgrep".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    }
}

/// Build a successful response carrying `result`.
pub fn respond(id: serde_json::Value, result: serde_json::Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Build an error response with the given JSON-RPC error code + message.
pub fn error(id: serde_json::Value, code: i32, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::Value::Number(1.into())),
            method: "totally.not.real".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(req).await;
        let err = resp.error.expect("error expected");
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn ping_returns_empty_object_result() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::Value::Number(1.into())),
            method: "ping".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result, Some(serde_json::json!({})));
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::Value::Number(1.into())),
            method: "initialize".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(req).await;
        let r = resp.result.expect("result");
        assert!(r.get("protocolVersion").is_some());
        assert!(r.get("serverInfo").is_some());
    }
}
