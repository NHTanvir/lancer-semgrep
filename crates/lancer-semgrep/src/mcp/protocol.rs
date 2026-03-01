//! JSON-RPC 2.0 framing types + MCP protocol wire structs.
//!
//! Kept dependency-light: just `serde` + `serde_json`. The transports
//! (stdio / http) own the framing (newline / Content-Length) — these types
//! only describe the payload itself.

use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request as received from an MCP client.
///
/// `id` is `None` when the message is a JSON-RPC notification (the client
/// expects no response). In that case the server should still consume the
/// payload but must not emit a response frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A JSON-RPC 2.0 response to send back to an MCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// Standard JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A single MCP tool descriptor returned by `tools/list`.
///
/// The MCP spec uses camelCase on the wire (`inputSchema`), but we use the
/// `serde(rename = ...)` attribute so the Rust field stays snake_case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// MCP `initialize` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: serde_json::Value,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// JSON-RPC error codes (per https://www.jsonrpc.org/specification#error_object).
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_request_with_no_id_is_notification() {
        let raw = r#"{"jsonrpc":"2.0","method":"ping"}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).expect("parse");
        assert!(req.id.is_none());
        assert_eq!(req.method, "ping");
    }

    #[test]
    fn response_omits_error_when_ok() {
        let r = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: serde_json::Value::Number(1.into()),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("\"error\""));
        assert!(s.contains("\"result\""));
    }

    #[test]
    fn mcp_tool_uses_camel_case_input_schema() {
        let t = McpTool {
            name: "x".into(),
            description: "y".into(),
            input_schema: serde_json::json!({"type": "object"}),
        };
        let s = serde_json::to_string(&t).unwrap();
        assert!(s.contains("inputSchema"));
        assert!(!s.contains("input_schema"));
    }
}
