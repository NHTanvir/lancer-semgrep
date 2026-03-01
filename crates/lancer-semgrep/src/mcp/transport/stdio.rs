//! stdio transport — newline-delimited JSON-RPC over stdin/stdout.
//!
//! One JSON-RPC frame per line on stdin, one response frame per line on
//! stdout. Parse errors emit a JSON-RPC parse error and the loop continues
//! (a malformed frame must not bring the whole server down). EOF on stdin
//! ends the loop cleanly.

use eyre::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::mcp::protocol::*;
use crate::mcp::server::handle_request;

pub async fn serve_stdio() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    tracing::info!("MCP stdio transport ready");

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed: std::result::Result<JsonRpcRequest, _> = serde_json::from_str(trimmed);
        let resp = match parsed {
            Ok(req) => {
                let is_notification = req.id.is_none();
                let resp = handle_request(req).await;
                if is_notification {
                    // JSON-RPC notifications expect no response — but the
                    // MCP protocol may still want acks for some methods.
                    // To stay strict to the spec, drop the frame entirely.
                    continue;
                }
                resp
            }
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: PARSE_ERROR,
                    message: e.to_string(),
                    data: None,
                }),
            },
        };

        let s = serde_json::to_string(&resp)? + "\n";
        stdout.write_all(s.as_bytes()).await?;
        stdout.flush().await?;
    }

    tracing::info!("MCP stdio transport closed");
    Ok(())
}
