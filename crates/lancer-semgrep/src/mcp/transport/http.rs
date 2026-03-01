//! HTTP transport — minimal hand-rolled HTTP/1.1 server.
//!
//! Workspace deps don't include `axum` or `httparse`, so this is a
//! deliberately small Tokio-only loop. It is *not* a production-grade web
//! server, but it satisfies the MCP Streamable HTTP transport's contract
//! while enforcing the security envelope from plan.md §"MCP DNS-rebinding
//! protection (Feb 2026)" + §"MCP OAuth for Streamable HTTP transport
//! (May 2026)":
//!
//! 1. Listening socket is bound to a loopback address only. Non-loopback
//!    `host` values cause `serve_http` to bail out before binding.
//! 2. Accepted connections from non-loopback peers are dropped.
//! 3. Every request's `Host:` header is validated against
//!    [`crate::mcp::security::is_loopback_host`]; anything that isn't a
//!    known loopback alias is rejected with `400 Bad Request`.
//! 4. When `oauth` is enabled (the default for HTTP), each request must
//!    carry a `Authorization: Bearer <token>` header validated by
//!    [`crate::mcp::oauth::verify_bearer`]; failures get `401`.
//! 5. The body must be a JSON-RPC 2.0 request; parse failures get the
//!    standard `-32700` parse error response.

use eyre::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::mcp::oauth::verify_bearer;
use crate::mcp::protocol::*;
use crate::mcp::security::is_loopback_host;
use crate::mcp::server::handle_request;

pub async fn serve_http(host: &str, port: u16, oauth_enabled: bool) -> Result<()> {
    // Refuse to bind to anything other than a loopback address. Even if the
    // user passes `--host 0.0.0.0` we error out here rather than expose the
    // MCP API to the network.
    if !is_loopback_host(host) {
        eyre::bail!("HTTP transport refuses to bind to non-loopback host: {host}");
    }
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    let actual = listener.local_addr()?;
    tracing::info!(
        addr = %actual,
        oauth = oauth_enabled,
        "MCP HTTP transport listening"
    );

    loop {
        let (sock, peer) = listener.accept().await?;
        // Second layer of defence: refuse non-loopback peers, even though
        // we bound to a loopback address (belt-and-braces against kernels
        // that bind 0.0.0.0 silently).
        if !peer.ip().is_loopback() {
            tracing::warn!(peer = %peer, "rejected non-loopback connection");
            drop(sock);
            continue;
        }
        tokio::spawn(handle_connection(sock, oauth_enabled));
    }
}

async fn handle_connection(mut sock: TcpStream, oauth_enabled: bool) {
    if let Err(e) = handle_connection_inner(&mut sock, oauth_enabled).await {
        tracing::debug!(error = %e, "http connection error");
    }
}

async fn handle_connection_inner(
    sock: &mut TcpStream,
    oauth_enabled: bool,
) -> std::io::Result<()> {
    // Read the request: headers + body. We read into a Vec until we see the
    // CRLFCRLF separator, then read out the body using Content-Length.
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let mut headers_end = None;
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = find_subseq(&buf, b"\r\n\r\n") {
            headers_end = Some(idx + 4);
            break;
        }
        // Soft cap to keep memory bounded for malformed clients.
        if buf.len() > 16 * 1024 * 1024 {
            return write_response(sock, 413, "Payload Too Large", b"headers too large").await;
        }
    }

    let Some(header_end) = headers_end else {
        return write_response(sock, 400, "Bad Request", b"incomplete headers").await;
    };
    let headers_raw = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();

    // Determine the Content-Length and read the rest of the body.
    let content_length: usize = header_value(&headers_raw, "Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_bytes = &buf[header_end..(header_end + content_length).min(buf.len())];
    let body = std::str::from_utf8(body_bytes).unwrap_or("");

    // --- DNS-rebinding protection -----------------------------------------
    // The `Host:` header is attacker-controlled; we reject any value that
    // isn't a known loopback alias.
    let host_hdr = header_value(&headers_raw, "Host").unwrap_or_default();
    let host_only = host_hdr.split(':').next().unwrap_or("");
    if !is_loopback_host(host_only) {
        return write_response(
            sock,
            400,
            "Bad Request",
            b"Host header must resolve to loopback",
        )
        .await;
    }

    // --- OAuth ------------------------------------------------------------
    if oauth_enabled {
        let auth = header_value(&headers_raw, "Authorization").unwrap_or_default();
        if !verify_bearer(&auth) {
            return write_response(sock, 401, "Unauthorized", b"OAuth Bearer token required")
                .await;
        }
    }

    // --- Dispatch ---------------------------------------------------------
    let req: JsonRpcRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let resp = JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: PARSE_ERROR,
                    message: e.to_string(),
                    data: None,
                }),
            };
            let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
            return write_response(sock, 400, "Bad Request", body.as_bytes()).await;
        }
    };
    let resp = handle_request(req).await;
    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
    write_response(sock, 200, "OK", body.as_bytes()).await
}

/// Locate the first occurrence of `needle` in `haystack`. Mirrors what
/// `Vec::windows().position()` does, but stays correct when `needle` is
/// shorter than `haystack` (the windowed call is fine, this is just a
/// readable helper).
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Case-insensitive header lookup. Returns the trimmed value (without the
/// leading colon / whitespace) or `None` if the header is missing.
fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if let Some(idx) = line.find(':') {
            let (k, v) = line.split_at(idx);
            if k.eq_ignore_ascii_case(name) {
                return Some(v[1..].trim().to_string());
            }
        }
    }
    None
}

async fn write_response(
    sock: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_is_case_insensitive() {
        let h = "HOST: 127.0.0.1\r\nAuthorization: Bearer abc";
        assert_eq!(header_value(h, "host"), Some("127.0.0.1".to_string()));
        assert_eq!(header_value(h, "authorization"), Some("Bearer abc".to_string()));
        assert_eq!(header_value(h, "missing"), None);
    }

    #[test]
    fn find_subseq_locates_crlfcrlf() {
        let raw = b"a: b\r\nc: d\r\n\r\nbody";
        assert_eq!(find_subseq(raw, b"\r\n\r\n"), Some(10));
        assert_eq!(find_subseq(raw, b"nope"), None);
        assert_eq!(find_subseq(raw, b""), None);
    }
}
