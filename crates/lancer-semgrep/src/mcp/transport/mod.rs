//! Transport implementations for the MCP server.
//!
//! Two concrete `serve_*` entrypoints — chosen by [`crate::mcp::serve`] based
//! on the `--transport` CLI flag:
//!
//! - [`stdio::serve_stdio`] — newline-delimited JSON-RPC frames over
//!   stdin/stdout. The Claude Desktop default.
//! - [`http::serve_http`] — a minimal HTTP/1.1 server bound to `127.0.0.1`
//!   with DNS-rebinding protection and OAuth Bearer enforcement.
//!
//! Both transports delegate request handling to
//! [`crate::mcp::server::handle_request`].

pub mod http;
pub mod stdio;
