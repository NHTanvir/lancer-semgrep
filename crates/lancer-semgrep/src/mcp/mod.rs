//! Model Context Protocol server — `lancer-semgrep mcp` subcommand.
//!
//! See plan.md §"MCP server (`semgrep mcp`) — first-class subcommand (must
//! clone)" and §"Research note 2026-05-31" for the spec we target. Highlights:
//!
//! * Two transports: `stdio` (newline-delimited JSON-RPC 2.0 over
//!   stdin/stdout — the Claude Desktop default) and `http` (a minimal
//!   hand-rolled HTTP/1.1 server bound to `127.0.0.1` with DNS-rebinding
//!   protection + OAuth 2.1 Bearer enforcement).
//! * Nine tools registered under `tools/list` / `tools/call`: the canonical
//!   eight from plan.md plus `semgrep_findings` for the May 2026
//!   `refs` / `autotriage_verdict` parameters.
//! * MCP protocol version pinned to `2025-11-05`; bumped opportunistically
//!   when the upstream spec moves.

pub mod oauth;
pub mod protocol;
pub mod security;
pub mod server;
pub mod tools;
pub mod transport;

use std::process::ExitCode;

use crate::cli::args::{McpArgs, McpTransport};

/// Top-level entrypoint dispatched from `subcommands::mcp::run`.
///
/// Selects the transport, then blocks on the transport's `serve_*` loop
/// until the client closes the connection or an error escapes. Errors are
/// reported on stderr and surface as exit code 3 (runtime error).
pub async fn serve(args: McpArgs) -> ExitCode {
    let r = match args.transport {
        McpTransport::Stdio => transport::stdio::serve_stdio().await,
        McpTransport::Http => {
            transport::http::serve_http(&args.host, args.port, args.oauth).await
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mcp transport error: {e}");
            ExitCode::from(3)
        }
    }
}
