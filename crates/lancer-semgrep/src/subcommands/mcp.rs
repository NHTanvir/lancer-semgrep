//! `mcp` subcommand — thin wrapper around [`crate::mcp::serve`].
//!
//! Argument parsing happens in `cli::args::McpArgs`; the actual transport
//! loop + tool dispatch lives under `crate::mcp`.

use std::process::ExitCode;

use crate::cli::args::McpArgs;

pub async fn run(args: McpArgs) -> ExitCode {
    crate::mcp::serve(args).await
}
