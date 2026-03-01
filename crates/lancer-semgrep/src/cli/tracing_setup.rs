//! tracing-subscriber setup driven by the global verbosity flags.
//!
//! Verbosity precedence: `--debug` > `--verbose` > `--quiet` > `RUST_LOG`
//! env var > default `warn`. The fmt layer always writes to stderr so
//! findings on stdout (text / json / sarif) are unpolluted.
//!
//! `--trace` is a placeholder: in a full build it would attach an OTLP
//! exporter pointed at `--trace-endpoint` (defaulting to `localhost:4317`).
//! Until that wiring lands (Task 12) we just log the request.

use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

use crate::cli::args::Cli;

/// Initialise tracing. Idempotent: subsequent calls (e.g. from tests) are
/// no-ops because `try_init` returns an error rather than panicking.
pub fn init(cli: &Cli) {
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else if cli.verbose {
        EnvFilter::new("info")
    } else if cli.quiet {
        EnvFilter::new("error")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
    };

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();

    if cli.trace {
        // Defer: OpenTelemetry exporter would attach here. Endpoint defaults
        // to localhost:4317.
        tracing::info!(
            endpoint = ?cli.trace_endpoint.as_deref().unwrap_or("localhost:4317"),
            "OpenTelemetry trace requested (stub)"
        );
    }
}
