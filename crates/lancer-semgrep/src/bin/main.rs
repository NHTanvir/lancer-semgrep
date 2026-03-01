//! lancer-semgrep — Rust clone of semgrep CLI. See plan.md.
//!
//! Thin binary entrypoint: spins up a tokio runtime and hands off to
//! `lancer_semgrep::cli::run`. All real work lives in the lib so it's testable
//! from `tests/cli.rs` and reusable by the future GUI / MCP entry points.

fn main() -> std::process::ExitCode {
    // Use a tokio runtime since registry fetch etc. is async.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to start tokio runtime: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    rt.block_on(lancer_semgrep::cli::run())
}
