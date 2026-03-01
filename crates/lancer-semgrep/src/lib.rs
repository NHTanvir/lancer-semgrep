//! lancer-semgrep — Rust clone of `semgrep`.
//!
//! The CLI binary (see `src/bin/main.rs`) is a thin entrypoint that hands off
//! to [`cli::run`]. Everything below the binary boundary lives in this lib so
//! it can be exercised from integration tests and reused by the future GUI /
//! MCP server entry points.
//!
//! See plan.md §"Granular feature catalog → CLI surface" for the full flag
//! list, and §"CLI flags newly important (2025-2026)" for the recent
//! additions.

pub mod ai;
pub mod appsec;
pub mod cli;
pub mod mcp;
pub mod scan;
pub mod subcommands;

#[cfg(feature = "gui")]
pub mod gui;
