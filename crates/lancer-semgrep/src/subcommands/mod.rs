//! Per-subcommand handler modules. One file per top-level verb.
//!
//! Each handler is a single `pub async fn run(...) -> ExitCode` that takes
//! whichever parsed args struct the verb uses. Dispatch is wired up in
//! `crate::cli::run`.

pub mod ci;
pub mod install_pro;
pub mod login;
pub mod logout;
pub mod mcp;
pub mod publish;
pub mod scan;
pub mod shouldafound;
pub mod test;
pub mod validate;
