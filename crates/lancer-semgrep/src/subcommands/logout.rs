//! `logout` subcommand stub.

use std::process::ExitCode;

use crate::cli::exit_codes;

pub async fn run() -> ExitCode {
    eprintln!("OSS-only mode: Semgrep AppSec logout is disabled in this build.");
    exit_codes::OK
}
