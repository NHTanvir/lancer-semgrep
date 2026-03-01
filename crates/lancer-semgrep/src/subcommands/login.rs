//! `login` subcommand stub.
//!
//! Semgrep AppSec auth is a commercial cloud feature; in OSS-only builds
//! we acknowledge the command and exit cleanly.

use std::process::ExitCode;

use crate::cli::args::LoginArgs;
use crate::cli::exit_codes;

pub async fn run(_args: LoginArgs) -> ExitCode {
    eprintln!("OSS-only mode: Semgrep AppSec login is disabled in this build.");
    exit_codes::OK
}
