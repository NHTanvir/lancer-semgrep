//! `install-semgrep-pro` subcommand stub - no-op in the OSS clone.

use std::process::ExitCode;

use crate::cli::args::InstallProArgs;
use crate::cli::exit_codes;

pub async fn run(args: InstallProArgs) -> ExitCode {
    eprintln!(
        "install-semgrep-pro: OSS-only build has no Pro engine to install. \
         requested version = {:?}",
        args.version
    );
    exit_codes::OK
}
