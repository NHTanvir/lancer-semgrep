//! `shouldafound` subcommand stub - Pro feature for reporting missed findings.

use std::process::ExitCode;

use crate::cli::args::ShouldaArgs;
use crate::cli::exit_codes;

pub async fn run(args: ShouldaArgs) -> ExitCode {
    eprintln!(
        "shouldafound: OSS-only build cannot submit to Semgrep AppSec. \
         report = {:?}",
        args.report
    );
    exit_codes::OK
}
