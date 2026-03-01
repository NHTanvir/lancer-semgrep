//! `publish` subcommand stub - upstream pushes private rules to AppSec.

use std::process::ExitCode;

use crate::cli::args::PublishArgs;
use crate::cli::exit_codes;

pub async fn run(args: PublishArgs) -> ExitCode {
    eprintln!(
        "publish: OSS-only build cannot push to Semgrep AppSec. \
         Would have published {} rule files at visibility={}",
        args.rule_files.len(),
        args.visibility,
    );
    exit_codes::OK
}
