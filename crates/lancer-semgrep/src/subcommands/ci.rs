//! `ci` subcommand: a thin wrapper around `scan` that auto-detects the PR
//! baseline before delegating.
//!
//! `--auto-baseline` is a stub for now; full env-var sniffing lives in
//! Task 9 (`$GITHUB_BASE_REF`, `$CI_MERGE_REQUEST_TARGET_BRANCH_SHA`, ...).

use std::process::ExitCode;

use crate::cli::args::{CiArgs, Cli};

pub async fn run(cli: &Cli, args: CiArgs) -> ExitCode {
    tracing::info!("ci: auto-detecting PR baseline...");
    if args.auto_baseline {
        // TODO (Task 9): detect base via $GITHUB_BASE_REF /
        // $CI_MERGE_REQUEST_TARGET_BRANCH_SHA / `git merge-base`.
    }
    crate::subcommands::scan::run(cli, args.scan).await
}
