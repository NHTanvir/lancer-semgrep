//! `validate` subcommand - schema-check rule files / dirs.
//!
//! Uses `semgrep_rules::load_file` / `load_dir`, which run the full loader
//! pipeline (YAML parse + canonicalise + schema validate) and return on the
//! first error. We surface load failures as exit code 2 (usage), matching
//! upstream Semgrep's "your rule file is broken" exit policy.

use std::process::ExitCode;

use crate::cli::args::ValidateArgs;
use crate::cli::exit_codes;

pub async fn run(args: ValidateArgs) -> ExitCode {
    let mut had_error = false;
    for path in &args.rule_files {
        let res = if path.is_dir() {
            semgrep_rules::load_dir(path)
        } else {
            semgrep_rules::load_file(path)
        };
        match res {
            Ok(rs) => println!("{}: OK ({} rules)", path.display(), rs.len()),
            Err(e) => {
                eprintln!("{}: FAIL - {e}", path.display());
                had_error = true;
            }
        }
    }
    if had_error {
        exit_codes::USAGE
    } else {
        exit_codes::OK
    }
}
