//! Exit-code constants matching upstream Semgrep.
//!
//!   0 - no findings (or only INFO)
//!   1 - findings present and `--error` / `--strict` triggered
//!   2 - CLI usage / invalid config
//!   3 - runtime error

use std::process::ExitCode;

pub const OK: ExitCode = ExitCode::SUCCESS;
pub const FINDINGS: ExitCode = ExitCode::from(1);
pub const USAGE: ExitCode = ExitCode::from(2);
pub const RUNTIME: ExitCode = ExitCode::from(3);
