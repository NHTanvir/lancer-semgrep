//! Handler for `--self-test`.
//!
//! Placeholder until Task 12 populates `tests/upstream_parity/` with the
//! actual matrix. The flag intentionally exits OK so CI users running it
//! against a Task 8 build don't see a spurious failure.

use std::process::ExitCode;

pub async fn run() -> ExitCode {
    println!(
        "self-test scaffold: parity matrix harness not yet populated; \
         see tests/upstream_parity/ in Task 12."
    );
    ExitCode::SUCCESS
}
