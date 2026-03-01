//! Terminal-colour override driven by `--force-color` / `--no-color`.
//!
//! When neither flag is set we leave the global override unset so each
//! emitter respects its own colour-mode default (Auto, which honours `TTY`
//! detection + the `NO_COLOR` env var).

use crate::cli::args::Cli;

/// Push the requested colour policy into `owo_colors`' global state.
pub fn apply(cli: &Cli) {
    if cli.force_color {
        owo_colors::set_override(true);
    } else if cli.no_color {
        owo_colors::set_override(false);
    } else {
        owo_colors::unset_override();
    }
}
