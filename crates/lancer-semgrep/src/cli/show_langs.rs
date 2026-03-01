//! Handler for `--show-supported-languages`.
//!
//! Prints the list of languages whose tree-sitter adapter is compiled in
//! (per the `lang-*` Cargo features), sorted by display name. Exits OK.

use semgrep_core::Language;
use std::process::ExitCode;
use tree_sitter_langs::enabled_languages;

pub fn run() -> ExitCode {
    let mut langs = enabled_languages();
    langs.sort_by_key(|l| l.display_name());
    println!("Supported languages ({} enabled):", langs.len());
    for l in &langs {
        println!("  {:<14}  ({})", l.display_name(), l.primary_extension());
    }
    println!("\nAll possible (build-time gated): see Cargo features `lang-*`.");
    // Ensure the linker keeps Language::all so callers (and dead-code
    // analyses) can still see every variant.
    let _ = Language::all();
    ExitCode::SUCCESS
}
