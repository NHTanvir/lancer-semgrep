//! CLI entrypoint and surface modules.
//!
//! `args` holds the clap derive structs; the other sub-modules each handle
//! one cross-cutting concern (color, tracing, language listing, ...).

pub mod args;
pub mod color;
pub mod exit_codes;
pub mod output_options;
pub mod self_test;
pub mod show_langs;
pub mod tracing_setup;

use clap::Parser;
use std::process::ExitCode;

/// Async entrypoint called from `src/bin/main.rs` inside a tokio runtime.
///
/// Wires up tracing + color, then dispatches to the requested subcommand
/// (defaulting to `scan` when none is given).
pub async fn run() -> ExitCode {
    // GUI shortcut: launch the native window when invoked with `--gui` (or
    // with no other meaningful args) and the `gui` feature is enabled.
    //
    // We re-parse `std::env::args` directly because clap eats `--gui` as a
    // global flag, and we want to short-circuit before the rest of the CLI
    // wiring (tracing, color, etc.) runs.
    #[cfg(feature = "gui")]
    {
        let args: Vec<String> = std::env::args().collect();
        let want_gui = args.iter().any(|a| a == "--gui")
            || (!args.iter().any(|a| a == "--cli") && args.len() == 1);
        if want_gui {
            match crate::gui::launch() {
                Ok(()) => return ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("gui launch failed: {e}");
                    return ExitCode::from(3);
                }
            }
        }
    }
    #[cfg(not(feature = "gui"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--gui") {
            eprintln!(
                "this build was compiled without the `gui` feature; \
                 rebuild with `--features gui` to enable the GUI"
            );
            return ExitCode::from(3);
        }
    }

    let cli = args::Cli::parse();
    tracing_setup::init(&cli);
    color::apply(&cli);

    if cli.show_supported_languages {
        return show_langs::run();
    }
    if cli.self_test {
        return self_test::run().await;
    }

    let command = cli
        .command
        .clone()
        .unwrap_or_else(|| args::Command::Scan(cli.scan_args.clone()));

    match command {
        args::Command::Scan(a) => crate::subcommands::scan::run(&cli, a).await,
        args::Command::Ci(a) => crate::subcommands::ci::run(&cli, a).await,
        args::Command::Login(a) => crate::subcommands::login::run(a).await,
        args::Command::Logout => crate::subcommands::logout::run().await,
        args::Command::Publish(a) => crate::subcommands::publish::run(a).await,
        args::Command::Test(a) => crate::subcommands::test::run(a).await,
        args::Command::Validate(a) => crate::subcommands::validate::run(a).await,
        args::Command::Shouldafound(a) => crate::subcommands::shouldafound::run(a).await,
        args::Command::InstallSemgrepPro(a) => crate::subcommands::install_pro::run(a).await,
        args::Command::Mcp(a) => crate::subcommands::mcp::run(a).await,
    }
}
