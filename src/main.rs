//! lancer-semgrep
//! Rust clone of semgrep. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-semgrep", version, about = "Rust clone of semgrep")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-semgrep - scaffold ready. Implement per plan.md.");
    Ok(())
}
