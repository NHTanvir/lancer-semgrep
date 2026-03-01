//! Integration tests for the CLI argument surface.
//!
//! These exercise the clap parser only - real scan / validate / MCP
//! orchestration is tested in later tasks. Each test goes through the lib
//! crate's `cli::args` so the binary entrypoint stays a thin wrapper.

use clap::Parser;
use lancer_semgrep::cli::args::{Cli, Command, MemPolicy, McpTransport, SeverityFilter};
use std::path::PathBuf;

#[test]
fn parses_scan_with_config_and_targets() {
    let cli =
        Cli::try_parse_from(["lancer-semgrep", "--config", "p/python", "src/"]).expect("parse");
    assert!(cli.command.is_none());
    assert_eq!(cli.scan_args.config, vec!["p/python".to_string()]);
    assert_eq!(cli.scan_args.targets, vec![PathBuf::from("src/")]);
}

#[test]
fn parses_validate_subcommand() {
    let cli = Cli::try_parse_from(["lancer-semgrep", "validate", "rules/"]).expect("parse");
    match cli.command {
        Some(Command::Validate(v)) => {
            assert_eq!(v.rule_files, vec![PathBuf::from("rules/")]);
        }
        other => panic!("expected Validate subcommand, got {other:?}"),
    }
}

#[test]
fn parses_mcp_subcommand_with_http_transport() {
    let cli = Cli::try_parse_from([
        "lancer-semgrep",
        "mcp",
        "--transport",
        "http",
        "--port",
        "8080",
    ])
    .expect("parse");
    match cli.command {
        Some(Command::Mcp(m)) => {
            assert_eq!(m.port, 8080);
            assert_eq!(m.transport, McpTransport::Http);
        }
        other => panic!("expected Mcp subcommand, got {other:?}"),
    }
}

#[test]
fn parses_x_mem_policy() {
    let cli = Cli::try_parse_from([
        "lancer-semgrep",
        "scan",
        "--x-mem-policy",
        "aggressive",
        "--config",
        "p/python",
    ])
    .expect("parse");
    match cli.command {
        Some(Command::Scan(s)) => {
            assert_eq!(s.x_mem_policy, Some(MemPolicy::Aggressive));
            assert_eq!(s.config, vec!["p/python".to_string()]);
        }
        other => panic!("expected Scan subcommand, got {other:?}"),
    }
}

#[test]
fn force_color_and_no_color_conflict() {
    let res = Cli::try_parse_from(["lancer-semgrep", "--force-color", "--no-color"]);
    assert!(
        res.is_err(),
        "--force-color and --no-color must conflict"
    );
}

#[test]
fn output_format_flags_in_one_conflict_group() {
    let res = Cli::try_parse_from([
        "lancer-semgrep",
        "--json",
        "--sarif",
        "--config",
        "p/python",
    ]);
    assert!(res.is_err(), "--json and --sarif must conflict (group)");
}

#[test]
fn show_supported_languages_flag() {
    let cli =
        Cli::try_parse_from(["lancer-semgrep", "--show-supported-languages"]).expect("parse");
    assert!(cli.show_supported_languages);
}

#[test]
fn severity_filter_parses_uppercase() {
    let cli = Cli::try_parse_from([
        "lancer-semgrep",
        "--config",
        "p/python",
        "--severity",
        "ERROR",
    ])
    .expect("parse");
    assert_eq!(cli.scan_args.severity, Some(SeverityFilter::Error));
}

#[test]
fn metrics_default_is_auto() {
    let cli = Cli::try_parse_from(["lancer-semgrep", "--config", "p/python"]).expect("parse");
    assert_eq!(
        cli.metrics,
        lancer_semgrep::cli::args::Metrics::Auto
    );
}

#[test]
fn parses_top_level_subcommands() {
    // Smoke-test that every documented subcommand parses with minimum args.
    let cases: &[(&[&str], &str)] = &[
        (&["lancer-semgrep", "scan", "--config", "p/python"], "scan"),
        (&["lancer-semgrep", "ci", "--config", "p/python"], "ci"),
        (&["lancer-semgrep", "login"], "login"),
        (&["lancer-semgrep", "logout"], "logout"),
        (&["lancer-semgrep", "publish", "rule.yaml"], "publish"),
        (&["lancer-semgrep", "test", "rules/"], "test"),
        (&["lancer-semgrep", "validate", "rules/"], "validate"),
        (&["lancer-semgrep", "shouldafound"], "shouldafound"),
        (&["lancer-semgrep", "install-semgrep-pro"], "install-pro"),
        (&["lancer-semgrep", "mcp"], "mcp"),
    ];
    for (argv, name) in cases {
        let res = Cli::try_parse_from(argv.iter().copied());
        assert!(
            res.is_ok(),
            "subcommand `{name}` failed to parse: {:?}",
            res.err()
        );
    }
}

#[test]
fn rewrite_rule_ids_and_no_rewrite_rule_ids_conflict() {
    let res = Cli::try_parse_from([
        "lancer-semgrep",
        "--config",
        "p/python",
        "--rewrite-rule-ids",
        "--no-rewrite-rule-ids",
    ]);
    assert!(
        res.is_err(),
        "--rewrite-rule-ids and --no-rewrite-rule-ids must conflict"
    );
}

#[test]
fn jobs_defaults_to_available_parallelism() {
    let cli = Cli::try_parse_from(["lancer-semgrep", "--config", "p/python"]).expect("parse");
    let expected = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    assert_eq!(cli.scan_args.jobs, expected);
}
