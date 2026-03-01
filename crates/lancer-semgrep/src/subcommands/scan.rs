//! `scan` subcommand handler.
//!
//! Task 9 wired this up to the real orchestrator: we still resolve
//! `--config` entries that point at local files / directories (slug / URL /
//! `auto` configs remain `tracing::warn`s until the registry path is
//! finished), then hand the `RuleSet` plus a `ScanOpts` derived from the
//! parsed CLI flags to [`crate::scan::run::run_scan`].

use std::process::ExitCode;

use semgrep_core::scan::EnumerateOpts;
use semgrep_output::emitter;

use crate::cli::args::{Cli, ScanArgs};
use crate::cli::exit_codes;
use crate::cli::output_options::select_format;
use crate::scan::run::{run_scan, ScanOpts};

pub async fn run(_cli: &Cli, args: ScanArgs) -> ExitCode {
    tracing::info!(
        targets = ?args.targets,
        configs = ?args.config,
        "scan starting"
    );

    if args.config.is_empty() {
        eprintln!("error: --config is required (or use `auto`).");
        return exit_codes::USAGE;
    }

    // 1. Resolve configs via semgrep_rules. Network-backed sources are
    //    deferred; for now we accept local file/dir paths.
    let registry = semgrep_rules::RegistryClient::new();
    let mut all_rules = semgrep_rules::RuleSet::new();
    for cfg in &args.config {
        let cs = semgrep_rules::ConfigSource::parse(cfg);
        match cs {
            semgrep_rules::ConfigSource::File(p) => match semgrep_rules::load_file(&p) {
                Ok(rs) => all_rules.extend(rs),
                Err(e) => {
                    eprintln!("config error: {e}");
                    return exit_codes::USAGE;
                }
            },
            semgrep_rules::ConfigSource::Dir(p) => match semgrep_rules::load_dir(&p) {
                Ok(rs) => all_rules.extend(rs),
                Err(e) => {
                    eprintln!("config error: {e}");
                    return exit_codes::USAGE;
                }
            },
            semgrep_rules::ConfigSource::Slug(_)
            | semgrep_rules::ConfigSource::Url(_)
            | semgrep_rules::ConfigSource::Auto => {
                tracing::warn!(
                    config = %cfg,
                    "registry slug / URL / auto config: network wiring deferred; skipping"
                );
            }
            semgrep_rules::ConfigSource::Stdin | semgrep_rules::ConfigSource::Inline(_) => {
                tracing::warn!("stdin / inline config: TODO wiring");
            }
        }
        let _ = &registry;
    }
    tracing::info!(rules_loaded = all_rules.len(), "rules loaded");

    if all_rules.is_empty() {
        eprintln!("no rules loaded — nothing to scan.");
        return exit_codes::USAGE;
    }

    // 2. Build ScanOpts from parsed CLI flags.
    let opts = ScanOpts {
        targets: args.targets.clone(),
        enumerate: EnumerateOpts {
            include: args.include.clone(),
            exclude: args.exclude.clone(),
            max_target_bytes: args.max_target_bytes,
            use_git_ignore: args.use_git_ignore,
            use_semgrep_ignore: true,
            force_language: args
                .lang
                .as_deref()
                .and_then(semgrep_core::Language::from_alias),
            scan_unknown_extensions: args.scan_unknown_extensions,
        },
        baseline_commit: args.baseline_commit.clone(),
        diff_depth: args.diff_depth,
        jobs: args.jobs,
        dataflow_traces: args.dataflow_traces,
        matching_explanations: args.matching_explanations,
    };

    // 3. Run.
    let report = run_scan(&opts, &all_rules).await;

    // 3a. Autofix: if --autofix or --dryrun was set, walk findings carrying a
    //     `fix:` and either rewrite files in place or print the diff.
    //
    //     NOTE: today `Finding::fix` is always `None` because the search/taint
    //     engine doesn't yet propagate `rule.fix` into the Finding. We log a
    //     warning so the wiring is observable; the actual application path is
    //     ready to fire as soon as Task 13 lands the propagation. The CLI
    //     contract is locked in so users / docs can rely on it now.
    if args.autofix || args.dryrun {
        let mut any_fixable = false;
        for f in &report.findings {
            if let Some(fix) = &f.fix {
                any_fixable = true;
                if args.dryrun {
                    println!("{}", fix.diff);
                } else {
                    if let Err(e) = std::fs::write(&f.file, fix.after.as_bytes()) {
                        eprintln!(
                            "autofix: failed to write {}: {}",
                            f.file.display(),
                            e
                        );
                    } else {
                        eprintln!("autofix applied to {}", f.file.display());
                    }
                }
            }
        }
        if !any_fixable {
            tracing::info!(
                "--autofix / --dryrun: no findings carried a `fix:` template \
                 (rule.fix propagation lands in Task 13)"
            );
        }
    }

    // 4. Emit.
    let format = select_format(&args);
    let mut buf: Box<dyn std::io::Write> = match args.output {
        Some(ref p) => match std::fs::File::create(p) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("could not open output {}: {}", p.display(), e);
                return exit_codes::RUNTIME;
            }
        },
        None => Box::new(std::io::stdout()),
    };
    if let Err(e) = emitter(format).emit(&report, &mut *buf) {
        eprintln!("emit error: {e}");
        return exit_codes::RUNTIME;
    }

    // 5. Exit code: nonzero if findings + `--error`.
    if args.error && !report.findings.is_empty() {
        return exit_codes::FINDINGS;
    }
    exit_codes::OK
}
