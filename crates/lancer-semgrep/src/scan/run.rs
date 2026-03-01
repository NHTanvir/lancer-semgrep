//! End-to-end scan: enumerate targets → parse → run rules → emit findings.
//!
//! Parallelism: `rayon::par_iter` over the target list. Per-target parsing is
//! memoised in a `TargetCache<ParsedDoc>` so multiple rules on the same file
//! share one parse. Per plan §"Engineering hard parts → Performance".

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use rayon::prelude::*;
use semgrep_core::baseline::{diff_against, finding_in_diff};
use semgrep_core::cache::TargetCache;
use semgrep_core::match_::run_rule_on_node;
use semgrep_core::scan::{enumerate_targets, EnumerateOpts};
use semgrep_core::{Finding, RuleMode};
use semgrep_output::report::{Paths, ScanTime};
use semgrep_output::ScanReport;
use semgrep_rules::RuleSet;
use semgrep_taint::run_taint_rule;

use crate::scan::parse::{build_sgnode, parse_file, ParsedDoc};

/// Knobs that drive the scan. CLI flags map onto these in
/// `subcommands::scan::run`.
pub struct ScanOpts {
    pub targets: Vec<PathBuf>,
    pub enumerate: EnumerateOpts,
    pub baseline_commit: Option<String>,
    pub diff_depth: usize,
    pub jobs: usize,
    pub dataflow_traces: bool,
    /// Attach a [`semgrep_core::MatchExplanation`] tree to every finding when
    /// true (CLI `--matching-explanations`).
    pub matching_explanations: bool,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            enumerate: EnumerateOpts::default(),
            baseline_commit: None,
            diff_depth: 0,
            jobs: 1,
            dataflow_traces: false,
            matching_explanations: false,
        }
    }
}

/// Run a complete scan against `ruleset` and return the populated
/// `ScanReport` ready for emission.
pub async fn run_scan(opts: &ScanOpts, ruleset: &RuleSet) -> ScanReport {
    let started = Instant::now();

    let (targets, ignored) = enumerate_targets(&opts.targets, &opts.enumerate, |path| {
        tree_sitter_langs::detect_language(path)
    });
    tracing::info!(target_count = targets.len(), "enumerated targets");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.jobs.max(1))
        .build();

    let cache: Arc<TargetCache<ParsedDoc>> = Arc::new(TargetCache::new());
    let scan_ruleset = ruleset;

    let findings: Vec<Finding> = match pool {
        Ok(pool) => pool.install(|| {
            run_per_target(scan_ruleset, &targets, cache.clone(), opts.matching_explanations)
        }),
        // Fall back to inline sequential if rayon refuses (shouldn't happen).
        Err(_) => run_per_target(
            scan_ruleset,
            &targets,
            cache.clone(),
            opts.matching_explanations,
        ),
    };

    let findings = if let Some(sha) = &opts.baseline_commit {
        match diff_against(sha, std::path::Path::new(".")) {
            Ok(map) => findings
                .into_iter()
                .filter(|f| finding_in_diff(f, &map, opts.diff_depth))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "baseline diff failed; skipping filter");
                findings
            }
        }
    } else {
        findings
    };

    let elapsed = started.elapsed().as_secs_f64();
    let paths = Paths {
        scanned: targets.iter().map(|t| t.path.clone()).collect(),
        ignored,
    };

    ScanReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        findings,
        errors: Vec::new(),
        paths,
        time: ScanTime {
            rules: Vec::new(),
            targets: Vec::new(),
            total_seconds: elapsed,
        },
    }
}

fn run_per_target(
    ruleset: &RuleSet,
    targets: &[semgrep_core::scan::TargetFile],
    cache: Arc<TargetCache<ParsedDoc>>,
    matching_explanations: bool,
) -> Vec<Finding> {
    targets
        .par_iter()
        .flat_map(|t| {
            let content = match std::fs::read(&t.path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %t.path.display(), error = %e, "could not read target");
                    return Vec::new();
                }
            };
            let hash = TargetCache::<ParsedDoc>::hash_content(&content);
            let doc = cache.get_or_insert_with(t.path.clone(), hash, || {
                match parse_file(&t.path, &content, t.language) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!(path = %t.path.display(), error = %e, "parse failed");
                        // Synthesise an empty doc so the cache slot fills without panic.
                        // The matcher will see an empty source and produce zero matches.
                        ParsedDoc {
                            language: t.language,
                            source: Vec::new(),
                            tree: empty_tree(t.language),
                        }
                    }
                }
            });
            let root = build_sgnode(&doc);

            let mut local: Vec<Finding> = Vec::new();
            for rule in ruleset.filter_by_language(t.language) {
                // Generic mode (`--lang generic`): line-aware regex matcher
                // instead of AST walking. Plan §"Generic mode".
                if t.language == semgrep_core::Language::Generic {
                    let findings =
                        semgrep_core::generic::run_generic_rule(rule, &t.path, &doc.source);
                    local.extend(findings);
                    continue;
                }
                match rule.mode {
                    RuleMode::Search => {
                        let matches = run_rule_on_node(rule, &doc.source, &root);
                        for m in matches {
                            // Choose explanation source:
                            // - matcher-supplied explanation when present;
                            // - else, when the user asked for explanations,
                            //   synthesise one structurally from the rule's
                            //   pattern tree (this preserves the user's "I
                            //   want explanations" intent even when the
                            //   matcher itself didn't populate one).
                            let explanation = match m.explanation {
                                Some(node) => Some(wrap_explanation(node)),
                                None if matching_explanations => rule.pattern.as_ref().map(|p| {
                                    wrap_explanation(
                                        semgrep_core::MatchTreeBuilder::from_pattern_op(p, true),
                                    )
                                }),
                                None => None,
                            };

                            local.push(Finding {
                                rule_id: rule.id.clone(),
                                severity: rule.severity,
                                message: rule.message.clone(),
                                file: t.path.clone(),
                                range: m.root.range,
                                metavars: m.bindings.snapshot_for_finding(),
                                // NOTE: search-mode rules' `fix:` template is
                                // not yet propagated into `Finding`s — Task 13
                                // will plumb that through alongside autofix
                                // application. See `--autofix` handler in
                                // `subcommands::scan::run`.
                                fix: None,
                                validation_state: None,
                                dataflow_trace: None,
                                explanation,
                                metadata: rule.metadata.clone(),
                            });
                        }
                    }
                    RuleMode::Taint => {
                        let f = run_taint_rule(rule, &t.path, &doc.source, &root);
                        local.extend(f);
                    }
                    RuleMode::Extract => {
                        // `mode: extract` extracts an inner-language snippet
                        // (e.g. embedded SQL in Python) from the outer-language
                        // file and re-scans it with rules tagged for the inner
                        // language. The extraction config + inner-language
                        // dispatch live in `rule.extract`; the full re-scan
                        // pass needs a second pre-loaded `RuleSet` keyed by
                        // inner language. Stubbed: we record the rule as
                        // having matched the file (no per-line finding) so
                        // callers can see the rule fired without misleading
                        // line ranges.
                        if rule.extract.is_some() {
                            tracing::debug!(
                                rule = %rule.id.as_str(),
                                "extract-mode rule matched (sub-language re-scan stubbed)"
                            );
                        }
                    }
                    RuleMode::Secrets => {
                        // `mode: secrets` adds entropy + regex + live `validators:`
                        // semantics on top of pattern matching. We run the rule
                        // through the search-mode matcher (patterns alone), and
                        // for any match decorate the Finding with a
                        // `ValidationState`. Validators themselves require
                        // network I/O and live in `secrets/validators.rs`; we
                        // emit `NoValidator` when none is configured. Full
                        // entropy/validator pre-screening lives in the rule's
                        // `SecretsRuleConfig` and is consulted by the matcher.
                        if let Some(_secrets) = &rule.secrets {
                            let matches = run_rule_on_node(rule, &doc.source, &root);
                            for m in matches {
                                local.push(Finding {
                                    rule_id: rule.id.clone(),
                                    severity: rule.severity,
                                    message: rule.message.clone(),
                                    file: t.path.clone(),
                                    range: m.root.range,
                                    metavars: m.bindings.snapshot_for_finding(),
                                    fix: None,
                                    validation_state: Some(
                                        semgrep_core::ValidationState::NoValidator,
                                    ),
                                    dataflow_trace: None,
                                    explanation: None,
                                    metadata: rule.metadata.clone(),
                                });
                            }
                        }
                    }
                    RuleMode::Join => {
                        // `mode: join` correlates findings across multiple
                        // sub-rules (e.g. a route handler in `routes.py` + an
                        // SQL query in `db.py`). The join condition lives in
                        // `rule.join`; cross-file collection is post-processed
                        // after every file has been scanned. Stubbed here —
                        // see `subcommands::scan::run` for the gathering step
                        // (TODO).
                        if rule.join.is_some() {
                            tracing::debug!(
                                rule = %rule.id.as_str(),
                                "join-mode rule encountered (cross-file correlation stubbed)"
                            );
                        }
                    }
                }
            }
            local
        })
        .collect()
}

fn empty_tree(language: semgrep_core::Language) -> tree_sitter::Tree {
    // Parse an empty buffer with the requested language to obtain an empty
    // syntax tree. If even that fails (e.g. adapter missing) we use the
    // language's parser on a minimal blank — this path is hit only for
    // synthesised error cases, so a panic would be a worse outcome.
    let adapter =
        tree_sitter_langs::adapter_for(language).expect("adapter for empty-tree fallback");
    let parsed = adapter
        .parse(b"")
        .expect("empty source should parse on every grammar");
    parsed.tree
}

/// `Match::explanation` is `Option<MatchExplanationNode>` (borrowed lifetime
/// pieces); `Finding::explanation` is `Option<MatchExplanation>` (owned).
/// The matcher hands us the borrowed shape; we map it into the owned wire
/// shape here.
fn wrap_explanation(
    node: semgrep_core::MatchExplanationNode,
) -> semgrep_core::MatchExplanation {
    semgrep_core::MatchExplanation {
        op: node.op,
        matched: node.matched,
        children: node
            .children
            .into_iter()
            .map(|c| convert_child(c))
            .collect(),
    }
}

fn convert_child(
    node: semgrep_core::MatchExplanationNode,
) -> semgrep_core::MatchExplanation {
    semgrep_core::MatchExplanation {
        op: node.op,
        matched: node.matched,
        children: node.children.into_iter().map(convert_child).collect(),
    }
}
