//! `test` subcommand — rule unit-test runner.
//!
//! Loads every `rule.yaml`-shaped file under the user-supplied target, finds
//! the sibling source file with the same stem, parses `// ruleid:` /
//! `// ok:` (and `# ruleid:` / `# ok:` etc.) annotations, runs the matcher
//! against the source, and asserts the annotated lines line up with the
//! reported finding lines. This mirrors the upstream `semgrep test`
//! contract.
//!
//! Exit codes:
//! - `OK`     when every yaml passed.
//! - `FINDINGS` when at least one yaml's annotations diverged from the actual
//!   findings (we re-use the "findings" exit code so CI tools that key off
//!   non-zero see failures).
//! - `USAGE`  when the target / sibling files are missing.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::args::TestArgs;
use crate::cli::exit_codes;

pub async fn run(args: TestArgs) -> ExitCode {
    let target = &args.target;
    if !target.exists() {
        eprintln!("test target not found: {}", target.display());
        return exit_codes::USAGE;
    }

    // Walk the dir (or single file pair) looking for rule yamls.
    let yamls = collect_yamls(target);
    if yamls.is_empty() {
        eprintln!("no rule .yaml files found under {}", target.display());
        return exit_codes::USAGE;
    }

    let mut failures = 0usize;
    for rule_yaml in &yamls {
        let stem = rule_yaml
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let dir = rule_yaml.parent().unwrap_or_else(|| Path::new("."));
        let Some(target_path) = pick_target(dir, stem) else {
            eprintln!(
                "{}: missing sibling target file (expected `{}.<ext>`)",
                rule_yaml.display(),
                stem
            );
            failures += 1;
            continue;
        };

        let source = match std::fs::read_to_string(&target_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: {e}", target_path.display());
                failures += 1;
                continue;
            }
        };
        let expected = parse_annotations(&source);

        // Load rule(s).
        let rs = match semgrep_rules::load_file(rule_yaml) {
            Ok(rs) => rs,
            Err(e) => {
                eprintln!("{}: load: {e}", rule_yaml.display());
                failures += 1;
                continue;
            }
        };

        // Run the scan against just this single target file.
        let opts = crate::scan::run::ScanOpts {
            targets: vec![target_path.clone()],
            enumerate: semgrep_core::scan::EnumerateOpts::default(),
            baseline_commit: None,
            diff_depth: 0,
            jobs: 1,
            dataflow_traces: false,
            matching_explanations: false,
        };
        let report = crate::scan::run::run_scan(&opts, &rs).await;
        let actual_lines: HashSet<usize> = report
            .findings
            .iter()
            .map(|f| f.range.start.line)
            .collect();

        // Compare.
        let mut ok = true;
        for (line, rule_id, kind) in &expected {
            let _ = rule_id;
            let hit = actual_lines.contains(line);
            match (kind, hit) {
                (Annotation::RuleId, true) | (Annotation::Ok, false) => {}
                (Annotation::RuleId, false) => {
                    eprintln!(
                        "{}:{}: expected match (// ruleid:) but got none",
                        target_path.display(),
                        line
                    );
                    ok = false;
                }
                (Annotation::Ok, true) => {
                    eprintln!(
                        "{}:{}: expected no match (// ok:) but got one",
                        target_path.display(),
                        line
                    );
                    ok = false;
                }
            }
        }
        if ok {
            println!("ok  {}", rule_yaml.display());
        } else {
            failures += 1;
        }
    }

    if failures > 0 {
        exit_codes::FINDINGS
    } else {
        exit_codes::OK
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Annotation {
    RuleId,
    Ok,
}

/// Parse `// ruleid: <id>` / `// ok: <id>` (and `#`/`/*`/`--` cousin
/// comments) out of `source`. Each annotation refers to the **next**
/// non-empty line — Semgrep's convention.
fn parse_annotations(source: &str) -> Vec<(usize, String, Annotation)> {
    let mut out = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let lineno = i + 1;
        if let Some(rest) = comment_payload(line, "ruleid:") {
            out.push((lineno + 1, rest.trim().to_string(), Annotation::RuleId));
        } else if let Some(rest) = comment_payload(line, "ok:") {
            out.push((lineno + 1, rest.trim().to_string(), Annotation::Ok));
        }
    }
    out
}

/// Find a `<prefix><keyword>` occurrence in `line` and return everything
/// after it. Each prefix is also tried without the trailing space, so an
/// annotation written tightly (`//ruleid:`) still parses.
fn comment_payload<'a>(line: &'a str, kw: &str) -> Option<&'a str> {
    for prefix in ["# ", "// ", "/* ", "-- ", "#", "//", "/*", "--"] {
        let head = format!("{prefix}{kw}");
        if let Some(idx) = line.find(&head) {
            return Some(&line[idx + head.len()..]);
        }
    }
    None
}

/// Recursively gather `*.yaml` / `*.yml` files under `root`. If `root` is
/// a single yaml, it's returned directly.
fn collect_yamls(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        if matches!(
            root.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        ) {
            out.push(root.to_path_buf());
        }
        return out;
    }
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file()
            && matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            )
        {
            out.push(p.to_path_buf());
        }
    }
    out
}

/// Find the sibling target file for `stem` (any extension except yaml/yml).
fn pick_target(dir: &Path, stem: &str) -> Option<PathBuf> {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if let (Some(s), Some(ext)) = (
                p.file_stem().and_then(|s| s.to_str()),
                p.extension().and_then(|s| s.to_str()),
            ) {
                if s == stem && !matches!(ext, "yaml" | "yml") {
                    return Some(p);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ruleid_and_ok_annotations() {
        let src = "x = 1\n// ruleid: my.rule\nbad_call()\n// ok: my.rule\nsafe_call()\n";
        let ann = parse_annotations(src);
        assert_eq!(ann.len(), 2);
        assert_eq!(ann[0].0, 3);
        assert_eq!(ann[0].2, Annotation::RuleId);
        assert_eq!(ann[1].0, 5);
        assert_eq!(ann[1].2, Annotation::Ok);
    }

    #[test]
    fn parse_hash_comment_annotations() {
        let src = "# ruleid: rs\nfoo()\n# ok: rs\nbar()\n";
        let ann = parse_annotations(src);
        assert_eq!(ann.len(), 2);
        assert_eq!(ann[0].2, Annotation::RuleId);
        assert_eq!(ann[1].2, Annotation::Ok);
    }

    #[test]
    fn comment_payload_handles_tight_form() {
        // No space between `//` and `ruleid:`.
        assert_eq!(comment_payload("//ruleid: foo", "ruleid:"), Some(" foo"));
    }
}
