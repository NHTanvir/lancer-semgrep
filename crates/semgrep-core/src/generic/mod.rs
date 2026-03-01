//! Generic mode: `--lang generic` — line-aware regex-style matcher for any
//! text file (ERB, Jinja templates, INI, etc.). No AST, just
//! `pattern-regex` / literal string matching.
//!
//! Per plan §"Granular feature catalog → Generic mode" and
//! §"Languages — extended matrix → Generic mode".
//!
//! Generic mode bypasses tree-sitter entirely: targets pass through a
//! line-walker and rules contribute one regex per line they want to match.
//! Useful for text formats we don't have a grammar for.

use crate::node::{Position, Range};
use crate::{Finding, Rule, Severity};

/// Run a search-mode rule's `pattern` and `pattern-regex` against a target's
/// raw bytes, line-by-line. Recognises `\$IDENT` metavariables in pattern
/// strings and re-emits them as `(?P<X>.*?)` captures.
///
/// Returns one `Finding` per matched line.
pub fn run_generic_rule(rule: &Rule, file: &std::path::Path, source: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let body = std::str::from_utf8(source).unwrap_or("");

    let regex_sources = collect_pattern_regexes(rule);
    let compiled: Vec<regex::Regex> = regex_sources
        .iter()
        .filter_map(|s| compile_generic_pattern(s).ok())
        .collect();

    for (lineno_zero, line) in body.lines().enumerate() {
        for re in &compiled {
            if let Some(m) = re.find(line) {
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    message: rule.message.clone(),
                    file: file.to_path_buf(),
                    range: Range {
                        start: Position {
                            line: lineno_zero + 1,
                            column: m.start() + 1,
                            offset: 0,
                        },
                        end: Position {
                            line: lineno_zero + 1,
                            column: m.end() + 1,
                            offset: 0,
                        },
                    },
                    metavars: Default::default(),
                    fix: None,
                    validation_state: None,
                    dataflow_trace: None,
                    explanation: None,
                    metadata: rule.metadata.clone(),
                });
            }
        }
    }
    let _ = Severity::Info;
    findings
}

/// Walk the rule's `pattern` / `pattern-regex` operators and return the raw
/// strings as a flat list.
fn collect_pattern_regexes(rule: &Rule) -> Vec<String> {
    use crate::rule::PatternOp;
    let mut out = Vec::new();
    fn walk(op: &PatternOp, out: &mut Vec<String>) {
        match op {
            PatternOp::Pattern(s) => out.push(s.clone()),
            PatternOp::PatternRegex(s) => out.push(s.clone()),
            PatternOp::Patterns(list) | PatternOp::PatternEither(list) => {
                for o in list {
                    walk(o, out);
                }
            }
            PatternOp::PatternInside(inner) => walk(inner, out),
            _ => {}
        }
    }
    if let Some(op) = &rule.pattern {
        walk(op, &mut out);
    }
    out
}

/// Translate a Semgrep-style generic pattern (with `$IDENT` metavars) into a
/// `regex::Regex`. Each `$IDENT` becomes a named capture `(?P<IDENT>.*?)`.
pub fn compile_generic_pattern(src: &str) -> Result<regex::Regex, regex::Error> {
    let mut out = String::with_capacity(src.len() + 16);
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && is_id_start(bytes[i + 1]) {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && is_id_continue(bytes[end]) {
                end += 1;
            }
            let name = std::str::from_utf8(&bytes[start..end]).unwrap_or("X");
            out.push_str("(?P<");
            out.push_str(name);
            out.push_str(">.*?)");
            i = end;
        } else if "\\.+*?()[]{}|^$".as_bytes().contains(&bytes[i]) {
            out.push('\\');
            out.push(bytes[i] as char);
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    regex::Regex::new(&out)
}

fn is_id_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}
fn is_id_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metavar_becomes_named_capture() {
        let re = compile_generic_pattern("eval($X)").unwrap();
        let caps = re.captures("eval(user_input)").unwrap();
        assert_eq!(&caps["X"], "user_input");
    }

    #[test]
    fn literal_text_is_escaped() {
        let re = compile_generic_pattern("foo.bar").unwrap();
        assert!(re.is_match("foo.bar"));
        assert!(!re.is_match("foo_bar"));
    }
}
