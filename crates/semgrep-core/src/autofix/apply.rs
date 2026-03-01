//! Apply a fix to a finding's source range and emit an updated buffer +
//! unified diff suggestion.

use crate::autofix::diff::unified_diff;
use crate::autofix::regex::apply_fix_regex;
use crate::autofix::template::render_fix_template;
use crate::match_::MetavarBindings;
use crate::{FixRegex, FixSuggestion, FixTemplate, Range};

/// Result of applying a fix to a buffer.
///
/// `before` and `after` are full-buffer states; `diff` is the unified-diff
/// rendering of `before → after`; `suggestion` is the wire-shape value that
/// gets attached to a `Finding`.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub before: String,
    pub after: String,
    pub diff: String,
    pub suggestion: FixSuggestion,
}

/// Apply a *template* fix: substitute metavars into `template`, then splice
/// the rendered text into `content` at `range`. Returns the new buffer + diff.
pub fn apply_template_fix(
    file: &str,
    content: &str,
    range: Range,
    template: &FixTemplate,
    bindings: &MetavarBindings<'_>,
) -> ApplyResult {
    let rendered = render_fix_template(&template.0, bindings);
    splice_and_diff(file, content, range, &rendered)
}

/// Apply a *regex* fix: run `fix.regex` against the slice covered by `range`,
/// substituting `fix.replacement` per `fix.count` (or unlimited when `None`).
pub fn apply_regex_fix(
    file: &str,
    content: &str,
    range: Range,
    fix: &FixRegex,
) -> Result<ApplyResult, crate::SemgrepError> {
    let slice = &content[range.start.offset..range.end.offset];
    let replaced = apply_fix_regex(slice, fix)?;
    Ok(splice_and_diff(file, content, range, &replaced))
}

fn splice_and_diff(file: &str, content: &str, range: Range, rendered: &str) -> ApplyResult {
    let mut after = String::with_capacity(content.len());
    after.push_str(&content[..range.start.offset]);
    after.push_str(rendered);
    after.push_str(&content[range.end.offset..]);

    let diff = unified_diff(content, &after, file);
    let suggestion = FixSuggestion {
        diff: diff.clone(),
        before: content.to_string(),
        after: after.clone(),
    };
    ApplyResult {
        before: content.to_string(),
        after,
        diff,
        suggestion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Position, Range};

    #[test]
    fn splices_at_byte_range() {
        let content = "hello world";
        let range = Range {
            start: Position {
                line: 1,
                column: 1,
                offset: 0,
            },
            end: Position {
                line: 1,
                column: 6,
                offset: 5,
            },
        };
        let r = splice_and_diff("f.txt", content, range, "HELLO");
        assert_eq!(r.after, "HELLO world");
        assert!(r.diff.contains("-hello world"));
        assert!(r.diff.contains("+HELLO world"));
    }

    #[test]
    fn template_fix_substitutes_and_splices() {
        use crate::match_::MetavarBindings;
        use crate::node::{CanonicalKind, SgNode};

        let content = "call(foo)";
        let range = Range {
            start: Position {
                line: 1,
                column: 1,
                offset: 0,
            },
            end: Position {
                line: 1,
                column: content.len() + 1,
                offset: content.len(),
            },
        };
        let tmpl = FixTemplate::new("safe_call($X)");
        let mut bindings = MetavarBindings::new();
        let foo = SgNode::leaf(
            "identifier",
            CanonicalKind::Identifier,
            Range::new(
                Position::new(1, 6, 5),
                Position::new(1, 9, 8),
            ),
            b"foo",
        );
        bindings.try_bind("$X", foo).unwrap();

        let r = apply_template_fix("f.py", content, range, &tmpl, &bindings);
        assert_eq!(r.after, "safe_call(foo)");
        assert_eq!(r.suggestion.after, "safe_call(foo)");
        assert_eq!(r.suggestion.before, content);
    }

    #[test]
    fn regex_fix_replaces_within_range() {
        let content = "x = pickle.loads(buf)\n";
        // Range covers just `pickle.loads(buf)`.
        let range = Range {
            start: Position {
                line: 1,
                column: 5,
                offset: 4,
            },
            end: Position {
                line: 1,
                column: 22,
                offset: 21,
            },
        };
        let fix = FixRegex {
            regex: "pickle".into(),
            replacement: "json".into(),
            count: Some(1),
        };
        let r = apply_regex_fix("a.py", content, range, &fix).unwrap();
        assert_eq!(r.after, "x = json.loads(buf)\n");
    }
}
