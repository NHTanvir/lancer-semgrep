//! Autofix synthesis: apply a rule's `fix:` template or `fix-regex:` to a
//! finding's source range and emit a unified-diff suggestion.
//!
//! See plan.md §"Engineering hard parts → Autofix synthesis" for the design
//! constraints (byte-exact splicing, longest-name-first substitution).

pub mod apply;
pub mod diff;
pub mod regex;
pub mod template;

pub use apply::{apply_regex_fix, apply_template_fix, ApplyResult};
pub use diff::unified_diff;
pub use regex::apply_fix_regex;
pub use template::render_fix_template;

/// Public convenience wrapper around [`apply_template_fix`] — most rules carry
/// a [`crate::FixTemplate`] (`fix:` block), regex fixes are rarer.
pub fn apply_to_file(
    file: &str,
    content: &str,
    range: crate::Range,
    template: &crate::FixTemplate,
    bindings: &crate::match_::MetavarBindings<'_>,
) -> ApplyResult {
    apply_template_fix(file, content, range, template, bindings)
}
