//! Thin re-export of the matcher's required-string pre-filter so binary-side
//! callers (e.g. future `--explain-prefilter` UX) can reach it without
//! reaching into the engine module path.

pub use semgrep_core::match_::pre_filter::{pre_filter, required_strings};
