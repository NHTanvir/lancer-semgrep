//! Semgrep Registry sync: fetch `p/<slug>` and `r/<rule-id>` packs from
//! `semgrep.dev` with retry + on-disk cache.
//!
//! See plan.md §"Registry slugs (popular ones)" and §"Internal architecture →
//! semgrep-rules → Registry HTTP sync".

pub mod client;
pub mod pack;
pub mod slug;

pub use client::RegistryClient;
pub use pack::RulePack;
pub use slug::{well_known_slugs, Slug};
