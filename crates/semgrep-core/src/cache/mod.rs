//! On-disk + in-process caches.
//!
//! - `RuleCache` — `redb`-backed compiled-pattern cache keyed by content hash.
//! - `TargetCache<T>` — generic in-process cache for parsed documents, keyed
//!   by `(path, blake3(content))`. Generic over the parsed-doc type so this
//!   crate stays tree-sitter-free.

pub mod rule_cache;
pub mod target_cache;

pub use rule_cache::RuleCache;
pub use target_cache::TargetCache;
