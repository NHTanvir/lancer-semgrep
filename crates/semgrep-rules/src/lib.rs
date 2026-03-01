//! semgrep-rules — rule YAML loader, schema validator, registry sync, on-disk cache.
//!
//! See plan.md §"Granular feature catalog → Rule format", §"Internal architecture →
//! semgrep-rules", §"How a rule executes", and §"Registry slugs (popular ones)".
//!
//! Pipeline:
//!
//! 1. [`load`] parses a YAML file / dir / reader / string into a list of `Rule`s.
//!    Bare-string shorthand for `pattern-not` / `pattern-inside` / `pattern-not-inside`
//!    is canonicalised at the [`canonicalise`] step before serde deserialisation.
//! 2. [`schema::validate_rule`] enforces required fields and mode-specific
//!    invariants (search needs `pattern`, taint needs sources + sinks, etc.).
//! 3. [`config::ConfigSource`] resolves `--config <arg>` into a concrete fetch
//!    plan (file / dir / slug / URL / `auto` / stdin / inline YAML).
//! 4. [`registry::RegistryClient`] talks to `https://semgrep.dev/c/p/<slug>` with
//!    exponential-backoff retries on HTTP 429 / 5xx.
//! 5. [`cache::RuleCache`] keeps fetched packs on disk under
//!    `~/.cache/lancer/semgrep/rule_cache.redb`, keyed by `blake3(yaml)`.

pub mod cache;
pub mod canonicalise;
pub mod config;
pub mod error;
pub mod fast_json;
pub mod load;
pub mod registry;
pub mod ruleset;
pub mod schema;

pub use cache::RuleCache;
pub use config::{resolve, ConfigSource, ResolvedConfig};
pub use error::{LoadError, SchemaError};
pub use fast_json::parse_rule_pack_fast;
pub use load::{load_dir, load_file, load_reader, load_str};
pub use registry::{well_known_slugs, RegistryClient, RulePack, Slug};
pub use ruleset::RuleSet;
pub use schema::validate_rule;

/// Crate version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
