//! Secrets mode helpers: entropy heuristic + live validator runner.

pub mod entropy;
pub mod validators;

pub use entropy::shannon_entropy;
pub use validators::SecretValidatorRunner;
