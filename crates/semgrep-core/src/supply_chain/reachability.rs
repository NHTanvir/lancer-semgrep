//! Which languages support call-graph reachability analysis for the Supply
//! Chain product.
//!
//! Per plan §"Research note 2026-05-31": Python, JS, TS, Java, Go, Ruby,
//! C#, Kotlin, Scala, Rust, **PHP** (added Apr 2026, 11th language).

use crate::Language;

/// Is reachability supported for `lang`?
pub fn reachability_supported(lang: Language) -> bool {
    matches!(
        lang,
        Language::Python
            | Language::Javascript
            | Language::Typescript
            | Language::Java
            | Language::Go
            | Language::Ruby
            | Language::Csharp
            | Language::Kotlin
            | Language::Scala
            | Language::Rust
            | Language::Php
    )
}

/// The 11-element list of reachability-supported languages, in stable order.
pub fn reachability_supported_list() -> Vec<Language> {
    vec![
        Language::Python,
        Language::Javascript,
        Language::Typescript,
        Language::Java,
        Language::Go,
        Language::Ruby,
        Language::Csharp,
        Language::Kotlin,
        Language::Scala,
        Language::Rust,
        Language::Php,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn php_is_supported() {
        assert!(reachability_supported(Language::Php));
    }

    #[test]
    fn count_is_eleven() {
        assert_eq!(reachability_supported_list().len(), 11);
    }

    #[test]
    fn solidity_not_supported() {
        assert!(!reachability_supported(Language::Solidity));
    }
}
