//! Language detection + identification.
//!
//! `Language` is the canonical enum the rest of the engine uses to dispatch on
//! source language. Detection works three ways:
//!
//!   1. file extension (`.py` → Python, `.tsx` → Tsx, ...)
//!   2. shebang on the first line (`#!/usr/bin/env python3` → Python)
//!   3. user-supplied alias (`--lang py`, `--lang golang`)
//!
//! See plan.md §"Languages — extended matrix" for the full set.

use serde::{Deserialize, Serialize};

/// Source language a rule targets.
///
/// Variants intentionally span all GA / beta / experimental tiers documented in
/// plan.md §"Languages — extended matrix" (including OpenFGA and PowerShell
/// added in Feb / Mar 2026), plus `Generic` for the line-aware regex-style
/// matcher that has no associated AST grammar.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    // GA tier
    Python,
    Javascript,
    Typescript,
    Jsx,
    Tsx,
    Java,
    Go,
    Ruby,
    C,
    Cpp,
    Rust,
    Kotlin,
    Swift,
    Scala,
    Php,
    Csharp,
    Solidity,
    Bash,
    Lua,
    R,
    Julia,
    Ocaml,
    Clojure,
    Hack,
    Elixir,
    Dart,
    Apex,
    Cairo,
    Move,
    Bicep,
    Terraform,
    Dockerfile,
    Yaml,
    Json,
    Xml,
    Html,
    OpenFga,
    Powershell,
    /// Line-aware regex-style matcher (no AST). `--lang generic`.
    Generic,
}

impl Language {
    /// Map a bare extension (no leading dot, lower-cased) onto a language.
    ///
    /// Examples
    /// --------
    /// `"py"` → `Some(Python)`, `"tsx"` → `Some(Tsx)`, `"unknown"` → `None`.
    pub fn from_extension(ext: &str) -> Option<Self> {
        let ext = ext.trim_start_matches('.').to_ascii_lowercase();
        let lang = match ext.as_str() {
            "py" | "pyi" => Self::Python,
            "js" | "cjs" | "mjs" => Self::Javascript,
            "jsx" => Self::Jsx,
            "ts" | "mts" | "cts" => Self::Typescript,
            "tsx" => Self::Tsx,
            "java" => Self::Java,
            "go" => Self::Go,
            "rb" | "rbw" | "rake" | "gemspec" => Self::Ruby,
            "c" | "h" => Self::C,
            "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" | "ipp" => Self::Cpp,
            "cs" => Self::Csharp,
            "rs" => Self::Rust,
            "kt" | "kts" => Self::Kotlin,
            "swift" => Self::Swift,
            "scala" | "sc" => Self::Scala,
            "php" | "phtml" | "php4" | "php5" | "php7" | "phps" => Self::Php,
            "sol" => Self::Solidity,
            "sh" | "bash" | "zsh" | "ksh" => Self::Bash,
            "lua" => Self::Lua,
            "r" => Self::R,
            "jl" => Self::Julia,
            "ml" | "mli" => Self::Ocaml,
            "clj" | "cljs" | "cljc" | "edn" => Self::Clojure,
            "hack" | "hh-lang" => Self::Hack,
            "ex" | "exs" => Self::Elixir,
            "dart" => Self::Dart,
            "cls" | "trigger" => Self::Apex,
            "cairo" => Self::Cairo,
            "move" => Self::Move,
            "bicep" => Self::Bicep,
            "tf" | "tfvars" | "hcl" => Self::Terraform,
            "dockerfile" => Self::Dockerfile,
            "yaml" | "yml" => Self::Yaml,
            "json" | "jsonc" | "json5" => Self::Json,
            "xml" | "xsd" | "xsl" | "xslt" => Self::Xml,
            "html" | "htm" | "xhtml" => Self::Html,
            "fga" => Self::OpenFga,
            "ps1" | "psm1" | "psd1" => Self::Powershell,
            _ => return None,
        };
        Some(lang)
    }

    /// Resolve a `#!/usr/bin/env python3`-style shebang line to a language.
    ///
    /// The full first line is expected (with or without the leading `#!`). We
    /// pull the last whitespace-separated token's basename and map it.
    pub fn from_shebang(shebang: &str) -> Option<Self> {
        let line = shebang.trim_start();
        let line = line.strip_prefix("#!").unwrap_or(line).trim();
        if line.is_empty() {
            return None;
        }
        // Pull tokens; for `/usr/bin/env python3` we want `python3`,
        // for `/bin/bash` we want `bash`.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let interpreter = tokens.last()?;
        let basename = interpreter
            .rsplit(|c: char| c == '/' || c == '\\')
            .next()
            .unwrap_or(interpreter);
        // Strip a version suffix (`python3`, `python3.11` → `python`).
        let stem: String = basename
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '_')
            .collect();
        let stem = stem.to_ascii_lowercase();
        let lang = match stem.as_str() {
            "python" => Self::Python,
            "node" | "nodejs" => Self::Javascript,
            "deno" => Self::Typescript,
            "bash" | "sh" | "zsh" | "ksh" | "dash" => Self::Bash,
            "ruby" => Self::Ruby,
            "lua" => Self::Lua,
            "perl" => return None,
            "php" => Self::Php,
            "pwsh" | "powershell" => Self::Powershell,
            "ocaml" | "ocamlrun" => Self::Ocaml,
            "julia" => Self::Julia,
            "scala" => Self::Scala,
            "rscript" | "r" => Self::R,
            _ => return None,
        };
        Some(lang)
    }

    /// Resolve a user-facing alias (`py`, `js`, `golang`, `pwsh`, ...).
    pub fn from_alias(alias: &str) -> Option<Self> {
        let alias = alias.to_ascii_lowercase();
        let lang = match alias.as_str() {
            "py" | "python" | "python2" | "python3" => Self::Python,
            "js" | "javascript" | "node" | "nodejs" => Self::Javascript,
            "ts" | "typescript" => Self::Typescript,
            "jsx" => Self::Jsx,
            "tsx" => Self::Tsx,
            "java" => Self::Java,
            "go" | "golang" => Self::Go,
            "ruby" | "rb" => Self::Ruby,
            "c" => Self::C,
            "cpp" | "c++" | "cxx" => Self::Cpp,
            "rust" | "rs" => Self::Rust,
            "kotlin" | "kt" => Self::Kotlin,
            "swift" => Self::Swift,
            "scala" => Self::Scala,
            "php" => Self::Php,
            "csharp" | "cs" | "c#" => Self::Csharp,
            "solidity" | "sol" => Self::Solidity,
            "bash" | "sh" | "shell" => Self::Bash,
            "lua" => Self::Lua,
            "r" => Self::R,
            "julia" | "jl" => Self::Julia,
            "ocaml" | "ml" => Self::Ocaml,
            "clojure" | "clj" => Self::Clojure,
            "hack" => Self::Hack,
            "elixir" | "ex" => Self::Elixir,
            "dart" => Self::Dart,
            "apex" => Self::Apex,
            "cairo" => Self::Cairo,
            "move" => Self::Move,
            "bicep" => Self::Bicep,
            "terraform" | "tf" | "hcl" => Self::Terraform,
            "dockerfile" | "docker" => Self::Dockerfile,
            "yaml" | "yml" => Self::Yaml,
            "json" => Self::Json,
            "xml" => Self::Xml,
            "html" | "htm" => Self::Html,
            "openfga" | "fga" => Self::OpenFga,
            "powershell" | "pwsh" | "ps" => Self::Powershell,
            "generic" => Self::Generic,
            _ => return None,
        };
        Some(lang)
    }

    /// Filename extensions associated with this language (no leading dot).
    ///
    /// Used both for target enumeration and for round-tripping the
    /// `Language::from_extension` table. `Dockerfile` returns an empty slice
    /// since detection is by basename, not extension; callers should match the
    /// basename separately. `Generic` likewise has no extensions.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Python => &["py", "pyi"],
            Self::Javascript => &["js", "cjs", "mjs"],
            Self::Jsx => &["jsx"],
            Self::Typescript => &["ts", "mts", "cts"],
            Self::Tsx => &["tsx"],
            Self::Java => &["java"],
            Self::Go => &["go"],
            Self::Ruby => &["rb", "rbw", "rake", "gemspec"],
            Self::C => &["c", "h"],
            Self::Cpp => &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "ipp"],
            Self::Csharp => &["cs"],
            Self::Rust => &["rs"],
            Self::Kotlin => &["kt", "kts"],
            Self::Swift => &["swift"],
            Self::Scala => &["scala", "sc"],
            Self::Php => &["php", "phtml"],
            Self::Solidity => &["sol"],
            Self::Bash => &["sh", "bash"],
            Self::Lua => &["lua"],
            Self::R => &["r"],
            Self::Julia => &["jl"],
            Self::Ocaml => &["ml", "mli"],
            Self::Clojure => &["clj", "cljs", "cljc", "edn"],
            Self::Hack => &["hack"],
            Self::Elixir => &["ex", "exs"],
            Self::Dart => &["dart"],
            Self::Apex => &["cls", "trigger"],
            Self::Cairo => &["cairo"],
            Self::Move => &["move"],
            Self::Bicep => &["bicep"],
            Self::Terraform => &["tf", "tfvars", "hcl"],
            Self::Dockerfile => &[],
            Self::Yaml => &["yaml", "yml"],
            Self::Json => &["json", "jsonc"],
            Self::Xml => &["xml"],
            Self::Html => &["html", "htm"],
            Self::OpenFga => &["fga"],
            Self::Powershell => &["ps1", "psm1", "psd1"],
            Self::Generic => &[],
        }
    }

    /// The canonical extension to use when emitting / synthesising filenames.
    /// Returns an empty string for `Dockerfile` (basename-only) and `Generic`.
    pub fn primary_extension(self) -> &'static str {
        self.extensions().first().copied().unwrap_or("")
    }

    /// Human-readable language name (for `--show-supported-languages` etc.).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::Javascript => "JavaScript",
            Self::Jsx => "JSX",
            Self::Typescript => "TypeScript",
            Self::Tsx => "TSX",
            Self::Java => "Java",
            Self::Go => "Go",
            Self::Ruby => "Ruby",
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Csharp => "C#",
            Self::Rust => "Rust",
            Self::Kotlin => "Kotlin",
            Self::Swift => "Swift",
            Self::Scala => "Scala",
            Self::Php => "PHP",
            Self::Solidity => "Solidity",
            Self::Bash => "Bash",
            Self::Lua => "Lua",
            Self::R => "R",
            Self::Julia => "Julia",
            Self::Ocaml => "OCaml",
            Self::Clojure => "Clojure",
            Self::Hack => "Hack",
            Self::Elixir => "Elixir",
            Self::Dart => "Dart",
            Self::Apex => "Apex",
            Self::Cairo => "Cairo",
            Self::Move => "Move",
            Self::Bicep => "Bicep",
            Self::Terraform => "Terraform/HCL",
            Self::Dockerfile => "Dockerfile",
            Self::Yaml => "YAML",
            Self::Json => "JSON",
            Self::Xml => "XML",
            Self::Html => "HTML",
            Self::OpenFga => "OpenFGA",
            Self::Powershell => "PowerShell",
            Self::Generic => "Generic",
        }
    }

    /// Every variant, in declaration order. Useful for iterating in
    /// `--show-supported-languages` and tests.
    pub fn all() -> &'static [Language] {
        &[
            Self::Python,
            Self::Javascript,
            Self::Typescript,
            Self::Jsx,
            Self::Tsx,
            Self::Java,
            Self::Go,
            Self::Ruby,
            Self::C,
            Self::Cpp,
            Self::Rust,
            Self::Kotlin,
            Self::Swift,
            Self::Scala,
            Self::Php,
            Self::Csharp,
            Self::Solidity,
            Self::Bash,
            Self::Lua,
            Self::R,
            Self::Julia,
            Self::Ocaml,
            Self::Clojure,
            Self::Hack,
            Self::Elixir,
            Self::Dart,
            Self::Apex,
            Self::Cairo,
            Self::Move,
            Self::Bicep,
            Self::Terraform,
            Self::Dockerfile,
            Self::Yaml,
            Self::Json,
            Self::Xml,
            Self::Html,
            Self::OpenFga,
            Self::Powershell,
            Self::Generic,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_resolve_to_some_language() {
        // Every extension in every language's `extensions()` table must map
        // back to *some* language via `from_extension`. We don't require
        // bijective round-trip because a few extensions are listed in
        // multiple languages' tables for completeness.
        for &lang in Language::all() {
            for ext in lang.extensions() {
                assert!(
                    Language::from_extension(ext).is_some(),
                    "ext .{ext} for {lang:?} did not resolve"
                );
            }
        }
    }

    #[test]
    fn extension_specific_mappings() {
        assert_eq!(Language::from_extension("py"), Some(Language::Python));
        assert_eq!(Language::from_extension("js"), Some(Language::Javascript));
        assert_eq!(Language::from_extension("jsx"), Some(Language::Jsx));
        assert_eq!(Language::from_extension("ts"), Some(Language::Typescript));
        assert_eq!(Language::from_extension("tsx"), Some(Language::Tsx));
        assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
        assert_eq!(Language::from_extension("go"), Some(Language::Go));
        assert_eq!(Language::from_extension("tf"), Some(Language::Terraform));
        assert_eq!(Language::from_extension(".py"), Some(Language::Python));
        assert_eq!(Language::from_extension("PY"), Some(Language::Python));
        assert_eq!(Language::from_extension("nope"), None);
    }

    #[test]
    fn shebang_python() {
        assert_eq!(
            Language::from_shebang("#!/usr/bin/env python3"),
            Some(Language::Python)
        );
        assert_eq!(
            Language::from_shebang("#!/usr/bin/python3.11"),
            Some(Language::Python)
        );
    }

    #[test]
    fn shebang_node_bash() {
        assert_eq!(
            Language::from_shebang("#!/usr/bin/env node"),
            Some(Language::Javascript)
        );
        assert_eq!(Language::from_shebang("#!/bin/bash"), Some(Language::Bash));
        assert_eq!(Language::from_shebang("#!/bin/sh"), Some(Language::Bash));
    }

    #[test]
    fn alias_table() {
        assert_eq!(Language::from_alias("py"), Some(Language::Python));
        assert_eq!(Language::from_alias("golang"), Some(Language::Go));
        assert_eq!(Language::from_alias("cs"), Some(Language::Csharp));
        assert_eq!(Language::from_alias("pwsh"), Some(Language::Powershell));
        assert_eq!(Language::from_alias("hcl"), Some(Language::Terraform));
        assert_eq!(Language::from_alias("tf"), Some(Language::Terraform));
        assert_eq!(Language::from_alias("kt"), Some(Language::Kotlin));
        assert_eq!(Language::from_alias("nope"), None);
    }

    #[test]
    fn all_variants_present() {
        // 39 variants per the plan spec.
        assert_eq!(Language::all().len(), 39);
    }

    #[test]
    fn display_name_non_empty() {
        for lang in Language::all() {
            assert!(!lang.display_name().is_empty());
        }
    }
}
