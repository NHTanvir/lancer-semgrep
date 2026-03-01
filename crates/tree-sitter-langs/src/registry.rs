//! Language registry — dispatches a `Language` to its `LangAdapter`.
//!
//! Cargo features gate the per-language arms; with `default-features = false`
//! the registry compiles to a single `_ => None` and `enabled_languages()`
//! returns an empty slice — useful for downstream crates that want to bundle
//! their own grammar set.
//!
//! Adapters are zero-sized structs so `Box::new(SomeAdapter)` is cheap and
//! involves no allocation beyond the trait object's vtable pointer.

use semgrep_core::Language;

use crate::adapter::LangAdapter;

/// Look up the adapter for `lang`, if compiled in.
///
/// Returns `None` when either the language is unsupported by `tree-sitter-langs`
/// (e.g. `Generic`, `Json`, `Xml`, exotic languages without a grammar crate) or
/// the corresponding `lang-*` feature is disabled.
pub fn adapter_for(lang: Language) -> Option<Box<dyn LangAdapter>> {
    match lang {
        #[cfg(feature = "lang-python")]
        Language::Python => Some(Box::new(crate::adapters::python::PythonAdapter)),

        #[cfg(feature = "lang-javascript")]
        Language::Javascript => Some(Box::new(crate::adapters::javascript::JavascriptAdapter)),
        #[cfg(feature = "lang-javascript")]
        Language::Jsx => Some(Box::new(crate::adapters::javascript::JsxAdapter)),

        #[cfg(feature = "lang-typescript")]
        Language::Typescript => Some(Box::new(crate::adapters::typescript::TypescriptAdapter)),
        #[cfg(feature = "lang-typescript")]
        Language::Tsx => Some(Box::new(crate::adapters::typescript::TsxAdapter)),

        #[cfg(feature = "lang-go")]
        Language::Go => Some(Box::new(crate::adapters::go::GoAdapter)),

        #[cfg(feature = "lang-rust")]
        Language::Rust => Some(Box::new(crate::adapters::rust::RustAdapter)),

        #[cfg(feature = "lang-java")]
        Language::Java => Some(Box::new(crate::adapters::java::JavaAdapter)),

        #[cfg(feature = "lang-ruby")]
        Language::Ruby => Some(Box::new(crate::adapters::ruby::RubyAdapter)),

        #[cfg(feature = "lang-c")]
        Language::C => Some(Box::new(crate::adapters::c::CAdapter)),

        #[cfg(feature = "lang-cpp")]
        Language::Cpp => Some(Box::new(crate::adapters::cpp::CppAdapter)),

        #[cfg(feature = "lang-csharp")]
        Language::Csharp => Some(Box::new(crate::adapters::csharp::CSharpAdapter)),

        #[cfg(feature = "lang-php")]
        Language::Php => Some(Box::new(crate::adapters::php::PhpAdapter)),

        #[cfg(feature = "lang-kotlin")]
        Language::Kotlin => Some(Box::new(crate::adapters::kotlin::KotlinAdapter)),

        #[cfg(feature = "lang-swift")]
        Language::Swift => Some(Box::new(crate::adapters::swift::SwiftAdapter)),

        #[cfg(feature = "lang-scala")]
        Language::Scala => Some(Box::new(crate::adapters::scala::ScalaAdapter)),

        #[cfg(feature = "lang-bash")]
        Language::Bash => Some(Box::new(crate::adapters::bash::BashAdapter)),

        #[cfg(feature = "lang-lua")]
        Language::Lua => Some(Box::new(crate::adapters::lua::LuaAdapter)),

        #[cfg(feature = "lang-r")]
        Language::R => Some(Box::new(crate::adapters::r_::RAdapter)),

        #[cfg(feature = "lang-elixir")]
        Language::Elixir => Some(Box::new(crate::adapters::elixir::ElixirAdapter)),

        #[cfg(feature = "lang-clojure")]
        Language::Clojure => Some(Box::new(crate::adapters::clojure::ClojureAdapter)),

        #[cfg(feature = "lang-ocaml")]
        Language::Ocaml => Some(Box::new(crate::adapters::ocaml::OcamlAdapter)),

        #[cfg(feature = "lang-yaml")]
        Language::Yaml => Some(Box::new(crate::adapters::yaml::YamlAdapter)),

        #[cfg(feature = "lang-dockerfile")]
        Language::Dockerfile => Some(Box::new(crate::adapters::dockerfile::DockerfileAdapter)),

        #[cfg(feature = "lang-hcl")]
        Language::Terraform => Some(Box::new(crate::adapters::hcl::HclAdapter)),

        #[cfg(feature = "lang-solidity")]
        Language::Solidity => Some(Box::new(crate::adapters::solidity::SolidityAdapter)),

        #[cfg(feature = "lang-dart")]
        Language::Dart => Some(Box::new(crate::adapters::dart::DartAdapter)),

        #[cfg(feature = "lang-html")]
        Language::Html => Some(Box::new(crate::adapters::html::HtmlAdapter)),

        _ => None,
    }
}

/// All languages whose adapter is compiled in for this build.
///
/// Ordering is roughly "default tier first, then alphabetical" — not
/// load-bearing; callers that care about a stable order should sort.
pub fn enabled_languages() -> Vec<Language> {
    #[allow(unused_mut)]
    let mut v: Vec<Language> = Vec::new();

    #[cfg(feature = "lang-python")]
    v.push(Language::Python);
    #[cfg(feature = "lang-javascript")]
    {
        v.push(Language::Javascript);
        v.push(Language::Jsx);
    }
    #[cfg(feature = "lang-typescript")]
    {
        v.push(Language::Typescript);
        v.push(Language::Tsx);
    }
    #[cfg(feature = "lang-go")]
    v.push(Language::Go);
    #[cfg(feature = "lang-rust")]
    v.push(Language::Rust);
    #[cfg(feature = "lang-java")]
    v.push(Language::Java);
    #[cfg(feature = "lang-ruby")]
    v.push(Language::Ruby);
    #[cfg(feature = "lang-c")]
    v.push(Language::C);
    #[cfg(feature = "lang-cpp")]
    v.push(Language::Cpp);
    #[cfg(feature = "lang-csharp")]
    v.push(Language::Csharp);
    #[cfg(feature = "lang-php")]
    v.push(Language::Php);
    #[cfg(feature = "lang-kotlin")]
    v.push(Language::Kotlin);
    #[cfg(feature = "lang-swift")]
    v.push(Language::Swift);
    #[cfg(feature = "lang-scala")]
    v.push(Language::Scala);
    #[cfg(feature = "lang-bash")]
    v.push(Language::Bash);
    #[cfg(feature = "lang-lua")]
    v.push(Language::Lua);
    #[cfg(feature = "lang-r")]
    v.push(Language::R);
    #[cfg(feature = "lang-elixir")]
    v.push(Language::Elixir);
    #[cfg(feature = "lang-clojure")]
    v.push(Language::Clojure);
    #[cfg(feature = "lang-ocaml")]
    v.push(Language::Ocaml);
    #[cfg(feature = "lang-yaml")]
    v.push(Language::Yaml);
    #[cfg(feature = "lang-dockerfile")]
    v.push(Language::Dockerfile);
    #[cfg(feature = "lang-hcl")]
    v.push(Language::Terraform);
    #[cfg(feature = "lang-solidity")]
    v.push(Language::Solidity);
    #[cfg(feature = "lang-dart")]
    v.push(Language::Dart);
    #[cfg(feature = "lang-html")]
    v.push(Language::Html);

    v
}
