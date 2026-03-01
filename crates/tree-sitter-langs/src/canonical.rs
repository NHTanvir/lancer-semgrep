//! Per-grammar node-kind → `CanonicalKind` mapping.
//!
//! Each tree-sitter grammar names AST node types differently
//! (`function_definition` in Python, `function_declaration` in JS, `function_item`
//! in Rust, `method_declaration` in Java, …). The cross-language pattern matcher
//! needs to reason about these uniformly, so this module collapses the
//! grammar-specific names down to the small `CanonicalKind` taxonomy defined
//! in `semgrep_core::node`.
//!
//! Coverage policy: 15–20 entries per specialised language, plus a generic
//! heuristic fallback (`generic_kind`) for the long tail of languages where
//! it isn't worth hand-curating the table yet. The matcher then falls back to
//! comparing raw `kind` strings for kinds canonicalised to `Other`.

use semgrep_core::{node::CanonicalKind, Language};

/// Top-level dispatcher used by `LangAdapter::canonical_kind`'s default impl.
pub fn canonicalise(lang: Language, raw_kind: &str) -> CanonicalKind {
    match lang {
        Language::Python => python_kind(raw_kind),
        Language::Javascript | Language::Jsx => js_kind(raw_kind),
        Language::Typescript | Language::Tsx => ts_kind(raw_kind),
        Language::Go => go_kind(raw_kind),
        Language::Rust => rust_kind(raw_kind),
        Language::Java => java_kind(raw_kind),
        _ => generic_kind(raw_kind),
    }
}

// ---------------------------------------------------------------------------
// Python — tree-sitter-python grammar.
// Node kinds enumerated from `tree-sitter-python/src/node-types.json`.
// ---------------------------------------------------------------------------
fn python_kind(k: &str) -> CanonicalKind {
    match k {
        "function_definition" | "lambda" => CanonicalKind::Function,
        "call" => CanonicalKind::Call,
        "identifier" | "dotted_name" => CanonicalKind::Identifier,
        "string" | "string_content" | "concatenated_string" => CanonicalKind::String,
        "integer" | "float" => CanonicalKind::Number,
        "binary_operator" | "boolean_operator" | "comparison_operator" | "unary_operator" => {
            CanonicalKind::BinaryOp
        }
        "assignment" | "augmented_assignment" => CanonicalKind::Assign,
        "if_statement" | "elif_clause" | "else_clause" => CanonicalKind::IfStmt,
        "block" => CanonicalKind::Block,
        "return_statement" => CanonicalKind::Return,
        "argument_list" | "keyword_argument" => CanonicalKind::Argument,
        "parameters" | "default_parameter" | "typed_parameter" | "typed_default_parameter" => {
            CanonicalKind::Parameter
        }
        "import_statement" | "import_from_statement" | "future_import_statement" => {
            CanonicalKind::Import
        }
        "type" => CanonicalKind::TypeAnnotation,
        "comment" => CanonicalKind::Comment,
        "expression_statement" => CanonicalKind::Statement,
        _ => CanonicalKind::Other,
    }
}

// ---------------------------------------------------------------------------
// JavaScript — tree-sitter-javascript grammar (also drives JSX).
// ---------------------------------------------------------------------------
fn js_kind(k: &str) -> CanonicalKind {
    match k {
        "function_declaration"
        | "function_expression"
        | "arrow_function"
        | "generator_function_declaration"
        | "generator_function" => CanonicalKind::Function,
        "method_definition" => CanonicalKind::Method,
        "call_expression" | "new_expression" => CanonicalKind::Call,
        "identifier" | "property_identifier" | "shorthand_property_identifier" => {
            CanonicalKind::Identifier
        }
        "string" | "template_string" | "string_fragment" => CanonicalKind::String,
        "number" => CanonicalKind::Number,
        "binary_expression" | "logical_expression" | "unary_expression" => CanonicalKind::BinaryOp,
        "assignment_expression" | "augmented_assignment_expression" | "variable_declarator" => {
            CanonicalKind::Assign
        }
        "if_statement" | "else_clause" => CanonicalKind::IfStmt,
        "statement_block" | "class_body" => CanonicalKind::Block,
        "return_statement" => CanonicalKind::Return,
        "arguments" | "spread_element" => CanonicalKind::Argument,
        "formal_parameters" | "required_parameter" | "optional_parameter" | "rest_pattern" => {
            CanonicalKind::Parameter
        }
        "import_statement" | "import_specifier" | "import_clause" => CanonicalKind::Import,
        "comment" => CanonicalKind::Comment,
        "expression_statement" => CanonicalKind::Statement,
        _ => CanonicalKind::Other,
    }
}

// ---------------------------------------------------------------------------
// TypeScript — tree-sitter-typescript adds type-system nodes on top of JS.
// We delegate to `js_kind` and override only the TS-only kinds.
// ---------------------------------------------------------------------------
fn ts_kind(k: &str) -> CanonicalKind {
    match k {
        "type_annotation"
        | "type_identifier"
        | "predefined_type"
        | "union_type"
        | "intersection_type"
        | "generic_type"
        | "tuple_type"
        | "object_type" => CanonicalKind::TypeAnnotation,
        "interface_declaration" | "type_alias_declaration" | "enum_declaration" => {
            CanonicalKind::Statement
        }
        _ => js_kind(k),
    }
}

// ---------------------------------------------------------------------------
// Go — tree-sitter-go grammar.
// ---------------------------------------------------------------------------
fn go_kind(k: &str) -> CanonicalKind {
    match k {
        "function_declaration" | "func_literal" => CanonicalKind::Function,
        "method_declaration" => CanonicalKind::Method,
        "call_expression" => CanonicalKind::Call,
        "identifier" | "field_identifier" | "package_identifier" | "type_identifier" => {
            CanonicalKind::Identifier
        }
        "interpreted_string_literal" | "raw_string_literal" => CanonicalKind::String,
        "int_literal" | "float_literal" | "imaginary_literal" => CanonicalKind::Number,
        "binary_expression" | "unary_expression" => CanonicalKind::BinaryOp,
        "assignment_statement" | "short_var_declaration" | "inc_statement" | "dec_statement" => {
            CanonicalKind::Assign
        }
        "if_statement" => CanonicalKind::IfStmt,
        "block" => CanonicalKind::Block,
        "return_statement" => CanonicalKind::Return,
        "argument_list" => CanonicalKind::Argument,
        "parameter_list" | "parameter_declaration" | "variadic_parameter_declaration" => {
            CanonicalKind::Parameter
        }
        "import_declaration" | "import_spec" => CanonicalKind::Import,
        "type_spec" | "type_declaration" => CanonicalKind::TypeAnnotation,
        "comment" => CanonicalKind::Comment,
        "expression_statement" => CanonicalKind::Statement,
        _ => CanonicalKind::Other,
    }
}

// ---------------------------------------------------------------------------
// Rust — tree-sitter-rust grammar.
// ---------------------------------------------------------------------------
fn rust_kind(k: &str) -> CanonicalKind {
    match k {
        "function_item" | "closure_expression" => CanonicalKind::Function,
        "impl_item" => CanonicalKind::Block,
        "call_expression" | "macro_invocation" => CanonicalKind::Call,
        "identifier" | "field_identifier" | "type_identifier" | "scoped_identifier" => {
            CanonicalKind::Identifier
        }
        "string_literal" | "raw_string_literal" | "char_literal" => CanonicalKind::String,
        "integer_literal" | "float_literal" => CanonicalKind::Number,
        "binary_expression" | "unary_expression" | "compound_assignment_expr" => {
            CanonicalKind::BinaryOp
        }
        "assignment_expression" | "let_declaration" | "const_item" | "static_item" => {
            CanonicalKind::Assign
        }
        "if_expression" | "if_let_expression" | "match_expression" => CanonicalKind::IfStmt,
        "block" => CanonicalKind::Block,
        "return_expression" => CanonicalKind::Return,
        "arguments" => CanonicalKind::Argument,
        "parameters" | "parameter" | "self_parameter" => CanonicalKind::Parameter,
        "use_declaration" | "extern_crate_declaration" => CanonicalKind::Import,
        "type_arguments" | "generic_type" | "reference_type" | "primitive_type" => {
            CanonicalKind::TypeAnnotation
        }
        "line_comment" | "block_comment" => CanonicalKind::Comment,
        "expression_statement" => CanonicalKind::Statement,
        _ => CanonicalKind::Other,
    }
}

// ---------------------------------------------------------------------------
// Java — tree-sitter-java grammar.
// ---------------------------------------------------------------------------
fn java_kind(k: &str) -> CanonicalKind {
    match k {
        "constructor_declaration" | "lambda_expression" => CanonicalKind::Function,
        "method_declaration" => CanonicalKind::Method,
        "method_invocation" | "object_creation_expression" | "explicit_constructor_invocation" => {
            CanonicalKind::Call
        }
        "identifier" | "scoped_identifier" | "type_identifier" => CanonicalKind::Identifier,
        "string_literal" | "character_literal" => CanonicalKind::String,
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal"
        | "decimal_floating_point_literal"
        | "hex_floating_point_literal" => CanonicalKind::Number,
        "binary_expression" | "unary_expression" | "instanceof_expression" => {
            CanonicalKind::BinaryOp
        }
        "assignment_expression" | "local_variable_declaration" | "variable_declarator" => {
            CanonicalKind::Assign
        }
        "if_statement" => CanonicalKind::IfStmt,
        "block" | "class_body" | "interface_body" => CanonicalKind::Block,
        "return_statement" => CanonicalKind::Return,
        "argument_list" => CanonicalKind::Argument,
        "formal_parameter" | "formal_parameters" | "spread_parameter" => CanonicalKind::Parameter,
        "import_declaration" => CanonicalKind::Import,
        "type_arguments" | "generic_type" => CanonicalKind::TypeAnnotation,
        "line_comment" | "block_comment" => CanonicalKind::Comment,
        "expression_statement" => CanonicalKind::Statement,
        _ => CanonicalKind::Other,
    }
}

// ---------------------------------------------------------------------------
// Generic fallback for languages where we haven't hand-curated a table.
//
// Substring heuristics — wrong sometimes but close enough that pattern
// matching against `CanonicalKind::Other` only kicks in for genuinely
// grammar-specific kinds. As specific languages get hand-curated tables this
// stays as the long tail.
// ---------------------------------------------------------------------------
fn generic_kind(k: &str) -> CanonicalKind {
    if k.contains("function") || k.contains("def ") || k == "def" || k.contains("lambda") {
        return CanonicalKind::Function;
    }
    if k.contains("method") {
        return CanonicalKind::Method;
    }
    if k.contains("call") || k.contains("invocation") || k.contains("apply") {
        return CanonicalKind::Call;
    }
    if k == "identifier" || k.ends_with("_identifier") || k.ends_with("_name") {
        return CanonicalKind::Identifier;
    }
    if k.contains("string") {
        return CanonicalKind::String;
    }
    if k.contains("number")
        || k.contains("integer")
        || k.contains("float")
        || k.contains("numeric")
    {
        return CanonicalKind::Number;
    }
    if k.contains("assign") || k.contains("declarator") {
        return CanonicalKind::Assign;
    }
    if k.contains("if") && (k.contains("statement") || k.contains("expression")) {
        return CanonicalKind::IfStmt;
    }
    if k == "block" || k.ends_with("_block") || k.ends_with("_body") {
        return CanonicalKind::Block;
    }
    if k.contains("return") {
        return CanonicalKind::Return;
    }
    if k.contains("import") || k.contains("require") || k.contains("use_") || k == "use" {
        return CanonicalKind::Import;
    }
    if k.contains("argument") || k == "arguments" {
        return CanonicalKind::Argument;
    }
    if k.contains("parameter") {
        return CanonicalKind::Parameter;
    }
    if k.contains("type") {
        return CanonicalKind::TypeAnnotation;
    }
    if k.contains("comment") {
        return CanonicalKind::Comment;
    }
    if k.ends_with("_statement") || k.ends_with("_stmt") {
        return CanonicalKind::Statement;
    }
    if k.ends_with("_expression") || k.ends_with("_expr") {
        return CanonicalKind::Expression;
    }
    CanonicalKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_function_definition_maps_to_function() {
        assert_eq!(python_kind("function_definition"), CanonicalKind::Function);
        assert_eq!(python_kind("call"), CanonicalKind::Call);
        assert_eq!(python_kind("if_statement"), CanonicalKind::IfStmt);
        assert_eq!(python_kind("identifier"), CanonicalKind::Identifier);
        assert_eq!(python_kind("nope_does_not_exist"), CanonicalKind::Other);
    }

    #[test]
    fn js_and_ts_share_base_kinds() {
        assert_eq!(js_kind("function_declaration"), CanonicalKind::Function);
        assert_eq!(ts_kind("function_declaration"), CanonicalKind::Function);
        // TS-specific kind doesn't fall through to "Other".
        assert_eq!(ts_kind("interface_declaration"), CanonicalKind::Statement);
        assert_eq!(ts_kind("type_annotation"), CanonicalKind::TypeAnnotation);
    }

    #[test]
    fn go_rust_java_basic_mappings() {
        assert_eq!(go_kind("function_declaration"), CanonicalKind::Function);
        assert_eq!(go_kind("method_declaration"), CanonicalKind::Method);
        assert_eq!(rust_kind("function_item"), CanonicalKind::Function);
        assert_eq!(rust_kind("use_declaration"), CanonicalKind::Import);
        assert_eq!(java_kind("method_declaration"), CanonicalKind::Method);
        assert_eq!(java_kind("method_invocation"), CanonicalKind::Call);
    }

    #[test]
    fn generic_fallback_heuristics() {
        assert_eq!(generic_kind("function_declaration"), CanonicalKind::Function);
        assert_eq!(generic_kind("call_expression"), CanonicalKind::Call);
        assert_eq!(generic_kind("string_literal"), CanonicalKind::String);
        assert_eq!(generic_kind("integer_literal"), CanonicalKind::Number);
        assert_eq!(generic_kind("return_statement"), CanonicalKind::Return);
        assert_eq!(generic_kind("foo_statement"), CanonicalKind::Statement);
        assert_eq!(generic_kind("foo_expression"), CanonicalKind::Expression);
        assert_eq!(generic_kind("totally_unknown"), CanonicalKind::Other);
    }

    #[test]
    fn canonicalise_dispatches_per_language() {
        assert_eq!(
            canonicalise(Language::Python, "function_definition"),
            CanonicalKind::Function
        );
        assert_eq!(
            canonicalise(Language::Rust, "function_item"),
            CanonicalKind::Function
        );
        // Falls through to generic for unspecialised languages.
        assert_eq!(
            canonicalise(Language::Ruby, "method"),
            CanonicalKind::Method
        );
    }
}
