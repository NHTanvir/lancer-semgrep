//! `semgrep_rule_schema` MCP tool — return a JSON Schema sketch for a
//! Semgrep rule file. Driven by plan.md §"Granular feature catalog → Rule
//! format"; deliberately a useful subset, not exhaustive (AI rule
//! generation flows can already lean on it).

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_rule_schema",
        "description": "Return a JSON Schema describing the Semgrep rule format \
                        (top-level `rules:` array with one rule object per entry).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    })
}

pub async fn run(_args: serde_json::Value) -> Result<serde_json::Value> {
    Ok(schema())
}

/// The JSON Schema document. Lives in its own function so tests can render
/// it without going through the MCP call path.
pub fn schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://semgrep.dev/schemas/rule.json",
        "title": "Semgrep rule file",
        "type": "object",
        "required": ["rules"],
        "properties": {
            "rules": {
                "type": "array",
                "items": { "$ref": "#/$defs/Rule" }
            }
        },
        "$defs": {
            "Rule": {
                "type": "object",
                "required": ["id", "message", "languages", "severity"],
                "properties": {
                    "id":        { "type": "string" },
                    "mode":      { "enum": ["search", "taint", "join", "extract", "secrets"] },
                    "message":   { "type": "string" },
                    "languages": { "type": "array", "items": { "type": "string" } },
                    "severity":  { "enum": ["INFO", "WARNING", "ERROR"] },
                    "metadata":  { "type": "object" },
                    "options":   { "type": "object" },
                    "paths": {
                        "type": "object",
                        "properties": {
                            "include": { "type": "array", "items": { "type": "string" } },
                            "exclude": { "type": "array", "items": { "type": "string" } }
                        }
                    },
                    "pattern":           { "type": "string" },
                    "patterns":          { "type": "array", "items": { "$ref": "#/$defs/PatternOp" } },
                    "pattern-either":    { "type": "array", "items": { "$ref": "#/$defs/PatternOp" } },
                    "pattern-not":       { "type": "string" },
                    "pattern-inside":    { "type": "string" },
                    "pattern-not-inside":{ "type": "string" },
                    "pattern-regex":     { "type": "string" },
                    "pattern-not-regex": { "type": "string" },
                    "metavariable-regex": {
                        "type": "object",
                        "required": ["metavariable", "regex"],
                        "properties": {
                            "metavariable": { "type": "string" },
                            "regex":        { "type": "string" }
                        }
                    },
                    "metavariable-comparison": {
                        "type": "object",
                        "required": ["metavariable", "comparison"],
                        "properties": {
                            "metavariable": { "type": "string" },
                            "comparison":   { "type": "string" }
                        }
                    },
                    "metavariable-pattern": {
                        "type": "object",
                        "properties": {
                            "metavariable": { "type": "string" },
                            "pattern":      { "type": "string" }
                        }
                    },
                    "metavariable-type": {
                        "type": "object",
                        "properties": {
                            "metavariable": { "type": "string" },
                            "type":         { "type": "string" }
                        }
                    },
                    "fix":       { "type": "string" },
                    "fix-regex": {
                        "type": "object",
                        "properties": {
                            "regex":       { "type": "string" },
                            "replacement": { "type": "string" }
                        }
                    },
                    "pattern-sources": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/TaintNode" }
                    },
                    "pattern-sinks": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/TaintNode" }
                    },
                    "pattern-sanitizers": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/TaintNode" }
                    },
                    "pattern-propagators": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/TaintNode" }
                    }
                }
            },
            "PatternOp": {
                "description": "One pattern node — a string short-hand or a single-key object.",
                "oneOf": [
                    { "type": "string" },
                    { "type": "object" }
                ]
            },
            "TaintNode": {
                "type": "object",
                "properties": {
                    "pattern":  { "type": "string" },
                    "label":    { "type": "string" },
                    "requires": { "type": "string" },
                    "by-side-effect": { "type": "boolean" },
                    "from":     { "type": "string" },
                    "to":       { "type": "string" }
                }
            }
        }
    })
}
