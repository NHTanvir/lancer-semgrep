//! `semgrep_list_rules` MCP tool — list rules from a config source, with an
//! optional language filter.

use eyre::Result;

pub fn tool_def() -> serde_json::Value {
    serde_json::json!({
        "name": "semgrep_list_rules",
        "description": "List rules from a config source, optionally filtered by language.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {
                    "type": "string",
                    "default": "auto",
                    "description": "Config path / dir / slug / `auto`"
                },
                "language": {
                    "type": "string",
                    "description": "Optional language filter (e.g., python, javascript)"
                }
            }
        }
    })
}

pub async fn run(args: serde_json::Value) -> Result<serde_json::Value> {
    let config = args
        .get("config")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let language = args.get("language").and_then(|v| v.as_str());

    let mut rs = semgrep_rules::RuleSet::new();
    match semgrep_rules::ConfigSource::parse(config) {
        semgrep_rules::ConfigSource::File(p) => {
            rs.extend(semgrep_rules::load_file(&p)?);
        }
        semgrep_rules::ConfigSource::Dir(p) => {
            rs.extend(semgrep_rules::load_dir(&p)?);
        }
        _ => {
            // Slug / URL / Auto / stdin / inline: registry path not wired
            // yet. We return an empty rule list rather than failing — same
            // posture as the scan tool.
            tracing::warn!(config = %config, "non-local config: registry not wired");
        }
    }

    let lang_filter = language.and_then(|l| {
        semgrep_core::Language::from_alias(l)
            .or_else(|| semgrep_core::Language::from_extension(l))
    });

    let mut out: Vec<serde_json::Value> = Vec::new();
    for r in rs.iter() {
        if let Some(lang) = lang_filter {
            if !r.languages.contains(&lang) {
                continue;
            }
        }
        out.push(serde_json::json!({
            "id": r.id.0,
            "severity": r.severity,
            "languages": r.languages,
            "message": r.message,
        }));
    }
    Ok(serde_json::json!({ "rules": out }))
}
