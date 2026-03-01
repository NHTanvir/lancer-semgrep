//! `mode: join` cross-file rule configuration.
//!
//! A join rule declares a list of named sub-rules (each with its own
//! patterns / metavariables) and a set of join keys describing which
//! metavariables must agree across sub-rules. The engine runs each sub-rule
//! independently, then computes the relational join over the results. See
//! plan.md §"Join mode (cross-file)".
//!
//! Example:
//!
//! ```yaml
//! - id: route-touches-raw-sql
//!   mode: join
//!   join:
//!     rules:
//!       - id: route-handler
//!         rule:
//!           id: route-handler
//!           languages: [python]
//!           pattern: |
//!             @app.route($ROUTE)
//!             def $HANDLER(...): ...
//!       - id: raw-sql
//!         rule:
//!           id: raw-sql
//!           languages: [python]
//!           pattern: cursor.execute("..." + $X)
//!     on:
//!       - 'route-handler.$HANDLER'
//!       - 'raw-sql.$X'
//! ```

use serde::{Deserialize, Serialize};

use crate::rule::{Rule, RuleId};

/// `join:` block of a join-mode rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JoinRuleConfig {
    /// Named sub-rules.
    pub rules: Vec<JoinSubRule>,
    /// Join keys — each entry pairs a metavariable from one sub-rule with a
    /// metavariable from another.
    #[serde(default)]
    pub on: Vec<JoinKey>,
}

/// A named sub-rule inside a join configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinSubRule {
    pub id: RuleId,
    pub rule: Box<Rule>,
}

/// One join key: `left` and `right` each name (sub-rule-id, metavar-name).
///
/// In YAML this is typically encoded as the string `sub-rule.$METAVAR ==
/// other-sub-rule.$METAVAR2`, but for the in-memory form we use a structured
/// pair; the YAML loader in `semgrep-rules` parses the string form into this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinKey {
    pub left: JoinRef,
    pub right: JoinRef,
}

/// One side of a join key. `rule` is the sub-rule's id, `metavar` is the
/// metavariable name (with leading `$`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRef {
    pub rule: RuleId,
    pub metavar: String,
}

impl JoinRef {
    pub fn new(rule: impl Into<RuleId>, metavar: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            metavar: metavar.into(),
        }
    }
}
