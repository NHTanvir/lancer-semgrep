//! Taint-mode value types — labels, lattice, `requires:` expression DSL.
//!
//! Semgrep's classic taint mode tracks a single "tainted source" identity per
//! variable; the 2025–2026 upgrades let sources carry a textual `label:` and
//! sinks carry `requires:` boolean expressions over those labels (see plan.md
//! §"Newer rule-format features to support (2025–2026)" — taint labels).
//!
//! The lattice is:
//!
//! ```text
//!     Top
//!      |
//!  Tainted({A, B, ...})
//!      |
//!  Untainted
//! ```
//!
//! `join` of two states is the LUB. Sinks with a `requires:` expression
//! evaluate the expression against the inbound label set; a sink fires only
//! when the expression is true.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Free-form textual taint label (e.g. `"user-input"`, `"admin-only"`).
///
/// Stored as a `String` rather than interned — the volume is tiny (handful per
/// rule × handful of variables per function) so interning is overhead.
pub type TaintLabel = String;

/// Ordered set of labels carrying a tainted value.
///
/// Ordered (BTreeSet) so the `Debug` / `Serialize` output is deterministic,
/// which matters for snapshot-style tests of dataflow traces.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct TaintLabelSet {
    inner: BTreeSet<TaintLabel>,
}

impl TaintLabelSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn singleton(label: impl Into<TaintLabel>) -> Self {
        let mut s = Self::new();
        s.insert(label.into());
        s
    }

    pub fn insert(&mut self, label: TaintLabel) -> bool {
        self.inner.insert(label)
    }

    pub fn contains(&self, label: &str) -> bool {
        self.inner.contains(label)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn union(&self, other: &TaintLabelSet) -> TaintLabelSet {
        let mut out = self.clone();
        for l in &other.inner {
            out.insert(l.clone());
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = &TaintLabel> {
        self.inner.iter()
    }
}

impl FromIterator<TaintLabel> for TaintLabelSet {
    fn from_iter<I: IntoIterator<Item = TaintLabel>>(iter: I) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<&'a str> for TaintLabelSet {
    fn from_iter<I: IntoIterator<Item = &'a str>>(iter: I) -> Self {
        Self {
            inner: iter.into_iter().map(String::from).collect(),
        }
    }
}

/// Per-variable taint state at a program point.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "labels")]
pub enum TaintState {
    /// Definitely clean.
    Untainted,
    /// Carries one or more labels (the union of all reaching sources).
    Tainted(TaintLabelSet),
    /// Overapproximation — used when the dataflow gives up (e.g., unresolved
    /// extern call, recursion fix-point timed out).
    Top,
}

impl TaintState {
    /// Lattice LUB: combine two states meeting at a join point.
    pub fn join(&self, other: &TaintState) -> TaintState {
        match (self, other) {
            (TaintState::Top, _) | (_, TaintState::Top) => TaintState::Top,
            (TaintState::Untainted, x) | (x, TaintState::Untainted) => x.clone(),
            (TaintState::Tainted(a), TaintState::Tainted(b)) => {
                TaintState::Tainted(a.union(b))
            }
        }
    }

    /// True iff this state carries any taint.
    pub fn is_tainted(&self) -> bool {
        matches!(self, TaintState::Tainted(_) | TaintState::Top)
    }

    /// Returns the labels currently propagated, if any.
    pub fn labels(&self) -> Option<&TaintLabelSet> {
        match self {
            TaintState::Tainted(s) => Some(s),
            _ => None,
        }
    }
}

/// Error returned by `RequiresExpr::parse`. Carries a human-readable message.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("requires-expr parse error: {0}")]
pub struct RequiresParseError(pub String);

/// Boolean expression over taint labels. Grammar (sugar removed):
///
/// ```text
///     Expr := Or
///     Or   := And ( 'or' And )*
///     And  := Not ( 'and' Not )*
///     Not  := 'not'? Atom
///     Atom := Label | '(' Expr ')' | 'true' | 'false'
///     Label := [A-Za-z_][A-Za-z0-9_-]*
/// ```
///
/// Whitespace is skipped between tokens. Operator keywords (`and`, `or`,
/// `not`, `true`, `false`) are reserved and cannot appear as label names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum RequiresExpr {
    Label(TaintLabel),
    And(Box<RequiresExpr>, Box<RequiresExpr>),
    Or(Box<RequiresExpr>, Box<RequiresExpr>),
    Not(Box<RequiresExpr>),
    True,
    False,
}

impl RequiresExpr {
    /// Evaluate the expression against a label set.
    pub fn eval(&self, labels: &TaintLabelSet) -> bool {
        match self {
            RequiresExpr::Label(l) => labels.contains(l),
            RequiresExpr::And(a, b) => a.eval(labels) && b.eval(labels),
            RequiresExpr::Or(a, b) => a.eval(labels) || b.eval(labels),
            RequiresExpr::Not(e) => !e.eval(labels),
            RequiresExpr::True => true,
            RequiresExpr::False => false,
        }
    }

    /// Parse the expression DSL. Returns a structured `RequiresParseError` on
    /// malformed input.
    pub fn parse(s: &str) -> Result<Self, RequiresParseError> {
        let mut p = Parser::new(s);
        let expr = p.parse_or()?;
        p.skip_ws();
        if !p.at_end() {
            return Err(RequiresParseError(format!(
                "unexpected trailing input at position {}: {:?}",
                p.pos,
                &p.src[p.pos..]
            )));
        }
        Ok(expr)
    }
}

// ---------------------------------------------------------------------------
// Recursive-descent parser for RequiresExpr. Module-private.
// ---------------------------------------------------------------------------

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            src: s.as_bytes(),
            pos: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Consume a fixed keyword (alphabetic) iff it is present **and** the
    /// following byte is not an identifier continuation byte. Returns `true`
    /// on success without advancing on failure.
    fn consume_keyword(&mut self, kw: &str) -> bool {
        self.skip_ws();
        let kb = kw.as_bytes();
        if self.pos + kb.len() > self.src.len() {
            return false;
        }
        let slice = &self.src[self.pos..self.pos + kb.len()];
        if !slice.eq_ignore_ascii_case(kb) {
            return false;
        }
        // Boundary check: next char (if any) must not be ident-continuation.
        if let Some(&next) = self.src.get(self.pos + kb.len()) {
            if next.is_ascii_alphanumeric() || next == b'_' || next == b'-' {
                return false;
            }
        }
        self.pos += kb.len();
        true
    }

    fn parse_or(&mut self) -> Result<RequiresExpr, RequiresParseError> {
        let mut lhs = self.parse_and()?;
        loop {
            let save = self.pos;
            if self.consume_keyword("or") {
                let rhs = self.parse_and()?;
                lhs = RequiresExpr::Or(Box::new(lhs), Box::new(rhs));
            } else {
                self.pos = save;
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<RequiresExpr, RequiresParseError> {
        let mut lhs = self.parse_not()?;
        loop {
            let save = self.pos;
            if self.consume_keyword("and") {
                let rhs = self.parse_not()?;
                lhs = RequiresExpr::And(Box::new(lhs), Box::new(rhs));
            } else {
                self.pos = save;
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<RequiresExpr, RequiresParseError> {
        if self.consume_keyword("not") {
            let inner = self.parse_not()?;
            Ok(RequiresExpr::Not(Box::new(inner)))
        } else {
            self.parse_atom()
        }
    }

    fn parse_atom(&mut self) -> Result<RequiresExpr, RequiresParseError> {
        self.skip_ws();
        if self.consume_keyword("true") {
            return Ok(RequiresExpr::True);
        }
        if self.consume_keyword("false") {
            return Ok(RequiresExpr::False);
        }
        match self.peek() {
            Some(b'(') => {
                self.pos += 1;
                let inner = self.parse_or()?;
                self.skip_ws();
                if self.peek() != Some(b')') {
                    return Err(RequiresParseError(format!(
                        "expected ')' at position {}",
                        self.pos
                    )));
                }
                self.pos += 1;
                Ok(inner)
            }
            Some(c) if is_label_start(c) => Ok(RequiresExpr::Label(self.parse_label())),
            Some(c) => Err(RequiresParseError(format!(
                "unexpected byte {:?} at position {}",
                c as char, self.pos
            ))),
            None => Err(RequiresParseError(
                "unexpected end of input — expected label or '('".to_string(),
            )),
        }
    }

    fn parse_label(&mut self) -> String {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if is_label_continue(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        // Safe: `is_label_start` / `is_label_continue` only admit ASCII bytes.
        std::str::from_utf8(&self.src[start..self.pos])
            .unwrap()
            .to_string()
    }
}

fn is_label_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_label_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(s: &str) -> RequiresExpr {
        RequiresExpr::Label(s.to_string())
    }

    #[test]
    fn parse_single_label() {
        assert_eq!(RequiresExpr::parse("user-input").unwrap(), label("user-input"));
    }

    #[test]
    fn parse_and_or_not_precedence() {
        // `a or b and not c` -> `a or (b and (not c))`
        let e = RequiresExpr::parse("a or b and not c").unwrap();
        let expected = RequiresExpr::Or(
            Box::new(label("a")),
            Box::new(RequiresExpr::And(
                Box::new(label("b")),
                Box::new(RequiresExpr::Not(Box::new(label("c")))),
            )),
        );
        assert_eq!(e, expected);
    }

    #[test]
    fn parse_parens_override_precedence() {
        let e = RequiresExpr::parse("(a or b) and c").unwrap();
        let expected = RequiresExpr::And(
            Box::new(RequiresExpr::Or(Box::new(label("a")), Box::new(label("b")))),
            Box::new(label("c")),
        );
        assert_eq!(e, expected);
    }

    #[test]
    fn parse_true_false_literals() {
        assert_eq!(RequiresExpr::parse("true").unwrap(), RequiresExpr::True);
        assert_eq!(RequiresExpr::parse("false").unwrap(), RequiresExpr::False);
        // `truelabel` is a label, not `true` then `label`
        assert_eq!(
            RequiresExpr::parse("truelabel").unwrap(),
            label("truelabel")
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(RequiresExpr::parse("(a or b").is_err());
        assert!(RequiresExpr::parse("a or").is_err());
        assert!(RequiresExpr::parse("&& a").is_err());
    }

    #[test]
    fn eval_typical() {
        let e = RequiresExpr::parse("user-input and not admin-only").unwrap();
        let mut set = TaintLabelSet::new();
        set.insert("user-input".into());
        assert!(e.eval(&set));
        set.insert("admin-only".into());
        assert!(!e.eval(&set));
    }

    #[test]
    fn taint_state_join() {
        let a = TaintState::Tainted(TaintLabelSet::singleton("x"));
        let b = TaintState::Tainted(TaintLabelSet::singleton("y"));
        let c = a.join(&b);
        match c {
            TaintState::Tainted(s) => {
                assert!(s.contains("x"));
                assert!(s.contains("y"));
            }
            _ => panic!("expected tainted"),
        }
        let t = TaintState::Top.join(&a);
        assert!(matches!(t, TaintState::Top));
        let u = TaintState::Untainted.join(&a);
        match u {
            TaintState::Tainted(s) => assert!(s.contains("x")),
            _ => panic!("expected tainted"),
        }
    }
}
