//! Parse + evaluate the small Python-like expression DSL used by
//! `metavariable-comparison`.
//!
//! Supported:
//! - Metavariable references: `$X` — substituted with the binding's source
//!   text (optionally numeric- or string-coerced).
//! - String / int / float / bool literals.
//! - Comparison ops: `==`, `!=`, `<`, `<=`, `>`, `>=`.
//! - Boolean ops: `and`, `or`, `not`, `&&`, `||`, `!`.
//! - Builtins: `lower(EXPR)`, `upper(EXPR)`, `len(EXPR)`, `int(EXPR)`,
//!   `str(EXPR)`.
//! - `base:` honoured when a metavariable holds a numeric literal in a non-
//!   decimal base (`base: 16` → `$N` is parsed as hex).
//! - `strip:` strips a single layer of surrounding quotes off a string-typed
//!   binding before substitution.

use crate::error::{Result, SemgrepError};
use crate::match_::MetavarBindings;

/// Parsed comparison expression.
#[derive(Debug, Clone, PartialEq)]
pub enum CompExpr {
    Lit(CompValue),
    /// `$X` — looked up in the bindings map at evaluation time.
    Var(String),
    /// `fn(arg)` — `lower` / `upper` / `len` / `int` / `str`.
    Call { name: String, arg: Box<CompExpr> },
    /// Binary comparison.
    Cmp {
        op: CompOp,
        lhs: Box<CompExpr>,
        rhs: Box<CompExpr>,
    },
    /// `and` / `or` / `not`.
    And(Box<CompExpr>, Box<CompExpr>),
    Or(Box<CompExpr>, Box<CompExpr>),
    Not(Box<CompExpr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum CompToken {
    Ident(String),
    Var(String),
    Int(i64),
    Float(f64),
    Str(String),
    LParen,
    RParen,
    Comma,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    Eof,
}

struct CompLex<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> CompLex<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos + off).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek(0) {
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn lex(mut self) -> Result<Vec<CompToken>> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let c = match self.peek(0) {
                Some(c) => c,
                None => break,
            };
            let tok = match c {
                b'(' => {
                    self.pos += 1;
                    CompToken::LParen
                }
                b')' => {
                    self.pos += 1;
                    CompToken::RParen
                }
                b',' => {
                    self.pos += 1;
                    CompToken::Comma
                }
                b'=' if self.peek(1) == Some(b'=') => {
                    self.pos += 2;
                    CompToken::Eq
                }
                b'!' if self.peek(1) == Some(b'=') => {
                    self.pos += 2;
                    CompToken::Ne
                }
                b'!' => {
                    self.pos += 1;
                    CompToken::Bang
                }
                b'<' if self.peek(1) == Some(b'=') => {
                    self.pos += 2;
                    CompToken::Le
                }
                b'<' => {
                    self.pos += 1;
                    CompToken::Lt
                }
                b'>' if self.peek(1) == Some(b'=') => {
                    self.pos += 2;
                    CompToken::Ge
                }
                b'>' => {
                    self.pos += 1;
                    CompToken::Gt
                }
                b'&' if self.peek(1) == Some(b'&') => {
                    self.pos += 2;
                    CompToken::AndAnd
                }
                b'|' if self.peek(1) == Some(b'|') => {
                    self.pos += 2;
                    CompToken::OrOr
                }
                b'$' => {
                    self.pos += 1;
                    let start = self.pos;
                    while let Some(b) = self.peek(0) {
                        if b.is_ascii_alphanumeric() || b == b'_' {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    let name = std::str::from_utf8(&self.src[start..self.pos])
                        .map_err(|e| SemgrepError::PatternParse(e.to_string()))?;
                    CompToken::Var(format!("${}", name))
                }
                b'\'' | b'"' => {
                    let quote = c;
                    self.pos += 1;
                    let start = self.pos;
                    while let Some(b) = self.peek(0) {
                        if b == quote {
                            break;
                        }
                        self.pos += 1;
                    }
                    let body = std::str::from_utf8(&self.src[start..self.pos])
                        .map_err(|e| SemgrepError::PatternParse(e.to_string()))?
                        .to_string();
                    if self.peek(0) != Some(quote) {
                        return Err(SemgrepError::PatternParse(
                            "unterminated string in comparison".into(),
                        ));
                    }
                    self.pos += 1;
                    CompToken::Str(body)
                }
                c if c.is_ascii_digit() => {
                    if c == b'0' && matches!(self.peek(1), Some(b'x') | Some(b'X')) {
                        self.pos += 2;
                        let body_start = self.pos;
                        while let Some(b) = self.peek(0) {
                            if b.is_ascii_hexdigit() {
                                self.pos += 1;
                            } else {
                                break;
                            }
                        }
                        let body = std::str::from_utf8(&self.src[body_start..self.pos])
                            .unwrap_or("");
                        let v = i64::from_str_radix(body, 16).map_err(|e| {
                            SemgrepError::PatternParse(format!(
                                "bad hex in comparison: {e}"
                            ))
                        })?;
                        out.push(CompToken::Int(v));
                        continue;
                    }
                    let start = self.pos;
                    let mut saw_dot = false;
                    while let Some(b) = self.peek(0) {
                        if b.is_ascii_digit() {
                            self.pos += 1;
                        } else if b == b'.'
                            && !saw_dot
                            && self.peek(1).map_or(false, |b| b.is_ascii_digit())
                        {
                            saw_dot = true;
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    let raw = std::str::from_utf8(&self.src[start..self.pos])
                        .map_err(|e| SemgrepError::PatternParse(e.to_string()))?;
                    if saw_dot {
                        CompToken::Float(raw.parse().map_err(
                            |e: std::num::ParseFloatError| {
                                SemgrepError::PatternParse(format!("{e}"))
                            },
                        )?)
                    } else {
                        CompToken::Int(raw.parse().map_err(
                            |e: std::num::ParseIntError| {
                                SemgrepError::PatternParse(format!("{e}"))
                            },
                        )?)
                    }
                }
                c if c.is_ascii_alphabetic() || c == b'_' => {
                    let start = self.pos;
                    while let Some(b) = self.peek(0) {
                        if b.is_ascii_alphanumeric() || b == b'_' {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    let s = std::str::from_utf8(&self.src[start..self.pos])
                        .map_err(|e| SemgrepError::PatternParse(e.to_string()))?
                        .to_string();
                    CompToken::Ident(s)
                }
                other => {
                    return Err(SemgrepError::PatternParse(format!(
                        "unrecognised character `{}` in comparison",
                        other as char
                    )));
                }
            };
            out.push(tok);
        }
        out.push(CompToken::Eof);
        Ok(out)
    }
}

struct CompParser {
    toks: Vec<CompToken>,
    pos: usize,
}

impl CompParser {
    fn peek(&self) -> &CompToken {
        self.toks.get(self.pos).unwrap_or(&CompToken::Eof)
    }
    fn bump(&mut self) -> CompToken {
        let t = self.toks.get(self.pos).cloned().unwrap_or(CompToken::Eof);
        self.pos += 1;
        t
    }
    fn eat(&mut self, t: &CompToken) -> bool {
        if self.peek() == t {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse(&mut self) -> Result<CompExpr> {
        let e = self.parse_or()?;
        if !matches!(self.peek(), CompToken::Eof) {
            return Err(SemgrepError::PatternParse(format!(
                "trailing junk in comparison: {:?}",
                self.peek()
            )));
        }
        Ok(e)
    }

    fn parse_or(&mut self) -> Result<CompExpr> {
        let mut lhs = self.parse_and()?;
        loop {
            let is_or = match self.peek() {
                CompToken::OrOr => true,
                CompToken::Ident(s) if s == "or" => true,
                _ => false,
            };
            if !is_or {
                break;
            }
            self.pos += 1;
            let rhs = self.parse_and()?;
            lhs = CompExpr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<CompExpr> {
        let mut lhs = self.parse_not()?;
        loop {
            let is_and = match self.peek() {
                CompToken::AndAnd => true,
                CompToken::Ident(s) if s == "and" => true,
                _ => false,
            };
            if !is_and {
                break;
            }
            self.pos += 1;
            let rhs = self.parse_not()?;
            lhs = CompExpr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<CompExpr> {
        let is_not = match self.peek() {
            CompToken::Bang => true,
            CompToken::Ident(s) if s == "not" => true,
            _ => false,
        };
        if is_not {
            self.pos += 1;
            let inner = self.parse_not()?;
            return Ok(CompExpr::Not(Box::new(inner)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<CompExpr> {
        let lhs = self.parse_primary()?;
        let op = match self.peek() {
            CompToken::Eq => CompOp::Eq,
            CompToken::Ne => CompOp::Ne,
            CompToken::Lt => CompOp::Lt,
            CompToken::Le => CompOp::Le,
            CompToken::Gt => CompOp::Gt,
            CompToken::Ge => CompOp::Ge,
            _ => return Ok(lhs),
        };
        self.pos += 1;
        let rhs = self.parse_primary()?;
        Ok(CompExpr::Cmp {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        })
    }

    fn parse_primary(&mut self) -> Result<CompExpr> {
        match self.bump() {
            CompToken::Int(v) => Ok(CompExpr::Lit(CompValue::Int(v))),
            CompToken::Float(f) => Ok(CompExpr::Lit(CompValue::Float(f))),
            CompToken::Str(s) => Ok(CompExpr::Lit(CompValue::Str(s))),
            CompToken::Var(name) => Ok(CompExpr::Var(name)),
            CompToken::Ident(s) => {
                if s == "true" {
                    return Ok(CompExpr::Lit(CompValue::Bool(true)));
                }
                if s == "false" {
                    return Ok(CompExpr::Lit(CompValue::Bool(false)));
                }
                if self.eat(&CompToken::LParen) {
                    let arg = self.parse_or()?;
                    if !self.eat(&CompToken::RParen) {
                        return Err(SemgrepError::PatternParse(
                            "expected `)` after function arg".into(),
                        ));
                    }
                    return Ok(CompExpr::Call {
                        name: s,
                        arg: Box::new(arg),
                    });
                }
                Err(SemgrepError::PatternParse(format!(
                    "bare identifier `{s}` in comparison"
                )))
            }
            CompToken::LParen => {
                let inner = self.parse_or()?;
                if !self.eat(&CompToken::RParen) {
                    return Err(SemgrepError::PatternParse(
                        "expected `)` in comparison".into(),
                    ));
                }
                Ok(inner)
            }
            other => Err(SemgrepError::PatternParse(format!(
                "unexpected token in comparison: {other:?}"
            ))),
        }
    }
}

/// Parse a comparison string into a [`CompExpr`].
pub fn parse(s: &str) -> Result<CompExpr> {
    let toks = CompLex::new(s).lex()?;
    let mut p = CompParser { toks, pos: 0 };
    p.parse()
}

/// Evaluate `expr` against `bindings`. `base` is honoured for numeric
/// coercion of metavariable bindings (`base: 16` → parse `$N` as hex).
/// `strip` strips a single layer of surrounding quotes off string-typed
/// metavar bindings before substitution.
pub fn evaluate(
    expr: &CompExpr,
    bindings: &MetavarBindings<'_>,
    base: Option<u32>,
    strip: bool,
) -> Result<bool> {
    let v = eval(expr, bindings, base, strip)?;
    Ok(value_truthy(&v))
}

fn eval(
    expr: &CompExpr,
    bindings: &MetavarBindings<'_>,
    base: Option<u32>,
    strip: bool,
) -> Result<CompValue> {
    match expr {
        CompExpr::Lit(v) => Ok(v.clone()),
        CompExpr::Var(name) => resolve_var(name, bindings, base, strip),
        CompExpr::Call { name, arg } => {
            let inner = eval(arg, bindings, base, strip)?;
            apply_builtin(name, inner)
        }
        CompExpr::Cmp { op, lhs, rhs } => {
            let l = eval(lhs, bindings, base, strip)?;
            let r = eval(rhs, bindings, base, strip)?;
            Ok(CompValue::Bool(cmp_apply(*op, &l, &r)))
        }
        CompExpr::And(l, r) => {
            let lv = eval(l, bindings, base, strip)?;
            if !value_truthy(&lv) {
                return Ok(CompValue::Bool(false));
            }
            Ok(CompValue::Bool(value_truthy(
                &eval(r, bindings, base, strip)?,
            )))
        }
        CompExpr::Or(l, r) => {
            let lv = eval(l, bindings, base, strip)?;
            if value_truthy(&lv) {
                return Ok(CompValue::Bool(true));
            }
            Ok(CompValue::Bool(value_truthy(
                &eval(r, bindings, base, strip)?,
            )))
        }
        CompExpr::Not(inner) => {
            let v = eval(inner, bindings, base, strip)?;
            Ok(CompValue::Bool(!value_truthy(&v)))
        }
    }
}

fn resolve_var(
    name: &str,
    bindings: &MetavarBindings<'_>,
    base: Option<u32>,
    strip: bool,
) -> Result<CompValue> {
    let node = bindings.get(name).ok_or_else(|| {
        SemgrepError::PatternParse(format!("metavariable {name} not bound"))
    })?;
    let raw = node.text();
    let stripped: String = if strip {
        let trimmed = raw.trim();
        if trimmed.len() >= 2 {
            let first = trimmed.chars().next().unwrap();
            let last = trimmed.chars().last().unwrap();
            if (first == '"' || first == '\'' || first == '`') && first == last {
                trimmed[1..trimmed.len() - 1].to_string()
            } else {
                raw.to_string()
            }
        } else {
            raw.to_string()
        }
    } else {
        raw.to_string()
    };

    // Attempt numeric coercion (honouring base).
    if let Some(b) = base {
        if let Ok(v) = i64::from_str_radix(stripped.trim(), b) {
            return Ok(CompValue::Int(v));
        }
    }
    // Default coercions: int, float, bool, then string.
    let s = stripped.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(v) = i64::from_str_radix(rest, 16) {
            return Ok(CompValue::Int(v));
        }
    }
    if let Ok(v) = s.parse::<i64>() {
        return Ok(CompValue::Int(v));
    }
    if let Ok(v) = s.parse::<f64>() {
        return Ok(CompValue::Float(v));
    }
    if s == "true" {
        return Ok(CompValue::Bool(true));
    }
    if s == "false" {
        return Ok(CompValue::Bool(false));
    }
    Ok(CompValue::Str(stripped))
}

fn apply_builtin(name: &str, v: CompValue) -> Result<CompValue> {
    match name {
        "lower" => Ok(CompValue::Str(value_to_string(&v).to_lowercase())),
        "upper" => Ok(CompValue::Str(value_to_string(&v).to_uppercase())),
        "len" => Ok(CompValue::Int(value_to_string(&v).chars().count() as i64)),
        "int" => match v {
            CompValue::Int(i) => Ok(CompValue::Int(i)),
            CompValue::Float(f) => Ok(CompValue::Int(f as i64)),
            CompValue::Str(s) => {
                let t = s.trim();
                if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    i64::from_str_radix(rest, 16)
                        .map(CompValue::Int)
                        .map_err(|e| SemgrepError::PatternParse(format!("int(): {e}")))
                } else {
                    t.parse::<i64>()
                        .map(CompValue::Int)
                        .map_err(|e| SemgrepError::PatternParse(format!("int(): {e}")))
                }
            }
            CompValue::Bool(b) => Ok(CompValue::Int(if b { 1 } else { 0 })),
        },
        "str" => Ok(CompValue::Str(value_to_string(&v))),
        other => Err(SemgrepError::PatternParse(format!(
            "unknown builtin: {other}"
        ))),
    }
}

fn value_to_string(v: &CompValue) -> String {
    match v {
        CompValue::Str(s) => s.clone(),
        CompValue::Int(i) => i.to_string(),
        CompValue::Float(f) => f.to_string(),
        CompValue::Bool(b) => b.to_string(),
    }
}

fn value_truthy(v: &CompValue) -> bool {
    match v {
        CompValue::Bool(b) => *b,
        CompValue::Int(i) => *i != 0,
        CompValue::Float(f) => *f != 0.0,
        CompValue::Str(s) => !s.is_empty(),
    }
}

fn cmp_apply(op: CompOp, l: &CompValue, r: &CompValue) -> bool {
    // Coerce numbers across Int/Float; everything else falls back to string
    // comparison (matching Semgrep's documented semantics for cross-type
    // compare: strings sort lexically, mixed types fall back to string).
    if let (Some(a), Some(b)) = (as_f64(l), as_f64(r)) {
        return match op {
            CompOp::Eq => (a - b).abs() < 1e-12,
            CompOp::Ne => (a - b).abs() >= 1e-12,
            CompOp::Lt => a < b,
            CompOp::Le => a <= b,
            CompOp::Gt => a > b,
            CompOp::Ge => a >= b,
        };
    }
    let a = value_to_string(l);
    let b = value_to_string(r);
    match op {
        CompOp::Eq => a == b,
        CompOp::Ne => a != b,
        CompOp::Lt => a < b,
        CompOp::Le => a <= b,
        CompOp::Gt => a > b,
        CompOp::Ge => a >= b,
    }
}

fn as_f64(v: &CompValue) -> Option<f64> {
    match v {
        CompValue::Int(i) => Some(*i as f64),
        CompValue::Float(f) => Some(*f),
        CompValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        CompValue::Str(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{CanonicalKind, Position, Range, SgNode};

    fn r(start: usize, end: usize) -> Range {
        Range::new(Position::new(1, start + 1, start), Position::new(1, end + 1, end))
    }

    fn make_bindings<'a>(name: &str, text: &'a str, off: usize, kind: CanonicalKind) -> MetavarBindings<'a> {
        let mut b = MetavarBindings::new();
        let n = SgNode {
            kind: "tok",
            canonical_kind: kind,
            range: r(off, off + text.len()),
            bytes: text.as_bytes(),
            children: Vec::new(),
            field_name: None,
        };
        b.try_bind(name, n).unwrap();
        b
    }

    #[test]
    fn parses_simple_int_comparison() {
        let e = parse("$N > 100").unwrap();
        assert!(matches!(e, CompExpr::Cmp { op: CompOp::Gt, .. }));
    }

    #[test]
    fn evaluates_int_compare_true() {
        let e = parse("$N > 100").unwrap();
        let b = make_bindings("$N", "200", 0, CanonicalKind::Number);
        assert!(evaluate(&e, &b, None, false).unwrap());
    }

    #[test]
    fn evaluates_int_compare_false() {
        let e = parse("$N > 100").unwrap();
        let b = make_bindings("$N", "50", 0, CanonicalKind::Number);
        assert!(!evaluate(&e, &b, None, false).unwrap());
    }

    #[test]
    fn lower_builtin_string_compare() {
        let e = parse("lower($X) == 'abc'").unwrap();
        let b = make_bindings("$X", "\"ABC\"", 0, CanonicalKind::String);
        assert!(evaluate(&e, &b, None, true).unwrap());
    }

    #[test]
    fn and_or_not() {
        let e = parse("$N > 0 and not $N > 100").unwrap();
        let b = make_bindings("$N", "50", 0, CanonicalKind::Number);
        assert!(evaluate(&e, &b, None, false).unwrap());
    }

    #[test]
    fn base_16_coercion() {
        // base:16 — `$N` is "ff" as hex → 255.
        let e = parse("$N == 255").unwrap();
        let b = make_bindings("$N", "ff", 0, CanonicalKind::Number);
        assert!(evaluate(&e, &b, Some(16), false).unwrap());
    }
}
