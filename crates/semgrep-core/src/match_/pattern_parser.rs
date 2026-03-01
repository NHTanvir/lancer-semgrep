//! Hand-rolled mini-parser for Semgrep pattern strings.
//!
//! See [`super::pattern_ast`] for the limitations.
//!
//! ## Grammar (informal)
//!
//! ```text
//! pattern   := stmts EOF
//! stmts     := stmt (";" | "\n")* stmts? | ε
//! stmt      := expr | "..."
//! expr      := assign
//! assign    := orexpr ("=" assign)?
//! orexpr    := andexpr ("||" andexpr)*
//! andexpr   := eqexpr ("&&" eqexpr)*
//! eqexpr    := cmpexpr (("==" | "!=") cmpexpr)*
//! cmpexpr   := addexpr (("<" | "<=" | ">" | ">=") addexpr)*
//! addexpr   := mulexpr (("+" | "-") mulexpr)*
//! mulexpr   := unary  (("*" | "/" | "%") unary)*
//! unary     := "!" unary | "-" unary | postfix
//! postfix   := primary (call | attr | index)*
//! call      := "(" arglist? ")"
//! attr      := "." ident
//! index     := "[" expr "]"
//! primary   := ident | metavar | string | int | float | bool | "..."
//!            | "(" expr ")" | "{" stmts "}"
//! arglist   := stmt ("," stmt)*
//! ```
//!
//! Keywords-as-identifiers (`if`, `return`, `else`, ...) are recognised
//! when they appear at statement position and followed by an expression /
//! block; they become [`PatternAst::Keyword`] nodes carrying their payload.

use crate::error::{Result, SemgrepError};
use crate::match_::pattern_ast::{AtomKind, LitKind, PatternAst};

/// Entry point: parse a `pattern:` string into a [`PatternAst`].
///
/// Single-expression patterns return that expression directly. Multi-
/// statement patterns return a [`PatternAst::Block`] wrapping the
/// statements.
pub fn parse_pattern(input: &str) -> Result<PatternAst> {
    let tokens = Lexer::new(input).lex()?;
    let mut parser = Parser::new(tokens);
    let ast = parser.parse_program()?;
    Ok(ast)
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Some tokens (`:`, `=>`, `&`, `|`) are recognised by
                    // the lexer for forward-compat but not yet consumed by
                    // the parser. Suppress the warning.
enum Token {
    Ident(String),
    Metavar(String),
    Ellipsis,
    Str(String),
    Int(i64),
    Float(f64),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Semi,
    Colon,
    Dot,
    Eq,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    AndAnd,
    OrOr,
    Bang,
    Amp,
    Pipe,
    Arrow,
    Newline,
    Eof,
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn lex(mut self) -> Result<Vec<Token>> {
        let mut out = Vec::new();
        while let Some(tok) = self.next_token()? {
            out.push(tok);
        }
        out.push(Token::Eof);
        Ok(out)
    }

    fn peek(&self, offset: usize) -> Option<u8> {
        self.src.get(self.pos + offset).copied()
    }

    fn skip_inline_ws(&mut self) {
        while let Some(c) = self.peek(0) {
            // Skip spaces and tabs but keep newlines (they are statement
            // separators).
            if c == b' ' || c == b'\t' || c == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn next_token(&mut self) -> Result<Option<Token>> {
        self.skip_inline_ws();
        let c = match self.peek(0) {
            Some(c) => c,
            None => return Ok(None),
        };

        // Newline as a statement separator.
        if c == b'\n' {
            self.pos += 1;
            return Ok(Some(Token::Newline));
        }

        // Comments — `# ...` and `// ...`.
        if c == b'#' {
            while let Some(b) = self.peek(0) {
                if b == b'\n' {
                    break;
                }
                self.pos += 1;
            }
            return self.next_token();
        }
        if c == b'/' && self.peek(1) == Some(b'/') {
            while let Some(b) = self.peek(0) {
                if b == b'\n' {
                    break;
                }
                self.pos += 1;
            }
            return self.next_token();
        }

        // Ellipsis.
        if c == b'.' && self.peek(1) == Some(b'.') && self.peek(2) == Some(b'.') {
            self.pos += 3;
            return Ok(Some(Token::Ellipsis));
        }

        // Single-char punctuation / operators.
        match c {
            b'(' => {
                self.pos += 1;
                return Ok(Some(Token::LParen));
            }
            b')' => {
                self.pos += 1;
                return Ok(Some(Token::RParen));
            }
            b'[' => {
                self.pos += 1;
                return Ok(Some(Token::LBracket));
            }
            b']' => {
                self.pos += 1;
                return Ok(Some(Token::RBracket));
            }
            b'{' => {
                self.pos += 1;
                return Ok(Some(Token::LBrace));
            }
            b'}' => {
                self.pos += 1;
                return Ok(Some(Token::RBrace));
            }
            b',' => {
                self.pos += 1;
                return Ok(Some(Token::Comma));
            }
            b';' => {
                self.pos += 1;
                return Ok(Some(Token::Semi));
            }
            b':' => {
                self.pos += 1;
                return Ok(Some(Token::Colon));
            }
            b'.' => {
                self.pos += 1;
                return Ok(Some(Token::Dot));
            }
            b'+' => {
                self.pos += 1;
                return Ok(Some(Token::Plus));
            }
            b'-' => {
                self.pos += 1;
                return Ok(Some(Token::Minus));
            }
            b'*' => {
                self.pos += 1;
                return Ok(Some(Token::Star));
            }
            b'%' => {
                self.pos += 1;
                return Ok(Some(Token::Percent));
            }
            b'/' => {
                self.pos += 1;
                return Ok(Some(Token::Slash));
            }
            _ => {}
        }

        // Multi-char operators / arrow.
        if c == b'=' {
            if self.peek(1) == Some(b'=') {
                self.pos += 2;
                return Ok(Some(Token::EqEq));
            }
            if self.peek(1) == Some(b'>') {
                self.pos += 2;
                return Ok(Some(Token::Arrow));
            }
            self.pos += 1;
            return Ok(Some(Token::Eq));
        }
        if c == b'!' {
            if self.peek(1) == Some(b'=') {
                self.pos += 2;
                return Ok(Some(Token::NotEq));
            }
            self.pos += 1;
            return Ok(Some(Token::Bang));
        }
        if c == b'<' {
            if self.peek(1) == Some(b'=') {
                self.pos += 2;
                return Ok(Some(Token::Le));
            }
            self.pos += 1;
            return Ok(Some(Token::Lt));
        }
        if c == b'>' {
            if self.peek(1) == Some(b'=') {
                self.pos += 2;
                return Ok(Some(Token::Ge));
            }
            self.pos += 1;
            return Ok(Some(Token::Gt));
        }
        if c == b'&' {
            if self.peek(1) == Some(b'&') {
                self.pos += 2;
                return Ok(Some(Token::AndAnd));
            }
            self.pos += 1;
            return Ok(Some(Token::Amp));
        }
        if c == b'|' {
            if self.peek(1) == Some(b'|') {
                self.pos += 2;
                return Ok(Some(Token::OrOr));
            }
            self.pos += 1;
            return Ok(Some(Token::Pipe));
        }

        // String literals.
        if c == b'"' || c == b'\'' {
            return self.lex_string(c).map(Some);
        }

        // Metavariable: `$IDENT`.
        if c == b'$' {
            self.pos += 1;
            let start = self.pos;
            while let Some(b) = self.peek(0) {
                if b.is_ascii_alphanumeric() || b == b'_' {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == start {
                return Err(SemgrepError::PatternParse(format!(
                    "stray `$` at byte {}",
                    start - 1
                )));
            }
            let name =
                std::str::from_utf8(&self.src[start..self.pos])
                    .map_err(|e| SemgrepError::PatternParse(e.to_string()))?
                    .to_string();
            return Ok(Some(Token::Metavar(format!("${}", name))));
        }

        // Numeric literal.
        if c.is_ascii_digit() {
            return self.lex_number().map(Some);
        }

        // Identifier / keyword.
        if c.is_ascii_alphabetic() || c == b'_' {
            return Ok(Some(self.lex_ident()));
        }

        Err(SemgrepError::PatternParse(format!(
            "unrecognised character `{}` at byte {}",
            c as char, self.pos
        )))
    }

    fn lex_string(&mut self, quote: u8) -> Result<Token> {
        self.pos += 1; // opening quote
        let mut buf = Vec::<u8>::new();
        loop {
            let c = match self.peek(0) {
                Some(c) => c,
                None => {
                    return Err(SemgrepError::PatternParse(
                        "unterminated string literal".into(),
                    ));
                }
            };
            if c == quote {
                self.pos += 1;
                break;
            }
            if c == b'\\' {
                self.pos += 1;
                let esc = self.peek(0).ok_or_else(|| {
                    SemgrepError::PatternParse("dangling backslash in string".into())
                })?;
                self.pos += 1;
                let real = match esc {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'\'' => b'\'',
                    b'0' => 0,
                    other => other,
                };
                buf.push(real);
                continue;
            }
            buf.push(c);
            self.pos += 1;
        }
        let s = String::from_utf8(buf)
            .map_err(|e| SemgrepError::PatternParse(e.to_string()))?;
        Ok(Token::Str(s))
    }

    fn lex_number(&mut self) -> Result<Token> {
        let start = self.pos;
        // Optional `0x` / `0o` / `0b` prefix.
        if self.peek(0) == Some(b'0') {
            let next = self.peek(1);
            if matches!(next, Some(b'x') | Some(b'X')) {
                self.pos += 2;
                let body_start = self.pos;
                while let Some(b) = self.peek(0) {
                    if b.is_ascii_hexdigit() || b == b'_' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                let body =
                    std::str::from_utf8(&self.src[body_start..self.pos]).unwrap_or("");
                let cleaned: String = body.chars().filter(|c| *c != '_').collect();
                let v = i64::from_str_radix(&cleaned, 16).map_err(|e| {
                    SemgrepError::PatternParse(format!("bad hex literal: {e}"))
                })?;
                return Ok(Token::Int(v));
            }
            if matches!(next, Some(b'b') | Some(b'B')) {
                self.pos += 2;
                let body_start = self.pos;
                while let Some(b) = self.peek(0) {
                    if b == b'0' || b == b'1' || b == b'_' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                let body =
                    std::str::from_utf8(&self.src[body_start..self.pos]).unwrap_or("");
                let cleaned: String = body.chars().filter(|c| *c != '_').collect();
                let v = i64::from_str_radix(&cleaned, 2).map_err(|e| {
                    SemgrepError::PatternParse(format!("bad bin literal: {e}"))
                })?;
                return Ok(Token::Int(v));
            }
            if matches!(next, Some(b'o') | Some(b'O')) {
                self.pos += 2;
                let body_start = self.pos;
                while let Some(b) = self.peek(0) {
                    if (b'0'..=b'7').contains(&b) || b == b'_' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                let body =
                    std::str::from_utf8(&self.src[body_start..self.pos]).unwrap_or("");
                let cleaned: String = body.chars().filter(|c| *c != '_').collect();
                let v = i64::from_str_radix(&cleaned, 8).map_err(|e| {
                    SemgrepError::PatternParse(format!("bad oct literal: {e}"))
                })?;
                return Ok(Token::Int(v));
            }
        }

        let mut saw_dot = false;
        while let Some(b) = self.peek(0) {
            if b.is_ascii_digit() || b == b'_' {
                self.pos += 1;
            } else if b == b'.' && !saw_dot && self.peek(1).map_or(false, |b| b.is_ascii_digit()) {
                saw_dot = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        let raw =
            std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        let cleaned: String = raw.chars().filter(|c| *c != '_').collect();
        if saw_dot {
            let f: f64 = cleaned.parse().map_err(|e: std::num::ParseFloatError| {
                SemgrepError::PatternParse(format!("bad float literal: {e}"))
            })?;
            Ok(Token::Float(f))
        } else {
            let v: i64 = cleaned.parse().map_err(|e: std::num::ParseIntError| {
                SemgrepError::PatternParse(format!("bad int literal: {e}"))
            })?;
            Ok(Token::Int(v))
        }
    }

    fn lex_ident(&mut self) -> Token {
        let start = self.pos;
        while let Some(b) = self.peek(0) {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s =
            std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("").to_string();
        Token::Ident(s)
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn bump(&mut self) -> Token {
        let t = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        t
    }

    fn eat(&mut self, t: &Token) -> bool {
        if self.peek() == t {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_separators(&mut self) {
        while matches!(self.peek(), Token::Newline | Token::Semi) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, t: &Token) -> Result<()> {
        if self.eat(t) {
            Ok(())
        } else {
            Err(SemgrepError::PatternParse(format!(
                "expected {:?}, found {:?}",
                t,
                self.peek()
            )))
        }
    }

    fn parse_program(&mut self) -> Result<PatternAst> {
        self.skip_separators();
        if matches!(self.peek(), Token::Eof) {
            return Err(SemgrepError::PatternParse("empty pattern".into()));
        }

        let first = self.parse_stmt()?;
        self.skip_separators();
        if matches!(self.peek(), Token::Eof) {
            return Ok(first);
        }

        // Multi-statement pattern → Block.
        let mut stmts = vec![first];
        while !matches!(self.peek(), Token::Eof) {
            stmts.push(self.parse_stmt()?);
            self.skip_separators();
        }
        Ok(PatternAst::Block { stmts })
    }

    fn parse_stmt(&mut self) -> Result<PatternAst> {
        self.skip_separators();
        // Bare ellipsis as a statement.
        if matches!(self.peek(), Token::Ellipsis) {
            self.pos += 1;
            return Ok(PatternAst::Ellipsis);
        }

        // Keyword statements: `return EXPR?`, `if COND { BODY }`, `else { ... }`.
        if let Token::Ident(name) = self.peek().clone() {
            if is_statement_keyword(&name) {
                self.pos += 1;
                return self.parse_keyword_payload(name);
            }
        }

        let expr = self.parse_expr()?;
        Ok(PatternAst::ExprStmt(Box::new(expr)))
    }

    fn parse_keyword_payload(&mut self, name: String) -> Result<PatternAst> {
        // Greedy: collect either a block (`{ ... }`) or up to a separator the
        // following sub-expressions.
        let mut args = Vec::new();
        loop {
            match self.peek() {
                Token::Eof | Token::Semi | Token::Newline | Token::RBrace => break,
                Token::LBrace => {
                    args.push(self.parse_block()?);
                }
                _ => {
                    let e = self.parse_expr()?;
                    args.push(e);
                    if matches!(self.peek(), Token::Comma) {
                        self.pos += 1;
                        continue;
                    }
                    break;
                }
            }
        }
        Ok(PatternAst::Keyword { name, args })
    }

    fn parse_block(&mut self) -> Result<PatternAst> {
        self.expect(&Token::LBrace)?;
        let mut stmts = Vec::new();
        self.skip_separators();
        while !matches!(self.peek(), Token::RBrace | Token::Eof) {
            stmts.push(self.parse_stmt()?);
            self.skip_separators();
        }
        self.expect(&Token::RBrace)?;
        Ok(PatternAst::Block { stmts })
    }

    // expr := assign
    fn parse_expr(&mut self) -> Result<PatternAst> {
        self.parse_assign()
    }

    fn parse_assign(&mut self) -> Result<PatternAst> {
        let lhs = self.parse_or()?;
        if matches!(self.peek(), Token::Eq) {
            self.pos += 1;
            let rhs = self.parse_assign()?;
            return Ok(PatternAst::Assign {
                target: Box::new(lhs),
                value: Box::new(rhs),
            });
        }
        Ok(lhs)
    }

    fn parse_or(&mut self) -> Result<PatternAst> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Token::OrOr) {
            self.pos += 1;
            let rhs = self.parse_and()?;
            lhs = PatternAst::BinOp {
                op: "||".into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<PatternAst> {
        let mut lhs = self.parse_eq()?;
        while matches!(self.peek(), Token::AndAnd) {
            self.pos += 1;
            let rhs = self.parse_eq()?;
            lhs = PatternAst::BinOp {
                op: "&&".into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_eq(&mut self) -> Result<PatternAst> {
        let mut lhs = self.parse_cmp()?;
        loop {
            let op = match self.peek() {
                Token::EqEq => "==",
                Token::NotEq => "!=",
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_cmp()?;
            lhs = PatternAst::BinOp {
                op: op.into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_cmp(&mut self) -> Result<PatternAst> {
        let mut lhs = self.parse_add()?;
        loop {
            let op = match self.peek() {
                Token::Lt => "<",
                Token::Le => "<=",
                Token::Gt => ">",
                Token::Ge => ">=",
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_add()?;
            lhs = PatternAst::BinOp {
                op: op.into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<PatternAst> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Token::Plus => "+",
                Token::Minus => "-",
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_mul()?;
            lhs = PatternAst::BinOp {
                op: op.into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<PatternAst> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => "*",
                Token::Slash => "/",
                Token::Percent => "%",
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_unary()?;
            lhs = PatternAst::BinOp {
                op: op.into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<PatternAst> {
        let op = match self.peek() {
            Token::Bang => Some("!"),
            Token::Minus => Some("-"),
            _ => None,
        };
        if let Some(op) = op {
            self.pos += 1;
            let operand = self.parse_unary()?;
            return Ok(PatternAst::UnaryOp {
                op: op.into(),
                operand: Box::new(operand),
            });
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<PatternAst> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Token::LParen => {
                    self.pos += 1;
                    let args = self.parse_arglist()?;
                    self.expect(&Token::RParen)?;
                    expr = PatternAst::Call {
                        callee: Box::new(expr),
                        args,
                    };
                }
                Token::Dot => {
                    self.pos += 1;
                    let attr = match self.bump() {
                        Token::Ident(s) => s,
                        Token::Metavar(s) => s,
                        other => {
                            return Err(SemgrepError::PatternParse(format!(
                                "expected identifier after `.`, found {other:?}"
                            )));
                        }
                    };
                    expr = PatternAst::Attr {
                        obj: Box::new(expr),
                        attr,
                    };
                }
                Token::LBracket => {
                    self.pos += 1;
                    let idx = self.parse_expr()?;
                    self.expect(&Token::RBracket)?;
                    expr = PatternAst::Index {
                        obj: Box::new(expr),
                        idx: Box::new(idx),
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_arglist(&mut self) -> Result<Vec<PatternAst>> {
        let mut out = Vec::new();
        // Allow empty.
        if matches!(self.peek(), Token::RParen) {
            return Ok(out);
        }
        loop {
            self.skip_separators();
            if matches!(self.peek(), Token::Ellipsis) {
                self.pos += 1;
                out.push(PatternAst::Ellipsis);
            } else {
                out.push(self.parse_expr()?);
            }
            self.skip_separators();
            if matches!(self.peek(), Token::Comma) {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(out)
    }

    fn parse_primary(&mut self) -> Result<PatternAst> {
        match self.peek().clone() {
            Token::Ident(s) => {
                self.pos += 1;
                // Literal bool / null check.
                match s.as_str() {
                    "true" => Ok(PatternAst::Lit(LitKind::Bool(true))),
                    "false" => Ok(PatternAst::Lit(LitKind::Bool(false))),
                    "null" | "nil" | "None" => Ok(PatternAst::Lit(LitKind::Null)),
                    _ => {
                        let kind = if is_keyword(&s) {
                            AtomKind::Keyword
                        } else {
                            AtomKind::Identifier
                        };
                        Ok(PatternAst::Atom { kind, text: s })
                    }
                }
            }
            Token::Metavar(name) => {
                self.pos += 1;
                Ok(PatternAst::Metavar { name })
            }
            Token::Ellipsis => {
                self.pos += 1;
                Ok(PatternAst::Ellipsis)
            }
            Token::Str(s) => {
                self.pos += 1;
                Ok(PatternAst::Lit(LitKind::Str(s)))
            }
            Token::Int(v) => {
                self.pos += 1;
                Ok(PatternAst::Lit(LitKind::Int(v)))
            }
            Token::Float(f) => {
                self.pos += 1;
                Ok(PatternAst::Lit(LitKind::Float(f)))
            }
            Token::LParen => {
                self.pos += 1;
                let inner = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            Token::LBrace => self.parse_block(),
            other => Err(SemgrepError::PatternParse(format!(
                "unexpected token {:?} while parsing primary",
                other
            ))),
        }
    }
}

/// Identifiers that, when at statement position, are parsed as keyword forms
/// carrying a payload.
fn is_statement_keyword(s: &str) -> bool {
    matches!(
        s,
        "return"
            | "if"
            | "else"
            | "elif"
            | "for"
            | "while"
            | "match"
            | "case"
            | "switch"
            | "yield"
            | "throw"
            | "raise"
            | "break"
            | "continue"
            | "try"
            | "catch"
            | "finally"
            | "do"
            | "import"
            | "from"
            | "use"
            | "require"
    )
}

/// Identifiers that should be tagged as keyword [`AtomKind::Keyword`] even
/// when they don't start a statement (e.g. inside expressions).
fn is_keyword(s: &str) -> bool {
    is_statement_keyword(s)
        || matches!(
            s,
            "def" | "fn" | "function" | "class" | "struct" | "enum" | "impl" | "let"
                | "const" | "var"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_identifier() {
        let ast = parse_pattern("foo").unwrap();
        assert!(matches!(ast, PatternAst::ExprStmt(_)));
        if let PatternAst::ExprStmt(inner) = ast {
            assert!(matches!(*inner, PatternAst::Atom { .. }));
        }
    }

    #[test]
    fn parses_metavar() {
        let ast = parse_pattern("$X").unwrap();
        if let PatternAst::ExprStmt(inner) = ast {
            assert!(matches!(*inner, PatternAst::Metavar { .. }));
        } else {
            panic!("expected ExprStmt");
        }
    }

    #[test]
    fn parses_call_with_metavar() {
        let ast = parse_pattern("foo($X)").unwrap();
        if let PatternAst::ExprStmt(inner) = ast {
            if let PatternAst::Call { callee, args } = *inner {
                assert!(matches!(*callee, PatternAst::Atom { .. }));
                assert_eq!(args.len(), 1);
                assert!(matches!(args[0], PatternAst::Metavar { .. }));
            } else {
                panic!("expected call");
            }
        }
    }

    #[test]
    fn parses_call_with_ellipsis() {
        let ast = parse_pattern("subprocess.call(...)").unwrap();
        if let PatternAst::ExprStmt(inner) = ast {
            if let PatternAst::Call { callee, args } = *inner {
                assert!(matches!(*callee, PatternAst::Attr { .. }));
                assert_eq!(args.len(), 1);
                assert!(args[0].is_ellipsis());
            }
        }
    }

    #[test]
    fn parses_assignment() {
        let ast = parse_pattern("$X = foo($Y)").unwrap();
        if let PatternAst::ExprStmt(inner) = ast {
            assert!(matches!(*inner, PatternAst::Assign { .. }));
        }
    }

    #[test]
    fn parses_string_literal() {
        let ast = parse_pattern("\"hello\"").unwrap();
        if let PatternAst::ExprStmt(inner) = ast {
            assert!(matches!(*inner, PatternAst::Lit(LitKind::Str(_))));
        }
    }

    #[test]
    fn parses_integer_literal() {
        let ast = parse_pattern("42").unwrap();
        if let PatternAst::ExprStmt(inner) = ast {
            assert!(matches!(*inner, PatternAst::Lit(LitKind::Int(42))));
        }
    }

    #[test]
    fn parses_block_of_statements() {
        let ast = parse_pattern("foo();\nbar()\n").unwrap();
        assert!(matches!(ast, PatternAst::Block { .. }));
    }

    #[test]
    fn rejects_empty() {
        let err = parse_pattern("   ").unwrap_err();
        assert!(matches!(err, SemgrepError::PatternParse(_)));
    }

    #[test]
    fn parses_keyword_return() {
        let ast = parse_pattern("return $X").unwrap();
        match ast {
            PatternAst::Keyword { name, args } => {
                assert_eq!(name, "return");
                assert_eq!(args.len(), 1);
            }
            other => panic!("expected Keyword, got {other:?}"),
        }
    }
}
