//! Deck text to tokens. Newlines are tokens except inside `(` and `[`.

use super::parse::Diagnostic;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tok {
    Ident,
    /// The word after `rule`, `{name}` interpolation left in.
    RuleId,
    /// A number and its unit; the unit starts at `unit_at`.
    Num {
        unit_at: u32,
    },
    Str,
    /// One of `( ) [ ] { } , ; : = - . > < >= <= ==`.
    Punct,
    Newline,
    Eof,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Token {
    pub tok: Tok,
    pub start: u32,
    pub end: u32,
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.'
}

fn span(start: usize, end: usize) -> (u32, u32) {
    let narrow = |at: usize| u32::try_from(at).expect("a deck is under 4 GiB");
    (narrow(start), narrow(end))
}

/// Tokenise `source`, pushing a diagnostic per character it cannot read.
pub(crate) fn lex(source: &str, errors: &mut Vec<Diagnostic>) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut out: Vec<Token> = Vec::new();
    let mut depth = 0u32;
    let mut at = 0;
    let push = |out: &mut Vec<Token>, tok, start, end| {
        let (start, end) = span(start, end);
        out.push(Token { tok, start, end });
    };
    while at < bytes.len() {
        let c = bytes[at];
        let start = at;
        match c {
            b'#' => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'\n' => {
                at += 1;
                // One newline token per run: blank lines end nothing new.
                if depth == 0 && out.last().is_some_and(|t| t.tok != Tok::Newline) {
                    push(&mut out, Tok::Newline, start, at);
                }
            }
            b' ' | b'\t' | b'\r' => at += 1,
            b'"' => {
                at += 1;
                while at < bytes.len() && bytes[at] != b'"' && bytes[at] != b'\n' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                if at < bytes.len() && bytes[at] == b'"' {
                    at += 1;
                    push(&mut out, Tok::Str, start, at);
                } else {
                    errors.push(Diagnostic::new(start, at, "unterminated string"));
                }
            }
            _ if c.is_ascii_digit() => {
                at = number_end(bytes, at);
                let unit_at = at;
                if at < bytes.len() && (bytes[at].is_ascii_alphabetic() || bytes[at] == b'%') {
                    at += 1;
                    while at < bytes.len()
                        && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'/')
                    {
                        at += 1;
                    }
                }
                let unit_at = span(unit_at, unit_at).0;
                push(&mut out, Tok::Num { unit_at }, start, at);
            }
            _ if is_ident_start(c) => {
                while at < bytes.len() && is_ident(bytes[at]) {
                    at += 1;
                }
                push(&mut out, Tok::Ident, start, at);
                if &source[start..at] == "rule" {
                    // The id: everything up to the next blank.
                    while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
                        at += 1;
                    }
                    let id = at;
                    while at < bytes.len()
                        && (is_ident(bytes[at]) || matches!(bytes[at], b'{' | b'}'))
                    {
                        at += 1;
                    }
                    if at > id {
                        push(&mut out, Tok::RuleId, id, at);
                    }
                }
            }
            b'>' | b'<' | b'=' if bytes.get(at + 1) == Some(&b'=') => {
                at += 2;
                push(&mut out, Tok::Punct, start, at);
            }
            b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b';' | b':' | b'=' | b'-' | b'.'
            | b'>' | b'<' => {
                match c {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
                at += 1;
                push(&mut out, Tok::Punct, start, at);
            }
            _ => {
                let len = source[at..].chars().next().map_or(1, char::len_utf8);
                at += len;
                errors.push(Diagnostic::new(start, at, "unexpected character"));
            }
        }
    }
    let end = bytes.len();
    push(&mut out, Tok::Newline, end, end);
    push(&mut out, Tok::Eof, end, end);
    out
}

/// Digits, an optional fraction, and an exponent only when digits follow the
/// `e` (so `2eV` is two electron-volts).
fn number_end(bytes: &[u8], mut at: usize) -> usize {
    let digits = |at: &mut usize| {
        while *at < bytes.len() && bytes[*at].is_ascii_digit() {
            *at += 1;
        }
    };
    digits(&mut at);
    if bytes.get(at) == Some(&b'.') && bytes.get(at + 1).is_some_and(u8::is_ascii_digit) {
        at += 1;
        digits(&mut at);
    }
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        let sign = usize::from(matches!(bytes.get(at + 1), Some(b'+' | b'-')));
        if bytes.get(at + 1 + sign).is_some_and(u8::is_ascii_digit) {
            at += 1 + sign;
            digits(&mut at);
        }
    }
    at
}
