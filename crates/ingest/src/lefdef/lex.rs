//! The token stream LEF and DEF share: words split at white space, `(`,
//! `)` and `;` standing alone, `"…"` one token, `#` to the end of the line
//! a comment, as both files are written.

use super::{fault, LefDefError, Pt};

/// One token and the line it starts on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tok<'a> {
    pub text: &'a str,
    pub line: u32,
}

/// A cursor over one file's tokens.
pub(crate) struct Lexer<'a> {
    toks: Vec<Tok<'a>>,
    at: usize,
    file: &'static str,
}

impl<'a> Lexer<'a> {
    pub fn new(text: &'a str, file: &'static str) -> Self {
        let mut toks = Vec::new();
        let bytes = text.as_bytes();
        let (mut i, mut line) = (0, 1_u32);
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\n' {
                line += 1;
                i += 1;
            } else if b.is_ascii_whitespace() {
                i += 1;
            } else if b == b'#' {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            } else if b == b'"' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    line += u32::from(bytes[i] == b'\n');
                    i += 1;
                }
                i = (i + 1).min(bytes.len());
                toks.push(Tok {
                    text: &text[start..i],
                    line,
                });
            } else if matches!(b, b'(' | b')' | b';') {
                toks.push(Tok {
                    text: &text[i..=i],
                    line,
                });
                i += 1;
            } else {
                let start = i;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'(' | b')' | b';' | b'"')
                {
                    i += 1;
                }
                toks.push(Tok {
                    text: &text[start..i],
                    line,
                });
            }
        }
        Self { toks, at: 0, file }
    }

    pub fn line(&self) -> u32 {
        self.toks
            .get(self.at)
            .or(self.toks.last())
            .map_or(0, |t| t.line)
    }

    pub fn err(&self, message: impl Into<String>) -> LefDefError {
        fault(self.file, self.line(), message)
    }

    pub fn peek(&self) -> Option<&'a str> {
        self.toks.get(self.at).map(|t| t.text)
    }

    pub fn next(&mut self) -> Result<&'a str, LefDefError> {
        let tok = self
            .toks
            .get(self.at)
            .ok_or_else(|| self.err("the file ends inside a statement"))?;
        self.at += 1;
        Ok(tok.text)
    }

    /// Consumes `word` if it is next.
    pub fn eat(&mut self, word: &str) -> bool {
        let here = self.peek() == Some(word);
        self.at += usize::from(here);
        here
    }

    pub fn expect(&mut self, word: &str) -> Result<(), LefDefError> {
        let line = self.line();
        let got = self.next()?;
        if got == word {
            Ok(())
        } else {
            Err(fault(
                self.file,
                line,
                format!("expected {word}, found {got}"),
            ))
        }
    }

    /// Skips to just past the next `;`.
    pub fn skip_statement(&mut self) -> Result<(), LefDefError> {
        while self.next()? != ";" {}
        Ok(())
    }

    /// Skips to just past `END name`.
    pub fn skip_to_end(&mut self, name: &str) -> Result<(), LefDefError> {
        while !(self.next()? == "END" && self.eat(name)) {}
        Ok(())
    }

    /// An integer, as DEF writes its database units.
    pub fn int(&mut self) -> Result<i64, LefDefError> {
        let line = self.line();
        let text = self.next()?;
        text.parse::<i64>()
            .ok()
            .filter(|v| v.unsigned_abs() <= MAX_COORD)
            .ok_or_else(|| {
                fault(
                    self.file,
                    line,
                    format!("expected an integer within ±2^31, found {text}"),
                )
            })
    }

    /// A decimal in micrometres, converted exactly to `dbu` units per
    /// micrometre; a value between two units is refused.
    pub fn microns(&mut self, dbu: i64) -> Result<i64, LefDefError> {
        let line = self.line();
        let text = self.next()?;
        exact_units(text, dbu).ok_or_else(|| {
            fault(
                self.file,
                line,
                format!(
                    "{text} µm is not a whole number of database units at {dbu} per µm, \
                     or is past ±2^31 of them"
                ),
            )
        })
    }

    /// `( x y )`, with `*` taking the previous point's coordinate.
    pub fn point(&mut self, prev: Option<Pt>) -> Result<Pt, LefDefError> {
        self.expect("(")?;
        let x = self.coord(prev.map(|p| p.0))?;
        let y = self.coord(prev.map(|p| p.1))?;
        self.expect(")")?;
        Ok((x, y))
    }

    pub fn coord(&mut self, prev: Option<i64>) -> Result<i64, LefDefError> {
        if self.eat("*") {
            return prev.ok_or_else(|| self.err("* with no previous point"));
        }
        self.int()
    }
}

/// The largest coordinate magnitude: a GDSII `XY` is a 32-bit integer.
pub(crate) const MAX_COORD: u64 = i32::MAX as u64;

/// `text`, a decimal number of micrometres, in units of `1/dbu` µm, or
/// `None` when it is not a whole number of them or not a plain decimal.
pub(crate) fn exact_units(text: &str, dbu: i64) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (whole, frac) = digits.split_once('.').unwrap_or((digits, ""));
    if whole.is_empty() && frac.is_empty()
        || !whole
            .bytes()
            .chain(frac.bytes())
            .all(|b| b.is_ascii_digit())
        || whole.len() + frac.len() > 30
    {
        return None;
    }
    let mut mantissa: i128 = 0;
    for b in whole.bytes().chain(frac.bytes()) {
        mantissa = mantissa * 10 + i128::from(b - b'0');
    }
    let scale = 10_i128.checked_pow(u32::try_from(frac.len()).ok()?)?;
    let scaled = mantissa.checked_mul(i128::from(dbu))?;
    if scaled % scale != 0 {
        return None;
    }
    let value = i64::try_from(scaled / scale).ok()?;
    (value.unsigned_abs() <= MAX_COORD).then_some(if negative { -value } else { value })
}
