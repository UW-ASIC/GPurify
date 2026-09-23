//! Deck text to the parsed deck the lowering reads. `let` and `for` are
//! expanded here; every error carries a span, and parsing continues past one.

use super::kinds::{Cmp, Dim, Kind, Param, KINDS, PEX, UNITS};
use super::lex::{lex, Tok, Token};
use super::{
    build, Deck, DeckError, DeckSrc, DerivedOp, DerivedSrc, DeviceKind, DeviceSrc, LabelSrc,
    ParamSrc, ParamValue, RuleSrc, StackSrc, ViaSrc,
};
use gpurify_geom::{prefix::NANO, Dbu, DbuArea, Grid, Qty, StrTable};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Parsing stops after this many errors.
const MAX_ERRORS: usize = 50;

const OPS: [(&str, DerivedOp); 3] = [
    ("and", DerivedOp::And),
    ("or", DerivedOp::Or),
    ("not", DerivedOp::Not),
];

const DEVICES: [(&str, DeviceKind); 5] = [
    ("mos", DeviceKind::Mos),
    ("bjt", DeviceKind::Bjt),
    ("resistor", DeviceKind::Resistor),
    ("capacitor", DeviceKind::Capacitor),
    ("diode", DeviceKind::Diode),
];

/// One error, located in the deck text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub message: String,
    /// 1-based line and column (in characters).
    pub line: u32,
    pub col: u32,
    /// The source line, for the caret display.
    pub text: String,
    /// Byte span in the deck text.
    pub start: u32,
    pub end: u32,
}

impl Diagnostic {
    pub(crate) fn new(start: usize, end: usize, message: &str) -> Self {
        let narrow = |at: usize| u32::try_from(at).expect("a deck is under 4 GiB");
        Self {
            message: message.to_owned(),
            line: 0,
            col: 0,
            text: String::new(),
            start: narrow(start),
            end: narrow(end),
        }
    }

    /// Fill line, column and line text from the span.
    fn locate(&mut self, source: &str) {
        let start = self.start as usize;
        let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
        let line_end = source[start..]
            .find('\n')
            .map_or(source.len(), |at| start + at);
        let count = |text: &str| u32::try_from(text.chars().count()).unwrap_or(u32::MAX);
        self.line = count(&source[..line_start].replace(|c| c != '\n', "")) + 1;
        self.col = count(&source[line_start..start]) + 1;
        source[line_start..line_end]
            .trim_end_matches('\r')
            .clone_into(&mut self.text);
    }
}

/// `file:line:col: message`, the line, and a caret under the span.
pub(crate) fn render(file: &str, diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let width = (d.end.saturating_sub(d.start) as usize)
            .clamp(1, d.text.len().saturating_sub(d.col as usize - 1).max(1));
        let _ = writeln!(out, "{file}:{}:{}: {}", d.line, d.col, d.message);
        let _ = writeln!(out, "{}", d.text);
        let _ = writeln!(
            out,
            "{}{}",
            " ".repeat(d.col as usize - 1),
            "^".repeat(width)
        );
    }
    out.truncate(out.trim_end().len());
    out
}

/// Parse deck text and lower it to a [`Deck`]. Lengths are checked against the
/// deck's `grid` and converted against the layout's `grid` exactly.
pub fn parse_deck(source: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let mut errors = Vec::new();
    let toks = lex(source, &mut errors);
    let mut parser = Parser::new(source, toks, grid, errors);
    parser.statements(parser.toks.len() - 1);
    if !parser.errors.is_empty() {
        let mut diagnostics = parser.errors;
        diagnostics.truncate(MAX_ERRORS);
        for d in &mut diagnostics {
            d.locate(source);
        }
        return Err(DeckError::Invalid {
            file: "<deck>".to_owned(),
            diagnostics,
        });
    }
    build(&parser.out, strings)
}

/// A value as written, before a parameter gives it a dimension.
#[derive(Debug, Clone)]
enum Val {
    /// A number and its unit (empty when bare).
    Num {
        text: String,
        unit: String,
        neg: bool,
        span: (u32, u32),
    },
    /// A bare word: a layer, `none`, `true`, `false`, or a modifier.
    Word {
        name: String,
        span: (u32, u32),
    },
    /// A quoted string: a device model name.
    Str(String, (u32, u32)),
    List(Vec<Val>, (u32, u32)),
    Tuple(Vec<Val>, (u32, u32)),
    Group(Vec<Named>, (u32, u32)),
    Pair(Box<Val>, Box<Val>, (u32, u32)),
}

impl Val {
    fn span(&self) -> (u32, u32) {
        match self {
            Val::Num { span, .. }
            | Val::Word { span, .. }
            | Val::Str(_, span)
            | Val::List(_, span)
            | Val::Tuple(_, span)
            | Val::Group(_, span)
            | Val::Pair(_, _, span) => *span,
        }
    }

    /// The same value, reported at `span` (a variable's use, not its `let`).
    fn at(mut self, at: (u32, u32)) -> Self {
        match &mut self {
            Val::Num { span, .. }
            | Val::Word { span, .. }
            | Val::Str(_, span)
            | Val::List(_, span)
            | Val::Tuple(_, span)
            | Val::Group(_, span)
            | Val::Pair(_, _, span) => *span = at,
        }
        self
    }

    /// How the value reads in an error.
    fn shown(&self) -> String {
        match self {
            Val::Num {
                text, unit, neg, ..
            } => {
                let sign = if *neg { "-" } else { "" };
                if unit.is_empty() {
                    format!("{sign}{text} (no unit)")
                } else {
                    format!("{sign}{text}{unit}")
                }
            }
            Val::Word { name, .. } => format!("`{name}`"),
            Val::Str(text, _) => format!("\"{text}\""),
            Val::List(..) => "a list".to_owned(),
            Val::Tuple(..) => "a tuple".to_owned(),
            Val::Group(..) => "named arguments".to_owned(),
            Val::Pair(..) => "a pair".to_owned(),
        }
    }
}

/// `name: value`.
#[derive(Debug, Clone)]
struct Named {
    name: String,
    span: (u32, u32),
    value: Val,
}

/// An exact decimal, `m * 10^e`.
#[derive(Debug, Clone, Copy)]
struct Dec {
    m: i128,
    e: i32,
}

impl Dec {
    fn parse(text: &str, neg: bool) -> Option<Self> {
        let (body, exp) = match text.find(['e', 'E']) {
            Some(at) => (&text[..at], text[at + 1..].parse::<i32>().ok()?),
            None => (text, 0),
        };
        let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
        let digits: i128 = format!("{whole}{frac}").parse().ok()?;
        let frac_len = i32::try_from(frac.len()).ok()?;
        Some(Self {
            m: if neg { -digits } else { digits },
            e: exp.checked_sub(frac_len)?,
        })
    }

    fn shifted(self, shift: i32) -> Self {
        Self {
            m: self.m,
            e: self.e + shift,
        }
    }

    /// Correctly rounded, so the same decimal always gives the same `f64`.
    fn f64(self) -> f64 {
        format!("{}e{}", self.m, self.e)
            .parse()
            .expect("an integer and an exponent parse as f64")
    }

    /// `m` rescaled to exponent `e <= self.e`, if it fits.
    fn at(self, e: i32) -> Option<i128> {
        10i128
            .checked_pow(u32::try_from(self.e - e).ok()?)?
            .checked_mul(self.m)
    }

    fn is_multiple_of(self, of: Self) -> Option<bool> {
        let e = self.e.min(of.e);
        let of = of.at(e)?;
        Some(of != 0 && self.at(e)? % of == 0)
    }

    fn integer(self) -> Option<i128> {
        if self.e >= 0 {
            return self.at(0);
        }
        let div = 10i128.checked_pow(u32::try_from(-self.e).ok()?)?;
        (self.m % div == 0).then(|| self.m / div)
    }
}

/// Error already recorded; unwind to the statement.
struct Stop;
type R<T> = Result<T, Stop>;

struct Parser<'a> {
    src: &'a str,
    toks: Vec<Token>,
    pos: usize,
    errors: Vec<Diagnostic>,
    /// `let` and `for` bindings, innermost last.
    env: Vec<(String, Val)>,
    /// Layers declared so far.
    layers: HashSet<String>,
    /// Every `layer`/`let` name in the file and where it is declared, for
    /// reporting a use before its declaration.
    ahead: HashMap<String, u32>,
    rule_ids: HashSet<String>,
    /// The deck's grid in nanometres.
    deck_grid: Option<Dec>,
    layout: Grid,
    /// The rule being parsed, prefixed to its errors.
    context: String,
    touch: bool,
    out: DeckSrc,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str, toks: Vec<Token>, layout: Grid, errors: Vec<Diagnostic>) -> Self {
        let mut ahead = HashMap::new();
        for pair in toks.windows(2) {
            let word = &src[pair[0].start as usize..pair[0].end as usize];
            if pair[0].tok == Tok::Ident
                && (word == "layer" || word == "let")
                && pair[1].tok == Tok::Ident
            {
                let name = &src[pair[1].start as usize..pair[1].end as usize];
                ahead.entry(name.to_owned()).or_insert(pair[1].start);
            }
        }
        Self {
            src,
            toks,
            pos: 0,
            errors,
            env: Vec::new(),
            layers: HashSet::new(),
            ahead,
            rule_ids: HashSet::new(),
            deck_grid: None,
            layout,
            context: String::new(),
            touch: false,
            out: DeckSrc::default(),
        }
    }

    // ---- tokens ----

    fn peek(&self) -> Token {
        self.toks[self.pos]
    }

    fn peek_at(&self, ahead: usize) -> Token {
        self.toks[(self.pos + ahead).min(self.toks.len() - 1)]
    }

    fn text(&self, t: Token) -> &'a str {
        &self.src[t.start as usize..t.end as usize]
    }

    fn bump(&mut self) -> Token {
        let t = self.peek();
        if t.tok != Tok::Eof {
            self.pos += 1;
        }
        t
    }

    fn is(&self, text: &str) -> bool {
        let t = self.peek();
        matches!(t.tok, Tok::Punct | Tok::Ident) && self.text(t) == text
    }

    fn eat(&mut self, text: &str) -> bool {
        let hit = self.is(text);
        if hit {
            self.bump();
        }
        hit
    }

    fn expect(&mut self, text: &str) -> R<Token> {
        if self.is(text) {
            return Ok(self.bump());
        }
        let t = self.peek();
        Err(self.err_tok(t, &format!("expected `{text}`, found {}", self.found(t))))
    }

    fn found(&self, t: Token) -> String {
        match t.tok {
            Tok::Newline => "end of line".to_owned(),
            Tok::Eof => "end of file".to_owned(),
            _ => format!("`{}`", self.text(t)),
        }
    }

    fn ident(&mut self, what: &str) -> R<(String, (u32, u32))> {
        let t = self.peek();
        if t.tok == Tok::Ident {
            self.bump();
            return Ok((self.text(t).to_owned(), (t.start, t.end)));
        }
        Err(self.err_tok(t, &format!("expected {what}, found {}", self.found(t))))
    }

    // ---- errors ----

    fn err(&mut self, span: (u32, u32), message: &str) -> Stop {
        let message = if self.context.is_empty() {
            message.to_owned()
        } else {
            format!("{}: {message}", self.context)
        };
        let d = Diagnostic::new(span.0 as usize, span.1 as usize, &message);
        // A `for` body reports an error once, not once per element.
        if self.errors.len() < MAX_ERRORS && !self.errors.contains(&d) {
            self.errors.push(d);
        }
        Stop
    }

    fn err_tok(&mut self, t: Token, message: &str) -> Stop {
        self.err((t.start, t.end), message)
    }

    /// Skip to the end of the current statement.
    fn recover(&mut self) {
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            self.bump();
        }
    }

    // ---- statements ----

    /// Statements until token index `end`.
    fn statements(&mut self, end: usize) {
        while self.pos < end && self.errors.len() < MAX_ERRORS {
            if self.peek().tok == Tok::Newline {
                self.bump();
                continue;
            }
            self.context.clear();
            let done = self.statement();
            self.context.clear();
            let t = self.peek();
            match done {
                Ok(()) if matches!(t.tok, Tok::Newline | Tok::Eof) || self.pos == end => {}
                Ok(()) => {
                    let _ =
                        self.err_tok(t, &format!("expected end of line, found {}", self.found(t)));
                    self.recover();
                }
                Err(Stop) => self.recover(),
            }
        }
    }

    fn statement(&mut self) -> R<()> {
        let (word, span) = self.ident("a statement")?;
        match word.as_str() {
            "grid" => self.grid(span),
            "let" => self.let_(),
            "layer" => self.layer(),
            "rule" => self.rule(),
            "for" => self.for_(),
            "connect" => self.connect(),
            "device" => self.device(),
            "pex" => self.pex(),
            _ => Err(self.err(
                span,
                &format!("unknown statement `{word}`; expected grid, let, layer, rule, for, connect, device or pex"),
            )),
        }
    }

    fn grid(&mut self, span: (u32, u32)) -> R<()> {
        let value = self.value()?;
        if self.deck_grid.is_some() {
            return Err(self.err(span, "the grid is already stated"));
        }
        let nm = self.quantity(&value, Dim::Length, "grid")?;
        if nm.m <= 0 {
            return Err(self.err(value.span(), "the grid must be positive"));
        }
        self.deck_grid = Some(nm);
        Ok(())
    }

    fn let_(&mut self) -> R<()> {
        let (name, span) = self.ident("a name")?;
        self.expect("=")?;
        let value = self.value()?;
        self.bind(name, span, value)
    }

    /// Bind a name once; a name taken by a binding or a layer is an error.
    fn bind(&mut self, name: String, span: (u32, u32), value: Val) -> R<()> {
        if self.env.iter().any(|(bound, _)| *bound == name) || self.layers.contains(&name) {
            return Err(self.err(span, &format!("`{name}` is already bound")));
        }
        self.env.push((name, value));
        Ok(())
    }

    fn layer(&mut self) -> R<()> {
        let (name, span) = self.ident("a layer name")?;
        self.expect("=")?;
        if self.env.iter().any(|(bound, _)| *bound == name) || self.layers.contains(&name) {
            return Err(self.err(span, &format!("`{name}` is already bound")));
        }
        if self.is("gds") && self.peek_at(1).tok == Tok::Punct && self.text(self.peek_at(1)) == "("
        {
            self.bump();
            self.expect("(")?;
            let layer = self.gds_number()?;
            self.expect(",")?;
            let datatype = self.gds_number()?;
            self.expect(")")?;
            self.out.layers.push((name.clone(), (layer, datatype)));
        } else {
            let expr = self.layer_expr()?;
            match expr {
                LExpr::Layer(_) => {
                    return Err(self.err(span, "a derived layer needs an operator (and, or, not)"))
                }
                LExpr::Op(op, operands) | LExpr::Group(op, operands) => {
                    let mut count = 0;
                    let operands = self.lower_operands(&name, operands, &mut count);
                    self.out.derived.push(DerivedSrc {
                        name: name.clone(),
                        op,
                        layers: operands,
                    });
                }
            }
        }
        self.layers.insert(name);
        Ok(())
    }

    fn gds_number(&mut self) -> R<u16> {
        let t = self.peek();
        if let Tok::Num { unit_at } = t.tok {
            self.bump();
            if unit_at == t.end {
                if let Ok(n) = self.text(t).parse::<u16>() {
                    return Ok(n);
                }
            }
        }
        Err(self.err_tok(t, "expected a GDS number from 0 to 65535"))
    }

    /// `term { op term }`, same operators folding into one row.
    fn layer_expr(&mut self) -> R<LExpr> {
        let mut left = self.layer_term()?;
        while let Some(&(_, op)) = OPS.iter().find(|(word, _)| self.is(word)) {
            self.bump();
            let right = self.layer_term()?;
            left = match left {
                LExpr::Op(prev, mut operands) if prev == op => {
                    operands.push(right);
                    LExpr::Op(prev, operands)
                }
                other => LExpr::Op(op, vec![other, right]),
            };
        }
        Ok(left)
    }

    fn layer_term(&mut self) -> R<LExpr> {
        let term = if self.eat("(") {
            let inner = self.layer_expr()?;
            self.expect(")")?;
            // A parenthesised chain is its own row, never merged into the outer one.
            match inner {
                LExpr::Op(op, operands) => LExpr::Group(op, operands),
                other => other,
            }
        } else {
            let (word, span) = self.ident("a layer")?;
            // `met1.sized(..)` lexes as one word.
            if let Some((base, op)) = word.split_once('.') {
                let op_span = (span.0 + u32::try_from(base.len()).unwrap_or(0), span.1);
                return Err(self.reserved(op, op_span));
            }
            let value = self.resolve(word, span);
            LExpr::Layer(self.layer_name(&value)?)
        };
        if self.is(".") {
            let dot = self.bump();
            let t = self.peek();
            let op = self.text(t).to_owned();
            return Err(self.reserved(&op, (dot.start, t.end)));
        }
        Ok(term)
    }

    fn reserved(&mut self, op: &str, span: (u32, u32)) -> Stop {
        const RESERVED: [&str; 9] = [
            "sized",
            "interacting",
            "not_interacting",
            "inside",
            "outside",
            "holes",
            "extents",
            "with_area",
            "with_width",
        ];
        let op = op.split('.').next().unwrap_or(op);
        if RESERVED.contains(&op) {
            self.err(span, &format!("`.{op}` is not yet supported"))
        } else {
            self.err(span, &format!("unknown layer operation `.{op}`"))
        }
    }

    /// Operand names for a row; a nested chain becomes an intermediate derived
    /// layer named `name#k`, which no deck text can name.
    fn lower_operands(&mut self, name: &str, operands: Vec<LExpr>, count: &mut u32) -> Vec<String> {
        operands
            .into_iter()
            .map(|operand| match operand {
                LExpr::Layer(layer) => layer,
                LExpr::Op(op, inner) | LExpr::Group(op, inner) => {
                    let layers = self.lower_operands(name, inner, count);
                    *count += 1;
                    let hidden = format!("{name}#{count}");
                    self.out.derived.push(DerivedSrc {
                        name: hidden.clone(),
                        op,
                        layers,
                    });
                    hidden
                }
            })
            .collect()
    }

    fn for_(&mut self) -> R<()> {
        let header = self.for_header();
        if header.is_err() {
            // Skip the body: its names are unbound and would only add noise.
            while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) && !self.is("{") {
                self.bump();
            }
            if self.is("{") {
                let open = self.bump();
                let _ = self.block_end(open);
            }
        }
        let (pattern, items, open) = header?;
        let body = self.pos;
        let end = self.block_end(open)?;
        let close = end - 1;
        for item in items {
            let mark = self.env.len();
            let bound = if pattern.len() == 1 {
                let (name, span) = pattern[0].clone();
                self.bind(name, span, item)
            } else {
                match item {
                    Val::Tuple(parts, _) if parts.len() == pattern.len() => pattern
                        .clone()
                        .into_iter()
                        .zip(parts)
                        .try_for_each(|((name, span), part)| self.bind(name, span, part)),
                    other => Err(self.err(
                        other.span(),
                        &format!(
                            "expected a tuple of {}, got {}",
                            pattern.len(),
                            other.shown()
                        ),
                    )),
                }
            };
            if bound.is_ok() {
                self.pos = body;
                self.statements(close);
            }
            self.env.truncate(mark);
        }
        self.pos = end;
        Ok(())
    }

    /// The token index after the `}` matching `open`; leaves `pos` there.
    fn block_end(&mut self, open: Token) -> R<usize> {
        let mut depth = 1;
        let mut end = self.pos;
        while depth > 0 {
            let t = self.toks[end];
            match (t.tok, self.text(t)) {
                (Tok::Eof, _) => return Err(self.err_tok(open, "unclosed `{`")),
                (Tok::Punct, "{") => depth += 1,
                (Tok::Punct, "}") => depth -= 1,
                _ => {}
            }
            end += 1;
        }
        self.pos = end;
        Ok(end)
    }

    #[allow(clippy::type_complexity, reason = "one private call site")]
    fn for_header(&mut self) -> R<(Vec<(String, (u32, u32))>, Vec<Val>, Token)> {
        let mut pattern = Vec::new();
        if self.eat("(") {
            loop {
                pattern.push(self.ident("a loop variable")?);
                if !self.eat(",") {
                    break;
                }
            }
            self.expect(")")?;
        } else {
            pattern.push(self.ident("a loop variable")?);
        }
        self.expect("in")?;
        let list = self.value()?;
        let Val::List(items, _) = list else {
            return Err(self.err(
                list.span(),
                &format!("`for` needs a list, got {}", list.shown()),
            ));
        };
        let open = self.expect("{")?;
        Ok((pattern, items, open))
    }

    fn connect(&mut self) -> R<()> {
        let (what, span) = self.ident("conductors, touch_within_layer, via or label")?;
        match what.as_str() {
            "conductors" => {
                let layers = self.layer_list()?;
                self.out.connectivity.conductors.extend(layers);
            }
            "touch_within_layer" => {
                if std::mem::replace(&mut self.touch, true) {
                    return Err(self.err(span, "touch_within_layer is already stated"));
                }
                self.out.connectivity.intra_layer_touch = true;
            }
            "via" => {
                let layer = self.layer_word()?;
                let list_at = self.peek();
                let layers = self.layer_list()?;
                let [a, b] = <[String; 2]>::try_from(layers).map_err(|layers| {
                    self.err_tok(list_at, &format!("a via joins 2 layers, got {}", layers.len()))
                })?;
                self.out.connectivity.vias.push(ViaSrc {
                    layer,
                    connects: (a, b),
                });
            }
            "label" => {
                let layer = self.layer_word()?;
                self.expect("names")?;
                let names = self.layer_word()?;
                self.out.connectivity.labels.push(LabelSrc { layer, names });
            }
            _ => {
                return Err(self.err(
                    span,
                    &format!("unknown connect `{what}`; expected conductors, touch_within_layer, via or label"),
                ))
            }
        }
        Ok(())
    }

    fn device(&mut self) -> R<()> {
        let (kind, span) = self.ident("a device kind")?;
        let Some(&(_, kind)) = DEVICES.iter().find(|(word, _)| *word == kind) else {
            return Err(self.err(
                span,
                &format!(
                    "unknown device kind `{kind}`; expected mos, bjt, resistor, capacitor or diode"
                ),
            ));
        };
        let marker = self.layer_word()?;
        self.expect("model")?;
        let t = self.peek();
        if t.tok != Tok::Str {
            return Err(self.err_tok(
                t,
                &format!("expected a model name in quotes, found {}", self.found(t)),
            ));
        }
        self.bump();
        let model = self.string(t)?;
        self.expect("terminals")?;
        let terminals = self.layer_list()?;
        self.out.devices.push(DeviceSrc {
            kind,
            marker,
            model,
            terminals,
        });
        Ok(())
    }

    fn string(&mut self, t: Token) -> R<String> {
        let raw = &self.src[t.start as usize + 1..t.end as usize - 1];
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some(escaped @ ('"' | '\\')) => out.push(escaped),
                    _ => return Err(self.err_tok(t, "only \\\" and \\\\ escape in a string")),
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    }

    fn pex(&mut self) -> R<()> {
        let layer = self.layer_word()?;
        if self.out.pex.iter().any(|(name, _)| *name == layer) {
            return Err(self.err_tok(
                self.toks[self.pos - 1],
                &format!("`{layer}` already has a pex row"),
            ));
        }
        let mut row = [None::<f64>; PEX.len()];
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, span) = self.ident("a pex key")?;
            let Some(at) = PEX.iter().position(|&(name, _)| name == key) else {
                return Err(self.err(
                    span,
                    &format!("unknown pex key `{key}`; expected {}", pex_keys()),
                ));
            };
            let value = self.value()?;
            let dim = PEX[at].1;
            let number = self.quantity(&value, dim, &key)?.f64();
            if row[at].replace(number).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        let missing: Vec<&str> = PEX
            .iter()
            .zip(&row)
            .filter(|(_, v)| v.is_none())
            .map(|(&(name, _), _)| name)
            .collect();
        if !missing.is_empty() {
            let t = self.peek();
            return Err(self.err_tok(
                t,
                &format!("pex `{layer}` is missing {}", missing.join(", ")),
            ));
        }
        let [thickness_nm, height_nm, sheet_res_ohm_sq, dielectric_k, area_cap_af_um2, fringe_cap_af_um] =
            row.map(Option::unwrap_or_default);
        self.out.pex.push((
            layer,
            StackSrc {
                thickness_nm,
                height_nm,
                sheet_res_ohm_sq,
                area_cap_af_um2,
                fringe_cap_af_um,
                dielectric_k,
            },
        ));
        Ok(())
    }

    // ---- rules ----

    fn rule(&mut self) -> R<()> {
        let t = self.peek();
        if t.tok != Tok::RuleId {
            return Err(self.err_tok(t, "expected a rule id"));
        }
        self.bump();
        let id = self.rule_id(t)?;
        if !self.rule_ids.insert(id.clone()) {
            return Err(self.err_tok(t, &format!("duplicate rule id `{id}`")));
        }
        self.context.clone_from(&id);
        let warning = self.is("warning").then(|| self.bump());
        let (name, name_span) = self.ident("a check kind")?;
        self.expect("(")?;
        let (mut positional, mut named) = self.args(true)?;
        if self.eat("(") {
            named.extend(self.args(false)?.1);
        }
        let cmp = match self.peek() {
            t if t.tok == Tok::Punct && [">=", "<=", "=="].contains(&self.text(t)) => {
                self.bump();
                let cmp = match self.text(t) {
                    ">=" => Cmp::Ge,
                    "<=" => Cmp::Le,
                    _ => Cmp::Eq,
                };
                Some((cmp, (t.start, t.end), self.value()?))
            }
            _ => None,
        };
        let kind = self.pick(
            &name,
            name_span,
            &mut positional,
            cmp.as_ref().map(|c| (c.0, c.1)),
        )?;
        if let (Some(t), false) = (warning, kind.warns) {
            return Err(self.err_tok(
                t,
                &format!("`warning` is not legal on `{name}`: DRC rules are errors"),
            ));
        }

        let mut layers = Vec::with_capacity(positional.len());
        for &slot in kind.layers {
            layers.push(self.layer_name(&positional[usize::from(slot)])?);
        }
        if kind.more {
            for extra in &positional[kind.layers.len()..] {
                layers.push(self.layer_name(extra)?);
            }
        }

        let mut params = Vec::new();
        self.named(
            &named,
            kind.params,
            &format!("`{name}`"),
            (name_span.0, name_span.1),
            &mut params,
        )?;
        if let (Some(limit), Some((_, _, value))) = (kind.limit, &cmp) {
            self.param(
                value,
                Param {
                    name: kind.name,
                    ..limit
                },
                &mut params,
            )?;
        }
        params.extend(
            kind.fixed
                .iter()
                .map(|&(flag, on)| (flag, ParamSrc::Value(ParamValue::Flag(on)))),
        );
        if warning.is_some() {
            params.push(("warning", ParamSrc::Value(ParamValue::Flag(true))));
        }
        self.out.rules.push(RuleSrc {
            id,
            kind: kind.engine,
            layers,
            params,
        });
        Ok(())
    }

    /// The rule id with every `{name}` replaced by its binding.
    fn rule_id(&mut self, t: Token) -> R<String> {
        let raw = self.text(t);
        let mut out = String::new();
        let mut rest = raw;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let Some(close) = rest[open..].find('}') else {
                return Err(self.err_tok(t, "unclosed `{` in rule id"));
            };
            let name = &rest[open + 1..open + close];
            match self.env.iter().rev().find(|(bound, _)| bound == name) {
                Some((_, Val::Word { name, .. })) => out.push_str(name),
                Some((_, Val::Num { text, unit, .. })) => {
                    out.push_str(text);
                    out.push_str(unit);
                }
                _ => {
                    return Err(self.err_tok(
                        t,
                        &format!("`{{{name}}}` in the rule id is not a bound name or number"),
                    ))
                }
            }
            rest = &rest[open + close + 1..];
        }
        out.push_str(rest);
        if out.contains('}') {
            return Err(self.err_tok(t, "stray `}` in rule id"));
        }
        Ok(out)
    }

    /// Arguments up to `)`: positional layers then `name: value`, separated by
    /// `,` or `;`.
    fn args(&mut self, positional_ok: bool) -> R<(Vec<Val>, Vec<Named>)> {
        let mut positional = Vec::new();
        let mut named: Vec<Named> = Vec::new();
        loop {
            while self.eat(",") || self.eat(";") {}
            if self.eat(")") {
                return Ok((positional, named));
            }
            let t = self.peek();
            let next = self.peek_at(1);
            if t.tok == Tok::Ident && next.tok == Tok::Punct && self.text(next) == ":" {
                self.bump();
                self.bump();
                named.push(Named {
                    name: self.text(t).to_owned(),
                    span: (t.start, t.end),
                    value: self.value()?,
                });
            } else if !positional_ok || !named.is_empty() {
                return Err(self.err_tok(
                    t,
                    "expected `name: value` (layers come before named arguments)",
                ));
            } else {
                positional.push(self.value()?);
            }
            let t = self.peek();
            if !(self.is(",") || self.is(";") || self.is(")")) {
                return Err(
                    self.err_tok(t, &format!("expected `,` or `)`, found {}", self.found(t)))
                );
            }
        }
    }

    /// The table row for a kind name, its layer count, modifier and comparison.
    fn pick(
        &mut self,
        name: &str,
        span: (u32, u32),
        positional: &mut Vec<Val>,
        cmp: Option<(Cmp, (u32, u32))>,
    ) -> R<&'static Kind> {
        let rows: Vec<&'static Kind> = KINDS.iter().filter(|k| k.name == name).collect();
        if rows.is_empty() {
            return Err(self.err(span, &format!("unknown check kind `{name}`")));
        }
        // A trailing bare word the kind knows as a modifier (`opposite`).
        let modifier = match positional.last() {
            Some(Val::Word { name: word, .. })
                if rows.iter().any(|k| k.modifier == Some(word.as_str())) =>
            {
                let word = word.clone();
                positional.pop();
                Some(word)
            }
            _ => None,
        };
        let rows: Vec<_> = rows
            .into_iter()
            .filter(|k| k.modifier == modifier.as_deref())
            .collect();
        let n = positional.len();
        let fits = |k: &&Kind| n == k.layers.len() || (k.more && n > k.layers.len());
        let by_arity: Vec<_> = rows.iter().copied().filter(fits).collect();
        if by_arity.is_empty() {
            let mut arities: Vec<String> = rows
                .iter()
                .map(|k| format!("{}{}", k.layers.len(), if k.more { " or more" } else { "" }))
                .collect();
            arities.dedup();
            return Err(self.err(
                span,
                &format!("`{name}` takes {} layers, got {n}", arities.join(" or ")),
            ));
        }
        let given = cmp.map_or(Cmp::Absent, |c| c.0);
        if let Some(&kind) = by_arity.iter().find(|k| k.cmp == given) {
            return Ok(kind);
        }
        let legal: Vec<&str> = by_arity.iter().map(|k| cmp_text(k.cmp)).collect();
        Err(match cmp {
            None => self.err(
                span,
                &format!("`{name}` needs a comparison: {}", legal.join(" or ")),
            ),
            Some((_, at)) if legal == ["no comparison"] => self.err(
                at,
                &format!("`{name}` takes no comparison; its values are named arguments"),
            ),
            Some((c, at)) => self.err(
                at,
                &format!(
                    "{} is not legal on `{name}`; it takes {}",
                    cmp_text(c),
                    legal.join(" or ")
                ),
            ),
        })
    }

    /// Match named arguments to `params` by name: every one required, none unknown.
    fn named(
        &mut self,
        given: &[Named],
        params: &'static [Param],
        owner: &str,
        owner_span: (u32, u32),
        out: &mut Vec<(&'static str, ParamSrc)>,
    ) -> R<()> {
        let mut failed = false;
        for (at, arg) in given.iter().enumerate() {
            if given[..at].iter().any(|prev| prev.name == arg.name) {
                self.err(arg.span, &format!("`{}` is given twice", arg.name));
                failed = true;
            } else if !params.iter().any(|p| p.name == arg.name) {
                let expected: Vec<&str> = params.iter().map(|p| p.name).collect();
                let hint = if expected.is_empty() {
                    "it takes none".to_owned()
                } else {
                    format!("expected {}", expected.join(", "))
                };
                self.err(
                    arg.span,
                    &format!("unknown parameter `{}` for {owner}; {hint}", arg.name),
                );
                failed = true;
            }
        }
        for &param in params {
            if let Some(arg) = given.iter().find(|arg| arg.name == param.name) {
                failed |= self.param(&arg.value, param, out).is_err();
            } else {
                self.err(
                    owner_span,
                    &format!("{owner} is missing parameter `{}`", param.name),
                );
                failed = true;
            }
        }
        if failed {
            Err(Stop)
        } else {
            Ok(())
        }
    }

    /// Convert one value to its engine param(s).
    fn param(
        &mut self,
        value: &Val,
        param: Param,
        out: &mut Vec<(&'static str, ParamSrc)>,
    ) -> R<()> {
        let label = param.name;
        if matches!(value, Val::Word { name, .. } if name == "none") {
            if param.none {
                return Ok(());
            }
            return Err(self.err(value.span(), &format!("`{label}` cannot be none")));
        }
        let engine = param.engine;
        let converted = match param.dim {
            Dim::Length => ParamSrc::Value(ParamValue::Length(self.length(value, label)?)),
            Dim::Area => ParamSrc::Value(ParamValue::Area(self.area(value, label)?)),
            Dim::Count => ParamSrc::Value(ParamValue::Count(self.count(value, label)?)),
            Dim::Bool => match value {
                Val::Word { name, .. } if name == "true" || name == "false" => {
                    ParamSrc::Value(ParamValue::Flag(name == "true"))
                }
                other => return Err(self.wrong(other, "true or false", label)),
            },
            Dim::Layer => ParamSrc::Layer(self.layer_name(value)?),
            Dim::LengthPair(second) => {
                let Val::Pair(a, b, _) = value else {
                    return Err(self.wrong(value, "a pair `a x b` of lengths", label));
                };
                let a = self.length(a, label)?;
                let b = self.length(b, label)?;
                out.push((engine, ParamSrc::Value(ParamValue::Length(a))));
                out.push((second, ParamSrc::Value(ParamValue::Length(b))));
                return Ok(());
            }
            Dim::AngleList => {
                let Val::List(items, _) = value else {
                    return Err(self.wrong(value, "a list of angles", label));
                };
                if items.is_empty() {
                    return Err(
                        self.err(value.span(), &format!("`{label}` needs at least one angle"))
                    );
                }
                for item in items {
                    let degrees = self.quantity(item, Dim::Angle, label)?;
                    let Some(whole) = degrees.integer().and_then(|d| u32::try_from(d).ok()) else {
                        return Err(self.err(
                            item.span(),
                            "an angle is a whole, non-negative number of degrees",
                        ));
                    };
                    out.push((engine, ParamSrc::Value(ParamValue::Count(whole))));
                }
                return Ok(());
            }
            Dim::Models => {
                let Val::List(items, _) = value else {
                    return Err(self.wrong(value, "a list of model names", label));
                };
                if items.is_empty() {
                    return Err(self.err(
                        value.span(),
                        &format!("`{label}` needs at least one model; write none for no models"),
                    ));
                }
                for item in items {
                    let Val::Str(model, _) = item else {
                        return Err(self.wrong(item, "a model name in quotes", label));
                    };
                    out.push((engine, ParamSrc::Model(model.clone())));
                }
                return Ok(());
            }
            Dim::Group(inner) => {
                let Val::Group(named, span) = value else {
                    return Err(self.wrong(value, "named arguments `(name: value, ..)`", label));
                };
                return self.named(named, inner, &format!("`{label}`"), *span, out);
            }
            Dim::Fraction => {
                let v = self.quantity(value, Dim::Fraction, label)?.f64();
                if !(0.0..=1.0).contains(&v) {
                    return Err(self.err(
                        value.span(),
                        &format!("`{label}` is a fraction: 0 to 1, or 0% to 100%"),
                    ));
                }
                ParamSrc::Value(ParamValue::Ratio(v))
            }
            dim => ParamSrc::Value(ParamValue::Ratio(self.physical(value, dim, label)?)),
        };
        out.push((engine, converted));
        Ok(())
    }

    /// A physical quantity in its engine unit; temperatures accept `C`.
    fn physical(&mut self, value: &Val, dim: Dim, label: &str) -> R<f64> {
        if dim == Dim::Temperature {
            if let Val::Num {
                text,
                unit,
                neg,
                span,
            } = value
            {
                if unit == "C" {
                    let Some(d) = Dec::parse(text, *neg) else {
                        return Err(self.err(*span, "number too long"));
                    };
                    return Ok(d.f64() + 273.15);
                }
            }
        }
        Ok(self.quantity(value, dim, label)?.f64())
    }

    /// A value's number converted to `dim`'s engine unit, exactly.
    fn quantity(&mut self, value: &Val, dim: Dim, label: &str) -> R<Dec> {
        let Val::Num {
            text,
            unit,
            neg,
            span,
        } = value
        else {
            return Err(self.wrong(value, dim_name(dim), label));
        };
        let shift = if unit.is_empty() {
            if !matches!(dim, Dim::Scalar | Dim::Fraction | Dim::Count) {
                return Err(self.wrong(value, dim_name(dim), label));
            }
            0
        } else {
            match UNITS.iter().find(|(name, _, _)| name == unit) {
                Some(&(_, found, shift)) if found == dim => shift,
                Some(&(_, found, _)) => {
                    return Err(self.err(
                        *span,
                        &format!(
                            "{label} needs {}, got {}{unit} ({})",
                            dim_name(dim),
                            text,
                            dim_name(found)
                        ),
                    ))
                }
                None if unit == "C" => {
                    return Err(self.wrong(value, dim_name(dim), label));
                }
                None => return Err(self.err(*span, &format!("unknown unit `{unit}`"))),
            }
        };
        match Dec::parse(text, *neg) {
            Some(d) => Ok(d.shifted(shift)),
            None => Err(self.err(*span, "number too long")),
        }
    }

    fn wrong(&mut self, value: &Val, want: &str, label: &str) -> Stop {
        let forward = match value {
            Val::Word { name, span } => self.forward(name, span.0),
            _ => None,
        };
        let message =
            forward.unwrap_or_else(|| format!("{label} needs {want}, got {}", value.shown()));
        self.err(value.span(), &message)
    }

    /// "used before its declaration", when `name` is declared later in the file.
    fn forward(&self, name: &str, used: u32) -> Option<String> {
        let at = *self.ahead.get(name)?;
        if at < used {
            return None;
        }
        let line = self.src[..at as usize].matches('\n').count() + 1;
        Some(format!(
            "`{name}` is used before its declaration on line {line}"
        ))
    }

    /// A rule length: on the deck grid, then converted to the layout grid.
    fn length(&mut self, value: &Val, label: &str) -> R<Dbu> {
        let nm = self.quantity(value, Dim::Length, label)?;
        let grid = self
            .deck_grid
            .ok_or_else(|| self.err(value.span(), "no `grid` is stated before this length"))?;
        if nm.is_multiple_of(grid) != Some(true) {
            return Err(self.err(
                value.span(),
                &format!("{} is not a multiple of the grid", value.shown()),
            ));
        }
        self.layout
            .to_dbu(Qty::<gpurify_geom::Length, NANO>::new(nm.f64()))
            .map_err(|_| {
                self.err(
                    value.span(),
                    &format!("{} is not on the layout's grid", value.shown()),
                )
            })
    }

    /// An area: a multiple of the grid squared, converted to square layout units.
    fn area(&mut self, value: &Val, label: &str) -> R<DbuArea> {
        let nm2 = self.quantity(value, Dim::Area, label)?;
        let grid = self
            .deck_grid
            .ok_or_else(|| self.err(value.span(), "no `grid` is stated before this area"))?;
        let square = Dec {
            m: grid.m * grid.m,
            e: grid.e * 2,
        };
        if nm2.is_multiple_of(square) != Some(true) {
            return Err(self.err(
                value.span(),
                &format!("{} is not a multiple of the grid squared", value.shown()),
            ));
        }
        // nm2 * (dbu/um)^2 / 10^6 = square layout units.
        let per_um = i128::from(self.layout.dbu_per_um());
        let dbu2 = nm2
            .m
            .checked_mul(per_um * per_um)
            .and_then(|m| Dec { m, e: nm2.e - 6 }.integer());
        match dbu2 {
            Some(raw) => Ok(DbuArea::new(raw)),
            None => Err(self.err(
                value.span(),
                &format!("{} is not on the layout's grid", value.shown()),
            )),
        }
    }

    fn count(&mut self, value: &Val, label: &str) -> R<u32> {
        if let Val::Num {
            text,
            unit,
            neg: false,
            ..
        } = value
        {
            if unit.is_empty() {
                if let Ok(n) = text.parse::<u32>() {
                    return Ok(n);
                }
            }
        }
        Err(self.wrong(value, "a count (a whole number, no unit)", label))
    }

    // ---- values ----

    fn value(&mut self) -> R<Val> {
        let first = self.atom()?;
        if self.is("x") {
            self.bump();
            let second = self.atom()?;
            let span = (first.span().0, second.span().1);
            return Ok(Val::Pair(Box::new(first), Box::new(second), span));
        }
        Ok(first)
    }

    fn atom(&mut self) -> R<Val> {
        let t = self.peek();
        let neg = self.is("-");
        if neg {
            self.bump();
        }
        let n = self.peek();
        if let Tok::Num { unit_at } = n.tok {
            self.bump();
            return Ok(Val::Num {
                text: self.src[n.start as usize..unit_at as usize].to_owned(),
                unit: self.src[unit_at as usize..n.end as usize].to_owned(),
                neg,
                span: (t.start, n.end),
            });
        }
        if neg {
            return Err(self.err_tok(n, "expected a number after `-`"));
        }
        match t.tok {
            Tok::Ident => {
                self.bump();
                let name = self.text(t).to_owned();
                Ok(self.resolve(name, (t.start, t.end)))
            }
            Tok::Str => {
                self.bump();
                Ok(Val::Str(self.string(t)?, (t.start, t.end)))
            }
            Tok::Punct if self.text(t) == "[" => {
                self.bump();
                let items = self.items("]")?;
                Ok(Val::List(items, (t.start, self.toks[self.pos - 1].end)))
            }
            Tok::Punct if self.text(t) == "(" => {
                self.bump();
                let next = self.peek_at(1);
                if self.peek().tok == Tok::Ident && next.tok == Tok::Punct && self.text(next) == ":"
                {
                    let (_, named) = self.args(false)?;
                    return Ok(Val::Group(named, (t.start, self.toks[self.pos - 1].end)));
                }
                let items = self.items(")")?;
                Ok(Val::Tuple(items, (t.start, self.toks[self.pos - 1].end)))
            }
            _ => Err(self.err_tok(t, &format!("expected a value, found {}", self.found(t)))),
        }
    }

    fn items(&mut self, close: &str) -> R<Vec<Val>> {
        let mut items = Vec::new();
        loop {
            if self.eat(close) {
                return Ok(items);
            }
            items.push(self.value()?);
            if !self.eat(",") {
                self.expect(close)?;
                return Ok(items);
            }
        }
    }

    /// A word's binding, reported at its use; an unbound word stays a word.
    fn resolve(&self, name: String, span: (u32, u32)) -> Val {
        match self.env.iter().rev().find(|(bound, _)| *bound == name) {
            Some((_, value)) => value.clone().at(span),
            None => Val::Word { name, span },
        }
    }

    fn layer_word(&mut self) -> R<String> {
        let t = self.peek();
        if t.tok != Tok::Ident {
            return Err(self.err_tok(t, &format!("expected a layer, found {}", self.found(t))));
        }
        self.bump();
        let value = self.resolve(self.text(t).to_owned(), (t.start, t.end));
        self.layer_name(&value)
    }

    fn layer_list(&mut self) -> R<Vec<String>> {
        let value = self.value()?;
        let Val::List(items, _) = value else {
            return Err(self.err(
                value.span(),
                &format!("expected a list of layers, got {}", value.shown()),
            ));
        };
        items.iter().map(|item| self.layer_name(item)).collect()
    }

    /// A declared layer's name.
    fn layer_name(&mut self, value: &Val) -> R<String> {
        match value {
            Val::Word { name, .. } if self.layers.contains(name) => Ok(name.clone()),
            Val::Word { name, span } => {
                let message = self
                    .forward(name, span.0)
                    .unwrap_or_else(|| format!("unknown layer `{name}`"));
                Err(self.err(*span, &message))
            }
            other => Err(self.err(
                other.span(),
                &format!("expected a layer, got {}", other.shown()),
            )),
        }
    }
}

/// A layer expression before lowering.
enum LExpr {
    Layer(String),
    /// A left fold of one operator.
    Op(DerivedOp, Vec<LExpr>),
    /// A parenthesised fold, kept apart from the chain around it.
    Group(DerivedOp, Vec<LExpr>),
}

fn cmp_text(cmp: Cmp) -> &'static str {
    match cmp {
        Cmp::Absent => "no comparison",
        Cmp::Ge => "`>=`",
        Cmp::Le => "`<=`",
        Cmp::Eq => "`==`",
    }
}

fn pex_keys() -> String {
    PEX.iter()
        .map(|&(name, _)| name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn dim_name(dim: Dim) -> &'static str {
    match dim {
        Dim::Length => "a length",
        Dim::Area => "an area",
        Dim::Voltage => "a voltage",
        Dim::Current => "a current",
        Dim::CurrentPerWidth => "a current per width",
        Dim::Resistance => "a resistance",
        Dim::Temperature => "a temperature",
        Dim::Energy => "an energy",
        Dim::Time => "a time",
        Dim::CapPerArea => "a capacitance per area",
        Dim::CapPerLength => "a capacitance per length",
        Dim::Fraction => "a fraction",
        Dim::Angle => "an angle",
        Dim::Scalar => "a number",
        Dim::Count => "a count",
        Dim::Bool => "true or false",
        Dim::Layer => "a layer",
        Dim::LengthPair(_) => "a pair of lengths",
        Dim::AngleList => "a list of angles",
        Dim::Models => "a list of model names",
        Dim::Group(_) => "named arguments",
    }
}
