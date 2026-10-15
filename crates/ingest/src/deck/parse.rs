//! Deck text to the parsed deck the lowering reads. `let` and `for` are
//! expanded here; every error carries a span, and parsing continues past one.

use super::kinds::{Cmp, Dim, Kind, Param, EDGE_KINDS, KINDS, OPTIONAL_PEX_KEYS, PEX, UNITS};
use super::lex::{lex, Tok, Token};
use super::{
    lower, CornerSource, Deck, DeckError, DeckSource, DerivedOp, DerivedSource, DeviceKind,
    DeviceSource, DeviceValue, Extraction, ExtractionKind, LabelSource, LvsLimit, ParamSource,
    ParamValue, RuleSource, StackSource, ToleranceSrc, ViaSource, MAX_CELL_SELECTIONS,
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

const DEVICES: [(&str, DeviceKind); 6] = [
    ("mos", DeviceKind::Mos),
    ("bjt", DeviceKind::Bjt),
    ("resistor", DeviceKind::Resistor),
    ("capacitor", DeviceKind::Capacitor),
    ("diode", DeviceKind::Diode),
    ("inductor", DeviceKind::Inductor),
];

/// One error, located in the deck text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// What is wrong, prefixed with the rule id when inside a rule
    /// (`m1.5: enclosure needs a length, got 60 (no unit)`).
    pub message: String,
    /// 1-based line of `start`.
    pub line: u32,
    /// 1-based column of `start`, counted in characters, not bytes.
    pub col: u32,
    /// The source line, for the caret display.
    pub text: String,
    /// Byte offset of the offending text's start in the deck source.
    pub start: u32,
    /// Byte offset just past its end.
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

/// Parses deck text and lowers it to a [`Deck`], interning every name into
/// `strings`. `grid` is the layout's, from
/// [`Library::grid`](crate::layout::gds::Library::grid): every length must be a
/// multiple of the deck's own `grid` statement and convert to `grid` exactly.
/// The same text and the same table state give the same ids.
///
/// # Errors
///
/// [`DeckError::Invalid`] with every syntax, name, unit and grid error found
/// (a length off either grid, a parameter missing or misspelt, a layer used
/// before it is declared, an ignored pair also declared); then
/// [`DeckError::Malformed`] for the first contradiction between statements. On
/// error, `strings` may have gained names.
pub fn parse_deck(source: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError> {
    lower(&parse_source(source, grid)?, strings)
}

/// Parses deck text to its [`DeckSource`], every value converted onto the
/// layout grid `grid` and every name still a name: [`parse_deck`] without
/// the lowering, for a consumer that edits the deck before it is lowered.
///
/// # Errors
///
/// [`DeckError::Invalid`], as [`parse_deck`] gives it.
pub fn parse_source(source: &str, grid: Grid) -> Result<DeckSource, DeckError> {
    let mut errors = Vec::new();
    let toks = lex(source, &mut errors);
    let mut parser = Parser::new(source, toks, grid, errors);
    parser.statements(parser.toks.len() - 1);
    parser.check_ignored();
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
    Ok(parser.out)
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
    /// Layers declared so far, and which of them are edge layers.
    layers: HashSet<String>,
    edge_layers: HashSet<String>,
    /// Every `layer`/`let` name in the file and where it is declared, for
    /// reporting a use before its declaration.
    ahead: HashMap<String, u32>,
    rule_ids: HashSet<String>,
    /// The deck's grid in nanometres.
    deck_grid: Option<Dec>,
    layout: Grid,
    /// The rule being parsed, prefixed to its errors.
    context: String,
    /// Layer expressions lowered so far among the current rule's arguments.
    inline: u32,
    touch: bool,
    /// Each `ignore gds(L, D)` pair, and where it was written.
    ignored_at: Vec<((u16, u16), (u32, u32))>,
    /// `.in_cells` and `.not_in_cells` parsed so far, held to [`MAX_CELL_SELECTIONS`].
    cell_selections: usize,
    out: DeckSource,
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
            edge_layers: HashSet::new(),
            ahead,
            rule_ids: HashSet::new(),
            deck_grid: None,
            layout,
            context: String::new(),
            inline: 0,
            touch: false,
            ignored_at: Vec::new(),
            cell_selections: 0,
            out: DeckSource::default(),
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
            "if" => self.if_(),
            "connect" => self.connect(),
            "device" => self.device(),
            "pex" => self.pex(),
            "pex_fill" => self.pex_fill(),
            "pex_device" => self.pex_device(),
            "pex_tsv" => self.pex_tsv(),
            "temperature" => self.temperature(span),
            "extraction" => self.extraction(span),
            "corner" => self.corner(),
            "stage" => self.stage(span),
            "waive" => self.waive(),
            "ignore" => self.ignore(),
            "lvs" => self.lvs(),
            "fill" => self.fill(),
            "widen" => self.widen(),
            _ => Err(self.err(
                span,
                &format!("unknown statement `{word}`; expected grid, let, layer, ignore, rule, for, if, connect, device, pex, pex_fill, pex_device, pex_tsv, temperature, lvs, extraction, corner, stage, waive, fill or widen"),
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
            let pair = self.gds_pair()?;
            self.out.layers.push((name.clone(), pair));
        } else {
            let expr = self.layer_expr()?;
            if self.edges_of(&expr) {
                self.edge_layers.insert(name.clone());
            }
            match expr {
                LExpr::Layer(_) => {
                    return Err(self.err(
                        span,
                        "a derived layer needs an operator (and, or, not) or an operation (`.sized(..)`)",
                    ))
                }
                LExpr::Op(op, operands) | LExpr::Group(op, operands) | LExpr::Call(op, operands) => {
                    let mut count = 0;
                    let operands = self.lower_operands(&name, operands, &mut count);
                    self.out.derived.push(DerivedSource {
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

    /// `ignore gds(L, D)`: geometry on this stream pair is dropped, not refused.
    fn ignore(&mut self) -> R<()> {
        let (word, span) = self.ident("`gds`")?;
        if word != "gds" {
            return Err(self.err(
                span,
                &format!("expected `gds(layer, datatype)`, found `{word}`"),
            ));
        }
        let pair = self.gds_pair()?;
        let at = (span.0, self.toks[self.pos.saturating_sub(1)].end);
        if self.ignored_at.iter().any(|&(seen, _)| seen == pair) {
            return Err(self.err(
                at,
                &format!("gds({}, {}) is already ignored", pair.0, pair.1),
            ));
        }
        self.ignored_at.push((pair, at));
        self.out.ignored.push(pair);
        Ok(())
    }

    /// An ignored pair that is also a declared layer contradicts itself. Run
    /// once every statement is read, because a layer may be declared later.
    fn check_ignored(&mut self) {
        let clashes: Vec<_> = self
            .ignored_at
            .iter()
            .filter_map(|&(pair, at)| {
                let (name, _) = self.out.layers.iter().find(|(_, stream)| *stream == pair)?;
                Some((
                    at,
                    format!(
                        "gds({}, {}) is ignored, but layer `{name}` is declared on it",
                        pair.0, pair.1
                    ),
                ))
            })
            .collect();
        for (at, message) in clashes {
            let _ = self.err(at, &message);
        }
    }

    /// `(layer, datatype)` after the word `gds`.
    fn gds_pair(&mut self) -> R<(u16, u16)> {
        self.expect("(")?;
        let layer = self.gds_number()?;
        self.expect(",")?;
        let datatype = self.gds_number()?;
        self.expect(")")?;
        Ok((layer, datatype))
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
            let at = self.bump();
            let right = self.layer_term()?;
            if self.edges_of(&left) != self.edges_of(&right) {
                return Err(self.err_tok(at, "cannot combine an edge layer with a polygon layer"));
            }
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
        let mut method = None;
        let mut term = if self.eat("(") {
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
            let base = match word.split_once('.') {
                Some((base, op)) => {
                    let at = span.0 + u32::try_from(base.len()).unwrap_or(0);
                    method = Some((op.to_owned(), (at, span.1)));
                    base.to_owned()
                }
                None => word,
            };
            let end = span.0 + u32::try_from(base.len()).unwrap_or(0);
            let value = self.resolve(base, (span.0, end));
            LExpr::Layer(self.any_layer_name(&value)?)
        };
        loop {
            let (op, span) = match method.take() {
                Some(pending) => pending,
                None if self.is(".") => {
                    let dot = self.bump();
                    let t = self.peek();
                    if t.tok != Tok::Ident {
                        return Err(self.err_tok(t, "expected a layer operation after `.`"));
                    }
                    self.bump();
                    (self.text(t).to_owned(), (dot.start, t.end))
                }
                None => return Ok(term),
            };
            term = self.call(term, &op, span)?;
        }
    }

    /// One `.op(..)` applied to `receiver`.
    fn call(&mut self, receiver: LExpr, op: &str, span: (u32, u32)) -> R<LExpr> {
        let edges = self.edges_of(&receiver);
        // Which receiver the op takes: `Some(true)` edges, `Some(false)` polygons, `None` either.
        let (derived, takes_edges, argument) = match op {
            "sized" => {
                self.expect("(")?;
                let value = self.value()?;
                let dx = self.length(&value, "sized")?;
                let dy = if self.eat(",") {
                    let second = self.value()?;
                    let dy = self.length(&second, "sized")?;
                    if dx.raw().signum() * dy.raw().signum() < 0 {
                        return Err(self.err(
                            second.span(),
                            "`sized(dx, dy)` grows or shrinks both axes; chain two `sized` for one of each",
                        ));
                    }
                    dy
                } else {
                    dx
                };
                self.expect(")")?;
                (DerivedOp::Sized(dx, dy), Some(false), None)
            }
            "interacting" | "not_interacting" | "inside" | "outside" | "inside_part"
            | "outside_part" | "overlapping" | "not_overlapping" | "covering" | "not_covering" => {
                self.expect("(")?;
                let at = self.peek();
                let other = self.layer_expr()?;
                self.expect(")")?;
                if self.edges_of(&other) {
                    return Err(self.err_tok(at, &format!("`.{op}` takes a polygon layer")));
                }
                let (derived, takes) = match op {
                    "interacting" => (DerivedOp::Interacting(true), None),
                    "not_interacting" => (DerivedOp::Interacting(false), None),
                    "inside" => (DerivedOp::Inside, Some(false)),
                    "outside" | "not_overlapping" => (DerivedOp::Outside, Some(false)),
                    "overlapping" => (DerivedOp::Overlapping, Some(false)),
                    "covering" => (DerivedOp::Covering(true), Some(false)),
                    "not_covering" => (DerivedOp::Covering(false), Some(false)),
                    "inside_part" => (DerivedOp::Part(true), Some(true)),
                    _ => (DerivedOp::Part(false), Some(true)),
                };
                (derived, takes, Some(other))
            }
            "extended" => {
                let open = self.expect("(")?;
                let mut by = [Dbu::new_unchecked(0); 4];
                for (at, name) in ["begin", "end", "out", "in"].into_iter().enumerate() {
                    if at > 0 {
                        self.expect(",")?;
                    }
                    let t = self.peek();
                    let (word, _) = self.ident(&format!("`{name}:`"))?;
                    if word != name {
                        return Err(self.err_tok(
                            t,
                            "`extended` takes `begin:`, `end:`, `out:` and `in:`, in that order",
                        ));
                    }
                    self.expect(":")?;
                    let value = self.value()?;
                    by[at] = self.length(&value, "extended")?;
                    if by[at].raw() < 0 {
                        return Err(self.err(value.span(), "`extended` takes lengths of 0 or more"));
                    }
                }
                let close = self.expect(")")?;
                if by[2].raw() == 0 && by[3].raw() == 0 {
                    return Err(self.err(
                        (open.start, close.end),
                        "`extended` needs `out` or `in` above 0: a box needs a width",
                    ));
                }
                let derived = DerivedOp::Extended {
                    begin: by[0],
                    end: by[1],
                    outside: by[2],
                    inside: by[3],
                };
                (derived, Some(true), None)
            }
            "holes" | "extents" | "edges" => {
                self.expect("(")?;
                self.expect(")")?;
                let derived = match op {
                    "holes" => DerivedOp::Holes,
                    "extents" => DerivedOp::Extents,
                    _ => DerivedOp::Edges,
                };
                (derived, Some(false), None)
            }
            "rectangles" | "non_rectangles" | "squares" | "non_squares" => {
                self.expect("(")?;
                self.expect(")")?;
                let derived = DerivedOp::Rectangles {
                    square: op.ends_with("squares"),
                    keep: !op.starts_with("non_"),
                };
                (derived, Some(false), None)
            }
            "with_bbox_max" | "with_bbox_min" => {
                let (lo, hi) = self.bounds(op, Dim::Length, false)?;
                let derived = DerivedOp::WithBbox {
                    longer: op == "with_bbox_max",
                    lo,
                    hi,
                };
                (derived, Some(false), None)
            }
            "with_rect" | "without_rect" => {
                self.expect("(")?;
                let value = self.value()?;
                let Val::Pair(first, second, _) = &value else {
                    return Err(self.wrong(&value, "a box `w x h`", op));
                };
                let (w, h) = (self.length(first, op)?, self.length(second, op)?);
                if w.raw() <= 0 || h.raw() <= 0 {
                    return Err(self.err(
                        value.span(),
                        &format!("`.{op}` takes a box with positive sides"),
                    ));
                }
                self.expect(")")?;
                let keep = op == "with_rect";
                (DerivedOp::WithRect { keep, w, h }, Some(false), None)
            }
            "with_area" => {
                let (lo, hi) = self.bounds(op, Dim::Area, false)?;
                (DerivedOp::WithArea(lo, hi), Some(false), None)
            }
            "with_width" => {
                let (lo, hi) = self.bounds(op, Dim::Length, true)?;
                (DerivedOp::WithWidth(lo, hi), Some(false), None)
            }
            "with_length" => {
                let (lo, hi) = self.bounds(op, Dim::Length, false)?;
                (DerivedOp::WithLength(lo, hi), Some(true), None)
            }
            "horizontal" | "vertical" => {
                self.expect("(")?;
                self.expect(")")?;
                (DerivedOp::Oriented(op == "vertical"), Some(true), None)
            }
            "texts_outside" => {
                let drawn = matches!(&receiver, LExpr::Layer(name)
                    if self.out.layers.iter().any(|(drawn, _)| drawn == name));
                if !drawn {
                    return Err(self.err(
                        span,
                        "`.texts_outside` reads the texts drawn on a `gds(..)` layer; apply it to one",
                    ));
                }
                self.expect("(")?;
                let at = self.peek();
                let other = self.layer_expr()?;
                self.expect(")")?;
                if self.edges_of(&other) {
                    return Err(self.err_tok(at, "`.texts_outside` takes a polygon layer"));
                }
                (DerivedOp::TextsOutside, Some(false), Some(other))
            }
            "with_text" | "without_text" => {
                self.expect("(")?;
                let at = self.peek();
                let texts = self.layer_word()?;
                if !self.out.layers.iter().any(|(name, _)| *name == texts) {
                    return Err(self.err_tok(
                        at,
                        &format!("`{texts}` is derived; text is drawn on a GDS layer"),
                    ));
                }
                self.expect(",")?;
                let t = self.peek();
                if t.tok != Tok::Str {
                    return Err(self.err_tok(
                        t,
                        &format!("expected a text pattern in quotes, found {}", self.found(t)),
                    ));
                }
                self.bump();
                let pattern = self.string(t)?;
                if pattern.is_empty() {
                    return Err(self.err_tok(t, "an empty pattern matches no text"));
                }
                self.expect(")")?;
                let text = u32::try_from(self.out.texts.len()).expect("a deck has few patterns");
                self.out.texts.push(pattern);
                let keep = op == "with_text";
                (
                    DerivedOp::WithText { keep, text },
                    Some(false),
                    Some(LExpr::Layer(texts)),
                )
            }
            "in_cells" | "not_in_cells" => {
                let drawn = matches!(&receiver, LExpr::Layer(name)
                    if self.out.layers.iter().any(|(drawn, _)| drawn == name));
                if !drawn {
                    return Err(self.err(
                        span,
                        &format!("`.{op}` selects a drawn layer's shapes by the cell they are drawn in; apply it to a `gds(..)` layer"),
                    ));
                }
                self.expect("(")?;
                let first = u32::try_from(self.out.texts.len()).expect("a deck has few patterns");
                loop {
                    let t = self.peek();
                    if t.tok != Tok::Str {
                        return Err(self.err_tok(
                            t,
                            &format!(
                                "expected a cell-name pattern in quotes, found {}",
                                self.found(t)
                            ),
                        ));
                    }
                    self.bump();
                    let pattern = self.string(t)?;
                    if pattern.is_empty() {
                        return Err(self.err_tok(t, "an empty pattern matches no cell"));
                    }
                    // KLayout reads these as character classes, alternatives
                    // and escapes; refused rather than matched differently.
                    if pattern.contains(['[', ']', '{', '}', '\\']) {
                        return Err(self.err_tok(
                            t,
                            "a cell-name pattern takes `*` and `?` only; `[`, `]`, `{`, `}` and `\\` are refused",
                        ));
                    }
                    self.out.texts.push(pattern);
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect(")")?;
                let count =
                    u32::try_from(self.out.texts.len()).expect("a deck has few patterns") - first;
                // Each selection is one bit of a placement's tag (`layout.rs`).
                if self.cell_selections >= MAX_CELL_SELECTIONS {
                    return Err(self.err(
                        span,
                        &format!("a deck holds at most {MAX_CELL_SELECTIONS} `.in_cells` and `.not_in_cells` selections"),
                    ));
                }
                self.cell_selections += 1;
                let keep = op == "in_cells";
                (DerivedOp::InCells { keep, first, count }, Some(false), None)
            }
            _ => return Err(self.err(span, &format!("unknown layer operation `.{op}`"))),
        };
        if let Some(want) = takes_edges.filter(|&want| want != edges) {
            let (want, got) = if want {
                ("an edge layer", "polygons")
            } else {
                ("a polygon layer", "edges")
            };
            return Err(self.err(span, &format!("`.{op}` needs {want}, not {got}")));
        }
        let mut operands = vec![receiver];
        operands.extend(argument);
        Ok(LExpr::Call(derived, operands))
    }

    /// `(cmp value {, cmp value})`: at most one lower and one upper bound, or one
    /// `==`. Inclusive, in grid units (square grid units for an area). With
    /// `square`, a length bound `n` is on twice the squared measure, `2·n·|n|`
    /// (which keeps the order), so a strict bound stays exact on an irrational
    /// length, a 45-degree width whose square is a half unit included: `> 70`
    /// is `>= 9801`, which a `√5000` neck (10000) and a `99/√2` width (9801)
    /// both meet.
    fn bounds(&mut self, op: &str, dim: Dim, square: bool) -> R<(i128, i128)> {
        let open = self.expect("(")?;
        let (mut lo, mut hi) = (None, None);
        loop {
            let t = self.peek();
            let cmp = self.text(t);
            if t.tok != Tok::Punct || ![">=", ">", "<=", "<", "=="].contains(&cmp) {
                return Err(self.err_tok(
                    t,
                    &format!("expected a bound such as `>= 1um`, found {}", self.found(t)),
                ));
            }
            self.bump();
            let value = self.value()?;
            let n = if dim == Dim::Area {
                self.area(&value, op)?.raw()
            } else {
                i128::from(self.length(&value, op)?.raw())
            };
            let n = if square { 2 * n * n.abs() } else { n };
            let (low, high) = match cmp {
                ">=" => (Some(n), None),
                ">" => (Some(n + 1), None),
                "<=" => (None, Some(n)),
                "<" => (None, Some(n - 1)),
                _ => (Some(n), Some(n)),
            };
            if (low.is_some() && lo.is_some()) || (high.is_some() && hi.is_some()) {
                return Err(self.err_tok(t, &format!("`.{op}` takes one bound on each side")));
            }
            lo = lo.or(low);
            hi = hi.or(high);
            if !self.eat(",") {
                break;
            }
        }
        let close = self.expect(")")?;
        let (lo, hi) = (lo.unwrap_or(i128::MIN), hi.unwrap_or(i128::MAX));
        if lo > hi {
            return Err(self.err((open.start, close.end), "the range is empty"));
        }
        Ok((lo, hi))
    }

    /// Whether a layer expression is edges.
    fn edges_of(&self, expr: &LExpr) -> bool {
        match expr {
            LExpr::Layer(name) => self.edge_layers.contains(name),
            LExpr::Op(op, operands) | LExpr::Group(op, operands) | LExpr::Call(op, operands) => op
                .makes_edges()
                .unwrap_or_else(|| self.edges_of(&operands[0])),
        }
    }

    /// Operand names for a row; a nested chain becomes an intermediate derived
    /// layer named `name#k`, which no deck text can name.
    fn lower_operands(&mut self, name: &str, operands: Vec<LExpr>, count: &mut u32) -> Vec<String> {
        operands
            .into_iter()
            .map(|operand| match operand {
                LExpr::Layer(layer) => layer,
                LExpr::Op(op, inner) | LExpr::Group(op, inner) | LExpr::Call(op, inner) => {
                    let layers = self.lower_operands(name, inner, count);
                    *count += 1;
                    let hidden = format!("{name}#{count}");
                    self.out.derived.push(DerivedSource {
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

    /// `if name { .. }` or `if not name { .. }`: the block's statements are
    /// read when the bound name is `true` (`false` with `not`), and skipped
    /// unread otherwise. A deck switch, as a Calibre deck's `#IFDEF` around
    /// rules or `KLayout`'s `$variables`: `let floating_labels = false` at the
    /// top of the deck is flipped there.
    fn if_(&mut self) -> R<()> {
        let negate = self.eat("not");
        let (name, span) = self.ident("a switch name")?;
        let on = match self.env.iter().rev().find(|(bound, _)| *bound == name) {
            Some((_, Val::Word { name: word, .. })) if word == "true" => true,
            Some((_, Val::Word { name: word, .. })) if word == "false" => false,
            Some((_, other)) => {
                let shown = other.shown();
                return Err(self.err(
                    span,
                    &format!("`if` takes a name bound to true or false; `{name}` is {shown}"),
                ));
            }
            None => {
                return Err(self.err(
                    span,
                    &format!(
                    "`{name}` is not bound; write `let {name} = true` (or false) before the `if`"
                ),
                ))
            }
        };
        let open = self.expect("{")?;
        let body = self.pos;
        let end = self.block_end(open)?;
        if on != negate {
            self.pos = body;
            self.statements(end - 1);
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
        let (what, span) = self.ident("conductors, touch_within_layer, global, via or label")?;
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
            "global" => {
                let layer = self.layer_word()?;
                self.out.connectivity.global.push(layer);
            }
            "via" => {
                let layer = self.layer_word()?;
                let list_at = self.peek();
                let layers = self.layer_list()?;
                let [a, b] = <[String; 2]>::try_from(layers).map_err(|layers| {
                    self.err_tok(list_at, &format!("a via joins 2 layers, got {}", layers.len()))
                })?;
                self.out.connectivity.vias.push(ViaSource {
                    layer,
                    connects: (a, b),
                });
            }
            "label" => {
                let layer = self.layer_word()?;
                self.expect("names")?;
                let names = self.layer_word()?;
                self.out.connectivity.labels.push(LabelSource { layer, names });
            }
            _ => {
                return Err(self.err(
                    span,
                    &format!("unknown connect `{what}`; expected conductors, touch_within_layer, global, via or label"),
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
                    "unknown device kind `{kind}`; expected mos, bjt, resistor, capacitor, diode or inductor"
                ),
            ));
        };
        let marker = self.layer_word()?;
        self.expect("model")?;
        let model = self.model()?;
        self.expect("terminals")?;
        let terminals = self.layer_list()?;
        let mut value = DeviceValue::default();
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, span) = self.ident("a device value")?;
            // A transistor is an n- or a p-channel switch, never both.
            let other = match key.as_str() {
                "on_gate_min" => value.on_gate_max_mv,
                "on_gate_max" => value.on_gate_min_mv,
                _ => None,
            };
            if other.is_some() {
                return Err(self.err(
                    span,
                    "a transistor takes on_gate_min (n-channel) or on_gate_max \
                     (p-channel), not both",
                ));
            }
            let (slot, dim, owner) = match key.as_str() {
                "sheet" => (
                    &mut value.sheet_ohm_sq,
                    Dim::Resistance,
                    DeviceKind::Resistor,
                ),
                "area_cap" => (
                    &mut value.area_cap_af_um2,
                    Dim::CapPerArea,
                    DeviceKind::Capacitor,
                ),
                "fringe_cap" => (
                    &mut value.fringe_cap_af_um,
                    Dim::CapPerLength,
                    DeviceKind::Capacitor,
                ),
                "inductance" => (
                    &mut value.inductance_nh,
                    Dim::Inductance,
                    DeviceKind::Inductor,
                ),
                "on_gate_min" => (&mut value.on_gate_min_mv, Dim::Voltage, DeviceKind::Mos),
                "on_gate_max" => (&mut value.on_gate_max_mv, Dim::Voltage, DeviceKind::Mos),
                _ => {
                    return Err(self.err(
                        span,
                        &format!(
                            "unknown device value `{key}`; expected sheet (a resistor), \
                             area_cap or fringe_cap (a capacitor), inductance (an \
                             inductor), on_gate_min or on_gate_max (a mos)"
                        ),
                    ))
                }
            };
            if owner != kind {
                let word = |of| DEVICES.iter().find(|&&(_, k)| k == of).map_or("", |d| d.0);
                let (owner, kind) = (word(owner), word(kind));
                let article = |word: &str| {
                    if word.starts_with(['a', 'e', 'i', 'o', 'u']) {
                        "an"
                    } else {
                        "a"
                    }
                };
                return Err(self.err(
                    span,
                    &format!(
                        "`{key}` is {} {owner}'s value, not {} {kind}'s",
                        article(owner),
                        article(kind)
                    ),
                ));
            }
            let stated = self.value()?;
            let number = self.quantity(&stated, dim, &key)?.f64();
            // A decimal past f64's range reads as infinite: no value at all.
            if !number.is_finite() {
                return Err(self.err(stated.span(), &format!("`{key}` is too large a number")));
            }
            if slot.replace(number).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        self.out.devices.push(DeviceSource {
            kind,
            marker,
            model,
            terminals,
            value,
        });
        Ok(())
    }

    /// `lvs <control> "model" ...`, one comparison control (deck.md, "LVS
    /// controls").
    fn lvs(&mut self) -> R<()> {
        let (control, span) = self.ident("an lvs control")?;
        match control.as_str() {
            "tolerance" => self.lvs_tolerance(),
            "ignore_parameter" => self.lvs_ignore_parameter(),
            "permute" => {
                let model = self.model()?;
                let (a, _) = self.ident("a pin name")?;
                let (b, _) = self.ident("a pin name")?;
                self.out.lvs.permute.push((model, a, b));
                Ok(())
            }
            "ignore" => {
                let model = self.model()?;
                if self.out.lvs.ignore.contains(&model) {
                    return Err(self.err(span, &format!("\"{model}\" is already ignored")));
                }
                self.out.lvs.ignore.push(model);
                Ok(())
            }
            "range" => self.lvs_range(),
            "connect_implicit" => {
                let pattern = self.quoted("a label pattern in quotes")?;
                self.out.lvs.connect_implicit.push(pattern);
                Ok(())
            }
            "connect_explicit" => {
                let mut names = Vec::new();
                while self.peek().tok == Tok::Str {
                    names.push(self.quoted("a label in quotes")?);
                }
                if names.len() < 2 {
                    let t = self.peek();
                    return Err(self.err_tok(t, "connect_explicit joins two labels or more, each in quotes"));
                }
                self.out.lvs.connect_explicit.push(names);
                Ok(())
            }
            "topology" => {
                let (policy, at) = self.ident("strict or relaxed")?;
                let relaxed = match policy.as_str() {
                    "strict" => false,
                    "relaxed" => true,
                    _ => {
                        return Err(self.err(
                            at,
                            &format!("unknown topology `{policy}`; expected strict or relaxed"),
                        ))
                    }
                };
                if self.out.lvs.topology.replace(relaxed).is_some() {
                    return Err(self.err(span, "the topology is already stated"));
                }
                Ok(())
            }
            "recognize_gates" => {
                if std::mem::replace(&mut self.out.lvs.recognize_gates, true) {
                    return Err(self.err(span, "gates are already recognised"));
                }
                Ok(())
            }
            "ports_by_name" => {
                if std::mem::replace(&mut self.out.lvs.ports_by_name, true) {
                    return Err(self.err(span, "ports are already compared by name"));
                }
                Ok(())
            }
            "ignore_shorted" => {
                let model = self.model()?;
                if self.out.lvs.ignore_shorted.contains(&model) {
                    return Err(self.err(
                        span,
                        &format!("shorted \"{model}\" devices are already ignored"),
                    ));
                }
                self.out.lvs.ignore_shorted.push(model);
                Ok(())
            }
            "max_res" | "min_caps" => {
                let value = self.value()?;
                let (dim, slot) = if control == "max_res" {
                    (Dim::Resistance, &mut self.out.lvs.max_res)
                } else {
                    (Dim::Capacitance, &mut self.out.lvs.min_caps)
                };
                if slot.is_some() {
                    return Err(self.err(span, &format!("`{control}` is already stated")));
                }
                let amount = self.quantity(&value, dim, &control)?.f64();
                if !(amount > 0.0) {
                    return Err(self.err(value.span(), &format!("`{control}` must be positive")));
                }
                let slot = if control == "max_res" {
                    &mut self.out.lvs.max_res
                } else {
                    &mut self.out.lvs.min_caps
                };
                *slot = Some(amount);
                Ok(())
            }
            "count" => self.lvs_count(),
            "lde" => self.lvs_lde(),
            "same_nets" => {
                let layout = self.quoted("a layout net label in quotes")?;
                let reference = self.quoted("a reference net name in quotes")?;
                let taken = self
                    .out
                    .lvs
                    .same_nets
                    .iter()
                    .any(|(a, b)| *a == layout || *b == reference);
                if taken {
                    return Err(self.err(
                        span,
                        "each net is paired by one same_nets statement at most",
                    ));
                }
                self.out.lvs.same_nets.push((layout, reference));
                Ok(())
            }
            "asymmetric" => {
                let model = self.model()?;
                if self.out.lvs.asymmetric.contains(&model) {
                    return Err(self.err(span, &format!("\"{model}\" is already asymmetric")));
                }
                self.out.lvs.asymmetric.push(model);
                Ok(())
            }
            _ => Err(self.err(
                span,
                &format!(
                    "unknown lvs control `{control}`; expected tolerance, ignore_parameter, \
                     asymmetric, permute, ignore, ignore_shorted, ports_by_name, range, topology, connect_implicit, \
                     connect_explicit, max_res, min_caps, same_nets, count, lde or recognize_gates"
                ),
            )),
        }
    }

    /// A device model name in quotes.
    fn model(&mut self) -> R<String> {
        self.quoted("a model name in quotes")
    }

    /// A string in quotes, `what` naming it in an error.
    fn quoted(&mut self, what: &str) -> R<String> {
        let t = self.peek();
        if t.tok != Tok::Str {
            return Err(self.err_tok(t, &format!("expected {what}, found {}", self.found(t))));
        }
        self.bump();
        self.string(t)
    }

    /// `lvs range "model" param >= min <= max`, either bound or both, each
    /// in the parameter's kind (a length or an area on the deck's grid, or a
    /// count), converted to the layout's grid.
    fn lvs_range(&mut self) -> R<()> {
        let model = self.model()?;
        let (param, span) = self.ident("a parameter name")?;
        let param = param.to_ascii_lowercase();
        let dim = match param.as_str() {
            "w" | "l" | "perim" | "ps" | "pd" | "pe" => Dim::Length,
            "area" | "as" | "ad" | "ae" => Dim::Area,
            "nf" => Dim::Count,
            _ => {
                return Err(self.err(
                    span,
                    &format!(
                        "`{param}` is not measured on a device; expected w, l, perim, ps, pd, \
                         pe, area, as, ad, ae or nf"
                    ),
                ))
            }
        };
        if self
            .out
            .lvs
            .range
            .iter()
            .any(|row| row.0 == model && row.1 == param)
        {
            return Err(self.err(
                span,
                &format!("`{param}` of \"{model}\" already has a range"),
            ));
        }
        let (mut min, mut max) = (None, None);
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let t = self.peek();
            let slot = if self.eat(">=") {
                &mut min
            } else if self.eat("<=") {
                &mut max
            } else {
                return Err(self.err_tok(t, &format!("expected >= or <=, found {}", self.found(t))));
            };
            let value = self.value()?;
            let limit = match dim {
                Dim::Length => LvsLimit::Length(self.length(&value, &param)?),
                Dim::Area => LvsLimit::Area(self.area(&value, &param)?),
                _ => LvsLimit::Count(self.count(&value, &param)?),
            };
            if slot.replace(limit).is_some() {
                return Err(self.err_tok(t, "this bound is already given"));
            }
        }
        match (min, max) {
            (None, None) => {
                let t = self.peek();
                Err(self.err_tok(t, "a range needs >=, <= or both"))
            }
            (Some(low), Some(high)) if high < low => {
                Err(self.err(span, "the range admits no value"))
            }
            _ => {
                self.out.lvs.range.push((model, param, min, max));
                Ok(())
            }
        }
    }

    /// `lvs lde "model" od <layer> max <length> [well <layer> scref
    /// <length>]`, the keys in any order, each once; `od` and `max` are
    /// needed, `well` and `scref` go together.
    fn lvs_lde(&mut self) -> R<()> {
        let model = self.model()?;
        let span = self.peek();
        if self.out.lvs.lde.iter().any(|row| row.0 == model) {
            return Err(self.err_tok(span, &format!("\"{model}\" already has an lde row")));
        }
        let (mut od, mut max, mut well, mut scref) = (None, None, None, None);
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, at) = self.ident("od, max, well or scref")?;
            let taken = match key.as_str() {
                "od" => od.replace(self.layer_word()?).is_some(),
                "well" => well.replace(self.layer_word()?).is_some(),
                "max" | "scref" => {
                    let value = self.value()?;
                    let length = self.length(&value, &key)?;
                    if length.raw() <= 0 {
                        return Err(self.err(value.span(), &format!("`{key}` must be positive")));
                    }
                    let slot = if key == "max" { &mut max } else { &mut scref };
                    slot.replace(length).is_some()
                }
                _ => {
                    return Err(self.err(
                        at,
                        &format!("unknown lde key `{key}`; expected od, max, well or scref"),
                    ))
                }
            };
            if taken {
                return Err(self.err(at, &format!("`{key}` is given twice")));
            }
        }
        let (Some(od), Some(max)) = (od, max) else {
            let t = self.peek();
            return Err(self.err_tok(t, "an lde row needs od and max"));
        };
        let well = match (well, scref) {
            (Some(well), Some(scref)) => Some((well, scref)),
            (None, None) => None,
            _ => {
                let t = self.peek();
                return Err(self.err_tok(t, "well and scref go together"));
            }
        };
        self.out.lvs.lde.push((model, od, max, well));
        Ok(())
    }

    /// `lvs count "model" >= min <= max`, either bound or both, each a whole
    /// number of devices.
    fn lvs_count(&mut self) -> R<()> {
        let model = self.model()?;
        let span = self.peek();
        if self.out.lvs.count.iter().any(|row| row.0 == model) {
            return Err(self.err_tok(span, &format!("\"{model}\" already has a count")));
        }
        let (mut min, mut max) = (None, None);
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let t = self.peek();
            let slot = if self.eat(">=") {
                &mut min
            } else if self.eat("<=") {
                &mut max
            } else {
                return Err(self.err_tok(t, &format!("expected >= or <=, found {}", self.found(t))));
            };
            let value = self.value()?;
            let bound = self.count(&value, "count")?;
            if slot.replace(bound).is_some() {
                return Err(self.err_tok(t, "this bound is already given"));
            }
        }
        match (min, max) {
            (None, None) => {
                let t = self.peek();
                Err(self.err_tok(t, "a count needs >=, <= or both"))
            }
            (Some(low), Some(high)) if high < low => {
                Err(self.err_tok(span, "the count admits no value"))
            }
            _ => {
                self.out.lvs.count.push((model, min, max));
                Ok(())
            }
        }
    }

    /// `lvs ignore_parameter "model" param`. The count `m` is no parameter to
    /// ignore: it says how many devices a card is.
    fn lvs_ignore_parameter(&mut self) -> R<()> {
        let model = self.model()?;
        let (param, span) = self.ident("a parameter name")?;
        let param = param.to_ascii_lowercase();
        if param == "m" {
            return Err(self.err(span, "`m` counts devices, and cannot be ignored"));
        }
        let row = (model, param);
        if self.out.lvs.ignore_parameter.contains(&row) {
            return Err(self.err(span, &format!("`{}` is already ignored", row.1)));
        }
        self.out.lvs.ignore_parameter.push(row);
        Ok(())
    }

    /// `lvs tolerance "model" param relative r absolute a`, either part or
    /// both, the absolute one in the parameter's unit, converted to SI.
    fn lvs_tolerance(&mut self) -> R<()> {
        let model = self.model()?;
        let (param, param_span) = self.ident("a parameter name")?;
        let param = param.to_ascii_lowercase();
        if self
            .out
            .lvs
            .tolerance
            .iter()
            .any(|row| row.model == model && row.param == param)
        {
            return Err(self.err(
                param_span,
                &format!("`{param}` of \"{model}\" already has a tolerance"),
            ));
        }
        let (mut relative, mut absolute) = (None, None);
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, span) = self.ident("relative or absolute")?;
            let value = self.value()?;
            let (slot, number) = match key.as_str() {
                "relative" => {
                    let fraction = self.quantity(&value, Dim::Fraction, &key)?.f64();
                    if !(0.0..=1.0).contains(&fraction) {
                        return Err(self.err(
                            value.span(),
                            "a relative tolerance is a fraction: 0 to 1, or 0% to 100%",
                        ));
                    }
                    (&mut relative, fraction)
                }
                "absolute" => {
                    let Some(dim) = absolute_dim(&param) else {
                        return Err(self.err(
                            span,
                            &format!(
                                "`{param}` has no known unit, so it takes a relative tolerance only"
                            ),
                        ));
                    };
                    let amount = self.quantity(&value, dim, &key)?.f64();
                    if amount < 0.0 {
                        return Err(self.err(value.span(), "an absolute tolerance is zero or more"));
                    }
                    (&mut absolute, amount)
                }
                _ => {
                    return Err(self.err(
                        span,
                        &format!("unknown tolerance part `{key}`; expected relative or absolute"),
                    ))
                }
            };
            if slot.replace(number).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        if relative.is_none() && absolute.is_none() {
            let t = self.peek();
            return Err(self.err_tok(t, "a tolerance needs relative, absolute or both"));
        }
        self.out.lvs.tolerance.push(ToleranceSrc {
            model,
            param,
            relative: relative.unwrap_or(0.0),
            absolute: absolute.unwrap_or(0.0),
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
        let row = self.pex_values(&layer)?;
        let missing: Vec<&str> = PEX
            .iter()
            .zip(&row)
            .filter(|(&(name, _), v)| v.is_none() && !OPTIONAL_PEX_KEYS.contains(&name))
            .map(|(&(name, _), _)| name)
            .collect();
        if !missing.is_empty() {
            let t = self.peek();
            return Err(self.err_tok(
                t,
                &format!("pex `{layer}` is missing {}", missing.join(", ")),
            ));
        }
        let [thickness_nm, height_nm, sheet_res_ohm_sq, dielectric_k, area_cap_af_um2, fringe_cap_af_um, tc1, tc2] =
            row;
        // One coefficient alone is a resistance law half written.
        let tc = match (tc1, tc2) {
            (Some(tc1), Some(tc2)) => Some((tc1, tc2)),
            (None, None) => None,
            _ => {
                let t = self.peek();
                return Err(self.err_tok(
                    t,
                    &format!("pex `{layer}` gives one of tc1 and tc2; give both, or neither"),
                ));
            }
        };
        self.out.pex.push((
            layer,
            StackSource {
                thickness_nm: thickness_nm.unwrap_or_default(),
                height_nm: height_nm.unwrap_or_default(),
                sheet_res_ohm_sq: sheet_res_ohm_sq.unwrap_or_default(),
                area_cap_af_um2: area_cap_af_um2.unwrap_or_default(),
                fringe_cap_af_um: fringe_cap_af_um.unwrap_or_default(),
                dielectric_k: dielectric_k.unwrap_or_default(),
                tc,
            },
        ));
        Ok(())
    }

    /// `corner <name> <layer> <key> <value> ..`: the values of one layer's
    /// `pex` row at a process corner, any of the row's keys, at least one.
    /// Each corner names each layer once; the layer's `pex` row is checked
    /// when the deck is lowered, since it may come later.
    fn corner(&mut self) -> R<()> {
        let (corner, _) = self.ident("a corner name")?;
        let layer = self.layer_word()?;
        let at = self.toks[self.pos - 1];
        if self
            .out
            .corners
            .iter()
            .any(|line| line.corner == corner && line.layer == layer)
        {
            return Err(self.err_tok(at, &format!("corner `{corner}` already states `{layer}`")));
        }
        let values = self.pex_values(&layer)?;
        if values.iter().all(Option::is_none) {
            return Err(self.err_tok(
                at,
                &format!(
                    "corner `{corner}` states nothing for `{layer}`; expected {}",
                    pex_keys()
                ),
            ));
        }
        self.out.corners.push(CornerSource {
            corner,
            layer,
            values,
        });
        Ok(())
    }

    /// The `key value` pairs of a `pex` row (or a `corner` line) to the end
    /// of the line, each [`PEX`] key at most once, each value one a process
    /// can have; `None` for a key not given.
    fn pex_values(&mut self, layer: &str) -> R<[Option<f64>; PEX.len()]> {
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
            // A conductor has a thickness, and a dielectric that is stated
            // has a permittivity: both are positive. A temperature
            // coefficient takes either sign. Nothing else here can be below
            // zero, and a zero reads as "not stated" (`ProcessStack`); an
            // unstated dielectric is left out of the row instead. Past f64's
            // range a decimal reads as infinite, which no process has.
            let (physical, bound) = match key.as_str() {
                "thickness" | "dielectric" => {
                    (number > 0.0 && number.is_finite(), "positive and finite")
                }
                "tc1" | "tc2" => (number.is_finite(), "finite"),
                _ => (
                    number >= 0.0 && number.is_finite(),
                    "zero or more, and finite",
                ),
            };
            if !physical {
                return Err(self.err(
                    value.span(),
                    &format!("pex `{layer}`: {key} must be {bound}"),
                ));
            }
            if row[at].replace(number).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        Ok(row)
    }

    /// `temperature <operating> nominal <nominal>`: the temperature the run is
    /// signed off at, and the one the `pex` rows' `sheet` values are stated at.
    fn temperature(&mut self, span: (u32, u32)) -> R<()> {
        let operating = self.kelvin("temperature")?;
        self.expect("nominal")?;
        let nominal = self.kelvin("nominal")?;
        if self.out.temperature.replace((operating, nominal)).is_some() {
            return Err(self.err(span, "the temperature is already stated"));
        }
        Ok(())
    }

    /// `pex_fill <layer> floating|grounded|ignored`: how PEX treats the
    /// nets drawn only on that layer, metal fill ([`super::FillTreatment`]).
    fn pex_fill(&mut self) -> R<()> {
        let layer = self.layer_word()?;
        let (word, at) = self.ident("floating, grounded or ignored")?;
        let treatment = match word.as_str() {
            "floating" => super::FillTreatment::Floating,
            "grounded" => super::FillTreatment::Grounded,
            "ignored" => super::FillTreatment::Ignored,
            _ => {
                return Err(self.err(
                    at,
                    &format!(
                        "unknown fill treatment `{word}`; expected floating, grounded or ignored"
                    ),
                ))
            }
        };
        self.out.pex_models.fill.push((layer, treatment));
        Ok(())
    }

    /// `pex_device "<model>" gate_contact_cap <c> gate_diffusion_cap <c>`:
    /// a MOS model's device-region capacitances per µm of gate width
    /// ([`super::DeviceParasitics`]), both required, zero or more.
    fn pex_device(&mut self) -> R<()> {
        let model = self.model()?;
        let mut values = [None::<f64>; 2];
        let keys = ["gate_contact_cap", "gate_diffusion_cap"];
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, span) = self.ident("gate_contact_cap or gate_diffusion_cap")?;
            let Some(at) = keys.iter().position(|&k| k == key) else {
                return Err(self.err(
                    span,
                    &format!("unknown pex_device key `{key}`; expected gate_contact_cap or gate_diffusion_cap"),
                ));
            };
            let value = self.value()?;
            let af = self.quantity(&value, Dim::CapPerLength, &key)?.f64();
            if !(af >= 0.0 && af.is_finite()) {
                return Err(self.err(value.span(), &format!("{key} must be zero or more")));
            }
            if values[at].replace(af).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        let [Some(gate_contact_af_um), Some(gate_diffusion_af_um)] = values else {
            let t = self.peek();
            return Err(self.err_tok(
                t,
                "pex_device states both gate_contact_cap and gate_diffusion_cap",
            ));
        };
        self.out.pex_models.device.push(super::DeviceParasitics {
            model,
            gate_contact_af_um,
            gate_diffusion_af_um,
        });
        Ok(())
    }

    /// `pex_tsv <layer> length <l> liner <t> liner_k <k>`: a through-silicon
    /// via layer ([`super::TsvModel`]), every value required and positive.
    fn pex_tsv(&mut self) -> R<()> {
        let layer = self.layer_word()?;
        let keys = ["length", "liner", "liner_k"];
        let mut values = [None::<f64>; 3];
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, span) = self.ident("length, liner or liner_k")?;
            let Some(at) = keys.iter().position(|&k| k == key) else {
                return Err(self.err(
                    span,
                    &format!("unknown pex_tsv key `{key}`; expected length, liner or liner_k"),
                ));
            };
            let value = self.value()?;
            let dim = if at == 2 { Dim::Scalar } else { Dim::Length };
            let number = self.physical(&value, dim, &key)?;
            if !(number > 0.0 && number.is_finite()) {
                return Err(self.err(value.span(), &format!("{key} must be positive")));
            }
            if values[at].replace(number).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        let [Some(length_nm), Some(liner_nm), Some(liner_k)] = values else {
            let t = self.peek();
            return Err(self.err_tok(t, "pex_tsv states length, liner and liner_k"));
        };
        self.out.pex_models.tsv.push(super::TsvModel {
            layer,
            length_nm,
            liner_nm,
            liner_k,
        });
        Ok(())
    }

    /// `fill <layer> for <layer> size <l> space <l> keep <l> avoid [..]`:
    /// how `gpurify fill` draws density fill ([`super::FillSpec`]), every
    /// key required once, in any order.
    fn fill(&mut self) -> R<()> {
        let layer = self.layer_word()?;
        self.expect("for")?;
        let density = self.layer_word()?;
        let keys = ["size", "space", "keep"];
        let mut lengths = [None::<Dbu>; 3];
        let mut avoid = None;
        while !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, span) = self.ident("size, space, keep or avoid")?;
            if key == "avoid" {
                if avoid.replace(self.layer_list()?).is_some() {
                    return Err(self.err(span, "`avoid` is given twice"));
                }
                continue;
            }
            let Some(at) = keys.iter().position(|&k| k == key) else {
                return Err(self.err(
                    span,
                    &format!("unknown fill key `{key}`; expected size, space, keep or avoid"),
                ));
            };
            let value = self.value()?;
            let length = self.length(&value, &key)?;
            // `keep` may be zero (fill may touch what it avoids); the rest draw.
            if length.raw() < 0 || (at < 2 && length.raw() == 0) {
                return Err(self.err(value.span(), &format!("{key} must be positive")));
            }
            if lengths[at].replace(length).is_some() {
                return Err(self.err(span, &format!("`{key}` is given twice")));
            }
        }
        let ([Some(size), Some(space), Some(keep)], Some(avoid)) = (lengths, avoid) else {
            let t = self.peek();
            return Err(self.err_tok(t, "fill states size, space, keep and avoid"));
        };
        self.out.edits.fill.push(super::FillSpec {
            layer,
            density,
            size,
            space,
            keep,
            avoid,
        });
        Ok(())
    }

    /// `widen <layer> net "<pattern>" by <len>`: the power straps `gpurify
    /// enhance` widens ([`super::WidenSpec`]).
    fn widen(&mut self) -> R<()> {
        let layer = self.layer_word()?;
        self.expect("net")?;
        let net = self.quoted("a net name pattern in quotes")?;
        self.expect("by")?;
        let value = self.value()?;
        let by = self.length(&value, "by")?;
        if by.raw() <= 0 {
            return Err(self.err(value.span(), "by must be positive"));
        }
        self.out
            .edits
            .widen
            .push(super::WidenSpec { layer, net, by });
        Ok(())
    }

    /// `extraction <type> [coupling_threshold <capacitance>]`, at most once:
    /// which parasitics the output keeps ([`super::Extraction`]).
    fn extraction(&mut self, span: (u32, u32)) -> R<()> {
        let (word, at) = self.ident("an extraction type")?;
        let kind = match word.as_str() {
            "r" => ExtractionKind::R,
            "c" => ExtractionKind::C,
            "cc" => ExtractionKind::Cc,
            "rc" => ExtractionKind::Rc,
            "rcc" => ExtractionKind::Rcc,
            _ => {
                return Err(self.err(
                    at,
                    &format!("unknown extraction type `{word}`; expected r, c, cc, rc or rcc"),
                ))
            }
        };
        let mut coupling_threshold_af = 0.0;
        if !matches!(self.peek().tok, Tok::Newline | Tok::Eof) {
            let (key, key_span) = self.ident("`coupling_threshold`")?;
            if key != "coupling_threshold" {
                return Err(self.err(
                    key_span,
                    &format!("unknown extraction key `{key}`; expected coupling_threshold"),
                ));
            }
            let value = self.value()?;
            let af = self
                .quantity(&value, Dim::Capacitance, "coupling_threshold")?
                .f64();
            if !(af >= 0.0) {
                return Err(self.err(value.span(), "coupling_threshold must be zero or more"));
            }
            if af > 0.0 && !kind.keeps_coupling() {
                return Err(self.err(
                    key_span,
                    &format!(
                        "coupling_threshold grounds the coupling below it, and `{word}` keeps no coupling"
                    ),
                ));
            }
            coupling_threshold_af = af;
        }
        let stated = Extraction {
            kind,
            coupling_threshold_af,
        };
        if self.out.extraction.replace(stated).is_some() {
            return Err(self.err(span, "the extraction type is already stated"));
        }
        Ok(())
    }

    /// A temperature value, absolute, above absolute zero.
    fn kelvin(&mut self, label: &str) -> R<f64> {
        let value = self.value()?;
        let kelvin = self.physical(&value, Dim::Temperature, label)?;
        if kelvin > 0.0 {
            Ok(kelvin)
        } else {
            Err(self.err(
                value.span(),
                &format!("{label} must be above absolute zero"),
            ))
        }
    }

    /// `waive <rule id> <layer>`: a violation of the rule whose marker lies
    /// on a shape of the layer is waived. The rule must be the deck's
    /// (checked when the deck is built, since it may come later); a rule may
    /// have several waiver layers, each named once.
    fn waive(&mut self) -> R<()> {
        let t = self.peek();
        if t.tok != Tok::RuleId {
            return Err(self.err_tok(t, "expected the id of the rule to waive"));
        }
        self.bump();
        let rule = self.rule_id(t)?;
        let layer = self.layer_word()?;
        if self
            .out
            .waivers
            .iter()
            .any(|(have, on)| *have == rule && *on == layer)
        {
            return Err(self.err_tok(
                self.toks[self.pos - 1],
                &format!("`{rule}` is already waived by `{layer}`"),
            ));
        }
        self.out.waivers.push((rule, layer));
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
        self.inline = 0;
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
            &named,
        )?;
        let slots = EDGE_KINDS
            .iter()
            .find(|(engine, _)| *engine == kind.engine)
            .map_or(&[][..], |&(_, slots)| slots);
        let extra = if kind.more {
            &positional[kind.layers.len()..]
        } else {
            &[]
        };
        let mut layers = Vec::with_capacity(positional.len());
        for (at, value) in kind
            .layers
            .iter()
            .map(|&slot| &positional[usize::from(slot)])
            .chain(extra)
            .enumerate()
        {
            layers.push(match slots.get(at).copied().unwrap_or(Some(false)) {
                Some(false) => self.layer_name(value)?,
                None => self.any_layer_name(value)?,
                Some(true) => {
                    let layer = self.any_layer_name(value)?;
                    if !self.edge_layers.contains(&layer) {
                        return Err(self.err(
                            value.span(),
                            &format!("`{name}` here takes an edge layer; `{layer}` is polygons"),
                        ));
                    }
                    layer
                }
            });
        }

        let mut params = Vec::new();
        self.named(
            &named,
            kind.params,
            &format!("`{name}`"),
            (name_span.0, name_span.1),
            &mut params,
        )?;
        if kind.engine == "spacing_table" {
            self.spacing_table(&named)?;
        }
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
                .map(|&(flag, on)| (flag, ParamSource::Value(ParamValue::Flag(on)))),
        );
        if warning.is_some() {
            params.push(("warning", ParamSource::Value(ParamValue::Flag(true))));
        }
        self.out.rules.push(RuleSource {
            id,
            kind: kind.engine,
            layers,
            params,
        });
        // The last `stage` line's; a rule before the first one is refused there.
        if let Some((_, rules)) = self.out.stages.last_mut() {
            rules.push(
                self.out
                    .rules
                    .last()
                    .map(|rule| rule.id.clone())
                    .unwrap_or_default(),
            );
        }
        Ok(())
    }

    /// `stage <name>`: the rules written after this line, up to the next
    /// `stage` line, are one stage of a staged run ([`super::Stages`]). A
    /// staged deck puts every rule in a stage, and writes each stage's rules
    /// together.
    fn stage(&mut self, span: (u32, u32)) -> R<()> {
        let (name, at) = self.ident("a stage name")?;
        if self.out.stages.iter().any(|(stated, _)| *stated == name) {
            return Err(self.err(
                at,
                &format!("stage `{name}` is already stated; a stage's rules are written together"),
            ));
        }
        if self.out.stages.is_empty() && !self.out.rules.is_empty() {
            return Err(self.err(
                span,
                &format!(
                    "{} rules come before the first `stage` line; every rule of a staged \
                     deck belongs to a stage",
                    self.out.rules.len()
                ),
            ));
        }
        if self.out.stages.len() >= usize::from(u16::MAX) {
            return Err(self.err(at, "too many stages"));
        }
        self.out.stages.push((name, Vec::new()));
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
                positional.push(self.positional()?);
            }
            let t = self.peek();
            if !(self.is(",") || self.is(";") || self.is(")")) {
                return Err(
                    self.err_tok(t, &format!("expected `,` or `)`, found {}", self.found(t)))
                );
            }
        }
    }

    /// A rule's layer argument: a value, or a layer expression lowered to a
    /// derived layer named `<rule id>@<k>`, which no deck text can name.
    fn positional(&mut self) -> R<Val> {
        let t = self.peek();
        let next = self.peek_at(1);
        let word = t.tok == Tok::Ident && !self.text(t).contains('.');
        let ends = next.tok == Tok::Punct && [",", ";", ")"].contains(&self.text(next));
        if (word && ends) || !(t.tok == Tok::Ident || self.is("(")) {
            return self.value();
        }
        let expr = self.layer_expr()?;
        let span = (t.start, self.toks[self.pos - 1].end);
        let edges = self.edges_of(&expr);
        let (op, operands) = match expr {
            LExpr::Layer(name) => return Ok(Val::Word { name, span }),
            LExpr::Op(op, operands) | LExpr::Group(op, operands) | LExpr::Call(op, operands) => {
                (op, operands)
            }
        };
        self.inline += 1;
        let name = format!("{}@{}", self.context, self.inline);
        let mut count = 0;
        let layers = self.lower_operands(&name, operands, &mut count);
        self.out.derived.push(DerivedSource {
            name: name.clone(),
            op,
            layers,
        });
        if edges {
            self.edge_layers.insert(name.clone());
        }
        self.layers.insert(name.clone());
        Ok(Val::Word { name, span })
    }

    /// The table row for a kind name, its layer count, modifier and comparison.
    fn pick(
        &mut self,
        name: &str,
        span: (u32, u32),
        positional: &mut Vec<Val>,
        cmp: Option<(Cmp, (u32, u32))>,
        named: &[Named],
    ) -> R<&'static Kind> {
        let mut rows: Vec<&'static Kind> = KINDS.iter().filter(|k| k.name == name).collect();
        if rows.is_empty() {
            return Err(self.err(span, &format!("unknown check kind `{name}`")));
        }
        // An edge layer first picks the edge rows, a polygon layer the others;
        // when none fits, the layer check names the mismatch.
        let edges = matches!(positional.first(),
            Some(Val::Word { name, .. }) if self.edge_layers.contains(name));
        let fitting: Vec<_> = rows
            .iter()
            .copied()
            .filter(|k| {
                if edges {
                    EDGE_KINDS.iter().any(|(engine, _)| *engine == k.engine)
                } else {
                    !k.engine.starts_with("edge_")
                }
            })
            .collect();
        if !fitting.is_empty() {
            rows = fitting;
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
        // Rows alike but for their named arguments: the one knowing the most
        // of those given, the first on a tie.
        let known = |k: &Kind| {
            named
                .iter()
                .filter(|arg| k.params.iter().any(|p| p.name == arg.name))
                .count()
        };
        // A kind with forms both with and without a comparison (`width(L) >=
        // len` beside `width(L; allowed: [..])`): with no comparison and none
        // of the comparison-free form's arguments named, the comparison is
        // what is missing.
        let compared = by_arity.iter().any(|k| k.cmp != Cmp::Absent);
        let missing_comparison =
            |k: &Kind| given == Cmp::Absent && compared && named.is_empty() && !k.params.is_empty();
        let mut best: Option<&'static Kind> = None;
        for &kind in by_arity
            .iter()
            .filter(|&&k| k.cmp == given && !missing_comparison(k))
        {
            if best.is_none_or(|b| known(kind) > known(b)) {
                best = Some(kind);
            }
        }
        if let Some(kind) = best {
            return Ok(kind);
        }
        let legal: Vec<&str> = by_arity
            .iter()
            .filter(|k| !(cmp.is_none() && compared && k.cmp == Cmp::Absent))
            .map(|k| cmp_text(k.cmp))
            .collect();
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
        out: &mut Vec<(&'static str, ParamSource)>,
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
        out: &mut Vec<(&'static str, ParamSource)>,
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
            Dim::Length => ParamSource::Value(ParamValue::Length(self.length(value, label)?)),
            Dim::Area => ParamSource::Value(ParamValue::Area(self.area(value, label)?)),
            Dim::Count => ParamSource::Value(ParamValue::Count(self.count(value, label)?)),
            Dim::Bool => match value {
                Val::Word { name, .. } if name == "true" || name == "false" => {
                    ParamSource::Value(ParamValue::Flag(name == "true"))
                }
                other => return Err(self.wrong(other, "true or false", label)),
            },
            Dim::Layer => ParamSource::Layer(self.layer_name(value)?),
            Dim::LengthPair(second) => {
                let Val::Pair(a, b, _) = value else {
                    return Err(self.wrong(value, "a pair `a x b` of lengths", label));
                };
                let a = self.length(a, label)?;
                let b = self.length(b, label)?;
                out.push((engine, ParamSource::Value(ParamValue::Length(a))));
                out.push((second, ParamSource::Value(ParamValue::Length(b))));
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
                    out.push((engine, ParamSource::Value(ParamValue::Count(whole))));
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
                    out.push((engine, ParamSource::Model(model.clone())));
                }
                return Ok(());
            }
            Dim::Word(words) => match value {
                Val::Word { name, .. } if words.contains(&name.as_str()) => {
                    let at = words
                        .iter()
                        .position(|word| *word == name.as_str())
                        .expect("listed");
                    ParamSource::Value(ParamValue::Count(u32::try_from(at).expect("few words")))
                }
                other => return Err(self.wrong(other, &words.join(" or "), label)),
            },
            Dim::Nets => match value {
                Val::Word { name, .. } if name == "same" || name == "different" => {
                    ParamSource::Value(ParamValue::Flag(name == "same"))
                }
                other => return Err(self.wrong(other, "same or different", label)),
            },
            Dim::LengthList => {
                for item in self.lengths(value, label)? {
                    out.push((engine, ParamSource::Value(ParamValue::Length(item))));
                }
                return Ok(());
            }
            Dim::LengthPairList(second) => {
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, "a list of pairs `a x b` of lengths", label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one pair")));
                }
                for item in items {
                    let Val::Pair(a, b, _) = item else {
                        return Err(self.wrong(item, "a pair `a x b` of lengths", label));
                    };
                    let a = self.length(a, label)?;
                    let b = self.length(b, label)?;
                    out.push((engine, ParamSource::Value(ParamValue::Length(a))));
                    out.push((second, ParamSource::Value(ParamValue::Length(b))));
                }
                return Ok(());
            }
            Dim::VoltageList => {
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, "a list of voltages", label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one voltage")));
                }
                for item in items {
                    let millivolts = self.quantity(item, Dim::Voltage, label)?.f64();
                    out.push((engine, ParamSource::Value(ParamValue::Ratio(millivolts))));
                }
                return Ok(());
            }
            Dim::FrequencyList => {
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, "a list of frequencies", label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one frequency")));
                }
                for item in items {
                    let megahertz = self.quantity(item, Dim::Frequency, label)?.f64();
                    out.push((engine, ParamSource::Value(ParamValue::Ratio(megahertz))));
                }
                return Ok(());
            }
            Dim::CurrentPerWidthRows => {
                let want = "a list of rows of currents per width";
                let Val::List(rows, span) = value else {
                    return Err(self.wrong(value, want, label));
                };
                if rows.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one row")));
                }
                for row in rows {
                    let Val::List(items, _) = row else {
                        return Err(self.wrong(row, want, label));
                    };
                    for item in items {
                        let density = self.quantity(item, Dim::CurrentPerWidth, label)?.f64();
                        out.push((engine, ParamSource::Value(ParamValue::Ratio(density))));
                    }
                }
                return Ok(());
            }
            Dim::CountList | Dim::AreaList => {
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, dim_name(param.dim), label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one value")));
                }
                for item in items {
                    let stated = if param.dim == Dim::CountList {
                        ParamValue::Count(self.count(item, label)?)
                    } else {
                        ParamValue::Area(self.area(item, label)?)
                    };
                    out.push((engine, ParamSource::Value(stated)));
                }
                return Ok(());
            }
            Dim::FractionList => {
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, "a list of fractions", label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one fraction")));
                }
                for item in items {
                    let v = self.quantity(item, Dim::Fraction, label)?.f64();
                    if !(0.0..=1.0).contains(&v) {
                        return Err(self.err(
                            item.span(),
                            &format!("`{label}` holds fractions: 0 to 1, or 0% to 100%"),
                        ));
                    }
                    out.push((engine, ParamSource::Value(ParamValue::Ratio(v))));
                }
                return Ok(());
            }
            Dim::OptLengthList => {
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, "a list of lengths or none", label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one entry")));
                }
                for item in items {
                    let stated = if matches!(item, Val::Word { name, .. } if name == "none") {
                        ParamValue::Flag(false)
                    } else {
                        ParamValue::Length(self.length(item, label)?)
                    };
                    out.push((engine, ParamSource::Value(stated)));
                }
                return Ok(());
            }
            Dim::LengthRows => {
                let Val::List(rows, _) = value else {
                    return Err(self.wrong(value, "a list of rows of lengths", label));
                };
                for row in rows {
                    for item in self.lengths(row, label)? {
                        out.push((engine, ParamSource::Value(ParamValue::Length(item))));
                    }
                }
                return Ok(());
            }
            Dim::AreaTable(second) => {
                let want = "a list of (area, number) points";
                let Val::List(items, span) = value else {
                    return Err(self.wrong(value, want, label));
                };
                if items.is_empty() {
                    return Err(self.err(*span, &format!("`{label}` needs at least one point")));
                }
                let mut previous: Option<DbuArea> = None;
                for item in items {
                    let Val::Tuple(parts, _) = item else {
                        return Err(self.wrong(item, want, label));
                    };
                    let [area, number] = parts.as_slice() else {
                        return Err(self.wrong(item, want, label));
                    };
                    let area = self.area(area, label)?;
                    if area.raw() < 0 || previous.is_some_and(|before| area <= before) {
                        return Err(self.err(
                            item.span(),
                            &format!("`{label}`'s areas start at 0 or more and rise strictly"),
                        ));
                    }
                    previous = Some(area);
                    let number = self.physical(number, Dim::Scalar, label)?;
                    out.push((engine, ParamSource::Value(ParamValue::Area(area))));
                    out.push((second, ParamSource::Value(ParamValue::Ratio(number))));
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
                ParamSource::Value(ParamValue::Ratio(v))
            }
            dim => ParamSource::Value(ParamValue::Ratio(self.physical(value, dim, label)?)),
        };
        out.push((engine, converted));
        Ok(())
    }

    /// `[a, b, ..]`, a non-empty list of lengths.
    fn lengths(&mut self, value: &Val, label: &str) -> R<Vec<Dbu>> {
        let Val::List(items, span) = value else {
            return Err(self.wrong(value, "a list of lengths", label));
        };
        if items.is_empty() {
            return Err(self.err(*span, &format!("`{label}` needs at least one length")));
        }
        items.iter().map(|item| self.length(item, label)).collect()
    }

    /// A spacing table is complete and monotone: `prl` and `width` start at
    /// zero and rise, `space` has one row per width and one cell per run
    /// length, and no cell is below the one before it in its row or column.
    fn spacing_table(&mut self, named: &[Named]) -> R<()> {
        let arg = |key: &str| {
            named
                .iter()
                .find(|arg| arg.name == key)
                .map(|arg| arg.value.clone())
                .expect("`named` checked every parameter is given")
        };
        let (prl, width, space) = (arg("prl"), arg("width"), arg("space"));
        let mut counts = [0; 2];
        for (count, (value, key)) in counts.iter_mut().zip([(&prl, "prl"), (&width, "width")]) {
            let steps = self.lengths(value, key)?;
            if steps[0].raw() != 0 {
                return Err(self.err(
                    value.span(),
                    &format!("`{key}` starts at 0, so every pair has a row and a column"),
                ));
            }
            if steps.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(self.err(value.span(), &format!("`{key}` must rise strictly")));
            }
            *count = steps.len();
        }
        let [columns, rows] = counts;
        let Val::List(lines, span) = &space else {
            return Err(self.wrong(&space, "a list of rows of lengths", "space"));
        };
        if lines.len() != rows {
            return Err(self.err(
                *span,
                &format!(
                    "`space` needs one row per width: {rows}, got {}",
                    lines.len()
                ),
            ));
        }
        let mut above: Vec<Dbu> = Vec::new();
        for line in lines {
            let cells = self.lengths(line, "space")?;
            if cells.len() != columns {
                return Err(self.err(
                    line.span(),
                    &format!(
                        "a `space` row needs one cell per run length: {columns}, got {}",
                        cells.len()
                    ),
                ));
            }
            if cells[0].raw() <= 0 {
                return Err(self.err(line.span(), "a spacing must be positive"));
            }
            let falls = cells.windows(2).any(|pair| pair[1] < pair[0])
                || above.iter().zip(&cells).any(|(up, cell)| cell < up);
            if falls {
                return Err(self.err(
                    line.span(),
                    "`space` cannot fall along a row or down a column",
                ));
            }
            above = cells;
        }
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
        let square = grid
            .m
            .checked_mul(grid.m)
            .zip(grid.e.checked_mul(2))
            .map(|(m, e)| Dec { m, e })
            .ok_or_else(|| self.err(value.span(), "the grid squared is too long a number"))?;
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

    /// A declared polygon layer's name.
    fn layer_name(&mut self, value: &Val) -> R<String> {
        let name = self.any_layer_name(value)?;
        if self.edge_layers.contains(&name) {
            return Err(self.err(
                value.span(),
                &format!("`{name}` is an edge layer; only a check that takes edges can use it"),
            ));
        }
        Ok(name)
    }

    /// A declared layer's name, polygons or edges.
    fn any_layer_name(&mut self, value: &Val) -> R<String> {
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
    /// `receiver.op(argument)`: the receiver, then the layer argument if any.
    Call(DerivedOp, Vec<LExpr>),
}

fn cmp_text(cmp: Cmp) -> &'static str {
    match cmp {
        Cmp::Absent => "no comparison",
        Cmp::Ge => "`>=`",
        Cmp::Le => "`<=`",
        Cmp::Eq => "`==`",
    }
}

/// The kind an absolute tolerance on `param` is written as, in the unit
/// [`absolute_unit`](super::absolute_unit) names.
fn absolute_dim(param: &str) -> Option<Dim> {
    let (unit, _) = super::absolute_unit(param)?;
    Some(match unit {
        "nm" => Dim::Length,
        "nm2" => Dim::Area,
        "ohm" => Dim::Resistance,
        "aF" => Dim::Capacitance,
        "nH" => Dim::Inductance,
        _ => Dim::Count,
    })
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
        Dim::ThermalConductivity => "a thermal conductivity",
        Dim::Time => "a time",
        Dim::Field => "an electric field",
        Dim::CapPerArea => "a capacitance per area",
        Dim::CapPerLength => "a capacitance per length",
        Dim::PerKelvin => "a coefficient per kelvin",
        Dim::PerKelvin2 => "a coefficient per kelvin squared",
        Dim::Capacitance => "a capacitance",
        Dim::Inductance => "an inductance",
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
        Dim::Nets => "same or different",
        Dim::LengthList => "a list of lengths",
        Dim::LengthRows => "a list of rows of lengths",
        Dim::LengthPairList(_) => "a list of pairs of lengths",
        Dim::Word(_) => "one of the listed words",
        Dim::VoltageList => "a list of voltages",
        Dim::FractionList => "a list of fractions",
        Dim::CountList => "a list of counts",
        Dim::AreaList => "a list of areas",
        Dim::AreaTable(_) => "a list of (area, number) points",
        Dim::OptLengthList => "a list of lengths or none",
        Dim::Frequency => "a frequency",
        Dim::FrequencyList => "a list of frequencies",
        Dim::CurrentPerWidthRows => "a list of rows of currents per width",
    }
}
