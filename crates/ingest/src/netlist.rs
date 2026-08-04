//! Reference-netlist readers: SPICE/CDL and Spectre.
//!
//! These are parsers, and parsers belong here — they have nothing in common
//! with the subgraph matching in `lvs` beyond both involving netlists. Both
//! dialects produce the same [`Netlist`], so `lvs` sees one shape.
//!
//! # Declared subset
//!
//! Neither reader guesses. Each implements a stated subset and errors on
//! anything outside it, with the source line, because a reference netlist
//! silently misparsed produces an LVS mismatch that looks like a layout bug and
//! costs a day.

use crate::deck::DeviceKind;
use crate::intern::{StrId, StrTable};
use crate::{csr, narrow};

/// Where a token came from, for an error a human can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NetlistError {
    #[error("line {}: unexpected token {1}", .0.line)]
    Unexpected(SourceSpan, String),
    #[error("line {}: {1} is not in the supported subset", .0.line)]
    Unsupported(SourceSpan, String),
    #[error("line {}: subcircuit {1} is called but never defined", .0.line)]
    UndefinedSubckt(SourceSpan, String),
    #[error("line {}: {1} is defined twice", .0.line)]
    Redefined(SourceSpan, String),
    #[error("line {}: device {1} has {2} terminals, expected {3}", .0.line)]
    TerminalCount(SourceSpan, String, u32, u32),
    #[error("io: {0}")]
    Io(String),
}

/// Identifies a subcircuit definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SubcktId(pub u32);

/// Identifies a net within one subcircuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RefNetId(pub u32);

/// Identifies a device instance within one subcircuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RefDeviceId(pub u32);

/// Identifies a subcircuit instance — one `X` card. Indexes the `instance_*`
/// columns; the subcircuit it sits in is `instance_subckt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RefInstanceId(pub u32);

/// A parsed reference netlist, hierarchy preserved.
///
/// Hierarchy is kept rather than flattened, because hierarchical LVS compares
/// cell by cell and flattening first would throw away the structure it needs.
/// Flattening, where a run wants it, is a separate explicit step.
///
/// **Five questions.** In: text. Out: `SoA` tables of subcircuits, nets and
/// device instances. How many: thousands of devices for a block, millions for a
/// full chip. Access pattern: `lvs` walks devices per subcircuit and terminals
/// per device, so both are CSR ranges. Lifetime: whole run. Parallelisable:
/// per-subcircuit comparison is independent.
#[derive(Debug, Default)]
pub struct Netlist {
    /// One row per subcircuit definition.
    pub subckt_name: Vec<StrId>,
    /// Ports, as a CSR range into `port_net`.
    pub subckt_port_start: Vec<u32>,
    pub port_net: Vec<RefNetId>,
    /// Devices belonging to each subcircuit, CSR into the device columns.
    pub subckt_device_start: Vec<u32>,

    /// One row per device instance.
    pub device_name: Vec<StrId>,
    pub device_model: Vec<StrId>,
    pub device_kind: Vec<crate::deck::DeviceKind>,
    /// Terminals, CSR into `terminal_net`.
    pub device_terminal_start: Vec<u32>,
    /// The nets a device's terminals attach to, **in the card's order, which is
    /// the role**.
    ///
    /// | [`DeviceKind`](crate::deck::DeviceKind) | order, from the card |
    /// |---|---|
    /// | `Mos` (`M`) | drain, gate, source, bulk |
    /// | `Bjt` (`Q`) | collector, base, emitter, then substrate if stated |
    /// | `Resistor`, `Capacitor`, `Diode` | pin 0, pin 1 |
    ///
    /// This is SPICE's own card order and the Spectre reader normalises to it,
    /// so both dialects produce one shape. Written down in the Testing-Phase
    /// because `lvs`'s `Graph` carries a `TerminalRole` per terminal and nothing
    /// stated how a position became one — so the projection test could assert
    /// the MOS role *set* but not the order, and a reader that transposed drain
    /// and source would have passed it.
    ///
    /// **Note it is not `DeviceRecognition`'s order.** A recogniser lists gate
    /// first; a SPICE card lists drain first. The two orders meet in `lvs`, and
    /// they are different because the two source formats are.
    pub terminal_net: Vec<RefNetId>,
    /// Parameters, CSR into `param`.
    pub device_param_start: Vec<u32>,
    /// Interned name and value.
    ///
    /// **SI base units, suffixes expanded at parse.** `w=1u` is `1e-6`, and a
    /// bare `w=1` is one metre — a SPICE scale suffix is part of the number's
    /// syntax, not a unit annotation, so expanding it is the reader's job and
    /// nothing downstream can do it later. Stated in the Testing-Phase because
    /// "the netlist's own units" left `w=1u` as either `1e-6` or `1`, which is a
    /// factor of a million in every parametric LVS comparison. `lvs` attaches
    /// the dimension when it compares; the scale is already right.
    pub param: Vec<(StrId, f64)>,

    /// One row per subcircuit instance — an `X` card — in file order.
    ///
    /// Added in the Testing-Phase. Nothing pointed a row at a [`SubcktId`], so
    /// no netlist a caller could build contained an instantiation at all: the
    /// SPICE reader had nowhere to put an `X` card, [`Netlist::top`] — "the one
    /// nothing else instantiates" — had no input that exercised its search, and
    /// `lvs`'s `PlanError::Cyclic` and `Inconclusive::AmbiguousTop` were
    /// unreachable from any input, cycles and ambiguity both being properties of
    /// this edge.
    ///
    /// A separate table rather than a [`DeviceKind`](crate::deck::DeviceKind)
    /// variant: an instance is not a device family, it has no model to compare
    /// and no parameters to match, and adding it to that enum would put it in
    /// the deck's device recogniser, where geometry can never produce one.
    ///
    /// The parent is a column, as it is for nets, rather than a CSR range off
    /// the subcircuit: an empty instance table then means exactly "nothing is
    /// instantiated" for any number of subcircuits, so a default-constructed
    /// `Netlist` and every fixture that spreads one stay valid.
    pub instance_name: Vec<StrId>,
    /// The subcircuit each instance instantiates — the callee.
    pub instance_of: Vec<SubcktId>,
    /// The subcircuit each instance sits in — the caller. Together with
    /// `instance_of` this is the only cell-to-cell edge in the netlist, and so
    /// the only place a hierarchy cycle can be stated.
    pub instance_subckt: Vec<SubcktId>,
    /// Terminals, CSR into `instance_terminal_net`. Positional, matching the
    /// instantiated subcircuit's `port_net` order — that correspondence is the
    /// whole content of an `X` card and dropping it would silently disconnect
    /// the hierarchy.
    pub instance_terminal_start: Vec<u32>,
    pub instance_terminal_net: Vec<RefNetId>,

    /// One row per net.
    pub net_name: Vec<StrId>,
    pub net_subckt: Vec<SubcktId>,
}

impl Netlist {
    pub fn subckt_count(&self) -> usize {
        debug_assert!(
            self.subckt_name.is_empty()
                || self.subckt_port_start.len() == self.subckt_name.len() + 1,
            "the port CSR column carries one entry per subcircuit plus a terminator"
        );
        self.subckt_name.len()
    }
    pub fn devices_of(&self, subckt: SubcktId) -> std::ops::Range<u32> {
        let row = subckt.0 as usize;
        debug_assert!(
            row + 1 < self.subckt_device_start.len(),
            "subcircuit {row} is past the end of the device CSR column"
        );
        let (first, last) = (
            self.subckt_device_start[row],
            self.subckt_device_start[row + 1],
        );
        debug_assert!(
            first <= last && last as usize <= self.device_name.len(),
            "subcircuit {row}'s device range {first}..{last} leaves the device table"
        );
        first..last
    }
    pub fn terminals_of(&self, device: RefDeviceId) -> &[RefNetId] {
        csr(
            &self.device_terminal_start,
            &self.terminal_net,
            device.0 as usize,
        )
    }
    pub fn params_of(&self, device: RefDeviceId) -> &[(StrId, f64)] {
        csr(&self.device_param_start, &self.param, device.0 as usize)
    }
    /// The nets one instance's terminals attach to, in port order.
    pub fn instance_terminals_of(&self, instance: RefInstanceId) -> &[RefNetId] {
        csr(
            &self.instance_terminal_start,
            &self.instance_terminal_net,
            instance.0 as usize,
        )
    }
    /// The top-level subcircuit — the one nothing else instantiates, by way of
    /// `instance_of`.
    ///
    /// `None` when there is no unique top, which is an ambiguity `lvs` must
    /// refuse rather than resolve by guessing. A netlist with no subcircuits has
    /// no top; one whose only subcircuit instantiates itself has none either,
    /// since it appears in `instance_of`.
    pub fn top(&self) -> Option<SubcktId> {
        let subckts = self.subckt_count();

        // A scatter: `instance_of` supplies the write *address*, so the output
        // index is data-dependent and the loop is unvectorisable without
        // lane-conflict detection. It is nevertheless the finished form: the
        // store is already unconditional and there is no branch left to remove.
        let mut instantiated = vec![false; subckts];
        for &callee in &self.instance_of {
            debug_assert!(
                (callee.0 as usize) < subckts,
                "an instance names subcircuit {} of {subckts}",
                callee.0
            );
            instantiated[callee.0 as usize] = true;
        }

        // Count the uninstantiated subcircuits and keep the last one seen; when
        // the count is one, that is the only one. A strict ascending fold, so
        // "last seen" means the highest row. The select is arithmetic — `used`
        // widens to 0/1 and blends the two candidates — so the body carries no
        // data-dependent branch.
        // `narrow` once above the loop, so the row index rides in a `u32`
        // without a per-row conversion and without a truncating cast.
        let rows = narrow(subckts);
        let mut free = 0u32;
        let mut top = 0u32;
        for row in 0..rows {
            let uninstantiated = u32::from(!instantiated[row as usize]);
            free += uninstantiated;
            top = uninstantiated * row + (1 - uninstantiated) * top;
        }
        debug_assert!(
            free as usize <= subckts,
            "more uninstantiated subcircuits than subcircuits"
        );
        debug_assert!(free != 1 || (top as usize) < subckts);
        (free == 1).then_some(SubcktId(top))
    }
}

// ---------------------------------------------------------------------------
// The shared reader.
//
// Both dialects are the same three steps over the same tables — lex to cards,
// collect the definitions, then read each card — so there is one
// implementation and the two `read`s below name a dialect. The surface syntax
// differs in four places and nowhere else: the comment marker, the
// continuation marker, whether parentheses wrap a terminal list, and how a
// device's family is named.
//
// SIMD/bulk triage: every loop here is a *chain*. A token's start is only known
// once the previous one has been scanned, interning mutates the string table in
// sequence, and a card parser branches on the card's own text. A chain is the
// blocker `/simd-loops` names, so the loops below stay scalar and their
// branches are the parse itself rather than a predicate over bulk data. The
// counts are file-sized and read once per run, not polygon-sized and read per
// rule.
// ---------------------------------------------------------------------------

/// Which surface syntax a card is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Spice,
    Spectre,
}

/// One whitespace-separated token and the place a human should be sent to.
#[derive(Debug, Clone, Copy)]
struct Tok<'a> {
    text: &'a str,
    span: SourceSpan,
}

/// `net_of`'s "this name is not a net of the open subcircuit".
const NO_NET: u32 = u32::MAX;

/// The port-count scan's "no instance is miswired" accumulator sentinel.
const NO_ROW: u32 = u32::MAX;

/// The subcircuit keyword, for the one error that names it without a token.
const fn subckt_keyword(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Spice => ".subckt",
        Dialect::Spectre => "subckt",
    }
}

/// Drop a card's comment. Returns the text left to lex, which may be empty.
fn strip_comment(raw: &str, dialect: Dialect) -> &str {
    let lead = raw.trim_start();
    if lead.starts_with('*') || (dialect == Dialect::Spectre && lead.starts_with("//")) {
        return "";
    }
    let cut = match dialect {
        Dialect::Spice => raw.find(['$', ';']),
        Dialect::Spectre => raw.find("//"),
    };
    cut.map_or(raw, |at| &raw[..at])
}

/// Spectre wraps a terminal list in parentheses and SPICE does not. Both then
/// read as "the last positional token is the master", so the parentheses carry
/// no information past the lexer and are separators. The dialect is a uniform,
/// not per-token data.
fn is_separator(c: char, dialect: Dialect) -> bool {
    c.is_whitespace() || (dialect == Dialect::Spectre && (c == '(' || c == ')'))
}

/// Lex `source` into tokens grouped into logical cards. **Transform, A-to-B.**
///
/// In: text. Out: one token arena plus a CSR column of card starts, with
/// `card_start.len() == cards + 1`. Comments are dropped and a continuation
/// line is folded into the card it continues — SPICE marks one with a leading
/// `+`, Spectre with a trailing `\` on the line before — so a card's first
/// token sits on the line a human is told about.
fn lex(source: &str, dialect: Dialect) -> (Vec<Tok<'_>>, Vec<u32>) {
    let mut toks: Vec<Tok<'_>> = Vec::new();
    let mut card_start: Vec<u32> = Vec::new();
    let mut fold_next = false;

    for (index, raw) in source.lines().enumerate() {
        let line = narrow(index) + 1;
        let mut rest = strip_comment(raw, dialect);
        let mut continues = fold_next;
        fold_next = false;
        match dialect {
            Dialect::Spice => {
                if let Some(after) = rest.trim_start().strip_prefix('+') {
                    rest = after;
                    continues = true;
                }
            }
            Dialect::Spectre => {
                let trimmed = rest.trim_end();
                rest = match trimmed.strip_suffix('\\') {
                    Some(head) => {
                        fold_next = true;
                        head
                    }
                    None => trimmed,
                };
            }
        }

        // Hoisted above the token loop: whether this line opens a card is a
        // property of the line, not of any token in it.
        let base = raw.as_ptr() as usize;
        let mut tokens = rest
            .split(|c| is_separator(c, dialect))
            .filter(|t| !t.is_empty())
            .peekable();
        if tokens.peek().is_some() && (!continues || card_start.is_empty()) {
            card_start.push(narrow(toks.len()));
        }
        for text in tokens {
            let column = narrow(text.as_ptr() as usize - base) + 1;
            toks.push(Tok {
                text,
                span: SourceSpan { line, column },
            });
        }
    }

    card_start.push(narrow(toks.len()));
    debug_assert!(!card_start.is_empty(), "the terminator is always pushed");
    debug_assert!(
        card_start.windows(2).all(|w| w[0] <= w[1]),
        "card starts are not ascending"
    );
    (toks, card_start)
}

/// A SPICE numeric literal, in SI base units. **Decision.**
///
/// One token in, one `f64` out. The scale suffix is part of the number's
/// syntax rather than a unit annotation — `1u` is `1e-6` and a bare `1` is one
/// metre — so expanding it is the reader's job and nothing downstream can do it
/// later. Letters after the suffix are the unit a human wrote and SPICE ignores
/// them, so `1uF` is also `1e-6`. An unrecognised suffix is `None`, not a
/// silent factor of one.
fn spice_number(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let mut at = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let digits = at;
    while at < bytes.len() && bytes[at].is_ascii_digit() {
        at += 1;
    }
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
    }
    if at == digits {
        return None;
    }
    // An `e` is an exponent only when a digit follows it, with or without a
    // sign. `1e` on its own is not a number this reader guesses at.
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        let mut exponent = at + 1;
        exponent += usize::from(matches!(bytes.get(exponent), Some(b'+' | b'-')));
        if bytes.get(exponent).is_some_and(u8::is_ascii_digit) {
            at = exponent;
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                at += 1;
            }
        }
    }

    let suffix = &bytes[at..];
    let head = &suffix[..suffix.len().min(3)];
    // `meg` and `mil` before `m`: longest match first, or a megohm reads as a
    // milliohm and a parametric LVS comparison is out by 1e9.
    let scale = if head.eq_ignore_ascii_case(b"meg") {
        1e6
    } else if head.eq_ignore_ascii_case(b"mil") {
        25.4e-6
    } else {
        match suffix.first().map(u8::to_ascii_lowercase) {
            None => 1.0,
            Some(b't') => 1e12,
            Some(b'g') => 1e9,
            Some(b'x') => 1e6,
            Some(b'k') => 1e3,
            Some(b'm') => 1e-3,
            Some(b'u') => 1e-6,
            Some(b'n') => 1e-9,
            Some(b'p') => 1e-12,
            Some(b'f') => 1e-15,
            Some(b'a') => 1e-18,
            Some(_) => return None,
        }
    };

    let value = text[..at].parse::<f64>().ok()? * scale;
    value.is_finite().then_some(value)
}

/// Split a card's tail into its positional tokens and its `k=v` tokens.
///
/// A positional token *after* a parameter is refused rather than read as a
/// terminal: every dialect here states all terminals before the first
/// parameter, so a card that does not is outside the subset.
fn split_params<'t>(card: &'t [Tok<'t>]) -> Result<(&'t [Tok<'t>], &'t [Tok<'t>]), NetlistError> {
    let tail = &card[1..];
    let at = tail
        .iter()
        .position(|t| t.text.contains('='))
        .unwrap_or(tail.len());
    let (positional, params) = tail.split_at(at);
    match params.iter().find(|t| !t.text.contains('=')) {
        Some(stray) => Err(NetlistError::Unexpected(stray.span, stray.text.to_string())),
        None => Ok((positional, params)),
    }
}

/// Split a device card's positional tokens into its terminals and its model,
/// refusing a terminal count this device family does not have.
fn split_terminals<'t>(
    kind: DeviceKind,
    positional: &'t [Tok<'t>],
    head: Tok<'t>,
) -> Result<(&'t [Tok<'t>], Tok<'t>), NetlistError> {
    let want: u32 = match kind {
        DeviceKind::Mos => 4,
        DeviceKind::Bjt => 3,
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode => 2,
    };
    let got = narrow(positional.len().saturating_sub(1));
    // A `Q` card states its substrate terminal or leaves it out — "then
    // substrate if stated", per `terminal_net`'s own table. Nothing else in the
    // subset has an optional terminal.
    let stated = got == want || (kind == DeviceKind::Bjt && got == 4);
    if !stated {
        return Err(NetlistError::TerminalCount(
            head.span,
            head.text.to_string(),
            got,
            want,
        ));
    }
    let (model, nets) = positional
        .split_last()
        .expect("a stated terminal count is at least one less than the positional count");
    Ok((nets, *model))
}

/// The Spectre primitive masters this subset reads.
///
/// Every Spectre built-in device master that lands in one of
/// [`DeviceKind`](crate::deck::DeviceKind)'s five families, plus the four SPICE
/// model types (`nmos`, `pmos`, `npn`, `pnp`) a mixed-flow netlist writes in the
/// same position. The MOS entries are the compact-model names a foundry model
/// card names as its master — a `model` card of its own reaches
/// [`Build::models`] and never gets here, so this list is what an *instance*
/// may name directly.
///
/// A master outside the list is `Unsupported` with its line, never guessed at
/// from its terminal count: a four-terminal master read as a MOS when it is a
/// four-terminal subcircuit produces an LVS mismatch that reads as a layout bug.
/// Spectre's remaining built-ins — `inductor`, `vsource`, `isource`, the
/// controlled sources, `switch`, `tline` — have no `DeviceKind` variant to land
/// in, so they stay `Unsupported`; see `docs/SIGNATURE_DEFECTS.md`.
///
/// The match is over a fixed compile-time vocabulary and runs once per instance
/// card, so it is a `match` rather than a table. Spectre is case-sensitive, so
/// this is too.
fn spectre_primitive(master: &str) -> Option<DeviceKind> {
    Some(match master {
        "resistor" | "res" => DeviceKind::Resistor,
        "capacitor" | "cap" => DeviceKind::Capacitor,
        "diode" => DeviceKind::Diode,
        "bjt" | "npn" | "pnp" | "vbic" | "hicum" | "mextram" => DeviceKind::Bjt,
        "mos" | "nmos" | "pmos" | "mos0" | "mos1" | "mos2" | "mos3" | "mos9" | "bsim1"
        | "bsim2" | "bsim3" | "bsim3v3" | "bsim4" | "bsim4v5" | "bsimsoi" | "bsimcmg"
        | "hisim" | "hisim2" | "hisimhv" | "psp" | "ekv" => DeviceKind::Mos,
        _ => return None,
    })
}

/// The tables under construction, plus the three side tables a parse needs and
/// a [`Netlist`] does not carry.
struct Build<'a> {
    strings: &'a mut StrTable,
    out: Netlist,
    /// `net_of[name.0]` is the [`RefNetId`] that name has in the subcircuit
    /// currently open, or [`NO_NET`]. A dense side table rather than a map: net
    /// names are already interned to a dense `u32`, so a lookup is one indexed
    /// load where a `HashMap` would be a hash per terminal. It is reset per
    /// subcircuit by walking only the rows that subcircuit created.
    net_of: Vec<u32>,
    /// Definitions sorted by interned name, for binary search. Sorted rather
    /// than hashed for the reason `StrTable` is: one iteration order on every
    /// machine.
    defs: Vec<(StrId, SubcktId)>,
    /// Spectre `model` cards, sorted the same way.
    models: Vec<(StrId, DeviceKind)>,
    /// The open subcircuit and the `net_name` row its nets start at.
    open: Option<(SubcktId, u32)>,
    open_span: SourceSpan,
    /// Where each instance was written, for the arity check at end of file.
    instance_span: Vec<SourceSpan>,
}

impl Build<'_> {
    /// The net a name denotes in `subckt`, creating it on first mention.
    fn net(&mut self, name: &str, subckt: SubcktId) -> RefNetId {
        let id = self.strings.intern(name);
        let slot = id.0 as usize;
        if slot >= self.net_of.len() {
            self.net_of.resize(slot + 1, NO_NET);
        }
        if self.net_of[slot] != NO_NET {
            return RefNetId(self.net_of[slot]);
        }
        let row = narrow(self.out.net_name.len());
        debug_assert_ne!(
            row, NO_NET,
            "the last addressable net row is also `net_of`'s absent sentinel, so \
             every later mention of this name would create a second row for it"
        );
        self.out.net_name.push(id);
        self.out.net_subckt.push(subckt);
        self.net_of[slot] = row;
        RefNetId(row)
    }

    /// The subcircuit a card sits in. A card outside every subcircuit has no
    /// row to land in — this netlist has no top-level cell — so it is outside
    /// the subset rather than silently dropped.
    fn open_id(&self, head: Tok) -> Result<SubcktId, NetlistError> {
        self.open
            .map(|(id, _)| id)
            .ok_or_else(|| NetlistError::Unsupported(head.span, head.text.to_string()))
    }

    fn open_subckt(&mut self, card: &[Tok], next: &mut u32) -> Result<(), NetlistError> {
        let head = card[0];
        if self.open.is_some() {
            return Err(NetlistError::Unexpected(head.span, head.text.to_string()));
        }
        let name = *card
            .get(1)
            .ok_or_else(|| NetlistError::Unexpected(head.span, head.text.to_string()))?;

        // The definition pass walked these same cards in this same order, so
        // the row it pushed for this definition is `*next`.
        let id = SubcktId(*next);
        *next += 1;
        debug_assert!((id.0 as usize) < self.out.subckt_name.len());
        debug_assert_eq!(
            self.out.subckt_name[id.0 as usize],
            self.strings.intern(name.text),
            "the definition pass and the reading pass disagree on subcircuit order"
        );

        self.out
            .subckt_port_start
            .push(narrow(self.out.port_net.len()));
        self.out
            .subckt_device_start
            .push(narrow(self.out.device_name.len()));
        self.open = Some((id, narrow(self.out.net_name.len())));
        self.open_span = head.span;

        for port in &card[2..] {
            // A parameterised subcircuit has nowhere to keep its parameters.
            if port.text.contains('=') {
                return Err(NetlistError::Unsupported(port.span, port.text.to_string()));
            }
            let net = self.net(port.text, id);
            self.out.port_net.push(net);
        }
        Ok(())
    }

    fn close_subckt(&mut self) {
        let Some((_, first_net)) = self.open.take() else {
            return;
        };
        // A scatter — `net_name[row]` supplies the write address — so it is
        // unvectorisable without lane-conflict detection, for the same reason
        // as `Netlist::top`. It is the finished form: the store is
        // unconditional, the row count is the subcircuit's own net count, and
        // resetting only those rows is what keeps `net_of` a dense table
        // instead of a per-subcircuit map. A generation counter would make the
        // reset O(1) per subcircuit but not per file — every net is reset
        // exactly once either way — while widening the table and adding a
        // compare to every lookup.
        for row in first_net as usize..self.out.net_name.len() {
            self.net_of[self.out.net_name[row].0 as usize] = NO_NET;
        }
    }

    fn param(&mut self, tok: Tok) -> Result<(StrId, f64), NetlistError> {
        let bad = || NetlistError::Unexpected(tok.span, tok.text.to_string());
        let (key, value) = tok.text.split_once('=').ok_or_else(bad)?;
        if key.is_empty() {
            return Err(bad());
        }
        let value = spice_number(value).ok_or_else(bad)?;
        Ok((self.strings.intern(key), value))
    }

    fn device(
        &mut self,
        head: Tok,
        kind: DeviceKind,
        nets: &[Tok],
        model: Tok,
        params: &[Tok],
        subckt: SubcktId,
    ) -> Result<(), NetlistError> {
        // A bare number where a model name belongs is SPICE's positional value
        // form, `R1 a b 1k`. This subset does not read it: interning `1k` as a
        // model would compare a resistor against a model that does not exist,
        // and LVS would report that as a layout bug.
        if spice_number(model.text).is_some() {
            return Err(NetlistError::Unsupported(
                model.span,
                model.text.to_string(),
            ));
        }
        let name = self.strings.intern(head.text);
        let model = self.strings.intern(model.text);
        self.out
            .device_terminal_start
            .push(narrow(self.out.terminal_net.len()));
        self.out
            .device_param_start
            .push(narrow(self.out.param.len()));
        self.out.device_name.push(name);
        self.out.device_model.push(model);
        self.out.device_kind.push(kind);

        // Card order is the role — drain, gate, source, bulk for a `Mos` — so
        // the terminals are pushed exactly as written. Spectre states them in
        // the same order, which is why its reader normalises to this one by
        // doing nothing.
        for net in nets {
            let net = self.net(net.text, subckt);
            self.out.terminal_net.push(net);
        }
        for param in params {
            let param = self.param(*param)?;
            self.out.param.push(param);
        }
        Ok(())
    }

    fn instance(
        &mut self,
        head: Tok,
        cell: Tok,
        nets: &[Tok],
        params: &[Tok],
        subckt: SubcktId,
    ) -> Result<(), NetlistError> {
        // A parameterised instantiation has nowhere to land — the instance
        // table carries no parameters — and dropping them silently would
        // compare against the wrong device sizes.
        if let Some(param) = params.first() {
            return Err(NetlistError::Unsupported(
                param.span,
                param.text.to_string(),
            ));
        }
        let id = self.strings.intern(cell.text);
        let of = self
            .defs
            .binary_search_by_key(&id, |&(name, _)| name)
            .map(|at| self.defs[at].1)
            .map_err(|_| NetlistError::UndefinedSubckt(cell.span, cell.text.to_string()))?;

        let name = self.strings.intern(head.text);
        self.out
            .instance_terminal_start
            .push(narrow(self.out.instance_terminal_net.len()));
        self.out.instance_name.push(name);
        self.out.instance_of.push(of);
        self.out.instance_subckt.push(subckt);
        self.instance_span.push(head.span);
        for net in nets {
            let net = self.net(net.text, subckt);
            self.out.instance_terminal_net.push(net);
        }
        Ok(())
    }
}

/// Is this card a subcircuit definition? Asked by the definition pass, which
/// reads nothing else.
fn is_definition(card: &[Tok], dialect: Dialect) -> bool {
    match dialect {
        Dialect::Spice => card[0].text.eq_ignore_ascii_case(".subckt"),
        Dialect::Spectre => card[0].text == "subckt",
    }
}

/// One SPICE or CDL card.
///
/// Card keywords are a fixed compile-time vocabulary, so dispatch is a `match`
/// on the leading token rather than a map lookup.
fn spice_card(b: &mut Build, card: &[Tok], next: &mut u32) -> Result<(), NetlistError> {
    let head = card[0];
    if let Some(word) = head.text.strip_prefix('.') {
        if word.eq_ignore_ascii_case("subckt") {
            return b.open_subckt(card, next);
        }
        if word.eq_ignore_ascii_case("ends") || word.eq_ignore_ascii_case("end") {
            b.close_subckt();
            return Ok(());
        }
        return Err(NetlistError::Unsupported(head.span, head.text.to_string()));
    }

    let subckt = b.open_id(head)?;
    let (positional, params) = split_params(card)?;
    let kind = match head.text.as_bytes()[0].to_ascii_uppercase() {
        b'M' => DeviceKind::Mos,
        b'Q' => DeviceKind::Bjt,
        b'R' => DeviceKind::Resistor,
        b'C' => DeviceKind::Capacitor,
        b'D' => DeviceKind::Diode,
        b'X' => {
            let (cell, nets) = positional
                .split_last()
                .ok_or_else(|| NetlistError::Unexpected(head.span, head.text.to_string()))?;
            return b.instance(head, *cell, nets, params, subckt);
        }
        _ => return Err(NetlistError::Unsupported(head.span, head.text.to_string())),
    };
    let (nets, model) = split_terminals(kind, positional, head)?;
    b.device(head, kind, nets, model, params, subckt)
}

/// One Spectre statement.
fn spectre_card(b: &mut Build, card: &[Tok], next: &mut u32) -> Result<(), NetlistError> {
    let head = card[0];
    match head.text {
        "subckt" => return b.open_subckt(card, next),
        "ends" | "endsubckt" => {
            b.close_subckt();
            return Ok(());
        }
        "model" => {
            let (name, master) = match card {
                [_, name, master, ..] => (*name, *master),
                _ => return Err(NetlistError::Unexpected(head.span, head.text.to_string())),
            };
            let kind = spectre_primitive(master.text)
                .ok_or_else(|| NetlistError::Unsupported(master.span, master.text.to_string()))?;
            let id = b.strings.intern(name.text);
            match b.models.binary_search_by_key(&id, |&(n, _)| n) {
                Ok(_) => return Err(NetlistError::Redefined(name.span, name.text.to_string())),
                Err(at) => b.models.insert(at, (id, kind)),
            }
            return Ok(());
        }
        _ => {}
    }

    // An instance statement: `name (nets…) master [params]`. Everything else
    // the language has — `alter`, a sweep, an `inline subckt`, `parameters` —
    // is outside the declared subset and is refused at its line rather than
    // skipped, because a skipped statement is a netlist missing whatever it
    // said. Classification comes before "is a subcircuit open", so a statement
    // between subcircuits is refused as unsupported rather than as misplaced.
    let (positional, params) = split_params(card)?;
    let unsupported = || NetlistError::Unsupported(head.span, head.text.to_string());
    let (master, nets) = positional.split_last().ok_or_else(unsupported)?;
    let master_id = b.strings.intern(master.text);

    if b.defs
        .binary_search_by_key(&master_id, |&(name, _)| name)
        .is_ok()
    {
        let subckt = b.open_id(head)?;
        return b.instance(head, *master, nets, params, subckt);
    }
    let kind = b
        .models
        .binary_search_by_key(&master_id, |&(name, _)| name)
        .map(|at| b.models[at].1)
        .ok()
        .or_else(|| spectre_primitive(master.text))
        .ok_or_else(unsupported)?;
    let subckt = b.open_id(head)?;
    let (nets, model) = split_terminals(kind, positional, head)?;
    b.device(head, kind, nets, model, params, subckt)
}

/// Read a reference netlist in either dialect. **Transform, generative.**
///
/// In: text plus the run's string table. Out: the [`Netlist`] tables, or the
/// first thing outside the declared subset with the line it sits on.
///
/// Two passes over the cards. The first collects every definition, so a call
/// may precede the `.subckt` it names and still be resolved at the call's own
/// line; a name defined twice is refused there rather than after the file has
/// been read. The second reads every card against those definitions.
fn read_dialect(
    source: &str,
    strings: &mut StrTable,
    dialect: Dialect,
) -> Result<Netlist, NetlistError> {
    let (toks, card_start) = lex(source, dialect);
    let cards = card_start.len() - 1;
    let mut b = Build {
        strings,
        out: Netlist::default(),
        net_of: Vec::new(),
        defs: Vec::new(),
        models: Vec::new(),
        open: None,
        open_span: SourceSpan { line: 0, column: 0 },
        instance_span: Vec::new(),
    };

    let card = |c: usize| &toks[card_start[c] as usize..card_start[c + 1] as usize];

    for c in 0..cards {
        let card = card(c);
        if !is_definition(card, dialect) {
            continue;
        }
        let head = card[0];
        let name = *card
            .get(1)
            .ok_or_else(|| NetlistError::Unexpected(head.span, head.text.to_string()))?;
        let id = b.strings.intern(name.text);
        match b.defs.binary_search_by_key(&id, |&(n, _)| n) {
            Ok(_) => return Err(NetlistError::Redefined(head.span, name.text.to_string())),
            Err(at) => {
                let subckt = SubcktId(narrow(b.out.subckt_name.len()));
                b.out.subckt_name.push(id);
                b.defs.insert(at, (id, subckt));
            }
        }
    }

    let mut next = 0u32;
    for c in 0..cards {
        match dialect {
            Dialect::Spice => spice_card(&mut b, card(c), &mut next)?,
            Dialect::Spectre => spectre_card(&mut b, card(c), &mut next)?,
        }
    }
    if b.open.is_some() {
        return Err(NetlistError::Unexpected(
            b.open_span,
            subckt_keyword(dialect).to_string(),
        ));
    }
    debug_assert_eq!(
        next as usize,
        b.out.subckt_name.len(),
        "the reading pass opened a different number of subcircuits than the definition pass found"
    );

    // The terminating entry of every CSR offset column.
    b.out.subckt_port_start.push(narrow(b.out.port_net.len()));
    b.out
        .subckt_device_start
        .push(narrow(b.out.device_name.len()));
    b.out
        .device_terminal_start
        .push(narrow(b.out.terminal_net.len()));
    b.out.device_param_start.push(narrow(b.out.param.len()));
    b.out
        .instance_terminal_start
        .push(narrow(b.out.instance_terminal_net.len()));

    // Fail closed on a miswired instantiation: an instance with the wrong
    // number of nets silently disconnects the hierarchy, which LVS reports as a
    // layout bug. The callee may be defined after the call, so this is the
    // first point every port count is known.
    //
    // Find, then report. The scan body has no panic edge and no error return:
    // it carries the lowest offending row in the accumulator, and the one
    // branch that builds the error sits outside it. That leaves the scan itself
    // branchless over every instance in the file: the callee's port count is a
    // gather off `subckt_port_start`, the instance's own terminal count comes
    // from two offset views of one CSR column — the adjacent-pair shape — and
    // the "is this row an offender" decision is a select rather than an `if`.
    let instances = b.out.instance_name.len();
    let port_start = &b.out.subckt_port_start[..];
    debug_assert!(
        {
            let mut worst = 0u32;
            for row in 0..b.out.instance_of.len() {
                worst = worst.max(b.out.instance_of[row].0);
            }
            worst as usize + 1 < port_start.len().max(2)
        },
        "an instance names a subcircuit with no port range"
    );
    debug_assert!(
        instances < NO_ROW as usize,
        "u32::MAX is the no-offender sentinel and cannot also be an instance row"
    );
    let of_col = &b.out.instance_of[..];
    let first_col = &b.out.instance_terminal_start[..instances];
    let last_col = &b.out.instance_terminal_start[1..];
    debug_assert_eq!(of_col.len(), instances, "SoA columns must agree");
    debug_assert_eq!(first_col.len(), instances, "SoA columns must agree");
    debug_assert_eq!(last_col.len(), instances, "SoA columns must agree");

    let mut offender = NO_ROW;
    for row in 0..narrow(instances) {
        let i = row as usize;
        let of = of_col[i].0 as usize;
        let want = port_start[of + 1] - port_start[of];
        // A match smears to all-ones and swallows the row, a mismatch smears to
        // zero and lets it through; `min` then keeps the earliest offender,
        // which is the row a `break` would have stopped on. One loop, so "every
        // instance was scanned" is the trip count itself rather than a counter.
        let matched = u32::from(last_col[i] - first_col[i] == want);
        offender = offender.min(row | matched.wrapping_neg());
    }
    debug_assert!(offender == NO_ROW || (offender as usize) < instances);
    if offender != NO_ROW {
        let row = offender as usize;
        let of = b.out.instance_of[row].0 as usize;
        let want = port_start[of + 1] - port_start[of];
        let got = b.out.instance_terminal_start[row + 1] - b.out.instance_terminal_start[row];
        debug_assert_ne!(got, want, "the scan named a row whose arity agrees");
        let name = b.strings.resolve(b.out.instance_name[row]).to_string();
        return Err(NetlistError::TerminalCount(
            b.instance_span[row],
            name,
            got,
            want,
        ));
    }

    let out = b.out;
    debug_assert_eq!(out.subckt_port_start.len(), out.subckt_name.len() + 1);
    debug_assert_eq!(out.subckt_device_start.len(), out.subckt_name.len() + 1);
    debug_assert_eq!(out.device_terminal_start.len(), out.device_name.len() + 1);
    debug_assert_eq!(out.device_param_start.len(), out.device_name.len() + 1);
    debug_assert_eq!(out.device_model.len(), out.device_name.len());
    debug_assert_eq!(out.device_kind.len(), out.device_name.len());
    debug_assert_eq!(
        out.instance_terminal_start.len(),
        out.instance_name.len() + 1
    );
    debug_assert_eq!(out.instance_of.len(), out.instance_name.len());
    debug_assert_eq!(out.instance_subckt.len(), out.instance_name.len());
    debug_assert_eq!(out.net_subckt.len(), out.net_name.len());
    debug_assert!(
        {
            let mut worst = 0u32;
            for row in 0..out.terminal_net.len() {
                worst = worst.max(out.terminal_net[row].0);
            }
            worst < narrow(out.net_name.len()).max(1)
        },
        "a terminal names a net row that does not exist"
    );
    debug_assert!(
        {
            let mut worst = 0u32;
            for row in 0..out.port_net.len() {
                worst = worst.max(out.port_net[row].0);
            }
            worst < narrow(out.net_name.len()).max(1)
        },
        "a port names a net row that does not exist"
    );
    Ok(out)
}

/// SPICE and CDL.
///
/// Card keywords are a fixed compile-time vocabulary, so dispatch is a `match`
/// on the leading token rather than a map lookup.
pub mod spice {
    use super::{Netlist, NetlistError};
    use crate::intern::StrTable;

    pub fn read(source: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError> {
        super::read_dialect(source, strings, super::Dialect::Spice)
    }
}

/// Spectre.
///
/// A different surface syntax over the same model, so it produces the same
/// [`Netlist`] and everything downstream is unchanged.
///
/// # Declared subset
///
/// No `inline subckt`, no `alter`, no sweeps. Anything outside the subset is
/// `NetlistError::Unsupported` with the line it sits on. That is the reader's
/// stated interface rather than an unfinished corner, and each exclusion is the
/// same refusal for a different reason:
///
/// - `alter` and a sweep are simulator control, not circuit structure. There is
///   no [`Netlist`] column for a corner or a swept parameter, so accepting one
///   would mean reading it and dropping it — a netlist quietly missing what the
///   statement said.
/// - An `inline subckt` scopes its ports into the enclosing cell rather than
///   away from it. Reading it as a plain `subckt` would be a guess about
///   connectivity, and a wrong guess reconnects nets: exactly the misparse this
///   module's header refuses to make.
///
/// Widening any of these needs somewhere for the meaning to land, not a looser
/// parser.
pub mod spectre {
    use super::{Netlist, NetlistError};
    use crate::intern::StrTable;

    pub fn read(source: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError> {
        super::read_dialect(source, strings, super::Dialect::Spectre)
    }
}

