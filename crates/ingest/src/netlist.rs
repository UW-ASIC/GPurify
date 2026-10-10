//! Reference-netlist readers: SPICE/CDL and Spectre.
//!
//! Data in: netlist text and the run's `StrTable`. Data out: [`Netlist`], hierarchy kept.
//! Anything outside the declared subset is an error with its source line, never a guess.
//!
//! # The subset
//!
//! Both dialects: subcircuit definitions with ports, device cards with every
//! terminal written before any `name=value` parameter, and subcircuit
//! instances. A call may come before the definition it names. Every device
//! and instance card sits inside a subcircuit.
//!
//! - **SPICE/CDL** ([`spice::read`]): `.subckt`/`.ends` (`.end` also closes),
//!   `M`, `Q`, `R`, `C`, `D` and `X` cards, `+` continuation lines, `*` comment
//!   lines and `$` or `;` trailing comments. Card letters and dot keywords
//!   are case-insensitive and parameter names are stored lowercase; net and
//!   cell names keep their case. An `X` card calling a model the deck's
//!   `device` statements name, with no `.subckt` of that name, is that device.
//! - **Spectre** ([`spectre::read`]): `subckt`/`ends`, `model <name> <master>`
//!   cards, and instances `name (nets) master params` of a subcircuit, a
//!   `model`, or a built-in primitive master; `\` continuation, `//` comments.
//!   Case-sensitive.
//!
//! Refused with [`NetlistError::Unsupported`]: any other dot card (`.param`,
//! `.include`, `.global`, `.model`, …), sources and other element letters,
//! SPICE's positional value form (`R1 a b 1k`), parameters on a `.subckt`
//! line or an `X` card, and a card outside every subcircuit.

use crate::deck::DeviceKind;
use crate::narrow;
use gpurify_geom::{StrId, StrTable};

/// Where a token came from: its 1-based line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    /// 1-based line number in the netlist text; a continued card reports the
    /// line the token is on.
    pub line: u32,
}

/// Why a netlist was refused. Each but [`NetlistError::Io`] carries the line
/// and the offending token.
#[derive(Debug, Clone, thiserror::Error)]
pub enum NetlistError {
    /// A token that does not fit the card: a missing name, a malformed
    /// `name=value`, a positional token after a parameter, a subcircuit opened
    /// inside another or never closed.
    #[error("line {}: unexpected token {1}", .0.line)]
    Unexpected(SourceSpan, String),
    /// A construct outside the subset the module documents.
    #[error("line {}: {1} is not in the supported subset", .0.line)]
    Unsupported(SourceSpan, String),
    /// An instance of a subcircuit the file never defines.
    #[error("line {}: subcircuit {1} is called but never defined", .0.line)]
    UndefinedSubckt(SourceSpan, String),
    /// A subcircuit, or a Spectre `model`, defined twice.
    #[error("line {}: {1} is defined twice", .0.line)]
    Redefined(SourceSpan, String),
    /// A device or instance with the wrong number of terminals: got, then
    /// expected. A MOS takes 4, a BJT 3 or 4, a two-pin device 2, an instance
    /// its subcircuit's port count.
    #[error("line {}: device {1} has {2} terminals, expected {3}", .0.line)]
    TerminalCount(SourceSpan, String, u32, u32),
    /// A subcircuit that places itself, directly or through others: the
    /// hierarchy cannot be flattened ([`Netlist::flatten_top`]).
    #[error("subcircuit {0} places itself through its instances")]
    CyclicHierarchy(String),
    /// The netlist file could not be read. The readers never return it; a
    /// caller reading the file does.
    #[error("io: {0}")]
    Io(String),
}

/// Identifies a subcircuit definition: its position in file order, from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SubcktId(pub u32);

/// Identifies a net: a row of [`Netlist::net_name`]. Every row belongs to
/// exactly one subcircuit ([`Netlist::net_subckt`]), so the same name in two
/// subcircuits is two nets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RefNetId(pub u32);

/// A parsed reference netlist, hierarchy preserved.
///
/// Columns are grouped into tables that share a row index. Each `*_start`
/// column is CSR: one longer than its table, row `i` owning
/// `start[i]..start[i + 1]` of the column it indexes.
#[derive(Debug, Default)]
pub struct Netlist {
    /// One row per subcircuit definition, indexed by [`SubcktId`].
    pub subckt_name: Vec<StrId>,
    /// Ports, as a CSR range into `port_net`.
    pub subckt_port_start: Vec<u32>,
    /// Every subcircuit's port nets, in the order the definition lists them.
    pub port_net: Vec<RefNetId>,
    /// Devices belonging to each subcircuit, CSR into the device columns.
    /// [`Netlist::devices_of`] reads it.
    pub subckt_device_start: Vec<u32>,

    /// One row per device instance (not per subcircuit instance): its model
    /// name, interned.
    pub device_model: Vec<StrId>,
    /// The device's family, from its card letter, its Spectre master, or the
    /// deck `device` statement an `X` card called.
    pub device_kind: Vec<crate::deck::DeviceKind>,
    /// Terminals, CSR into `terminal_net`.
    pub device_terminal_start: Vec<u32>,
    /// The nets a device's terminals attach to, **in the card's order, which is
    /// the role**.
    ///
    /// | [`crate::deck::DeviceKind`] | order, from the card |
    /// |---|---|
    /// | `Mos` (`M`) | drain, gate, source, bulk |
    /// | `Bjt` (`Q`) | collector, base, emitter, then substrate if stated |
    /// | `Resistor`, `Capacitor`, `Diode` | pin 0, pin 1 |
    ///
    /// SPICE's own card order; the Spectre reader normalises to it. **Not**
    /// `DeviceRecognition`'s order, which lists gate first.
    pub terminal_net: Vec<RefNetId>,
    /// Parameters, CSR into `param`.
    pub device_param_start: Vec<u32>,
    /// Interned name and value, in SI base units with scale suffixes already
    /// expanded: `w=1u` is `1e-6` and a bare `w=1` is one metre, except on an
    /// `X` card calling a deck device model, where a bare `w`/`l` is in µm
    /// (the PDK convention, `.option scale=1u`). SPICE names are lowercased.
    pub param: Vec<(StrId, f64)>,

    /// One row per subcircuit instance, an `X` card, in file order: the callee.
    pub instance_of: Vec<SubcktId>,
    /// The subcircuit each instance sits in — the caller. With `instance_of`,
    /// the only cell-to-cell edge, so the only place a cycle can be stated.
    pub instance_subckt: Vec<SubcktId>,
    /// Each instance's name, interned (`X1`).
    pub instance_name: Vec<StrId>,
    /// The caller's nets each instance connects to the callee's ports, in port
    /// order: CSR into `instance_net`, one row per instance plus a final end.
    /// Empty when the netlist has no instances.
    pub instance_net_start: Vec<u32>,
    /// See `instance_net_start`.
    pub instance_net: Vec<RefNetId>,

    /// One row per net, indexed by [`RefNetId`]: its name, interned.
    pub net_name: Vec<StrId>,
    /// The subcircuit each net belongs to.
    pub net_subckt: Vec<SubcktId>,
}

impl Netlist {
    /// Returns the number of subcircuit definitions.
    pub fn subckt_count(&self) -> usize {
        self.subckt_name.len()
    }
    /// Returns the device rows a subcircuit holds directly, not through its
    /// instances. Panics on an id past [`Self::subckt_count`].
    pub fn devices_of(&self, subckt: SubcktId) -> std::ops::Range<u32> {
        let row = subckt.0 as usize;
        self.subckt_device_start[row]..self.subckt_device_start[row + 1]
    }
    /// `top` with every instance below it expanded: one subcircuit holding
    /// every leaf device, wired as the hierarchy wires it.
    ///
    /// The result has a single subcircuit, `top` under its own name and with
    /// its own ports. Its nets are `top`'s, then each instance's internal nets
    /// (those not on a port) under the instance path, `X1.X2.n1`, interned
    /// into `strings`. A device keeps its kind, model and parameters, with its
    /// terminals on the flattened nets. LVS compares devices, not cells, so a
    /// block the schematic places by instance has to be in the comparison; a
    /// graph built from `top`'s own devices alone would let a layout missing
    /// that block match.
    ///
    /// # Errors
    ///
    /// [`NetlistError::CyclicHierarchy`] when a subcircuit places itself.
    ///
    /// # Panics
    ///
    /// On a `top` past [`Self::subckt_count`].
    pub fn flatten_top(
        &self,
        top: SubcktId,
        strings: &mut StrTable,
    ) -> Result<Netlist, NetlistError> {
        let mut out = Netlist {
            subckt_name: vec![self.subckt_name[top.0 as usize]],
            subckt_port_start: vec![0],
            subckt_device_start: vec![0],
            device_terminal_start: vec![0],
            device_param_start: vec![0],
            ..Netlist::default()
        };
        // The caller's nets for `top`: its own, under their own names.
        let own: Vec<RefNetId> = (0..narrow(self.net_name.len()))
            .filter(|&row| self.net_subckt[row as usize] == top)
            .map(RefNetId)
            .collect();
        let mut map = vec![u32::MAX; self.net_name.len()];
        for &net in &own {
            map[net.0 as usize] = narrow(out.net_name.len());
            out.net_name.push(self.net_name[net.0 as usize]);
            out.net_subckt.push(SubcktId(0));
        }
        let ports = self.subckt_port_start[top.0 as usize] as usize
            ..self.subckt_port_start[top.0 as usize + 1] as usize;
        for &port in &self.port_net[ports] {
            out.port_net.push(RefNetId(map[port.0 as usize]));
        }
        out.subckt_port_start.push(narrow(out.port_net.len()));
        let mut on_chain = vec![false; self.subckt_count()];
        self.expand(top, &map, "", strings, &mut on_chain, &mut out)?;
        out.subckt_device_start.push(narrow(out.device_model.len()));
        Ok(out)
    }

    /// Append `cell`'s devices to `out`, its nets mapped by `map` (indexed by
    /// this netlist's net ids, `u32::MAX` for none yet), then each instance in
    /// it, recursively, under `path`.
    fn expand(
        &self,
        cell: SubcktId,
        map: &[u32],
        path: &str,
        strings: &mut StrTable,
        on_chain: &mut [bool],
        out: &mut Netlist,
    ) -> Result<(), NetlistError> {
        let row = cell.0 as usize;
        if on_chain[row] {
            return Err(NetlistError::CyclicHierarchy(
                strings.resolve(self.subckt_name[row]).to_owned(),
            ));
        }
        on_chain[row] = true;
        for device in self.devices_of(cell) {
            let device = device as usize;
            out.device_model.push(self.device_model[device]);
            out.device_kind.push(self.device_kind[device]);
            let terminals = self.device_terminal_start[device] as usize
                ..self.device_terminal_start[device + 1] as usize;
            for &net in &self.terminal_net[terminals] {
                out.terminal_net.push(RefNetId(map[net.0 as usize]));
            }
            out.device_terminal_start
                .push(narrow(out.terminal_net.len()));
            let params = self.device_param_start[device] as usize
                ..self.device_param_start[device + 1] as usize;
            out.param.extend_from_slice(&self.param[params]);
            out.device_param_start.push(narrow(out.param.len()));
        }
        for instance in 0..self.instance_of.len() {
            if self.instance_subckt[instance] != cell {
                continue;
            }
            let callee = self.instance_of[instance];
            let name = strings.resolve(self.instance_name[instance]).to_owned();
            let inner = if path.is_empty() {
                name
            } else {
                format!("{path}.{name}")
            };
            let mut child = vec![u32::MAX; self.net_name.len()];
            // Ports first: each takes the caller's net the instance passes.
            let passed = self.instance_net_start[instance] as usize
                ..self.instance_net_start[instance + 1] as usize;
            let ports = self.subckt_port_start[callee.0 as usize] as usize
                ..self.subckt_port_start[callee.0 as usize + 1] as usize;
            for (&port, &net) in self.port_net[ports].iter().zip(&self.instance_net[passed]) {
                child[port.0 as usize] = map[net.0 as usize];
            }
            // Every other net of the callee is new, named under the path.
            for net in 0..self.net_name.len() {
                if self.net_subckt[net] == callee && child[net] == u32::MAX {
                    let local = strings.resolve(self.net_name[net]).to_owned();
                    child[net] = narrow(out.net_name.len());
                    out.net_name
                        .push(strings.intern(&format!("{inner}.{local}")));
                    out.net_subckt.push(SubcktId(0));
                }
            }
            self.expand(callee, &child, &inner, strings, on_chain, out)?;
        }
        on_chain[row] = false;
        Ok(())
    }

    /// The one subcircuit nothing instantiates. `None` when not unique, or
    /// when there is none: `lvs` refuses, never guesses.
    pub fn top(&self) -> Option<SubcktId> {
        let mut instantiated = vec![false; self.subckt_count()];
        for &callee in &self.instance_of {
            instantiated[callee.0 as usize] = true;
        }
        let mut free = (0..narrow(instantiated.len())).filter(|&row| !instantiated[row as usize]);
        match (free.next(), free.next()) {
            (Some(top), None) => Some(SubcktId(top)),
            _ => None,
        }
    }
}

// The shared reader: lex to cards, collect the definitions, then read each card.

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

/// Spectre's parentheses carry no information past the lexer.
fn is_separator(c: char, dialect: Dialect) -> bool {
    c.is_whitespace() || (dialect == Dialect::Spectre && (c == '(' || c == ')'))
}

/// Lex `source` into tokens plus a CSR column of card starts, comments dropped
/// and continuation lines folded into the card they continue.
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

        let mut tokens = rest
            .split(|c| is_separator(c, dialect))
            .filter(|t| !t.is_empty())
            .peekable();
        if tokens.peek().is_some() && (!continues || card_start.is_empty()) {
            card_start.push(narrow(toks.len()));
        }
        toks.extend(tokens.map(|text| Tok {
            text,
            span: SourceSpan { line },
        }));
    }

    card_start.push(narrow(toks.len()));
    (toks, card_start)
}

/// A SPICE numeric literal, in SI base units with its scale suffix expanded;
/// letters after the suffix are ignored, so `1uF` is `1e-6`. An unrecognised
/// suffix is `None`, not a silent factor of one.
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

/// Split a card's tail into its positional tokens and its `k=v` tokens. A
/// positional token *after* a parameter is refused rather than read as a
/// terminal: every dialect here states all terminals first.
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
    // A `Q` card's substrate terminal is optional; nothing else in the subset
    // has an optional terminal.
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

/// The Spectre primitive masters this subset reads. Case-sensitive, as Spectre
/// is; a master outside the list is `Unsupported` with its line, never guessed
/// at from its terminal count.
fn spectre_primitive(master: &str) -> Option<DeviceKind> {
    Some(match master {
        "resistor" | "res" => DeviceKind::Resistor,
        "capacitor" | "cap" => DeviceKind::Capacitor,
        "diode" => DeviceKind::Diode,
        "bjt" | "npn" | "pnp" | "vbic" | "hicum" | "mextram" => DeviceKind::Bjt,
        "mos" | "nmos" | "pmos" | "mos0" | "mos1" | "mos2" | "mos3" | "mos9" | "bsim1"
        | "bsim2" | "bsim3" | "bsim3v3" | "bsim4" | "bsim4v5" | "bsimsoi" | "bsimcmg" | "hisim"
        | "hisim2" | "hisimhv" | "psp" | "ekv" => DeviceKind::Mos,
        _ => return None,
    })
}

/// The tables under construction, plus the three side tables a parse needs and
/// a [`Netlist`] does not carry.
struct Build<'a> {
    strings: &'a mut StrTable,
    out: Netlist,
    /// `net_of[name.0]` is the [`RefNetId`] that name has in the subcircuit
    /// currently open, or [`NO_NET`]. Reset per subcircuit.
    net_of: Vec<u32>,
    /// Definitions sorted by interned name, for binary search.
    defs: Vec<(StrId, SubcktId)>,
    /// Spectre `model` cards, and for SPICE the deck's device models an `X`
    /// card may call, sorted the same way.
    models: Vec<(StrId, DeviceKind)>,
    /// The open subcircuit and the `net_name` row its nets start at.
    open: Option<(SubcktId, u32)>,
    open_span: SourceSpan,
    /// Per instance: where it was written, its name and terminal count, for the
    /// arity check at end of file.
    instances: Vec<(SourceSpan, StrId, u32)>,
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
        self.out.net_name.push(id);
        self.out.net_subckt.push(subckt);
        self.net_of[slot] = row;
        RefNetId(row)
    }

    /// The subcircuit a card sits in. A card outside every subcircuit has no row
    /// to land in, so it is refused rather than silently dropped.
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
        card.get(1)
            .ok_or_else(|| NetlistError::Unexpected(head.span, head.text.to_string()))?;

        // The definition pass walked the same cards in the same order.
        let id = SubcktId(*next);
        *next += 1;

        self.out
            .subckt_port_start
            .push(narrow(self.out.port_net.len()));
        self.out
            .subckt_device_start
            .push(narrow(self.out.device_model.len()));
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
        for row in first_net as usize..self.out.net_name.len() {
            self.net_of[self.out.net_name[row].0 as usize] = NO_NET;
        }
    }

    /// `micron`: a bare `w`/`l` is in µm, as on a PDK model's `X` card.
    fn param(
        &mut self,
        tok: Tok,
        dialect: Dialect,
        micron: bool,
    ) -> Result<(StrId, f64), NetlistError> {
        let bad = || NetlistError::Unexpected(tok.span, tok.text.to_string());
        let (key, text) = tok.text.split_once('=').ok_or_else(bad)?;
        if key.is_empty() {
            return Err(bad());
        }
        let mut value = spice_number(text).ok_or_else(bad)?;
        // SPICE names are case-insensitive; the layout side compares as `w`.
        let key = match dialect {
            Dialect::Spice => key.to_ascii_lowercase(),
            Dialect::Spectre => key.to_string(),
        };
        let bare = text.ends_with(|c: char| c.is_ascii_digit() || c == '.');
        if micron && bare && (key == "w" || key == "l") {
            value *= 1e-6;
        }
        Ok((self.strings.intern(&key), value))
    }

    fn device(
        &mut self,
        head: Tok,
        kind: DeviceKind,
        nets: &[Tok],
        model: Tok,
        params: &[Tok],
        subckt: SubcktId,
        (dialect, micron): (Dialect, bool),
    ) -> Result<(), NetlistError> {
        // A bare number where a model name belongs is SPICE's positional value
        // form, `R1 a b 1k`, refused rather than interned as a model name.
        if spice_number(model.text).is_some() {
            return Err(NetlistError::Unsupported(
                model.span,
                model.text.to_string(),
            ));
        }
        // Not stored; interned only because interning order is report order.
        self.strings.intern(head.text);
        let model = self.strings.intern(model.text);
        self.out
            .device_terminal_start
            .push(narrow(self.out.terminal_net.len()));
        self.out
            .device_param_start
            .push(narrow(self.out.param.len()));
        self.out.device_model.push(model);
        self.out.device_kind.push(kind);

        // Card order is the role, so terminals are pushed exactly as written.
        for net in nets {
            let net = self.net(net.text, subckt);
            self.out.terminal_net.push(net);
        }
        for param in params {
            let param = self.param(*param, dialect, micron)?;
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
        // A parameterised instantiation has nowhere to land, and dropping the
        // parameters silently would compare against the wrong device sizes.
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
        self.out.instance_of.push(of);
        self.out.instance_subckt.push(subckt);
        self.out.instance_name.push(name);
        self.instances.push((head.span, name, narrow(nets.len())));
        if self.out.instance_net_start.is_empty() {
            self.out.instance_net_start.push(0);
        }
        for net in nets {
            let id = self.net(net.text, subckt);
            self.out.instance_net.push(id);
        }
        self.out
            .instance_net_start
            .push(narrow(self.out.instance_net.len()));
        Ok(())
    }
}

/// Is this card a subcircuit definition?
fn is_definition(card: &[Tok], dialect: Dialect) -> bool {
    match dialect {
        Dialect::Spice => card[0].text.eq_ignore_ascii_case(".subckt"),
        Dialect::Spectre => card[0].text == "subckt",
    }
}

/// One SPICE or CDL card.
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
            // A PDK primitive called as a subcircuit, `XM1 d g s b <model> W=..`:
            // a device when the netlist does not define it and the deck names it.
            let id = b.strings.intern(cell.text);
            let defined = b.defs.binary_search_by_key(&id, |&(n, _)| n).is_ok();
            let model = b.models.binary_search_by_key(&id, |&(n, _)| n);
            return match model {
                Ok(at) if !defined => {
                    let kind = b.models[at].1;
                    let (nets, model) = split_terminals(kind, positional, head)?;
                    b.device(
                        head,
                        kind,
                        nets,
                        model,
                        params,
                        subckt,
                        (Dialect::Spice, true),
                    )
                }
                _ => b.instance(head, *cell, nets, params, subckt),
            };
        }
        _ => return Err(NetlistError::Unsupported(head.span, head.text.to_string())),
    };
    let (nets, model) = split_terminals(kind, positional, head)?;
    b.device(
        head,
        kind,
        nets,
        model,
        params,
        subckt,
        (Dialect::Spice, false),
    )
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

    // An instance statement: `name (nets…) master [params]`. Classification
    // comes before "is a subcircuit open", so a statement between subcircuits is
    // unsupported rather than misplaced.
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
    b.device(
        head,
        kind,
        nets,
        model,
        params,
        subckt,
        (Dialect::Spectre, false),
    )
}

/// Read a reference netlist in either dialect. Two passes: the first collects
/// every definition, so a call may precede the `.subckt` it names.
fn read_dialect(
    source: &str,
    strings: &mut StrTable,
    dialect: Dialect,
    mut models: Vec<(StrId, DeviceKind)>,
) -> Result<Netlist, NetlistError> {
    models.sort_unstable_by_key(|&(name, _)| name);
    models.dedup_by_key(|&mut (name, _)| name);
    let (toks, card_start) = lex(source, dialect);
    let cards = card_start.len() - 1;
    let mut b = Build {
        strings,
        out: Netlist::default(),
        net_of: Vec::new(),
        defs: Vec::new(),
        models,
        open: None,
        open_span: SourceSpan { line: 0 },
        instances: Vec::new(),
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
    // The terminating entry of every CSR offset column.
    b.out.subckt_port_start.push(narrow(b.out.port_net.len()));
    b.out
        .subckt_device_start
        .push(narrow(b.out.device_model.len()));
    b.out
        .device_terminal_start
        .push(narrow(b.out.terminal_net.len()));
    b.out.device_param_start.push(narrow(b.out.param.len()));

    // Fail closed on a miswired instantiation: the first point every port count is known.
    let port_start = &b.out.subckt_port_start;
    for (&(span, name, got), of) in b.instances.iter().zip(&b.out.instance_of) {
        let of = of.0 as usize;
        let want = port_start[of + 1] - port_start[of];
        if got != want {
            let name = b.strings.resolve(name).to_string();
            return Err(NetlistError::TerminalCount(span, name, got, want));
        }
    }
    Ok(b.out)
}

/// SPICE and CDL. The accepted subset is in the [module docs](super).
pub mod spice {
    use super::{Netlist, NetlistError};
    use crate::deck::DeviceRecognition;
    use gpurify_geom::StrTable;

    /// Reads a SPICE or CDL netlist, interning its names into `strings`.
    ///
    /// `devices`: the deck's recognisers, whose models an `X` card may call as
    /// a device (`XM1 d g s b sky130_fd_pr__nfet_01v8 W=0.42 L=0.15`). On such a
    /// card a bare `W`/`L` is in micrometres, as PDK models take it.
    ///
    /// # Errors
    ///
    /// The first [`NetlistError`] found, with its line; nothing partial is
    /// returned. Definitions are read before cards, and instance port counts
    /// checked last, so the first error found need not be the first in the file.
    pub fn read(
        source: &str,
        strings: &mut StrTable,
        devices: &DeviceRecognition,
    ) -> Result<Netlist, NetlistError> {
        let models = devices
            .model
            .iter()
            .copied()
            .zip(devices.kind.iter().copied())
            .collect();
        super::read_dialect(source, strings, super::Dialect::Spice, models)
    }
}

/// Spectre.
///
/// Declared subset: no `inline subckt`, no `alter`, no sweeps. Anything outside
/// it is [`NetlistError::Unsupported`] with the line it sits on. The accepted
/// subset is in the [module docs](super).
pub mod spectre {
    use super::{Netlist, NetlistError};
    use gpurify_geom::StrTable;

    /// Reads a Spectre netlist, interning its names into `strings`. A device's
    /// family comes from its `model` card's master or a built-in primitive
    /// master (`nmos`, `bsim4`, `resistor`, …); any other master is refused.
    ///
    /// # Errors
    ///
    /// The first [`NetlistError`] found, with its line; nothing partial is
    /// returned. Definitions are read before cards, and instance port counts
    /// checked last, so the first error found need not be the first in the file.
    pub fn read(source: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError> {
        super::read_dialect(source, strings, super::Dialect::Spectre, Vec::new())
    }
}
