//! Structural (gate-level) Verilog, read on top of a cell library.
//!
//! Data in: Verilog text, the run's `StrTable`, and the [`Netlist`] the
//! library's SPICE or Spectre file was read into. Data out: that netlist with
//! one subcircuit per Verilog module appended, each holding instances only.
//! This is how Netgen reads a digital top level (`readnet verilog` into the
//! netlist the standard cells were read into, as `OpenLane`'s LVS script
//! does) and what Calibre's `v2lvs` converts to SPICE (catalog LVS-075).
//!
//! # The subset
//!
//! The netlist subset of IEEE 1364-2005 a synthesis or place-and-route tool
//! writes:
//!
//! - `module name (ports); ... endmodule`, the port list in either style:
//!   names declared below (`input a;`) or declared in place (`input [3:0]
//!   a, output y`);
//! - `input`, `output`, `inout`, `wire`, `supply0` and `supply1`
//!   declarations, scalar or with a constant range `[msb:lsb]`, a `wire`
//!   optionally assigned (`wire a = b;`);
//! - `assign a = b;`, which makes the two nets one, as Netgen joins them;
//! - instances `cell name (connections);`, several per statement, of a
//!   library cell or of another module, connected by name (`.A(n)`, `.A()`
//!   left open) or in order; a connection is a net, a bit `d[3]`, a part
//!   `d[3:0]` or a concatenation `{a, d[1:0]}`;
//! - `//` and `/* */` comments, attributes `(* ... *)`, and escaped
//!   identifiers (`\a[0] `, read as `a[0]`).
//!
//! A bus is its bits, named `d[3]` and so on in declared order, most
//! significant first. A library cell's port connects by name to the
//! connection of that name; a cell whose ports are bits (`D[0]`, `D[1]`)
//! takes a bus connected to `.D(...)` bit for bit, in the cell's port order.
//! A port the instance leaves out is open: a net of its own in the caller,
//! named `instance.port`. An undeclared name in a connection is a scalar
//! wire, as Verilog's default net type makes it. A module with no instance
//! and no `assign`, named as a library cell with as many ports, declares
//! that cell (a synthesis tool's blackbox stub) and adds nothing.
//!
//! Refused with [`NetlistError::Unsupported`]: compiler directives
//! (`` `ifdef ``, `` `include ``; write power connections plainly), constants
//! in a connection (`1'b0`), parameters (`#(...)`), instance arrays,
//! behavioural code (`always`, `reg`, `function`, ...), and anything else
//! outside the list.

use super::{tables_hold, Netlist, NetlistError, RefNetId, SourceSpan, SubcktId};
use crate::narrow;
use gpurify_geom::StrTable;
use std::collections::HashMap;

/// One token and the line it starts on.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// An identifier or keyword, escaped identifiers without their `\`.
    Ident(String),
    /// A plain decimal number, as in a range or a bit select.
    Number(u32),
    /// Any other literal (`1'b0`, `4'hf`, a real): never accepted.
    Constant(String),
    /// One punctuation character.
    Punct(char),
}

/// Splits Verilog text into tokens, dropping comments and attributes.
fn tokens(source: &str) -> Result<Vec<(Tok, SourceSpan)>, NetlistError> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let (mut at, mut line) = (0usize, 1u32);
    let span = |line| SourceSpan { line };
    while at < bytes.len() {
        let c = bytes[at];
        match c {
            b'\n' => {
                line += 1;
                at += 1;
            }
            _ if c.is_ascii_whitespace() => at += 1,
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let start = line;
                at += 2;
                loop {
                    match bytes.get(at) {
                        None => {
                            return Err(NetlistError::Unexpected(
                                span(start),
                                "an unclosed /* comment".to_owned(),
                            ))
                        }
                        Some(b'*') if bytes.get(at + 1) == Some(&b'/') => {
                            at += 2;
                            break;
                        }
                        Some(&b) => {
                            line += u32::from(b == b'\n');
                            at += 1;
                        }
                    }
                }
            }
            b'(' if bytes.get(at + 1) == Some(&b'*') && bytes.get(at + 2) != Some(&b')') => {
                // An attribute, `(* keep *)`: says nothing about connectivity.
                let start = line;
                at += 2;
                loop {
                    match bytes.get(at) {
                        None => {
                            return Err(NetlistError::Unexpected(
                                span(start),
                                "an unclosed (* attribute".to_owned(),
                            ))
                        }
                        Some(b'*') if bytes.get(at + 1) == Some(&b')') => {
                            at += 2;
                            break;
                        }
                        Some(&b) => {
                            line += u32::from(b == b'\n');
                            at += 1;
                        }
                    }
                }
            }
            b'`' => {
                let end = source[at..]
                    .find(|c: char| c.is_whitespace())
                    .map_or(bytes.len(), |n| at + n);
                return Err(NetlistError::Unsupported(
                    span(line),
                    format!("the compiler directive {}", &source[at..end]),
                ));
            }
            b'\\' => {
                let end = source[at..]
                    .find(|c: char| c.is_whitespace())
                    .map_or(bytes.len(), |n| at + n);
                out.push((Tok::Ident(source[at + 1..end].to_owned()), span(line)));
                at = end;
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let end = source[at..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                    .map_or(bytes.len(), |n| at + n);
                out.push((Tok::Ident(source[at..end].to_owned()), span(line)));
                at = end;
            }
            _ if c.is_ascii_digit() || c == b'\'' => {
                let end = source[at..]
                    .find(|c: char| {
                        !(c.is_ascii_alphanumeric() || c == '_' || c == '\'' || c == '.')
                    })
                    .map_or(bytes.len(), |n| at + n);
                let text = &source[at..end];
                let tok = match text.parse::<u32>() {
                    Ok(n) if text.bytes().all(|b| b.is_ascii_digit()) => Tok::Number(n),
                    _ => Tok::Constant(text.to_owned()),
                };
                out.push((tok, span(line)));
                at = end;
            }
            // Punctuation outside the subset (`@`, `+`, ...) is a token too,
            // so the construct it belongs to is named when refused.
            _ if c.is_ascii_punctuation() => {
                out.push((Tok::Punct(char::from(c)), span(line)));
                at += 1;
            }
            _ => {
                let ch = source[at..].chars().next().unwrap_or('?');
                return Err(NetlistError::Unexpected(span(line), ch.to_string()));
            }
        }
    }
    Ok(out)
}

/// A declared net: its range, `None` for a scalar.
type Range = Option<(u32, u32)>;

/// The bits of a net of `range`, most significant (first declared) first.
fn bit_names(name: &str, range: Range) -> Vec<String> {
    match range {
        None => vec![name.to_owned()],
        Some((from, to)) => {
            let bits: Vec<u32> = if from >= to {
                (to..=from).rev().collect()
            } else {
                (from..=to).collect()
            };
            bits.into_iter().map(|b| format!("{name}[{b}]")).collect()
        }
    }
}

/// One connection of an instance: by port name or by position.
enum Conn {
    /// `.port(bits)`, the bits empty for `.port()`.
    Named(String, Vec<String>, SourceSpan),
    /// The `k`-th expression of an ordered list.
    Ordered(Vec<String>, SourceSpan),
}

/// One instance as written.
struct Inst {
    cell: String,
    name: String,
    conns: Vec<Conn>,
    span: SourceSpan,
}

/// One module as written: its ports as bits, its declared nets, its
/// assignments as bit pairs, its instances.
struct Module {
    name: String,
    span: SourceSpan,
    /// Port names in the port list's order, then each one's range once
    /// declared.
    ports: Vec<String>,
    declared: HashMap<String, Range>,
    assigns: Vec<(String, String)>,
    insts: Vec<Inst>,
}

impl Module {
    /// The module's port bits, in port order.
    fn port_bits(&self) -> Vec<String> {
        self.ports
            .iter()
            .flat_map(|port| bit_names(port, self.declared.get(port).copied().flatten()))
            .collect()
    }
}

/// A cursor over the tokens.
struct Parser {
    toks: Vec<(Tok, SourceSpan)>,
    at: usize,
}

const KEYWORDS: &[&str] = &[
    "module",
    "endmodule",
    "input",
    "output",
    "inout",
    "wire",
    "supply0",
    "supply1",
    "assign",
];

impl Parser {
    fn span(&self) -> SourceSpan {
        self.toks
            .get(self.at)
            .or_else(|| self.toks.last())
            .map_or(SourceSpan { line: 1 }, |t| t.1)
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|t| &t.0)
    }

    fn unexpected(&self) -> NetlistError {
        let text = match self.peek() {
            None => "the end of the file".to_owned(),
            Some(Tok::Ident(s) | Tok::Constant(s)) => s.clone(),
            Some(Tok::Number(n)) => n.to_string(),
            Some(Tok::Punct(c)) => c.to_string(),
        };
        NetlistError::Unexpected(self.span(), text)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, c: char) -> Result<(), NetlistError> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn ident(&mut self) -> Result<String, NetlistError> {
        match self.peek() {
            Some(Tok::Ident(s)) if !KEYWORDS.contains(&s.as_str()) => {
                let s = s.clone();
                self.at += 1;
                Ok(s)
            }
            _ => Err(self.unexpected()),
        }
    }

    fn keyword(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Ident(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn number(&mut self) -> Result<u32, NetlistError> {
        match self.peek() {
            Some(&Tok::Number(n)) => {
                self.at += 1;
                Ok(n)
            }
            Some(Tok::Constant(s)) => Err(NetlistError::Unsupported(
                self.span(),
                format!("the constant {s}"),
            )),
            _ => Err(self.unexpected()),
        }
    }

    /// `[msb:lsb]`, when one follows.
    fn range(&mut self) -> Result<Range, NetlistError> {
        if !self.eat('[') {
            return Ok(None);
        }
        let from = self.number()?;
        self.expect(':')?;
        let to = self.number()?;
        self.expect(']')?;
        Ok(Some((from, to)))
    }

    /// Every module in the file.
    fn modules(&mut self) -> Result<Vec<Module>, NetlistError> {
        let mut out = Vec::new();
        while self.peek().is_some() {
            if self.keyword() != Some("module") {
                return Err(self.unsupported_or_unexpected());
            }
            out.push(self.module()?);
        }
        Ok(out)
    }

    /// A keyword outside the subset is `Unsupported`; anything else is
    /// unexpected.
    fn unsupported_or_unexpected(&self) -> NetlistError {
        match self.peek() {
            Some(Tok::Ident(word))
                if matches!(
                    word.as_str(),
                    "always"
                        | "initial"
                        | "reg"
                        | "integer"
                        | "function"
                        | "task"
                        | "generate"
                        | "parameter"
                        | "localparam"
                        | "defparam"
                        | "specify"
                        | "primitive"
                        | "tri"
                        | "wand"
                        | "wor"
                        | "logic"
                ) =>
            {
                NetlistError::Unsupported(self.span(), word.clone())
            }
            _ => self.unexpected(),
        }
    }

    fn module(&mut self) -> Result<Module, NetlistError> {
        let span = self.span();
        self.at += 1;
        let name = self.ident()?;
        if self.peek() == Some(&Tok::Punct('#')) {
            return Err(NetlistError::Unsupported(
                self.span(),
                format!("the parameters of module {name}"),
            ));
        }
        let mut module = Module {
            name,
            span,
            ports: Vec::new(),
            declared: HashMap::new(),
            assigns: Vec::new(),
            insts: Vec::new(),
        };
        if self.eat('(') && !self.eat(')') {
            loop {
                if matches!(self.keyword(), Some("input" | "output" | "inout")) {
                    // In place: a direction, a range, then names until the
                    // next direction.
                    self.at += 1;
                    if self.keyword() == Some("wire") {
                        self.at += 1;
                    }
                    let range = self.range()?;
                    let port = self.ident()?;
                    module.declared.insert(port.clone(), range);
                    module.ports.push(port);
                    while self.peek() == Some(&Tok::Punct(','))
                        && !matches!(
                            self.toks.get(self.at + 1).map(|t| &t.0),
                            Some(Tok::Ident(w)) if matches!(w.as_str(), "input" | "output" | "inout")
                        )
                    {
                        self.at += 1;
                        let port = self.ident()?;
                        module.declared.insert(port.clone(), range);
                        module.ports.push(port);
                    }
                } else if self.peek() == Some(&Tok::Punct('.')) {
                    return Err(NetlistError::Unsupported(
                        self.span(),
                        "a port expression".to_owned(),
                    ));
                } else {
                    module.ports.push(self.ident()?);
                }
                if self.eat(')') {
                    break;
                }
                self.expect(',')?;
            }
        }
        self.expect(';')?;
        loop {
            match self.keyword() {
                Some("endmodule") => {
                    self.at += 1;
                    return Ok(module);
                }
                Some("input" | "output" | "inout" | "wire" | "supply0" | "supply1") => {
                    self.declaration(&mut module)?;
                }
                Some("assign") => {
                    self.at += 1;
                    loop {
                        let lhs = self.expression(&module)?;
                        self.expect('=')?;
                        let rhs = self.expression(&module)?;
                        self.pair(&mut module, lhs, rhs)?;
                        if !self.eat(',') {
                            break;
                        }
                    }
                    self.expect(';')?;
                }
                Some(_) if self.unsupported_or_unexpected_is_keyword() => {
                    return Err(self.unsupported_or_unexpected());
                }
                Some(word) if !KEYWORDS.contains(&word) => self.instances(&mut module)?,
                _ => return Err(self.unsupported_or_unexpected()),
            }
        }
    }

    /// Whether the word at the cursor is a keyword outside the subset.
    fn unsupported_or_unexpected_is_keyword(&self) -> bool {
        matches!(
            self.unsupported_or_unexpected(),
            NetlistError::Unsupported(..)
        )
    }

    /// `input|output|inout|wire|supply0|supply1 [range] name [= expr], ...;`
    fn declaration(&mut self, module: &mut Module) -> Result<(), NetlistError> {
        let word = self.keyword().unwrap_or_default().to_owned();
        self.at += 1;
        if word != "wire" && self.keyword() == Some("wire") {
            self.at += 1;
        }
        let range = self.range()?;
        loop {
            let name = self.ident()?;
            module.declared.insert(name.clone(), range);
            if word == "wire" && self.eat('=') {
                let rhs = self.expression(module)?;
                self.pair(module, bit_names(&name, range), rhs)?;
            }
            if !self.eat(',') {
                break;
            }
        }
        self.expect(';')
    }

    /// Joins two equally wide expressions bit for bit.
    fn pair(
        &self,
        module: &mut Module,
        lhs: Vec<String>,
        rhs: Vec<String>,
    ) -> Result<(), NetlistError> {
        if lhs.len() != rhs.len() {
            return Err(NetlistError::Unexpected(
                self.span(),
                format!("an assignment of {} bits to {}", rhs.len(), lhs.len()),
            ));
        }
        module.assigns.extend(lhs.into_iter().zip(rhs));
        Ok(())
    }

    /// A connection expression as its bits, most significant first.
    fn expression(&mut self, module: &Module) -> Result<Vec<String>, NetlistError> {
        if self.eat('{') {
            let mut bits = Vec::new();
            loop {
                bits.extend(self.expression(module)?);
                if self.eat('}') {
                    return Ok(bits);
                }
                self.expect(',')?;
            }
        }
        if let Some(Tok::Constant(text)) = self.peek() {
            return Err(NetlistError::Unsupported(
                self.span(),
                format!("the constant {text} in a connection"),
            ));
        }
        if let Some(Tok::Number(n)) = self.peek() {
            return Err(NetlistError::Unsupported(
                self.span(),
                format!("the constant {n} in a connection"),
            ));
        }
        let span = self.span();
        let name = self.ident()?;
        let range = module.declared.get(&name).copied().flatten();
        if !self.eat('[') {
            return Ok(bit_names(&name, range));
        }
        let Some((msb, lsb)) = range else {
            return Err(NetlistError::Unexpected(
                span,
                format!("a bit select of the scalar {name}"),
            ));
        };
        let within = |bit: u32| (msb.min(lsb)..=msb.max(lsb)).contains(&bit);
        let from = self.number()?;
        let to = if self.eat(':') { self.number()? } else { from };
        self.expect(']')?;
        if !within(from) || !within(to) {
            return Err(NetlistError::Unexpected(
                span,
                format!("{name}[{from}:{to}] outside {name}[{msb}:{lsb}]"),
            ));
        }
        Ok(bit_names(&name, Some((from, to))))
    }

    /// `cell name (conns), name (conns);`
    fn instances(&mut self, module: &mut Module) -> Result<(), NetlistError> {
        let cell = self.ident()?;
        if self.peek() == Some(&Tok::Punct('#')) {
            return Err(NetlistError::Unsupported(
                self.span(),
                format!("the parameters of an instance of {cell}"),
            ));
        }
        loop {
            let span = self.span();
            let name = self.ident()?;
            if self.peek() == Some(&Tok::Punct('[')) {
                return Err(NetlistError::Unsupported(
                    self.span(),
                    format!("the instance array {name}"),
                ));
            }
            self.expect('(')?;
            let mut conns = Vec::new();
            if !self.eat(')') {
                loop {
                    let at = self.span();
                    if self.eat('.') {
                        let port = self.ident()?;
                        self.expect('(')?;
                        let bits = if self.eat(')') {
                            Vec::new()
                        } else {
                            let bits = self.expression(module)?;
                            self.expect(')')?;
                            bits
                        };
                        conns.push(Conn::Named(port, bits, at));
                    } else {
                        conns.push(Conn::Ordered(self.expression(module)?, at));
                    }
                    if self.eat(')') {
                        break;
                    }
                    self.expect(',')?;
                }
            }
            module.insts.push(Inst {
                cell: cell.clone(),
                name,
                conns,
                span,
            });
            if !self.eat(',') {
                break;
            }
        }
        self.expect(';')
    }
}

/// The base of a port bit's name, `D` for `D[3]`, and whether it is a bit.
fn base(port: &str) -> (&str, bool) {
    match port.strip_suffix(']').and_then(|p| p.rsplit_once('[')) {
        Some((base, index)) if index.bytes().all(|b| b.is_ascii_digit()) && !index.is_empty() => {
            (base, true)
        }
        _ => (port, false),
    }
}

/// Reads `sources`, each a Verilog file, into `netlist`, a library already
/// read (or [`Netlist::default`] for none), interning names into `strings`.
/// Returns the subcircuits the modules became, in file order: a module is
/// the top when none of the others instantiates it
/// ([`Netlist::top_in`]).
///
/// # Errors
///
/// The first [`NetlistError`] found, with its line: a construct outside
/// the subset ([`NetlistError::Unsupported`]), a malformed one
/// ([`NetlistError::Unexpected`]), a module defined twice or named as a
/// library cell it does not declare ([`NetlistError::Redefined`]), an
/// instance of a cell defined nowhere ([`NetlistError::UndefinedSubckt`]),
/// or one whose connections do not fit the cell's ports
/// ([`NetlistError::TerminalCount`], or `Unexpected` naming the port).
/// `netlist` is unchanged on error.
pub fn read_into(
    sources: &[&str],
    strings: &mut StrTable,
    netlist: &mut Netlist,
) -> Result<std::ops::Range<u32>, NetlistError> {
    let mut modules = Vec::new();
    for source in sources {
        let mut parser = Parser {
            toks: tokens(source)?,
            at: 0,
        };
        modules.extend(parser.modules()?);
    }
    let mut out = std::mem::take(netlist);
    let result = append(&modules, strings, &mut out);
    match result {
        Ok(range) => {
            debug_assert!(tables_hold(&out), "the appended tables hold");
            *netlist = out;
            Ok(range)
        }
        Err(why) => {
            // `append` adds rows only once everything resolved.
            *netlist = out;
            Err(why)
        }
    }
}

/// Resolves every module and appends it; nothing is written before the last
/// check passes.
fn append(
    modules: &[Module],
    strings: &mut StrTable,
    out: &mut Netlist,
) -> Result<std::ops::Range<u32>, NetlistError> {
    // Every cell by name, and each one's port names by id: the library's,
    // then the modules'.
    let mut by_name: HashMap<String, SubcktId> = HashMap::new();
    let mut ports: Vec<Vec<String>> = Vec::new();
    for cell in 0..narrow(out.subckt_count()) {
        let rows = out.subckt_port_start[cell as usize] as usize
            ..out.subckt_port_start[cell as usize + 1] as usize;
        ports.push(
            out.port_net[rows]
                .iter()
                .map(|net| strings.resolve(out.net_name[net.0 as usize]).to_owned())
                .collect(),
        );
        by_name.insert(
            strings.resolve(out.subckt_name[cell as usize]).to_owned(),
            SubcktId(cell),
        );
    }
    // Modules that become subcircuits, and the stubs that declare a cell.
    let first = narrow(out.subckt_count());
    let mut kept: Vec<&Module> = Vec::new();
    for module in modules {
        let bits = module.port_bits();
        if let Some(&cell) = by_name.get(&module.name) {
            let stub = module.insts.is_empty() && module.assigns.is_empty();
            if stub && cell.0 < first && ports[cell.0 as usize].len() == bits.len() {
                continue;
            }
            return Err(NetlistError::Redefined(module.span, module.name.clone()));
        }
        by_name.insert(module.name.clone(), SubcktId(narrow(ports.len())));
        ports.push(bits);
        kept.push(module);
    }

    // Resolve every instance before writing anything.
    let mut resolved: Vec<Vec<(SubcktId, Vec<Option<String>>)>> = Vec::new();
    for module in &kept {
        let mut insts = Vec::new();
        for inst in &module.insts {
            let &callee = by_name
                .get(&inst.cell)
                .ok_or_else(|| NetlistError::UndefinedSubckt(inst.span, inst.cell.clone()))?;
            insts.push((callee, connect(inst, &ports[callee.0 as usize])?));
        }
        resolved.push(insts);
    }

    // Append: per module its nets (bits joined by `assign`), ports, then
    // instances.
    if out.subckt_port_start.is_empty() {
        out.subckt_port_start.push(0);
        out.subckt_device_start.push(0);
        out.device_terminal_start.push(0);
        out.device_param_start.push(0);
    }
    let devices = narrow(out.device_model.len());
    for (k, module) in kept.iter().enumerate() {
        let id = SubcktId(first + narrow(k));
        out.subckt_name.push(strings.intern(&module.name));
        let mut nets = Nets::default();
        for (a, b) in &module.assigns {
            nets.join(a, b);
        }
        for bit in module.port_bits() {
            let net = nets.net(&bit, id, strings, out);
            out.port_net.push(net);
        }
        out.subckt_port_start.push(narrow(out.port_net.len()));
        out.subckt_device_start.push(devices);
        for (inst, (callee, bits)) in module.insts.iter().zip(&resolved[k]) {
            if out.instance_net_start.is_empty() {
                out.instance_net_start.push(0);
            }
            out.instance_of.push(*callee);
            out.instance_subckt.push(id);
            out.instance_name.push(strings.intern(&inst.name));
            for (port, bit) in ports[callee.0 as usize].iter().zip(bits) {
                let name = bit
                    .clone()
                    .unwrap_or_else(|| format!("{}.{port}", inst.name));
                let net = nets.net(&name, id, strings, out);
                out.instance_net.push(net);
            }
            out.instance_net_start.push(narrow(out.instance_net.len()));
        }
    }
    Ok(first..narrow(out.subckt_count()))
}

/// The net each of the callee's `ports` is connected to, `None` where the
/// instance leaves it open. By name: a port takes the connection of its
/// name, a bus port's bits (`D[0]`, `D[1]`, in the cell's order) the bits
/// of the connection named for their base. In order: the k-th expression
/// takes the k-th port, a run of one base's bits counting as one port.
fn connect(inst: &Inst, ports: &[String]) -> Result<Vec<Option<String>>, NetlistError> {
    let mut out = vec![None; ports.len()];
    let named = inst.conns.iter().any(|c| matches!(c, Conn::Named(..)));
    if named {
        for conn in &inst.conns {
            let Conn::Named(port, bits, span) = conn else {
                return Err(NetlistError::Unexpected(
                    inst.span,
                    format!("{}: ordered and named connections mixed", inst.name),
                ));
            };
            let slots: Vec<usize> = match ports.iter().position(|p| p == port) {
                Some(at) => vec![at],
                None => (0..ports.len())
                    .filter(|&at| base(&ports[at]) == (port.as_str(), true))
                    .collect(),
            };
            if slots.is_empty() {
                return Err(NetlistError::Unexpected(
                    *span,
                    format!("{}: {} has no port {port}", inst.name, inst.cell),
                ));
            }
            if bits.is_empty() {
                continue;
            }
            if bits.len() != slots.len() {
                return Err(NetlistError::Unexpected(
                    *span,
                    format!(
                        "{}: {} bits on the {}-bit port {port}",
                        inst.name,
                        bits.len(),
                        slots.len()
                    ),
                ));
            }
            for (slot, bit) in slots.into_iter().zip(bits) {
                if out[slot].replace(bit.clone()).is_some() {
                    return Err(NetlistError::Unexpected(
                        *span,
                        format!("{}: port {port} connected twice", inst.name),
                    ));
                }
            }
        }
        return Ok(out);
    }
    // In order: group the ports into runs of one base.
    let mut groups: Vec<std::ops::Range<usize>> = Vec::new();
    let mut at = 0;
    while at < ports.len() {
        let (head, bus) = base(&ports[at]);
        let mut end = at + 1;
        while bus && end < ports.len() && base(&ports[end]) == (head, true) {
            end += 1;
        }
        groups.push(at..end);
        at = end;
    }
    if groups.len() != inst.conns.len() {
        return Err(NetlistError::TerminalCount(
            inst.span,
            inst.name.clone(),
            narrow(inst.conns.len()),
            narrow(groups.len()),
        ));
    }
    for (group, conn) in groups.into_iter().zip(&inst.conns) {
        let Conn::Ordered(bits, span) = conn else {
            unreachable!("no named connection here");
        };
        if bits.len() != group.len() {
            return Err(NetlistError::Unexpected(
                *span,
                format!(
                    "{}: {} bits on the {}-bit port {}",
                    inst.name,
                    bits.len(),
                    group.len(),
                    base(&ports[group.start]).0
                ),
            ));
        }
        for (slot, bit) in group.zip(bits) {
            out[slot] = Some(bit.clone());
        }
    }
    Ok(out)
}

/// A module's nets: bits `assign` made one, as a union-find over names, and
/// the row each class became.
#[derive(Default)]
struct Nets {
    parent: HashMap<String, String>,
    row: HashMap<String, RefNetId>,
}

impl Nets {
    fn root(&self, name: &str) -> String {
        let mut at = name;
        while let Some(up) = self.parent.get(at) {
            at = up;
        }
        at.to_owned()
    }

    /// The net row of `name`'s class in `subckt`, appended to `out` on its
    /// first use under the class's root name.
    fn net(
        &mut self,
        name: &str,
        subckt: SubcktId,
        strings: &mut StrTable,
        out: &mut Netlist,
    ) -> RefNetId {
        let root = self.root(name);
        if let Some(&row) = self.row.get(&root) {
            return row;
        }
        let row = RefNetId(narrow(out.net_name.len()));
        out.net_name.push(strings.intern(&root));
        out.net_subckt.push(subckt);
        self.row.insert(root, row);
        row
    }

    /// Joins the classes of `a` and `b`, the lesser name the root, so the
    /// result does not depend on the order of the assignments.
    fn join(&mut self, a: &str, b: &str) {
        let (ra, rb) = (self.root(a), self.root(b));
        if ra != rb {
            let (low, high) = if ra < rb { (ra, rb) } else { (rb, ra) };
            self.parent.insert(high, low);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{base, bit_names};

    /// Oracle: IEEE 1364-2005 §6.1 (a vector's bits from its msb to its
    /// lsb, either order of indices). Breaks if a descending or ascending
    /// range is reversed.
    #[test]
    fn a_bus_lists_its_bits_from_the_first_index_declared() {
        assert_eq!(bit_names("d", Some((2, 0))), ["d[2]", "d[1]", "d[0]"]);
        assert_eq!(bit_names("d", Some((0, 1))), ["d[0]", "d[1]"]);
        assert_eq!(bit_names("a", None), ["a"]);
        assert_eq!(base("D[12]"), ("D", true));
        assert_eq!(base("D[x]"), ("D[x]", false));
        assert_eq!(base("D"), ("D", false));
    }
}
