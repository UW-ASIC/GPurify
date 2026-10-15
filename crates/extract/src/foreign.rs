//! Another tool's parasitic netlist, SPEF or DSPF, read into a
//! [`ParasiticNetwork`] so [`compare`](crate::compare) can qualify one
//! extraction against another tool's, nets linked by name.
//!
//! Data in: SPEF text (IEEE 1481-2009, the `*D_NET` detailed form) or DSPF
//! text (Cadence's DSPF 1.x, `*|NET` sections and SPICE element cards).
//! Data out: a [`Read`]: the net names, ascending, and the network on them
//! (`NetId(i)` is `names[i]`), in fF, Ω and pH.
//!
//! **What is read.** SPEF: the units (`*C_UNIT`, `*R_UNIT`, `*L_UNIT`), the
//! delimiter, `*NAME_MAP`, and every `*D_NET` with its `*CONN`, `*CAP`,
//! `*RES` and `*INDUC` sections; a `min:typ:max` triplet reads as its typical
//! value. DSPF: `*|DELIMITER`, `*|GROUND_NET`, each `*|NET` with its `*|P`,
//! `*|I` and `*|S` node declarations, and the `R`, `C` and `L` cards (with
//! SPICE scale suffixes and `+` continuations); a `K` card (mutual
//! inductance) and an instance (`X`) card are skipped, as `compare` reads
//! neither. Everything else in the header is skipped.
//!
//! **Refused.** A reduced net (`*R_NET`), a physical net (`*D_PNET`,
//! `*R_PNET`), a hierarchical `*DEFINE`, a value that is not a finite number,
//! a `*CONN`, `*CAP`, `*RES` or `*INDUC` section before any `*D_NET`,
//! and a node whose net cannot be told: one no net's `*CONN` (or `*|NET`
//! section) declares, no element of its own net names, and whose name
//! before the delimiter is no net's.
//!
//! **Nets and nodes.** A node belongs to the net that declares it, else to
//! the net named by its prefix (`net:3` is `net`'s), else to the net whose
//! resistor or first capacitor terminal it is. A net's first node is its
//! driver, which [`compare`](crate::compare) measures resistance and delay
//! from: the first `*P` port of direction `I`, else the first `*I` pin of
//! direction `O` (SPEF; `*|P`/`*|I` in DSPF), else the first node an
//! element names. Names are compared with `\` escapes removed, so `a\[0\]`
//! and `a[0]` are one net.
//!
//! **Coupling written twice.** SPEF lets a coupling capacitance be listed
//! in the `*CAP` section of both nets it joins (the usual form) or of one.
//! A coupling between two nodes listed once in each of their nets' sections
//! is one capacitor; listed twice within one section, it is two.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::NetId;
use gpurify_geom::{LayerId, Qty};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Where in a SPEF file a line is read.
#[derive(PartialEq)]
enum At {
    Header,
    NameMap,
    Conn,
    Cap,
    Res,
    Ind,
}

/// Why a parasitic netlist could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct ReadError {
    /// The 1-based line at fault; 0 for the file as a whole.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

/// A parasitic netlist as read.
#[derive(Debug, Default, PartialEq)]
pub struct Read {
    /// Every net's name, ascending, escapes removed; `NetId(i)` is
    /// `names[i]`.
    pub names: Vec<String>,
    /// The network, canonical, every net's driver its first node.
    pub network: ParasiticNetwork,
}

impl Read {
    /// The network with its nets renumbered onto `names`, a sorted list
    /// that holds every one of this file's names (the union of two files'
    /// names, so two files' networks share net ids). Nodes keep their order.
    ///
    /// # Panics
    ///
    /// If `names` is unsorted or lacks one of this file's names.
    pub fn on_names(&self, names: &[String]) -> ParasiticNetwork {
        assert!(names.is_sorted(), "the union of names is sorted");
        let id: Vec<NetId> = self
            .names
            .iter()
            .map(|n| {
                let at = names.binary_search(n).expect("the union holds every name");
                NetId(u32::try_from(at).expect("a NetId is a u32"))
            })
            .collect();
        ParasiticNetwork {
            node_net: self
                .network
                .node_net
                .iter()
                .map(|n| id[n.0 as usize])
                .collect(),
            node_layer: self.network.node_layer.clone(),
            from: self.network.from.clone(),
            to: self.network.to.clone(),
            value: self.network.value.clone(),
        }
    }
}

/// The kind of an element as read, before its nodes are placed.
#[derive(Clone, Copy)]
enum Kind {
    Cap,
    Res,
    Ind,
}

/// One element: its section's net, nodes, kind and value in fF, Ω or pH.
struct Element {
    net: usize,
    a: String,
    b: Option<String>,
    kind: Kind,
    value: f64,
    line: usize,
}

/// What both readers collect before the network is built.
#[derive(Default)]
struct Collect {
    /// Every net's name, in file order, escapes removed.
    nets: Vec<String>,
    /// Node name to the net that declares it (its first declaration wins).
    declared: HashMap<String, usize>,
    /// Per net: its driver, the first node declared to drive.
    driver: Vec<Option<String>>,
    elements: Vec<Element>,
    delimiter: char,
}

fn unescape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn fault(line: usize, message: impl Into<String>) -> ReadError {
    ReadError {
        line,
        message: message.into(),
    }
}

impl Collect {
    fn net(&mut self, name: &str) -> usize {
        self.nets.push(unescape(name));
        self.driver.push(None);
        self.nets.len() - 1
    }

    fn declare(&mut self, net: usize, node: &str, drives: bool) {
        let node = unescape(node);
        if drives && self.driver[net].is_none() {
            self.driver[net] = Some(node.clone());
        }
        self.declared.entry(node).or_insert(net);
    }

    /// The network: nets sorted by name, each net's nodes in order of first
    /// mention (its driver first), elements canonical. A coupling listed in
    /// both its nets' sections counts once.
    fn build(self) -> Result<Read, ReadError> {
        let Collect {
            nets,
            mut declared,
            driver,
            elements,
            delimiter,
        } = self;
        let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
        for (k, name) in nets.iter().enumerate() {
            if by_name.insert(name, k).is_some() {
                return Err(fault(0, format!("net {name} is listed twice")));
            }
        }
        // A node's net: declared, else its prefix's, else the element's own
        // net for a resistor terminal or a capacitor's first terminal.
        let prefix_net = |node: &str| {
            node.rfind(delimiter)
                .and_then(|at| by_name.get(&node[..at]).copied())
                .or_else(|| by_name.get(node).copied())
        };
        for e in &elements {
            for (node, own) in [
                (Some(&e.a), true),
                (e.b.as_ref(), !matches!(e.kind, Kind::Cap)),
            ] {
                let Some(node) = node else { continue };
                if declared.contains_key(node) {
                    continue;
                }
                match prefix_net(node) {
                    Some(net) => {
                        declared.insert(node.clone(), net);
                    }
                    None if own => {
                        declared.insert(node.clone(), e.net);
                    }
                    None => {
                        return Err(fault(
                            e.line,
                            format!("node {node} belongs to no net the file names"),
                        ))
                    }
                }
            }
        }
        // Nodes per net, in order of first mention, the driver first.
        let mut order: Vec<Vec<String>> = vec![Vec::new(); nets.len()];
        let mut seen: HashSet<&str> = HashSet::new();
        for (net, d) in driver.iter().enumerate() {
            if let Some(d) = d {
                order[net].push(d.clone());
                seen.insert(d);
            }
        }
        for e in &elements {
            for node in std::iter::once(&e.a).chain(&e.b) {
                if seen.insert(node.as_str()) {
                    order[declared[node]].push(node.clone());
                }
            }
        }
        let mut rank: Vec<usize> = (0..nets.len()).collect();
        rank.sort_by(|&a, &b| nets[a].cmp(&nets[b]));
        let mut node_id: HashMap<&str, NodeId> = HashMap::new();
        let mut network = ParasiticNetwork::default();
        for (new, &old) in rank.iter().enumerate() {
            for node in &order[old] {
                let id = NodeId(
                    u32::try_from(network.node_net.len())
                        .map_err(|_| fault(0, "more nodes than a NodeId holds"))?,
                );
                node_id.insert(node, id);
                network
                    .node_net
                    .push(NetId(u32::try_from(new).expect("fewer nets than nodes")));
                network.node_layer.push(LayerId(0));
            }
        }
        // A coupling between two nodes, by unordered pair: in which net's
        // section it was listed, so the other net's listing is not counted.
        let mut couplings: HashMap<(NodeId, NodeId), usize> = HashMap::new();
        for e in &elements {
            let a = node_id[e.a.as_str()];
            let b = e.b.as_deref().map(|b| node_id[b]);
            let value = match (e.kind, b) {
                (Kind::Res, Some(_)) => Parasitic::Resistance(Qty::new(e.value)),
                (Kind::Ind, Some(_)) => Parasitic::Inductance(Qty::new(e.value)),
                (Kind::Cap, None) => Parasitic::GroundCap(Qty::new(e.value)),
                (Kind::Cap, Some(b))
                    if network.node_net[a.0 as usize] == network.node_net[b.0 as usize] =>
                {
                    // Two nodes of one net: a capacitor that shorts itself
                    // out of every net total; read it as written.
                    Parasitic::CouplingCap(Qty::new(e.value))
                }
                (Kind::Cap, Some(b)) => {
                    let key = (a.min(b), a.max(b));
                    match couplings.get(&key) {
                        Some(&net) if net != e.net => {
                            couplings.remove(&key);
                            continue;
                        }
                        _ => {
                            couplings.insert(key, e.net);
                        }
                    }
                    Parasitic::CouplingCap(Qty::new(e.value))
                }
                (_, None) => return Err(fault(e.line, "a resistance or inductance has two nodes")),
            };
            network.push(a, b, value);
        }
        network.sort_canonical();
        let names = rank.iter().map(|&k| nets[k].clone()).collect();
        Ok(Read { names, network })
    }
}

/// A number with an optional `min:typ:max` triplet, its typical value.
fn number(text: &str, line: usize) -> Result<f64, ReadError> {
    let typ = match text.split(':').collect::<Vec<_>>()[..] {
        [one] => one,
        [_, typ, _] => typ,
        _ => return Err(fault(line, format!("{text} is not a value or a triplet"))),
    };
    typ.parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .ok_or_else(|| fault(line, format!("{text} is not a finite number")))
}

/// Reads a SPEF file.
///
/// # Errors
///
/// What the module docs list as refused, and a malformed line, by line.
pub fn read_spef(text: &str) -> Result<Read, ReadError> {
    let mut c = Collect {
        delimiter: ':',
        ..Collect::default()
    };
    let (mut cap_unit, mut res_unit, mut ind_unit) = (1e3_f64, 1.0_f64, 1e12_f64);
    let mut name_map: HashMap<String, String> = HashMap::new();
    let mut at = At::Header;
    let mut net = 0usize;
    // `*12:3` with `*12` mapped to `n` reads `n:3`.
    let resolve = |name: &str, map: &HashMap<String, String>, delimiter: char| -> String {
        if let Some(rest) = name.strip_prefix('*') {
            let (key, tail) = rest
                .find(delimiter)
                .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
            if let Some(full) = map.get(key) {
                return unescape(&format!("{full}{tail}"));
            }
        }
        unescape(name)
    };
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let body = raw.split("//").next().unwrap_or("");
        let tokens: Vec<&str> = body.split_whitespace().collect();
        let Some(&head) = tokens.first() else {
            continue;
        };
        let unit = |tokens: &[&str], scales: &[(&str, f64)]| -> Result<f64, ReadError> {
            let [_, n, u] = tokens[..] else {
                return Err(fault(line, "a unit is a number and a name"));
            };
            let scale = scales
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(u))
                .map(|s| s.1)
                .ok_or_else(|| fault(line, format!("unknown unit {u}")))?;
            Ok(number(n, line)? * scale)
        };
        // A keyword (`*PORTS`, `*POWER_NETS`, …) ends the name map, whose
        // entries are `*<digits> name`.
        let keyword = head
            .strip_prefix('*')
            .is_some_and(|rest| rest.starts_with(|ch: char| ch.is_ascii_alphabetic()));
        if at == At::NameMap && keyword {
            at = At::Header;
        }
        match head {
            "*C_UNIT" => cap_unit = unit(&tokens, &[("PF", 1e3), ("FF", 1.0)])?,
            "*R_UNIT" => res_unit = unit(&tokens, &[("OHM", 1.0), ("KOHM", 1e3)])?,
            "*L_UNIT" => {
                ind_unit = unit(&tokens, &[("HENRY", 1e12), ("MH", 1e9), ("UH", 1e6)])?;
            }
            "*DELIMITER" => {
                c.delimiter = tokens
                    .get(1)
                    .and_then(|d| d.chars().next())
                    .ok_or_else(|| fault(line, "*DELIMITER names a character"))?;
            }
            "*NAME_MAP" => at = At::NameMap,
            "*R_NET" | "*D_PNET" | "*R_PNET" | "*DEFINE" | "*PDEFINE" => {
                return Err(fault(line, format!("{head} is not read")))
            }
            "*D_NET" => {
                let name = tokens
                    .get(1)
                    .ok_or_else(|| fault(line, "*D_NET names a net"))?;
                net = c.net(&resolve(name, &name_map, c.delimiter));
                at = At::Header;
            }
            // A section belongs to the `*D_NET` above it.
            "*CONN" | "*CAP" | "*RES" | "*INDUC" if c.nets.is_empty() => {
                return Err(fault(line, format!("{head} before any *D_NET")));
            }
            "*CONN" => at = At::Conn,
            "*CAP" => at = At::Cap,
            "*RES" => at = At::Res,
            "*INDUC" => at = At::Ind,
            "*END" => at = At::Header,
            _ => match at {
                At::NameMap if head.starts_with('*') && tokens.len() == 2 => {
                    name_map.insert(head[1..].to_owned(), tokens[1].to_owned());
                }
                At::Conn => match head {
                    "*P" | "*I" => {
                        let [_, node, dir, ..] = tokens[..] else {
                            return Err(fault(line, "a connection has a name and a direction"));
                        };
                        let drives = (head == "*P" && dir == "I") || (head == "*I" && dir == "O");
                        let node = resolve(node, &name_map, c.delimiter);
                        c.declare(net, &node, drives);
                    }
                    "*N" => {
                        let node = tokens
                            .get(1)
                            .ok_or_else(|| fault(line, "*N names a node"))?;
                        let node = resolve(node, &name_map, c.delimiter);
                        c.declare(net, &node, false);
                    }
                    _ => return Err(fault(line, format!("unexpected {head} in *CONN"))),
                },
                At::Cap | At::Res | At::Ind => {
                    let (kind, scale) = match at {
                        At::Cap => (Kind::Cap, cap_unit),
                        At::Res => (Kind::Res, res_unit),
                        _ => (Kind::Ind, ind_unit),
                    };
                    let (a, b, value) = match tokens[..] {
                        [_, a, value] if matches!(kind, Kind::Cap) => (a, None, value),
                        [_, a, b, value] => (a, Some(b), value),
                        _ => return Err(fault(line, "an element is an id, its nodes and a value")),
                    };
                    c.elements.push(Element {
                        net,
                        a: resolve(a, &name_map, c.delimiter),
                        b: b.map(|b| resolve(b, &name_map, c.delimiter)),
                        kind,
                        value: number(value, line)? * scale,
                        line,
                    });
                }
                _ => {}
            },
        }
    }
    if c.nets.is_empty() {
        return Err(fault(0, "no *D_NET"));
    }
    c.build()
}

/// A SPICE number with an optional scale suffix (`f`, `p`, `n`, `u`, `m`,
/// `k`, `meg`, `g`, `t`, any case, then any unit letters).
fn spice_number(text: &str, line: usize) -> Result<f64, ReadError> {
    let end = text
        .find(|c: char| c.is_ascii_alphabetic() && c != 'e' && c != 'E')
        .unwrap_or(text.len());
    // An exponent `e` followed by no digit starts the suffix.
    let (digits, suffix) = text.split_at(end);
    let value = digits
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .ok_or_else(|| fault(line, format!("{text} is not a number")))?;
    let lower = suffix.to_ascii_lowercase();
    let scale = if lower.starts_with("meg") {
        1e6
    } else {
        match lower.chars().next() {
            Some('f') => 1e-15,
            Some('p') => 1e-12,
            Some('n') => 1e-9,
            Some('u') => 1e-6,
            Some('m') => 1e-3,
            Some('k') => 1e3,
            Some('g') => 1e9,
            Some('t') => 1e12,
            // No suffix, or a unit with no scale (`ohm`, `F`, `H`).
            _ => 1.0,
        }
    };
    Ok(value * scale)
}

/// Reads a DSPF file.
///
/// # Errors
///
/// A malformed declaration or card, a node no net owns, by line.
pub fn read_dspf(text: &str) -> Result<Read, ReadError> {
    let mut c = Collect {
        delimiter: ':',
        ..Collect::default()
    };
    let mut ground = String::from("0");
    let mut net: Option<usize> = None;
    // Join `+` continuations onto the card before them.
    let mut lines: Vec<(usize, String)> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        match (raw.trim_start().strip_prefix('+'), lines.last_mut()) {
            (Some(rest), Some((_, last))) => {
                last.push(' ');
                last.push_str(rest);
            }
            _ => lines.push((index + 1, raw.to_owned())),
        }
    }
    for (line, text) in &lines {
        let line = *line;
        let tokens: Vec<&str> = text
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter(|t| !t.is_empty())
            .collect();
        let Some(&head) = tokens.first() else {
            continue;
        };
        match head {
            "*|DELIMITER" => {
                c.delimiter = tokens
                    .get(1)
                    .and_then(|d| d.chars().next())
                    .ok_or_else(|| fault(line, "*|DELIMITER names a character"))?;
            }
            "*|GROUND_NET" => {
                (*tokens
                    .get(1)
                    .ok_or_else(|| fault(line, "*|GROUND_NET names a net"))?)
                .clone_into(&mut ground);
            }
            "*|NET" => {
                let name = tokens
                    .get(1)
                    .ok_or_else(|| fault(line, "*|NET names a net"))?;
                net = Some(c.net(name));
            }
            "*|P" | "*|I" | "*|S" => {
                let at = net.ok_or_else(|| fault(line, format!("{head} before any *|NET")))?;
                let node = tokens
                    .get(1)
                    .ok_or_else(|| fault(line, "a node has a name"))?;
                // `*|P (name dir cap x y)`, `*|I (inst:pin inst pin dir cap x y)`.
                let drives = match head {
                    "*|P" => tokens.get(2) == Some(&"I"),
                    "*|I" => tokens.get(4) == Some(&"O"),
                    _ => false,
                };
                c.declare(at, node, drives);
            }
            _ if head.starts_with('*') || head.starts_with('.') => {}
            _ => {
                let kind = match head.chars().next().map(|ch| ch.to_ascii_uppercase()) {
                    Some('R') => Kind::Res,
                    Some('C') => Kind::Cap,
                    Some('L') => Kind::Ind,
                    // Mutual inductance and instances: not compared.
                    Some('K' | 'X') => continue,
                    _ => return Err(fault(line, format!("unexpected card {head}"))),
                };
                let [_, a, b, value, ..] = tokens[..] else {
                    return Err(fault(line, "a card has two nodes and a value"));
                };
                let scale = match kind {
                    Kind::Cap => 1e15,
                    Kind::Res => 1.0,
                    Kind::Ind => 1e12,
                };
                let b = (b != ground).then(|| unescape(b));
                if b.is_none() && !matches!(kind, Kind::Cap) {
                    return Err(fault(line, "a resistance or inductance to ground"));
                }
                let a = unescape(a);
                // A card's section is the net of its first declared node.
                let own = c.declared.get(&a).copied().or(net).unwrap_or(0);
                c.elements.push(Element {
                    net: own,
                    a,
                    b,
                    kind,
                    value: spice_number(value, line)? * scale,
                    line,
                });
            }
        }
    }
    if c.nets.is_empty() {
        return Err(fault(0, "no *|NET"));
    }
    c.build()
}

#[cfg(test)]
mod tests;
