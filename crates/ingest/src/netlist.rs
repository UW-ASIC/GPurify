//! Reference-netlist readers: SPICE/CDL and Spectre, and structural
//! Verilog read over either as its cell library ([`verilog`]).
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
//!   `M`, `Q`, `R`, `C`, `D`, `L` and `X` cards, `+` continuation lines, `*` comment
//!   lines and `$` or `;` trailing comments. Card letters and dot keywords
//!   are case-insensitive and parameter names are stored lowercase; net and
//!   cell names keep their case. An `X` card calling a model the deck's
//!   `device` statements name is that device, its parameters read as on an
//!   `M` card (a bare `w`/`l` in µm), whether or not the netlist also
//!   defines a `.subckt` of that name: such a definition is the device's
//!   model, as a PDK's `rsubcircuit` resistors and fixed ESD cells are
//!   written, and is never compared (catalog LVS-067; `KLayout`'s
//!   `NetlistSpiceReaderDelegate::wants_subcircuit`).
//! - **Spectre** ([`spectre::read`]): `subckt`/`ends`, `model <name> <master>`
//!   cards, and instances `name (nets) master params` of a subcircuit, a
//!   `model`, or a built-in primitive master; `\` continuation, `//` comments.
//!   Case-sensitive. A primitive master (`resistor`, `nmos`, …) names no
//!   model, so the instance is the deck's one recogniser of its kind, as a
//!   SPICE card naming none is (below).
//!
//! An `R`, `C` or `L` card may state its value positionally, between its
//! nets and its model: `R1 a b 1k rpoly` is `R1 a b rpoly r=1k`, `C1 a b 1p
//! cmim` is `C1 a b cmim c=1p`, and `L1 a b 2n spiral` is an inductance,
//! `ind`, as is an inductor's `l=` (Spectre's `inductor` primitive names it
//! `l`), so it never reads as a length (catalog LVS-065). Stating it both ways is refused, as is any
//! parameter stated twice.
//!
//! On an `R`, `C` or `D` card, SPICE parameters other tools name differently
//! are read under the name LVS compares (testing-plan F87): ngspice's diode
//! perimeter `pj`, and `KLayout`'s `A` and `P`, are `perim`, `area` and
//! `perim`.
//!
//! An `R`, `C` or `D` card may leave its model out (`R1 a b 1k`, `C1 a b
//! c=1p`, `D1 a b`). LVS pairs a device by its model, so such a card is the
//! deck's one recogniser of its kind; a deck with none of that kind, or
//! several, refuses it with [`NetlistError::NoModel`], naming them
//! (testing-plan F86). So is a Spectre instance of a primitive master with
//! no `model` card, of any kind (testing-plan F97): `R1 (a b) resistor
//! r=1k` is the deck's one resistor, not a device of model `resistor`.
//!
//! Refused with [`NetlistError::Unsupported`]: any other dot card (`.param`,
//! `.include`, `.global`, `.model`, …), sources and other element letters,
//! a number where a model belongs on any other card, parameters on a
//! `.subckt` line or an `X` card, and a card outside every subcircuit.

use crate::deck::{DeviceKind, DeviceRecognition};
use crate::layout::MAX_HIERARCHY_DEPTH;
use crate::narrow;
use gpurify_geom::{StrId, StrTable};

/// Where a token came from: its 1-based line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    /// 1-based line number in the netlist text; a continued card reports the
    /// line the token is on.
    pub line: u32,
}

/// The most devices, nets and instances [`Netlist::flatten_top`] expands a
/// reference to.
///
/// LVS compares a flat reference, so every instance is expanded, and a few
/// lines can place a cell 2ⁿ times (each of `n` subcircuits placing the next
/// twice): 766 bytes reached 2²⁰ devices, and 30 levels would exhaust memory.
/// The expansion is counted from the tables first and a reference over the cap
/// is refused before anything is expanded. Nets and instances count with the
/// devices because each costs memory or a step of the walk on its own: a
/// chain that places no device still names a net per placement. The cap is a
/// layout's, [`MAX_FLAT_POLYGONS`](crate::layout::MAX_FLAT_POLYGONS): a
/// layout's every device and net is at least one polygon, so a reference past
/// it could not match any layout the reader accepts.
// ponytail: a flat cap, as the layout's; comparing hierarchically is the
// upgrade that lifts both.
pub const MAX_FLAT_ELEMENTS: u64 = crate::layout::MAX_FLAT_POLYGONS;

/// Why a netlist was refused. Each but [`NetlistError::Io`] and the
/// hierarchy's refusals ([`NetlistError::CyclicHierarchy`],
/// [`NetlistError::TooDeep`], [`NetlistError::TooLarge`]) carries the line
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
    /// An `R`, `C` or `D` card with no model, or a Spectre instance of a
    /// primitive master, where the deck has no one recogniser of its kind to
    /// bind it to: the card, then what the deck has of that kind (none, or
    /// the models it would have to choose from).
    #[error("line {}: {1} states no model, and {2}", .0.line)]
    NoModel(SourceSpan, String, String),
    /// A subcircuit that places itself, directly or through others: the
    /// hierarchy cannot be flattened ([`Netlist::flatten_top`]).
    #[error("subcircuit {0} places itself through its instances")]
    CyclicHierarchy(String),
    /// A placement chain from the top deeper than [`MAX_HIERARCHY_DEPTH`]
    /// levels, the top included, refused as a layout's is: flattening
    /// recurses once per level, so a deeper chain would overflow the stack.
    /// Names the subcircuit the chain passes the cap at
    /// ([`Netlist::flatten_top`]).
    #[error("the reference hierarchy is deeper than {MAX_HIERARCHY_DEPTH} levels at {0}")]
    TooDeep(String),
    /// A top that flattens to more than [`MAX_FLAT_ELEMENTS`] devices, nets
    /// and instances, counted from the tables before anything is expanded
    /// ([`Netlist::flatten_top`]).
    #[error(
        "the reference flattens to {0} devices, nets and instances, over the \
         {MAX_FLAT_ELEMENTS} a flat comparison holds; LVS flattens every instance"
    )]
    TooLarge(u64),
    /// Two SPICE or Spectre netlists given for one reference, which takes
    /// one beside any number of Verilog files: the two paths.
    #[error("the reference takes one SPICE or Spectre netlist, but {0} and {1} were both given")]
    Several(String, String),
    /// A subcircuit kept whole as a black box
    /// ([`Netlist::flatten_top_with`]) with more ports than a device has
    /// pins, [`MAX_CELL_PINS`]: its name, then its port count.
    #[error("black box {0} has {1} ports, over the {MAX_CELL_PINS} a compared cell holds")]
    TooManyPins(String, u32),
    /// The netlist file could not be read. The readers never return it; a
    /// caller reading the file does.
    #[error("io: {0}")]
    Io(String),
}

/// The most ports a subcircuit kept whole as a black box may have: a
/// device's pins are told apart by a one-byte position.
// ponytail: a byte per pin role; widen `TerminalRole::Pin` when a macro
// with more pins must be boxed.
pub const MAX_CELL_PINS: u32 = 256;

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
    /// name, interned. An `R`, `C` or `D` card that names none, and a
    /// Spectre instance of a primitive master, has the deck's one recogniser
    /// of its kind.
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
    /// (the PDK convention, `.option scale=1u`). SPICE names are lowercased,
    /// and a two-pin card's `pj`, `a` and `p` are `perim`, `area` and `perim`.
    /// An `R` or `C` card's positional value is its first parameter, `r` or
    /// `c`, in ohms or farads.
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

    /// What [`Netlist::flatten_top`] expanded, one row per placement below
    /// the top, in the order it expanded them (a placement before the ones
    /// inside it); empty on a netlist read from text. Each placement's
    /// devices, its own and those of every placement inside it, are one
    /// run of the flattened rows, so a device of the flat comparison can be
    /// traced back to the instance that placed it (catalog LVS-017).
    pub placements: Vec<Placement>,
    /// Each subcircuit [`Netlist::flatten_top_with`] kept whole as a black
    /// box, once, in the order first placed: its name and its port names in
    /// port order, the order of every such device's terminals. Empty on a
    /// netlist read from text.
    pub black_box_ports: Vec<(StrId, Vec<StrId>)>,
}

/// One instance [`Netlist::flatten_top`] expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The instance path, `X1.X2`, interned: the prefix its nets were
    /// named under.
    pub path: StrId,
    /// The placed subcircuit's name.
    pub cell: StrId,
    /// The flattened device rows the placement holds, inside placements
    /// included.
    pub devices: std::ops::Range<u32>,
}

impl Netlist {
    /// Returns the number of subcircuit definitions.
    pub fn subckt_count(&self) -> usize {
        self.subckt_name.len()
    }
    /// The port nets of `cell`, in port order.
    fn ports_of(&self, cell: SubcktId) -> &[RefNetId] {
        &self.port_net[csr(&self.subckt_port_start, cell.0 as usize)]
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
    /// its own ports, and records each instance it expanded
    /// ([`Netlist::placements`]). Its nets are `top`'s, then each instance's internal nets
    /// (those not on a port) under the instance path, `X1.X2.n1`, interned
    /// into `strings`. A device keeps its kind, model and parameters, with its
    /// terminals on the flattened nets. LVS compares devices, not cells, so a
    /// block the schematic places by instance has to be in the comparison; a
    /// graph built from `top`'s own devices alone would let a layout missing
    /// that block match.
    ///
    /// # Errors
    ///
    /// [`NetlistError::CyclicHierarchy`] when a subcircuit `top` reaches
    /// places itself, [`NetlistError::TooDeep`] when a placement chain from
    /// `top` is more than [`MAX_HIERARCHY_DEPTH`] levels deep, `top`
    /// included, then [`NetlistError::TooLarge`] when the result
    /// would hold more than [`MAX_FLAT_ELEMENTS`] devices, nets and
    /// instances. All are found by counting, before anything is expanded.
    ///
    /// # Panics
    ///
    /// On a `top` past [`Self::subckt_count`].
    ///
    /// # Time complexity
    ///
    /// Linear in the netlist and in what the expansion produces, each net
    /// name produced costing its instance path's length: each subcircuit's
    /// instances and nets are indexed once, and one net map serves every
    /// placement.
    pub fn flatten_top(
        &self,
        top: SubcktId,
        strings: &mut StrTable,
    ) -> Result<Netlist, NetlistError> {
        self.flatten_top_with(top, &[], strings)
    }

    /// [`Self::flatten_top`], keeping every instance of a subcircuit whose
    /// name matches one of `black_boxes` whole: one device of
    /// [`DeviceKind::Cell`], its model the subcircuit's name, its terminals
    /// the instance's nets in port order, no parameters, and its body never
    /// read (catalog LVS-033, the deck's `lvs blackbox`). A pattern is a
    /// whole-name glob, `*` any run and `?` one character, case included
    /// ([`glob_matches`](crate::layout::glob_matches)). Such a placement is
    /// still recorded, holding its one device, and each such subcircuit's
    /// port names are in [`Netlist::black_box_ports`].
    ///
    /// # Errors
    ///
    /// As [`Self::flatten_top`], counting a kept instance as one device;
    /// and [`NetlistError::TooManyPins`] for a kept subcircuit placed with
    /// more than [`MAX_CELL_PINS`] ports.
    ///
    /// # Panics
    ///
    /// On a `top` past [`Self::subckt_count`].
    pub fn flatten_top_with(
        &self,
        top: SubcktId,
        black_boxes: &[String],
        strings: &mut StrTable,
    ) -> Result<Netlist, NetlistError> {
        let mut hierarchy = Hierarchy::of(self);
        if !black_boxes.is_empty() {
            hierarchy.kept = self
                .subckt_name
                .iter()
                .map(|&name| {
                    let name = strings.resolve(name);
                    black_boxes
                        .iter()
                        .any(|pattern| crate::layout::glob_matches(pattern, name))
                })
                .collect();
        }
        let size = self.flat_size(top, &hierarchy, strings)?;
        if size > MAX_FLAT_ELEMENTS {
            return Err(NetlistError::TooLarge(size));
        }
        let mut out = Netlist {
            subckt_name: vec![self.subckt_name[top.0 as usize]],
            subckt_port_start: vec![0],
            subckt_device_start: vec![0],
            device_terminal_start: vec![0],
            device_param_start: vec![0],
            ..Netlist::default()
        };
        // The caller's nets for `top`: its own, under their own names.
        let mut map = vec![u32::MAX; self.net_name.len()];
        for &net in hierarchy.nets_of(top) {
            map[net as usize] = narrow(out.net_name.len());
            out.net_name.push(self.net_name[net as usize]);
            out.net_subckt.push(SubcktId(0));
        }
        for &port in self.ports_of(top) {
            out.port_net.push(RefNetId(map[port.0 as usize]));
        }
        out.subckt_port_start.push(narrow(out.port_net.len()));
        self.expand(top, &hierarchy, &mut map, "", strings, &mut out);
        out.subckt_device_start.push(narrow(out.device_model.len()));
        Ok(out)
    }

    /// What [`Self::flatten_top`] expands `top` to, counted from the tables:
    /// its devices, its nets and the instances it places, all the way down,
    /// saturating. `top`'s own nets are all in the result; each instance adds
    /// its callee's nets that are not on a port.
    fn flat_size(
        &self,
        top: SubcktId,
        hierarchy: &Hierarchy,
        strings: &StrTable,
    ) -> Result<u64, NetlistError> {
        let cells = self.subckt_count();
        let inner: Vec<u64> = (0..narrow(cells))
            .map(|cell| {
                let nets = hierarchy.nets_of(SubcktId(cell));
                let inner = nets.iter().filter(|&&net| !hierarchy.on_port[net as usize]);
                inner.count() as u64
            })
            .collect();
        let (mut counted, mut on_chain) = (vec![None; cells], vec![false; cells]);
        let walk = (hierarchy, &inner[..], strings);
        let (below, _) = self.flat_below(top, 1, walk, &mut counted, &mut on_chain)?;
        Ok((hierarchy.nets_of(top).len() as u64).saturating_add(below))
    }

    /// The devices and instances below one placement of `cell`, `depth`
    /// levels down from the top (the top is 1), each instance with the nets
    /// it adds (`inner` of its callee), saturating; and how many levels
    /// `cell` spans, itself included. Both memoised in `counted`, so a cell
    /// first counted shallow and met again deep is held to the depth cap as
    /// walking it again would be. Refuses a cycle, naming the subcircuit met
    /// twice on one chain, and a chain past the cap, so `expand` meets
    /// neither.
    fn flat_below(
        &self,
        cell: SubcktId,
        depth: u32,
        (hierarchy, inner, strings): (&Hierarchy, &[u64], &StrTable),
        counted: &mut [Option<(u64, u32)>],
        on_chain: &mut [bool],
    ) -> Result<(u64, u32), NetlistError> {
        let row = cell.0 as usize;
        let name = || strings.resolve(self.subckt_name[row]).to_owned();
        if let Some((count, levels)) = counted[row] {
            if depth + levels - 1 > MAX_HIERARCHY_DEPTH {
                return Err(NetlistError::TooDeep(name()));
            }
            return Ok((count, levels));
        }
        if on_chain[row] {
            return Err(NetlistError::CyclicHierarchy(name()));
        }
        if depth > MAX_HIERARCHY_DEPTH {
            return Err(NetlistError::TooDeep(name()));
        }
        on_chain[row] = true;
        let devices = self.devices_of(cell);
        let (mut count, mut levels) = (u64::from(devices.end - devices.start), 1);
        for &instance in hierarchy.instances_of(cell) {
            let callee = self.instance_of[instance as usize];
            if hierarchy.is_kept(callee) {
                let (from, to) = (
                    self.subckt_port_start[callee.0 as usize],
                    self.subckt_port_start[callee.0 as usize + 1],
                );
                if to - from > MAX_CELL_PINS {
                    let name = strings.resolve(self.subckt_name[callee.0 as usize]);
                    return Err(NetlistError::TooManyPins(name.to_owned(), to - from));
                }
                count = count.saturating_add(1);
                continue;
            }
            let walk = (hierarchy, inner, strings);
            let (below, spans) = self.flat_below(callee, depth + 1, walk, counted, on_chain)?;
            count = count
                .saturating_add(1 + inner[callee.0 as usize])
                .saturating_add(below);
            levels = levels.max(spans + 1);
        }
        on_chain[row] = false;
        counted[row] = Some((count, levels));
        Ok((count, levels))
    }

    /// Append `cell`'s devices to `out`, its nets mapped by `map` (indexed by
    /// this netlist's net ids), then each instance in it, recursively, under
    /// `path`. An instance writes only its callee's rows of `map`, and no
    /// subcircuit is on the chain twice, so every caller's rows stay as they
    /// were: one map serves every placement.
    fn expand(
        &self,
        cell: SubcktId,
        hierarchy: &Hierarchy,
        map: &mut [u32],
        path: &str,
        strings: &mut StrTable,
        out: &mut Netlist,
    ) {
        for device in self.devices_of(cell) {
            let device = device as usize;
            out.device_model.push(self.device_model[device]);
            out.device_kind.push(self.device_kind[device]);
            for &net in &self.terminal_net[csr(&self.device_terminal_start, device)] {
                out.terminal_net.push(RefNetId(map[net.0 as usize]));
            }
            out.device_terminal_start
                .push(narrow(out.terminal_net.len()));
            out.param
                .extend_from_slice(&self.param[csr(&self.device_param_start, device)]);
            out.device_param_start.push(narrow(out.param.len()));
        }
        for &instance in hierarchy.instances_of(cell) {
            let instance = instance as usize;
            let callee = self.instance_of[instance];
            let name = strings.resolve(self.instance_name[instance]).to_owned();
            let inner = if path.is_empty() {
                name
            } else {
                format!("{path}.{name}")
            };
            // Ports first: each takes the caller's net the instance passes.
            let passed = csr(&self.instance_net_start, instance);
            if hierarchy.is_kept(callee) {
                let first = narrow(out.device_model.len());
                out.placements.push(Placement {
                    path: strings.intern(&inner),
                    cell: self.subckt_name[callee.0 as usize],
                    devices: first..first + 1,
                });
                self.keep_whole(callee, &self.instance_net[passed], map, out);
                continue;
            }
            for (&port, &net) in self.ports_of(callee).iter().zip(&self.instance_net[passed]) {
                map[port.0 as usize] = map[net.0 as usize];
            }
            // Every other net of the callee is new, named under the path.
            for &net in hierarchy.nets_of(callee) {
                let net = net as usize;
                if !hierarchy.on_port[net] {
                    let local = strings.resolve(self.net_name[net]).to_owned();
                    map[net] = narrow(out.net_name.len());
                    out.net_name
                        .push(strings.intern(&format!("{inner}.{local}")));
                    out.net_subckt.push(SubcktId(0));
                }
            }
            let at = out.placements.len();
            let first = narrow(out.device_model.len());
            out.placements.push(Placement {
                path: strings.intern(&inner),
                cell: self.subckt_name[callee.0 as usize],
                devices: first..first,
            });
            self.expand(callee, hierarchy, map, &inner, strings, out);
            out.placements[at].devices.end = narrow(out.device_model.len());
        }
    }

    /// Appends one placement of `cell`, kept whole, as a device of
    /// [`DeviceKind::Cell`] on the caller's nets `passed` (mapped by `map`),
    /// in port order; and `cell`'s port names to
    /// [`Netlist::black_box_ports`] the first time it is placed.
    fn keep_whole(&self, cell: SubcktId, passed: &[RefNetId], map: &[u32], out: &mut Netlist) {
        let name = self.subckt_name[cell.0 as usize];
        out.device_model.push(name);
        out.device_kind.push(DeviceKind::Cell);
        out.terminal_net
            .extend(passed.iter().map(|net| RefNetId(map[net.0 as usize])));
        out.device_terminal_start
            .push(narrow(out.terminal_net.len()));
        out.device_param_start.push(narrow(out.param.len()));
        if !out.black_box_ports.iter().any(|(kept, _)| *kept == name) {
            let names = self
                .ports_of(cell)
                .iter()
                .map(|port| self.net_name[port.0 as usize])
                .collect();
            out.black_box_ports.push((name, names));
        }
    }

    /// The one subcircuit nothing instantiates. `None` when not unique, or
    /// when there is none: `lvs` refuses, never guesses. A subcircuit named
    /// as some device card's model is that device's definition, called by
    /// those cards, and never the top.
    pub fn top(&self) -> Option<SubcktId> {
        self.top_in(0..narrow(self.subckt_count()))
    }

    /// The one subcircuit of `rows` nothing instantiates, as [`Self::top`]
    /// asks of all: what a Verilog top level read over a cell library is
    /// ([`verilog::read_into`] returns its modules' rows), the library's
    /// unused cells aside.
    pub fn top_in(&self, rows: std::ops::Range<u32>) -> Option<SubcktId> {
        let mut instantiated = vec![false; self.subckt_count()];
        for &callee in &self.instance_of {
            instantiated[callee.0 as usize] = true;
        }
        // A subcircuit named as a card's model is that device's definition,
        // called as a device rather than placed (catalog LVS-067).
        let mut models = self.device_model.clone();
        models.sort_unstable();
        for (cell, name) in self.subckt_name.iter().enumerate() {
            instantiated[cell] |= models.binary_search(name).is_ok();
        }
        let mut free = rows.filter(|&row| !instantiated[row as usize]);
        match (free.next(), free.next()) {
            (Some(top), None) => Some(SubcktId(top)),
            _ => None,
        }
    }
}

/// What both walks of [`Netlist::flatten_top`] read per subcircuit, indexed
/// once: its instances in file order and its nets in row order, each a CSR
/// run, and whether each net is on a port. Without it each placement
/// scanned every instance and every net of the netlist (testing-plan F95).
struct Hierarchy {
    instance_start: Vec<u32>,
    instance: Vec<u32>,
    net_start: Vec<u32>,
    net: Vec<u32>,
    on_port: Vec<bool>,
    /// Per subcircuit, whether its instances are kept whole as black boxes;
    /// empty when none is.
    kept: Vec<bool>,
}

impl Hierarchy {
    fn of(netlist: &Netlist) -> Self {
        let cells = netlist.subckt_count();
        let (instance_start, instance) = group(&netlist.instance_subckt, cells);
        let (net_start, net) = group(&netlist.net_subckt, cells);
        let mut on_port = vec![false; netlist.net_name.len()];
        for &port in &netlist.port_net {
            on_port[port.0 as usize] = true;
        }
        Self {
            instance_start,
            instance,
            net_start,
            net,
            on_port,
            kept: Vec::new(),
        }
    }

    /// Whether instances of `cell` are kept whole.
    fn is_kept(&self, cell: SubcktId) -> bool {
        self.kept.get(cell.0 as usize).copied().unwrap_or(false)
    }

    /// The instance rows `cell` places, in file order.
    fn instances_of(&self, cell: SubcktId) -> &[u32] {
        &self.instance[csr(&self.instance_start, cell.0 as usize)]
    }

    /// The net rows of `cell`, ascending.
    fn nets_of(&self, cell: SubcktId) -> &[u32] {
        &self.net[csr(&self.net_start, cell.0 as usize)]
    }
}

/// Row `row`'s run in a CSR start column: `start[row]..start[row + 1]`.
fn csr(start: &[u32], row: usize) -> std::ops::Range<usize> {
    start[row] as usize..start[row + 1] as usize
}

/// The rows of `owner` grouped by the subcircuit each names, ascending
/// within a group: a CSR start column over `cells` subcircuits, and the rows.
fn group(owner: &[SubcktId], cells: usize) -> (Vec<u32>, Vec<u32>) {
    let mut start = vec![0u32; cells + 1];
    for &cell in owner {
        start[cell.0 as usize + 1] += 1;
    }
    for at in 1..start.len() {
        start[at] += start[at - 1];
    }
    let mut next = start.clone();
    let mut rows = vec![0u32; owner.len()];
    for (row, &cell) in owner.iter().enumerate() {
        let at = &mut next[cell.0 as usize];
        rows[*at as usize] = narrow(row);
        *at += 1;
    }
    (start, rows)
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
    // Past the run of digits starting at `from`.
    let digits_end = |from: usize| {
        from + bytes[from..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    };
    let digits = at;
    at = digits_end(at);
    if bytes.get(at) == Some(&b'.') {
        at = digits_end(at + 1);
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
            at = digits_end(exponent);
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
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode | DeviceKind::Inductor => {
            2
        }
        // Never a card's kind: a black box's arity is its subcircuit's.
        DeviceKind::Cell => u32::MAX,
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
        "inductor" => DeviceKind::Inductor,
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
    /// The deck's device models, sorted the same way, one row per name: what
    /// a card that names no model binds to.
    deck: Vec<(StrId, DeviceKind)>,
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
        kind: DeviceKind,
        (dialect, micron): (Dialect, bool),
    ) -> Result<(StrId, f64), NetlistError> {
        let bad = || NetlistError::Unexpected(tok.span, tok.text.to_string());
        let (key, text) = tok.text.split_once('=').ok_or_else(bad)?;
        if key.is_empty() {
            return Err(bad());
        }
        let mut value = spice_number(text).ok_or_else(bad)?;
        // SPICE names are case-insensitive; the layout side compares as `w`.
        let mut key = match dialect {
            Dialect::Spice => key.to_ascii_lowercase(),
            Dialect::Spectre => key.to_string(),
        };
        // Other tools' names for a two-pin device's area and perimeter:
        // ngspice's diode `pj`, KLayout's `A` and `P` (testing-plan F87).
        let two_pin = matches!(
            kind,
            DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode
        );
        if dialect == Dialect::Spice && two_pin {
            match key.as_str() {
                "a" => "area".clone_into(&mut key),
                "p" | "pj" => "perim".clone_into(&mut key),
                _ => {}
            }
        }
        // An inductor's `l` (SPICE, Spectre, `KLayout`'s `L`) is its
        // inductance, compared as `ind` so it never reads as a length.
        if kind == DeviceKind::Inductor && key.eq_ignore_ascii_case("l") {
            "ind".clone_into(&mut key);
        }
        let bare = text.ends_with(|c: char| c.is_ascii_digit() || c == '.');
        if micron && bare && (key == "w" || key == "l") {
            value *= 1e-6;
        }
        Ok((self.strings.intern(&key), value))
    }

    /// The model a card that names none is: the deck's one recogniser of
    /// `kind` (testing-plan F86, F97). None, or several, is a refusal naming
    /// them.
    fn only_model(&self, head: Tok, kind: DeviceKind) -> Result<StrId, NetlistError> {
        let of_kind: Vec<StrId> = self
            .deck
            .iter()
            .filter(|&&(_, of)| of == kind)
            .map(|&(name, _)| name)
            .collect();
        if let [model] = of_kind[..] {
            return Ok(model);
        }
        let what = format!("{kind:?}").to_lowercase();
        let has = if of_kind.is_empty() {
            format!("the deck has no {what} recogniser to bind it to")
        } else {
            let names: Vec<&str> = of_kind.iter().map(|&n| self.strings.resolve(n)).collect();
            format!("the deck has several {what} models: {}", names.join(", "))
        };
        Err(NetlistError::NoModel(head.span, head.text.to_string(), has))
    }

    /// `value`: an `R` or `C` card's positional value token, stored as its
    /// first parameter, `r` or `c`. `model`: `None` binds the card to the
    /// deck's one recogniser of its kind.
    fn device(
        &mut self,
        head: Tok,
        kind: DeviceKind,
        nets: &[Tok],
        (value, model): (Option<Tok>, Option<Tok>),
        params: &[Tok],
        subckt: SubcktId,
        (dialect, micron): (Dialect, bool),
    ) -> Result<(), NetlistError> {
        // A bare number where a model name belongs is a value that is not
        // this card's, refused rather than interned as a model name.
        if let Some(model) = model.filter(|model| spice_number(model.text).is_some()) {
            return Err(NetlistError::Unsupported(
                model.span,
                format!("{} with no model after it", model.text),
            ));
        }
        let primary = match value {
            Some(tok) => {
                let number = spice_number(tok.text)
                    .ok_or_else(|| NetlistError::Unexpected(tok.span, tok.text.to_string()))?;
                let name = match kind {
                    DeviceKind::Capacitor => "c",
                    DeviceKind::Inductor => "ind",
                    _ => "r",
                };
                Some((self.strings.intern(name), number))
            }
            None => None,
        };
        // Not stored; interned only because interning order is report order.
        self.strings.intern(head.text);
        let model = match model {
            Some(model) => self.strings.intern(model.text),
            None => self.only_model(head, kind)?,
        };
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
        let first = self.out.param.len();
        self.out.param.extend(primary);
        for tok in params {
            let param = self.param(*tok, kind, (dialect, micron))?;
            // A parameter stated twice, the value positionally and by name or
            // a perimeter as `perim` and `pj`: which one is meant is a guess.
            if self.out.param[first..]
                .iter()
                .any(|&(name, _)| name == param.0)
            {
                return Err(NetlistError::Unexpected(tok.span, tok.text.to_string()));
            }
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
        b'L' => DeviceKind::Inductor,
        b'X' => {
            let (cell, nets) = positional
                .split_last()
                .ok_or_else(|| NetlistError::Unexpected(head.span, head.text.to_string()))?;
            // A PDK primitive called as a subcircuit, `XM1 d g s b <model> W=..`:
            // a device when the deck names it, whether or not the netlist
            // also defines it (catalog LVS-067: the definition is the
            // device's model, `KLayout`'s `wants_subcircuit`, and is not
            // compared).
            let id = b.strings.intern(cell.text);
            let model = b.models.binary_search_by_key(&id, |&(n, _)| n);
            return match model {
                Ok(at) => {
                    let kind = b.models[at].1;
                    let (nets, model) = split_terminals(kind, positional, head)?;
                    b.device(
                        head,
                        kind,
                        nets,
                        (None, Some(model)),
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
    // `R1 a b 1k rpoly`: two nets, the value, the model. A two-pin card may
    // leave its model out, `R1 a b 1k` or `D1 a b` (testing-plan F86).
    let valued = matches!(
        kind,
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Inductor
    );
    let (nets, value, model) = match positional {
        [_, _, value, model] if valued => (&positional[..2], Some(*value), Some(*model)),
        [_, _, value] if valued && spice_number(value.text).is_some() => {
            (&positional[..2], Some(*value), None)
        }
        [_, _] if valued || kind == DeviceKind::Diode => (positional, None, None),
        _ => {
            let (nets, model) = split_terminals(kind, positional, head)?;
            (nets, None, Some(model))
        }
    };
    b.device(
        head,
        kind,
        nets,
        (value, model),
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
    // A `model` card's name is the model; a primitive master names none, so
    // the instance is the deck's one recogniser of its kind (F97).
    let (kind, named) = match b.models.binary_search_by_key(&master_id, |&(name, _)| name) {
        Ok(at) => (b.models[at].1, true),
        Err(_) => (
            spectre_primitive(master.text).ok_or_else(unsupported)?,
            false,
        ),
    };
    let subckt = b.open_id(head)?;
    let (nets, model) = split_terminals(kind, positional, head)?;
    b.device(
        head,
        kind,
        nets,
        (None, named.then_some(model)),
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
    devices: &DeviceRecognition,
) -> Result<Netlist, NetlistError> {
    let mut deck: Vec<(StrId, DeviceKind)> = devices
        .model
        .iter()
        .copied()
        .zip(devices.kind.iter().copied())
        .collect();
    deck.sort_unstable_by_key(|&(name, _)| name);
    deck.dedup_by_key(|&mut (name, _)| name);
    // SPICE's `X` card may call a deck model; Spectre's models are its cards.
    let models = match dialect {
        Dialect::Spice => deck.clone(),
        Dialect::Spectre => Vec::new(),
    };
    let (toks, card_start) = lex(source, dialect);
    let cards = card_start.len() - 1;
    let mut b = Build {
        strings,
        out: Netlist::default(),
        net_of: Vec::new(),
        defs: Vec::new(),
        models,
        deck,
        open: None,
        open_span: SourceSpan { line: 0 },
        instances: Vec::new(),
    };

    let card = |c: usize| &toks[csr(&card_start, c)];

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
    debug_assert!(
        tables_hold(&b.out),
        "every CSR column is one longer than its table, monotone and terminated, and \
         every net and subcircuit id is a row"
    );
    Ok(b.out)
}

/// Debug check of [`Netlist`]'s table invariants: each `*_start` column one
/// longer than its table, monotone, ending at the column it indexes (the
/// instance one empty when there are no instances), the parallel columns
/// equally long, and every net and subcircuit id in range.
pub(crate) fn tables_hold(netlist: &Netlist) -> bool {
    let csr = |start: &[u32], rows: usize, len: usize| {
        start.len() == rows + 1
            && start.windows(2).all(|w| w[0] <= w[1])
            && start[rows] as usize == len
    };
    let (subckts, devices, nets) = (
        netlist.subckt_count(),
        netlist.device_model.len(),
        netlist.net_name.len(),
    );
    let instances = netlist.instance_of.len();
    let net_ok = |net: &RefNetId| (net.0 as usize) < nets;
    let subckt_ok = |subckt: &SubcktId| (subckt.0 as usize) < subckts;
    csr(&netlist.subckt_port_start, subckts, netlist.port_net.len())
        && csr(&netlist.subckt_device_start, subckts, devices)
        && csr(
            &netlist.device_terminal_start,
            devices,
            netlist.terminal_net.len(),
        )
        && csr(&netlist.device_param_start, devices, netlist.param.len())
        && ((instances == 0 && netlist.instance_net_start.is_empty())
            || csr(
                &netlist.instance_net_start,
                instances,
                netlist.instance_net.len(),
            ))
        && netlist.device_kind.len() == devices
        && netlist.instance_subckt.len() == instances
        && netlist.instance_name.len() == instances
        && netlist.net_subckt.len() == nets
        && netlist.port_net.iter().all(net_ok)
        && netlist.terminal_net.iter().all(net_ok)
        && netlist.instance_net.iter().all(net_ok)
        && netlist.net_subckt.iter().all(subckt_ok)
        && netlist.instance_of.iter().all(subckt_ok)
        && netlist.instance_subckt.iter().all(subckt_ok)
}

pub mod verilog;

/// SPICE and CDL. The accepted subset is in the [module docs](super).
pub mod spice {
    use super::{Netlist, NetlistError};
    use crate::deck::DeviceRecognition;
    use gpurify_geom::StrTable;

    /// Reads a SPICE or CDL netlist, interning its names into `strings`.
    ///
    /// `devices`: the deck's recognisers, whose models an `X` card may call as
    /// a device (`XM1 d g s b sky130_fd_pr__nfet_01v8 W=0.42 L=0.15`). On such a
    /// card a bare `W`/`L` is in micrometres, as PDK models take it. An `R`,
    /// `C` or `D` card with no model is the one recogniser of its kind here.
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
        super::read_dialect(source, strings, super::Dialect::Spice, devices)
    }
}

/// Spectre.
///
/// Declared subset: no `inline subckt`, no `alter`, no sweeps. Anything outside
/// it is [`NetlistError::Unsupported`] with the line it sits on. The accepted
/// subset is in the [module docs](super).
pub mod spectre {
    use super::{Netlist, NetlistError};
    use crate::deck::DeviceRecognition;
    use gpurify_geom::StrTable;

    /// Reads a Spectre netlist, interning its names into `strings`. A device's
    /// family comes from its `model` card's master or a built-in primitive
    /// master (`nmos`, `bsim4`, `resistor`, …); any other master is refused.
    ///
    /// `devices`: the deck's recognisers. An instance of a primitive master
    /// names no model, so it is the one recogniser of its kind here.
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
        super::read_dialect(source, strings, super::Dialect::Spectre, devices)
    }
}
