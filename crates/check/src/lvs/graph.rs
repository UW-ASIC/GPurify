//! The bipartite device/net graph both sides are projected to before matching.
//!
//! Data in: a `topology` extraction, or one subcircuit of a reference netlist.
//! Data out: a [`Graph`] with CSR incidence in both directions.

use crate::lvs::refine::kind_code;
use crate::topology::device::{DeviceMeasure, DeviceParam};
use crate::topology::{csr_run, DeviceTable, NetId, NetTable, PortTable, TerminalRole};
use gpurify_geom::Grid;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::{StrId, StrTable};

/// A row count as a `u32` id; panics rather than truncating.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a table addresses its own rows with u32")
}

/// A netlist reduced to what matching needs: `SoA` device and net columns with
/// CSR incidence in both directions. Devices and nets are numbered separately,
/// each from zero.
///
/// The columns are public so tests can build a graph by hand. Every function
/// here returns a graph that keeps these invariants, and [`compare`],
/// [`reduce`] and [`check_layout`] read theirs as given:
///
/// - `device_kind` and `device_model` hold one row per device, and
///   `net_name` one row per net;
/// - each `*_start` column holds one offset per row plus a terminator,
///   ascending from zero, and the column it indexes ends at the terminator;
/// - every `terminal_net` is a net row, or `u32::MAX` for a terminal on no
///   net;
/// - `net_terminal` is the transpose of the device side: each net's
///   terminals ascending by device, a terminal on no net on none;
/// - every `port_net` is a net row.
///
/// The empty [`Default`] graph is valid as it is.
///
/// [`compare`]: crate::lvs::compare
/// [`reduce`]: crate::lvs::reduce::reduce
/// [`check_layout`]: crate::lvs::check_layout
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Graph {
    /// The family of each device. With `device_model`, the class a device
    /// starts refinement in: devices of different kind or model never pair.
    pub device_kind: Vec<DeviceKind>,
    /// The model name of each device.
    pub device_model: Vec<StrId>,
    /// Terminals of each device, CSR into `terminal_net` / `terminal_role`.
    pub device_terminal_start: Vec<u32>,
    /// The net row each terminal lands on, or `u32::MAX` for none.
    pub terminal_net: Vec<u32>,
    /// The role of each terminal. Matching reads roles, never positions.
    pub terminal_role: Vec<TerminalRole>,
    /// Device parameters in SI units, CSR into `param`.
    pub device_param_start: Vec<u32>,
    /// `(name, value)` per parameter: a lowercased, interned SPICE name, and a
    /// value in SI base units (metres, square metres, a plain count).
    pub param: Vec<(StrId, f64)>,

    /// Devices attached to each net, CSR into `net_terminal`, ascending by device.
    pub net_terminal_start: Vec<u32>,
    /// `(device row, role)` of each terminal, grouped by net.
    pub net_terminal: Vec<(u32, TerminalRole)>,
    /// Each net's name: the reference's net name, or the layout's port label.
    /// A named net is never consumed by a series merge.
    pub net_name: Vec<Option<StrId>>,
    /// Nets that are ports of this cell. A port is never consumed by a series
    /// merge.
    pub port_net: Vec<u32>,
}

impl Graph {
    /// The number of device rows.
    pub fn device_count(&self) -> usize {
        self.device_kind.len()
    }
    /// The number of net rows.
    pub fn net_count(&self) -> usize {
        self.net_name.len()
    }
    /// One device's terminals as parallel `(nets, roles)` slices, in the order
    /// the graph was built with.
    ///
    /// # Panics
    ///
    /// Panics if `device` is not a device row.
    pub fn terminals_of(&self, device: u32) -> (&[u32], &[TerminalRole]) {
        let (from, to) = csr_run(&self.device_terminal_start, device as usize);
        (&self.terminal_net[from..to], &self.terminal_role[from..to])
    }
    /// Every terminal on one net as `(device row, role)`, ascending by device.
    ///
    /// # Panics
    ///
    /// Panics if `net` is not a net row.
    pub fn terminals_on(&self, net: u32) -> &[(u32, TerminalRole)] {
        let (from, to) = csr_run(&self.net_terminal_start, net as usize);
        &self.net_terminal[from..to]
    }
    /// One device's `(name, value)` parameters, in the order they were stated.
    ///
    /// # Panics
    ///
    /// Panics if `device` is not a device row.
    pub fn params_of(&self, device: u32) -> &[(StrId, f64)] {
        let (from, to) = csr_run(&self.device_param_start, device as usize);
        &self.param[from..to]
    }
}

/// The SPICE parameter name each measured [`DeviceParam`] compares under.
const fn spice_param_name(param: DeviceParam) -> &'static str {
    match param {
        DeviceParam::Width => "w",
        DeviceParam::Length => "l",
        DeviceParam::Area => "area",
        DeviceParam::Perimeter => "perim",
        DeviceParam::Fingers => "nf",
    }
}

/// Project a `topology` extraction. Device row `k` is `DeviceId(k)`,
/// net row `k` is `NetId(k)`; `port_net` is ascending.
///
/// `devices` and `ports` must have been built against `nets`. A net's name
/// is its port label, so an unlabelled net is unnamed. Terminals keep the
/// recogniser's order and roles.
///
/// A measured parameter is emitted in metres (area in m²) only when its SPICE
/// name is already interned in `strings` (so the reference can declare it) and a
/// grid is given; otherwise it is omitted. The names are `w`, `l`, `area`,
/// `perim` and `nf`. Interned anywhere means every device carries it, so
/// [`compare`](crate::lvs::compare) keeps a measure only on devices whose
/// kind and model the reference declares it for.
///
/// # Limits
///
/// Extraction measures MOS `w` and `l` and every device's marker `area`, and
/// nothing else (testing-plan F16).
///
/// # Panics
///
/// Panics if the tables hold `u32::MAX` or more rows.
pub fn from_layout(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    strings: &StrTable,
    grid: Option<Grid>,
) -> Graph {
    let net_count = nets.net_count();
    let mut graph = Graph::default();

    graph.device_kind.clone_from(&devices.kind);
    graph.device_model.clone_from(&devices.model);
    graph
        .device_terminal_start
        .clone_from(&devices.terminal_start);
    graph.terminal_role.clone_from(&devices.terminal_role);
    for device in 0..devices.kind.len() {
        let slots =
            devices.terminal_start[device] as usize..devices.terminal_start[device + 1] as usize;
        for slot in slots {
            graph.terminal_role[slot] = comparable(devices.kind[device], graph.terminal_role[slot]);
        }
    }
    graph.terminal_net.clear();
    graph
        .terminal_net
        .extend(devices.terminal_net.iter().map(|net| net.0));

    #[expect(
        clippy::cast_precision_loss,
        reason = "grid resolutions are small integers; compared under a relative tolerance"
    )]
    let metre_per_dbu = grid.map(|grid| 1e-6 / grid.dbu_per_um() as f64);
    graph.param.clear();
    graph.device_param_start.clear();
    graph.device_param_start.push(0);
    #[expect(
        clippy::cast_precision_loss,
        reason = "measured extents are bounded by the coordinate domain"
    )]
    for device in 0..devices.len() {
        for &(param, measure) in devices.params_of(crate::topology::DeviceId(narrow(device))) {
            let Some(name) = strings.get(spice_param_name(param)) else {
                continue;
            };
            let value = match (measure, metre_per_dbu) {
                (DeviceMeasure::Count(count), _) => f64::from(count),
                (DeviceMeasure::Length(length), Some(scale)) => length.raw() as f64 * scale,
                (DeviceMeasure::Area(area), Some(scale)) => area.raw() as f64 * scale * scale,
                (_, None) => continue,
            };
            graph.param.push((name, value));
        }
        graph.device_param_start.push(narrow(graph.param.len()));
    }

    // ponytail: O(nets · log ports) through `name_of`; a linear merge needs
    // `PortTable` to expose its columns.
    graph.net_name.clear();
    graph.port_net.clear();
    for net in 0..net_count {
        let id = narrow(net);
        let name = ports.name_of(NetId(id));
        graph.net_name.push(name);
        if name.is_some() {
            graph.port_net.push(id);
        }
    }

    transpose_into(&mut graph, net_count);
    graph
}

/// Build the net-side incidence from the device-side one, in place. Terminals
/// land ascending by device within each net; a terminal on no net is dropped.
pub(crate) fn transpose_into(graph: &mut Graph, net_count: usize) {
    // One bucket per net plus a trash bucket at `net_count`, truncated away.
    let trash = net_count;
    graph.net_terminal_start.clear();
    graph.net_terminal_start.resize(net_count + 1, 0);
    for &net in &graph.terminal_net {
        graph.net_terminal_start[(net as usize).min(trash)] += 1;
    }
    for bucket in 1..=net_count {
        graph.net_terminal_start[bucket] += graph.net_terminal_start[bucket - 1];
    }

    let filed = graph.net_terminal_start[net_count] as usize;
    graph.net_terminal.clear();
    graph.net_terminal.resize(filed, (0, TerminalRole::Pin(0)));

    // Each entry is its bucket's end and doubles as a descending write cursor,
    // coming to rest on the bucket's start.
    for device in (0..graph.device_kind.len()).rev() {
        let (from, to) = csr_run(&graph.device_terminal_start, device);
        for slot in (from..to).rev() {
            let bucket = (graph.terminal_net[slot] as usize).min(trash);
            let at = graph.net_terminal_start[bucket] as usize - 1;
            graph.net_terminal[at] = (narrow(device), graph.terminal_role[slot]);
            graph.net_terminal_start[bucket] = narrow(at);
        }
    }
    graph
        .net_terminal
        .truncate(graph.net_terminal_start[net_count] as usize);
}

/// Project one subcircuit of a reference netlist. Roles come from card
/// position (`card_role`); `port_net` keeps the subcircuit's port order.
///
/// | Card | Position 0 | 1 | 2 | 3 |
/// |---|---|---|---|---|
/// | MOS (`M`) | `Drain` | `Gate` | `Source` | `Bulk` |
/// | BJT (`Q`) | `Collector` | `Base` | `Emitter` | `Pin(3)` |
/// | resistor, capacitor, diode | `Pin(0)` | `Pin(1)` | | |
///
/// Device and net rows follow the netlist's order within the subcircuit.
/// Every net is named, and parameters are copied as the netlist states them.
/// A terminal on a net of another subcircuit lands on no net.
///
/// # Limits
///
/// - Only the subcircuit's own device cards are kept. An `X` card that calls a
///   deck device model is a device and is kept; an `X` instance of another
///   subcircuit is skipped, so flatten the netlist first
///   ([`Netlist::flatten_top`](gpurify_ingest::netlist::Netlist::flatten_top)),
///   as the load step does (testing-plan F1).
/// - A resistor's ends are both `Pin(0)`, so they match either way round; a
///   diode's anode and cathode, and a capacitor's plates, stay `Pin(0)` and
///   `Pin(1)` (testing-plan F15).
///
/// # Panics
///
/// Panics if `subckt` is not a subcircuit of `netlist`.
pub fn from_reference(netlist: &Netlist, subckt: SubcktId) -> Graph {
    let mut graph = Graph::default();
    let devices = netlist.devices_of(subckt);
    let (first, last) = (devices.start as usize, devices.end as usize);

    // `rank[reference row]` is the graph net index, or `u32::MAX` for a net of
    // another subcircuit (so a terminal on one is filed on no net).
    let mut rank = Vec::with_capacity(netlist.net_subckt.len());
    let mut net_count = 0u32;
    graph.net_name.clear();
    for (row, &owner) in netlist.net_subckt.iter().enumerate() {
        if owner == subckt {
            rank.push(net_count);
            net_count += 1;
            graph.net_name.push(Some(netlist.net_name[row]));
        } else {
            rank.push(u32::MAX);
        }
    }

    graph.device_kind.clear();
    graph
        .device_kind
        .extend_from_slice(&netlist.device_kind[first..last]);
    graph.device_model.clear();
    graph
        .device_model
        .extend_from_slice(&netlist.device_model[first..last]);

    // Both CSR offset columns rebased to start at zero; a netlist with no such
    // column still owes the graph a terminator. Returns the source span.
    let rebase = |column: &[u32], out: &mut Vec<u32>| -> (usize, usize) {
        let offsets = column.get(first..=last).unwrap_or(&[]);
        let base = offsets.first().copied().unwrap_or(0);
        out.clear();
        out.extend(offsets.iter().map(|&offset| offset - base));
        if out.is_empty() {
            out.push(0);
        }
        (base as usize, offsets.last().copied().unwrap_or(0) as usize)
    };
    let (tfirst, tlast) = rebase(
        &netlist.device_terminal_start,
        &mut graph.device_terminal_start,
    );
    let (qfirst, qlast) = rebase(&netlist.device_param_start, &mut graph.device_param_start);

    graph.terminal_net.clear();
    graph.terminal_net.extend(
        netlist.terminal_net[tfirst..tlast]
            .iter()
            .map(|net| rank[net.0 as usize]),
    );
    graph.param.clear();
    graph.param.extend_from_slice(&netlist.param[qfirst..qlast]);

    graph.terminal_role.clear();
    for device in 0..last - first {
        let kind = netlist.device_kind[first + device];
        let (from, to) = csr_run(&graph.device_terminal_start, device);
        graph
            .terminal_role
            .extend((0..to - from).map(|position| card_role(kind, position)));
    }

    let (pfirst, plast) = csr_run(&netlist.subckt_port_start, subckt.0 as usize);
    graph.port_net.clear();
    graph.port_net.extend(
        netlist.port_net[pfirst..plast]
            .iter()
            .map(|net| rank[net.0 as usize]),
    );

    transpose_into(&mut graph, net_count as usize);
    graph
}

/// Drop every reference `Bulk` terminal when no layout terminal is `Bulk` (the
/// deck extracts none). Side-wide, so a missing bulk strap still mismatches.
/// Only terminals are dropped, never nets.
pub(crate) fn drop_unextracted_bulk(layout: &Graph, graph: &mut Graph) {
    if layout.terminal_role.contains(&TerminalRole::Bulk) {
        return;
    }
    if !graph.terminal_role.contains(&TerminalRole::Bulk) {
        return;
    }

    let mut nets = Vec::with_capacity(graph.terminal_net.len());
    let mut roles = Vec::with_capacity(graph.terminal_role.len());
    let mut starts = Vec::with_capacity(graph.device_count() + 1);
    starts.push(0u32);
    for device in 0..graph.device_count() {
        let (terminal_nets, terminal_roles) = graph.terminals_of(narrow(device));
        for (&net, &role) in terminal_nets.iter().zip(terminal_roles) {
            if role != TerminalRole::Bulk {
                nets.push(net);
                roles.push(role);
            }
        }
        starts.push(narrow(nets.len()));
    }
    graph.terminal_net = nets;
    graph.terminal_role = roles;
    graph.device_terminal_start = starts;
    let net_count = graph.net_count();
    transpose_into(graph, net_count);
}

/// Keep each layout parameter only where the reference declares that name on
/// some device of the same kind and model. [`from_layout`] measures a name for
/// every device once anything declares it, and a reference that sizes one
/// model says nothing about another (testing-plan F22). Only parameters are
/// dropped, never devices.
pub(crate) fn keep_declared_params(reference: &Graph, layout: &mut Graph) {
    let identity = |graph: &Graph, device: usize| {
        (
            kind_code(graph.device_kind[device]),
            graph.device_model[device],
        )
    };
    let mut declared: Vec<(u64, StrId, StrId)> = (0..reference.device_count())
        .flat_map(|device| {
            let (kind, model) = identity(reference, device);
            reference
                .params_of(narrow(device))
                .iter()
                .map(move |&(name, _)| (kind, model, name))
        })
        .collect();
    declared.sort_unstable();
    declared.dedup();

    let mut param = Vec::with_capacity(layout.param.len());
    let mut start = Vec::with_capacity(layout.device_count() + 1);
    start.push(0);
    for device in 0..layout.device_count() {
        let (kind, model) = identity(layout, device);
        param.extend(
            layout
                .params_of(narrow(device))
                .iter()
                .filter(|&&(name, _)| declared.binary_search(&(kind, model, name)).is_ok()),
        );
        start.push(narrow(param.len()));
    }
    layout.param = param;
    layout.device_param_start = start;
}

/// The role LVS compares a terminal under: a resistor's two ends are
/// interchangeable, so both become `Pin(0)`; every other role is kept, and a
/// diode's or capacitor's pins stay distinct (testing-plan F15: a reversed diode
/// is a different circuit, and Netgen does not permute capacitor plates either).
fn comparable(kind: DeviceKind, role: TerminalRole) -> TerminalRole {
    match (kind, role) {
        (DeviceKind::Resistor, TerminalRole::Pin(_)) => TerminalRole::Pin(0),
        _ => role,
    }
}

/// A SPICE card position to its [`TerminalRole`]: drain-first MOS,
/// collector-first BJT.
fn card_role(kind: DeviceKind, position: usize) -> TerminalRole {
    use TerminalRole::{Base, Bulk, Collector, Drain, Emitter, Gate, Source};
    match (kind, position) {
        (DeviceKind::Mos, 0) => Drain,
        (DeviceKind::Mos, 1) => Gate,
        (DeviceKind::Mos, 2) => Source,
        (DeviceKind::Mos, 3) => Bulk,
        (DeviceKind::Bjt, 0) => Collector,
        (DeviceKind::Bjt, 1) => Base,
        (DeviceKind::Bjt, 2) => Emitter,
        _ => comparable(
            kind,
            TerminalRole::Pin(u8::try_from(position).unwrap_or(u8::MAX)),
        ),
    }
}
