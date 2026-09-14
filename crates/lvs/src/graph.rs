//! The one bipartite device/net graph shape both sides are reduced to before matching.

use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::{StrId, StrTable};
use gpurify_ingest::deck::DeviceKind;
use gpurify_topology::{DeviceTable, NetId, NetTable, PortTable, TerminalRole};

/// One row's run in a CSR offset column. Unguarded on purpose: a row past the
/// table panics rather than reading as an empty run.
fn csr_run(start: &[u32], row: usize) -> (usize, usize) {
    let (from, to) = (start[row] as usize, start[row + 1] as usize);
    debug_assert!(from <= to, "a CSR run runs backwards");
    (from, to)
}

/// A row count as the `u32` every id column in this workspace is made of. Panics
/// rather than truncating, which would leave a table's tail unchecked.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a table addresses its own rows with u32")
}

/// A node in the bipartite graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    Device(u32),
    Net(u32),
}

/// A netlist reduced to what matching needs: `SoA` device and net columns with
/// CSR incidence in both directions.
#[derive(Debug, Default, PartialEq)]
pub struct Graph {
    pub device_kind: Vec<DeviceKind>,
    pub device_model: Vec<StrId>,
    /// Terminals of each device, CSR into `terminal_net` / `terminal_role`.
    pub device_terminal_start: Vec<u32>,
    pub terminal_net: Vec<u32>,
    pub terminal_role: Vec<TerminalRole>,
    /// Device parameters for parametric comparison, CSR into `param`.
    pub device_param_start: Vec<u32>,
    pub param: Vec<(StrId, f64)>,

    /// Devices attached to each net, CSR into `net_terminal`.
    pub net_terminal_start: Vec<u32>,
    pub net_terminal: Vec<(u32, TerminalRole)>,
    /// Declared name, for nets that have one.
    pub net_name: Vec<Option<StrId>>,
    /// Nets that are ports of this cell.
    pub port_net: Vec<u32>,
}

impl Graph {
    pub fn device_count(&self) -> usize {
        debug_assert_eq!(
            self.device_model.len(),
            self.device_kind.len(),
            "a device lost its model, or a model lost its device"
        );
        // A `Default` graph carries no offsets at all, so the count comes off the
        // row column, not `start.len() - 1`.
        debug_assert!(
            self.device_terminal_start.is_empty()
                || self.device_terminal_start.len() == self.device_kind.len() + 1,
            "the terminal CSR column carries one offset per device plus a terminator"
        );
        debug_assert!(
            self.device_param_start.is_empty()
                || self.device_param_start.len() == self.device_kind.len() + 1,
            "the parameter CSR column carries one offset per device plus a terminator"
        );
        self.device_kind.len()
    }
    pub fn net_count(&self) -> usize {
        debug_assert!(
            self.net_terminal_start.is_empty()
                || self.net_terminal_start.len() == self.net_name.len() + 1,
            "the net CSR column carries one offset per net plus a terminator"
        );
        self.net_name.len()
    }
    pub fn terminals_of(&self, device: u32) -> (&[u32], &[TerminalRole]) {
        debug_assert!(
            (device as usize) < self.device_count(),
            "device {device} of {}",
            self.device_count()
        );
        debug_assert_eq!(
            self.terminal_net.len(),
            self.terminal_role.len(),
            "a net column and a role column arrive parallel"
        );
        let (from, to) = csr_run(&self.device_terminal_start, device as usize);
        (&self.terminal_net[from..to], &self.terminal_role[from..to])
    }
    pub fn terminals_on(&self, net: u32) -> &[(u32, TerminalRole)] {
        debug_assert!(
            (net as usize) < self.net_count(),
            "net {net} of {}",
            self.net_count()
        );
        let (from, to) = csr_run(&self.net_terminal_start, net as usize);
        &self.net_terminal[from..to]
    }
    pub fn params_of(&self, device: u32) -> &[(StrId, f64)] {
        debug_assert!(
            (device as usize) < self.device_count(),
            "device {device} of {}",
            self.device_count()
        );
        let (from, to) = csr_run(&self.device_param_start, device as usize);
        &self.param[from..to]
    }
}

/// The layout side. A newtype so the two sides cannot be transposed at a call
/// site: `compare(reference, layout)` is a silently reversed report.
#[derive(Debug, Default, PartialEq)]
pub struct LayoutGraph(pub Graph);

/// The reference side.
#[derive(Debug, Default, PartialEq)]
pub struct RefGraph(pub Graph);

/// Project a `topology` extraction into the matching graph, refilling `out`.
///
/// Index-preserving: graph device row `k` is `DeviceId(k)` and net row `k` is
/// `NetId(k)`, the graph's only link back to geometry. `port_net` is ascending.
pub fn from_layout_into(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    out: &mut LayoutGraph,
) {
    let device_count = devices.len();
    let net_count = nets.net_count();
    debug_assert_eq!(
        devices.terminal_net.len(),
        devices.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );
    debug_assert!(
        devices.terminal_start.is_empty() || devices.terminal_start.len() == device_count + 1,
        "the terminal CSR column carries one offset per device plus a terminator"
    );

    let graph = &mut out.0;

    graph.device_kind.clear();
    graph.device_kind.extend_from_slice(&devices.kind);
    graph.device_model.clear();
    graph.device_model.extend_from_slice(&devices.model);
    graph.device_terminal_start.clear();
    graph.device_terminal_start
        .extend_from_slice(&devices.terminal_start);
    graph.terminal_role.clear();
    graph.terminal_role.extend_from_slice(&devices.terminal_role);

    // `NetId::NONE` becomes `u32::MAX` and stays: a terminal on no net is an
    // extraction fault `check_topology` reports, not one to drop or renumber.
    graph.terminal_net.clear();
    graph.terminal_net.reserve(devices.terminal_net.len());
    for &net in &devices.terminal_net {
        graph.terminal_net.push(net.0);
    }

    // Parameters are left empty: converting `(DeviceParam, DeviceMeasure)` to
    // `(StrId, f64)` needs a `StrTable` and a `Dbu` scale, and this signature has
    // neither. Parametric comparison reports nothing rather than a wrong number.
    graph.param.clear();
    graph.device_param_start.clear();
    graph
        .device_param_start
        .resize(graph.device_terminal_start.len(), 0);

    // A port is a named net: `PortTable` is the only thing either column can
    // come from, so `net_name` and `port_net` are the same set read two ways.
    //
    // ponytail: `O(nets · log ports)`, because `PortTable` publishes none of its
    // four columns and `name_of` — a binary search, so a chain rather than a
    // lane op — is the only way to read one. That is the same missing accessor
    // six sites across three crates are blocked on, this one the hottest;
    // `## PortTable has no enumerable surface, third pass` in
    // `docs/SIGNATURE_DEFECTS.md` is the consolidated record. A merge of the
    // port column against `0 .. net_count` is one linear pass and needs no
    // search at all.
    //
    // `port_net`'s scratch is `ports.len() + 1` rows, not `net_count`: the store
    // below is unconditional and every unnamed net overwrites the slot past the
    // last port.
    graph.net_name.clear();
    graph.net_name.reserve(net_count);
    graph.port_net.clear();
    graph.port_net.resize(ports.len() + 1, 0);
    let mut named = 0usize;
    for net in 0..net_count {
        let id = narrow(net);
        let name = ports.name_of(NetId(id));
        graph.net_name.push(name);
        // Always store, conditionally advance.
        graph.port_net[named] = id;
        named += usize::from(name.is_some());
    }
    graph.port_net.truncate(named);
    debug_assert_eq!(
        named,
        ports.len(),
        "a bound port names a net outside 0..{net_count}"
    );
    debug_assert!(
        graph.port_net.windows(2).all(|pair| pair[0] < pair[1]),
        "port_net is documented ascending"
    );

    transpose_into(graph, net_count);

    debug_assert_eq!(graph.device_count(), device_count, "a device went missing");
    debug_assert_eq!(graph.net_count(), net_count, "a net went missing");
}

/// Build the net-side incidence from the device-side one, in place.
///
/// Terminals land ascending by device within each net.
pub(crate) fn transpose_into(graph: &mut Graph, net_count: usize) {
    let terminals = graph.terminal_net.len();
    debug_assert_eq!(
        terminals,
        graph.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );

    // One bucket per net, plus a trash bucket at `net_count` for a terminal on no
    // net; it is filed and then truncated away.
    let trash = net_count;
    graph.net_terminal_start.clear();
    graph.net_terminal_start.resize(net_count + 1, 0);

    // A histogram and a prefix sum; neither vectorises.
    for &net in &graph.terminal_net {
        debug_assert!(
            (net as usize) < net_count || net == u32::MAX,
            "terminal names net {net} of {net_count}, which is neither a net nor NONE"
        );
        graph.net_terminal_start[(net as usize).min(trash)] += 1;
    }
    for bucket in 1..=net_count {
        graph.net_terminal_start[bucket] += graph.net_terminal_start[bucket - 1];
    }

    // After the prefix sum each entry is its bucket's *end*, so the last one is
    // the total, including the trash bucket.
    let filed = graph.net_terminal_start[net_count] as usize;
    debug_assert_eq!(filed, terminals, "every terminal is filed exactly once");
    graph.net_terminal.clear();
    graph.net_terminal.resize(filed, (0, TerminalRole::Pin(0)));

    // `net_terminal_start[b]` doubles as bucket `b`'s write cursor. Descending,
    // cursor decremented before the store: terminals come out ascending by device
    // and every cursor comes to rest on its own bucket's start, which is then the
    // offset column.
    let device_count = graph.device_kind.len();
    for device in (0..device_count).rev() {
        let (from, to) = csr_run(&graph.device_terminal_start, device);
        for slot in (from..to).rev() {
            let bucket = (graph.terminal_net[slot] as usize).min(trash);
            let at = graph.net_terminal_start[bucket] as usize - 1;
            graph.net_terminal[at] = (narrow(device), graph.terminal_role[slot]);
            graph.net_terminal_start[bucket] = narrow(at);
        }
    }

    // `net_terminal_start[net_count]` is both the column's terminator and the
    // length of `net_terminal`.
    debug_assert_eq!(
        graph.net_terminal_start[0], 0,
        "the first bucket's cursor did not come to rest at zero"
    );
    graph
        .net_terminal
        .truncate(graph.net_terminal_start[net_count] as usize);

    debug_assert!(
        graph.net_terminal_start.windows(2).all(|pair| pair[0] <= pair[1]),
        "net offsets are non-decreasing"
    );
    debug_assert!(
        graph.net_terminal.len() <= terminals,
        "the transpose filed more terminals than the devices declared"
    );
    debug_assert!(
        graph.net_terminal.iter().all(|&(device, _)| (device as usize) < device_count),
        "a net lists a terminal of a device that does not exist"
    );
}

/// Project one subcircuit of a reference netlist into the matching graph.
///
/// The two sides must agree on which *role* a terminal carries, never on which
/// slot carries it: a card lists drain first, a recogniser lists gate first.
pub fn from_reference_into(
    netlist: &Netlist,
    subckt: SubcktId,
    strings: &StrTable,
    out: &mut RefGraph,
) {
    // `strings` is accepted and unread: every name this projection moves is
    // already a `StrId` on both sides.
    let _ = strings;

    let rows = netlist.net_subckt.len();
    debug_assert_eq!(
        netlist.net_name.len(),
        rows,
        "a reference net lost its name, or a name lost its net"
    );
    let devices = netlist.devices_of(subckt);
    let (first, last) = (devices.start as usize, devices.end as usize);
    let device_count = last - first;
    debug_assert!(
        last <= netlist.device_kind.len(),
        "subcircuit {} claims devices past the device table",
        subckt.0
    );

    let graph = &mut out.0;

    // `rank[reference row] == graph net index`, or `u32::MAX` for a net of
    // another subcircuit. Indexed by *global* reference row, so it is `rows` long.
    //
    // The buffer is `graph.net_terminal_start`, borrowed for the length of the
    // projection: from here until `transpose_into`, `graph` is NOT a readable
    // `Graph` — that column holds `rows` ranks, not `net_count + 1` offsets, so
    // `Graph::net_count` and `Graph::terminals_on` would fail their own asserts.
    // Nothing between here and there may call either.
    let rank = &mut graph.net_terminal_start;
    rank.clear();
    rank.reserve(rows);
    let mut count = 0u32;
    for row in 0..rows {
        let mine = u32::from(netlist.net_subckt[row] == subckt);
        // `mine - 1` is zero when the net is ours and all-ones when it is not,
        // so the sentinel and the rank come out of one `or`.
        rank.push(count | mine.wrapping_sub(1));
        count += mine;
    }
    let net_count = count as usize;
    debug_assert_eq!(rank.len(), rows, "the rank column is one entry per reference net");
    debug_assert!(net_count <= rows, "more nets ranked than the netlist declares");

    // The nets of this subcircuit, in ascending reference-row order. Every
    // reference net carries a name, so every projected net is `Some`.
    debug_assert_eq!(
        netlist.net_subckt.len(),
        netlist.net_name.len(),
        "the owner column and the name column arrive parallel"
    );
    graph.net_name.clear();
    graph.net_name.reserve(rows);
    let out = &mut graph.net_name.spare_capacity_mut()[..rows];
    let mut kept = 0usize;
    for row in 0..rows {
        let keep = netlist.net_subckt[row] == subckt;
        // `kept <= row` by induction: it advances by at most one per iteration.
        // Rejected slots are left uninitialised and never read — `set_len(kept)`
        // truncates them away and `Option<StrId>` is `Copy`, so nothing drops.
        debug_assert!(kept <= row);
        // SAFETY: `kept <= row < rows == out.len()`, from the induction above.
        // The store must be unchecked: `kept`'s step is data-dependent, so LLVM
        // gets no affine recurrence for it, cannot prove the bound, and emits a
        // live panic edge that pins the loop to one element per iteration.
        unsafe { out.get_unchecked_mut(kept) }.write(Some(netlist.net_name[row]));
        kept += usize::from(keep);
    }
    // SAFETY: slot `k` was written while `kept` held `k`, for every `k < kept`,
    // and `kept <= rows <= capacity`.
    unsafe { graph.net_name.set_len(kept) };
    debug_assert_eq!(
        kept, net_count,
        "the rank and the compact disagree on the net count"
    );

    graph.device_kind.clear();
    graph.device_kind
        .extend_from_slice(&netlist.device_kind[first..last]);
    graph.device_model.clear();
    graph.device_model
        .extend_from_slice(&netlist.device_model[first..last]);

    debug_assert!(
        device_count == 0 || last < netlist.device_terminal_start.len(),
        "the device terminal CSR column is missing its terminator"
    );
    let span = |column: &[u32], row: usize| column.get(row).copied().unwrap_or(0) as usize;
    let (tfirst, tlast) = (
        span(&netlist.device_terminal_start, first),
        span(&netlist.device_terminal_start, last),
    );
    debug_assert!(
        tfirst <= tlast && tlast <= netlist.terminal_net.len(),
        "terminal range {tfirst}..{tlast} leaves the terminal column"
    );
    let (qfirst, qlast) = (
        span(&netlist.device_param_start, first),
        span(&netlist.device_param_start, last),
    );
    debug_assert!(
        qfirst <= qlast && qlast <= netlist.param.len(),
        "parameter range {qfirst}..{qlast} leaves the parameter column"
    );
    // A terminal naming a net of another subcircuit gathers `u32::MAX` and is
    // filed on no net. Fail closed: `check_topology` reports it rather than this
    // body attaching it to net zero.
    graph.terminal_net.clear();
    graph.terminal_net.reserve(tlast - tfirst);
    let (rank, nets_out) = (&graph.net_terminal_start, &mut graph.terminal_net);
    for &net in &netlist.terminal_net[tfirst..tlast] {
        nets_out.push(rank[net.0 as usize]);
    }

    // Both CSR offset columns are the netlist's own, rebased by the span's start.
    // `wrapping_sub`, not `-`: a netlist whose offsets ran backwards wraps rather
    // than panicking in the loop, and the asserts below catch it. `first ..= last`
    // because a CSR column of `n` rows carries `n + 1` offsets.
    let base_terminal = narrow(tfirst);
    let terminal_offsets = netlist
        .device_terminal_start
        .get(first..=last)
        .unwrap_or(&[]);
    graph.device_terminal_start.clear();
    graph.device_terminal_start.reserve(terminal_offsets.len());
    for &offset in terminal_offsets {
        graph
            .device_terminal_start
            .push(offset.wrapping_sub(base_terminal));
    }
    let base_param = narrow(qfirst);
    let param_offsets = netlist.device_param_start.get(first..=last).unwrap_or(&[]);
    graph.device_param_start.clear();
    graph.device_param_start.reserve(param_offsets.len());
    for &offset in param_offsets {
        graph
            .device_param_start
            .push(offset.wrapping_sub(base_param));
    }
    // A netlist with no device column still owes the graph a terminator, and
    // either column can be missing on its own.
    if graph.device_terminal_start.is_empty() {
        graph.device_terminal_start.push(0);
    }
    if graph.device_param_start.is_empty() {
        graph.device_param_start.push(0);
    }
    debug_assert_eq!(
        graph.device_terminal_start[0], 0,
        "the rebased terminal CSR column does not start at its own zero"
    );
    debug_assert_eq!(
        graph.device_terminal_start[device_count] as usize,
        tlast - tfirst,
        "the rebased terminal CSR column does not end at the terminal count"
    );
    debug_assert_eq!(
        graph.device_param_start[0], 0,
        "the rebased parameter CSR column does not start at its own zero"
    );
    debug_assert_eq!(
        graph.device_param_start[device_count] as usize,
        qlast - qfirst,
        "the rebased parameter CSR column does not end at the parameter count"
    );

    // `(StrId, f64)` on both sides, already in SI base units.
    graph.param.clear();
    graph.param.extend_from_slice(&netlist.param[qfirst..qlast]);

    // A terminal's role is a function of its position *within its device*.
    graph.terminal_role.clear();
    graph.terminal_role.reserve(tlast - tfirst);
    for device in 0..device_count {
        let kind = netlist.device_kind[first + device];
        let (from, to) = csr_run(&graph.device_terminal_start, device);
        for position in 0..to - from {
            graph.terminal_role.push(card_role(kind, position));
        }
    }

    // Port order is the subcircuit's own, not sorted: an `X` card matches its
    // master's ports by position.
    let (pfirst, plast) = csr_run(&netlist.subckt_port_start, subckt.0 as usize);
    graph.port_net.clear();
    graph.port_net.reserve(plast - pfirst);
    let (rank, ports_out) = (&graph.net_terminal_start, &mut graph.port_net);
    for &net in &netlist.port_net[pfirst..plast] {
        ports_out.push(rank[net.0 as usize]);
    }

    // The last read of the rank column; `transpose_into` makes `graph` readable
    // again.
    transpose_into(graph, net_count);

    debug_assert_eq!(graph.device_count(), device_count, "a device went missing");
    debug_assert_eq!(graph.net_count(), net_count, "a net went missing");
    debug_assert_eq!(
        graph.terminal_role.len(),
        tlast - tfirst,
        "a terminal lost its role"
    );
}

/// A SPICE card position to the [`TerminalRole`] it names, in card order —
/// drain-first, collector-first — and not the recogniser order.
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
        // The saturation is unreachable for any real card and is here so the
        // conversion cannot panic.
        _ => TerminalRole::Pin(u8::try_from(position).unwrap_or(u8::MAX)),
    }
}
