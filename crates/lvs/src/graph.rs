//! The one graph shape both sides are reduced to before matching.
//!
//! The layout side comes from `topology`, the reference side from `ingest`. If
//! the matcher saw two different shapes it would need two of everything, and
//! every asymmetry between the two paths would be a place a mismatch could hide.
//! So both are projected into the same bipartite device/net graph first, and
//! the matcher has exactly one input type.

use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::{StrId, StrTable};
use gpurify_ingest::deck::DeviceKind;
use gpurify_topology::{DeviceTable, NetId, NetTable, PortTable, TerminalRole};

/// One row's run in a CSR offset column.
///
/// The same fail-closed argument `topology::csr_run` carries, restated here
/// because that one is `pub(crate)`: the column holds `rows + 1` offsets, so a
/// row past the table indexes out of bounds and panics in every profile rather
/// than reading as an empty run. "This device has no terminals" and "this device
/// does not exist" must not come back the same.
fn csr_run(start: &[u32], row: usize) -> (usize, usize) {
    let (from, to) = (start[row] as usize, start[row + 1] as usize);
    debug_assert!(from <= to, "a CSR run runs backwards");
    (from, to)
}

/// A row count as the `u32` every id column in this workspace is made of.
///
/// The one copy. `compare` and `checks` each wrote their own before this crate
/// was read whole, and a truncating third variant is exactly how the tail of a
/// table goes unchecked and comes back clean — so it fails closed here, once.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a table addresses its own rows with u32")
}

/// A node in the bipartite graph.
///
/// Devices and nets are different kinds of thing and can never be paired with
/// each other, so the distinction is in the type rather than in a convention
/// about index ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    Device(u32),
    Net(u32),
}

/// A netlist reduced to what matching needs.
///
/// **Five questions.** In: either a `topology` extraction or an `ingest`
/// netlist. Out: `SoA` device and net columns with CSR incidence in both
/// directions. How many: thousands to millions of devices. Access pattern:
/// refinement walks every node's neighbours every round, so both directions are
/// CSR and neither is recomputed. Lifetime: one comparison. Parallelisable:
/// the per-round signature computation is; the partition merge is not.
///
/// `PartialEq` and not `Eq`: `param` holds an `f64`. Comparing two graphs
/// column by column is what the determinism assertions want, and the
/// alternative they were written against — comparing `Debug` output — cannot
/// tell a real difference from a formatting one.
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

    /// Devices attached to each net, CSR into `net_terminal`. The reverse
    /// incidence; refinement needs both directions every round.
    pub net_terminal_start: Vec<u32>,
    pub net_terminal: Vec<(u32, TerminalRole)>,
    /// Declared name, for nets that have one. `None` is the common case.
    pub net_name: Vec<Option<StrId>>,
    /// Nets that are ports of this cell. Matching is anchored on these, so
    /// they are held separately rather than found by scanning names.
    pub port_net: Vec<u32>,
}

impl Graph {
    pub fn device_count(&self) -> usize {
        debug_assert_eq!(
            self.device_model.len(),
            self.device_kind.len(),
            "a device lost its model, or a model lost its device"
        );
        // Empty is allowed to carry no offsets at all — a `Default` graph has
        // none — but a non-empty one carries the terminator. Same argument as
        // `NetTable::net_count`, and the reason the count is read off the row
        // column rather than off `start.len() - 1`.
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

/// The layout side. A newtype over [`Graph`] so the two sides cannot be
/// transposed at a call site — `compare(layout, reference)` and
/// `compare(reference, layout)` are different questions and the second is a
/// silently reversed report.
#[derive(Debug, Default, PartialEq)]
pub struct LayoutGraph(pub Graph);

/// The reference side.
#[derive(Debug, Default, PartialEq)]
pub struct RefGraph(pub Graph);

/// Project a `topology` extraction into the matching graph.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled.
///
/// # The projection is index-preserving
///
/// Device row `k` of the graph is `DeviceId(k)` of `devices`, and net row `k`
/// is `NetId(k)` of `nets`; both tables are already canonically ordered, so
/// renumbering here would only lose the one link back to geometry the graph
/// does not carry. A device's terminals keep the order `devices` stores them
/// in, roles included. `port_net` is ascending.
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

    // Index-preserving, so every device column is a straight copy: graph row `k`
    // is `DeviceId(k)`, and renumbering here would drop the one link back to
    // geometry the graph does not carry. `clear` then `extend_from_slice` rather
    // than `clone_from`: both refill the caller's allocation, and the first is
    // one reserve and one `memcpy` with nothing per element at all.
    graph.device_kind.clear();
    graph.device_kind.extend_from_slice(&devices.kind);
    graph.device_model.clear();
    graph.device_model.extend_from_slice(&devices.model);
    graph.device_terminal_start.clear();
    graph.device_terminal_start
        .extend_from_slice(&devices.terminal_start);
    graph.terminal_role.clear();
    graph.terminal_role.extend_from_slice(&devices.terminal_role);

    // `NetId::NONE` becomes `u32::MAX` and stays. A terminal on no net is an
    // extraction fault `check_topology` reports; dropping the terminal here
    // would hide it, and renumbering it onto a real net would invent a
    // connection. It is filed on no net's list below, which is what "on no net"
    // means.
    //
    // The one column that is not a straight copy, so it is a loop: `NetId` is a
    // `u32` newtype and the body is a load, a field read and a store. `reserve`
    // above the loop is what makes `push`'s capacity test loop-invariant — it is
    // the same test every iteration and never taken, not a branch on the data.
    // Every mapping loop below is written this way and does not repeat the note.
    graph.terminal_net.clear();
    graph.terminal_net.reserve(devices.terminal_net.len());
    for &net in &devices.terminal_net {
        graph.terminal_net.push(net.0);
    }

    // Parameters are empty, and this is a reported gap rather than a body that
    // guessed: `DeviceTable::param` is `(DeviceParam, DeviceMeasure)` — a closed
    // enum and an exact integer in database units — while `Graph::param` is
    // `(StrId, f64)`. Turning one into the other needs a name for each
    // `DeviceParam` and the database-unit scale, and this signature is handed
    // neither a `StrTable` nor a `Dbu` scale. Inventing either would be a
    // Definition decision. Consequence: parametric comparison sees no layout
    // parameter, so it reports nothing rather than reporting a wrong number.
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
    // The `O(nets)` factor is not the debt and must not be optimised away: the
    // column being filled is `net_name`, one row per net, so the pass is owed
    // whatever the lookup costs. Only `log ports` is debt. Nor is the search
    // reducible from inside this body: `PortTable`'s read surface is `name_of`,
    // `net_of`, `len` and `is_empty`, which answer membership at a point and
    // never "how many ports below this net", so there is no rank to gallop on
    // and no way to narrow the next search's range with what the last one
    // returned. `net_of` is the one accessor that walks the other way, and it
    // needs a `StrId` to walk from — this signature is handed no `StrTable`, and
    // that route is wrong anyway for the reason filed under `## export`: it
    // answers with the lower net when one label reaches two, so it drops a port.
    // It takes the accessor or it stays a search per net.
    //
    // `port_net`'s scratch is `ports.len() + 1` rows and not `net_count`. The
    // store below is unconditional — that is the memory-for-branches trade — so
    // the buffer has to hold a write on *every* iteration, but not a distinct
    // one: `named` counts distinct rows of `PortTable`, since `name_of` is a hit
    // on one row per named net, so it never passes `ports.len()` and an unnamed
    // net simply overwrites the one slot past the last port. The trade therefore
    // costs the port count and not the net count, which is hundreds against
    // millions, and the `+ 1` is what keeps the store branchless.
    graph.net_name.clear();
    graph.net_name.reserve(net_count);
    graph.port_net.clear();
    graph.port_net.resize(ports.len() + 1, 0);
    let mut named = 0usize;
    for net in 0..net_count {
        let id = narrow(net);
        let name = ports.name_of(NetId(id));
        graph.net_name.push(name);
        // Always store, conditionally advance — the memory-for-branches trade,
        // and the reason the buffer above carries a slot past its last port for
        // every unnamed net to land on.
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

/// Build the net-side incidence from the device-side one.
///
/// **Transform, A-to-B**, in place on one graph: reads `device_terminal_start` /
/// `terminal_net` / `terminal_role`, writes `net_terminal_start` /
/// `net_terminal`. Both projections need it and the transpose is the one thing
/// neither of them can state independently — a fixture that supplied both
/// directions could supply them inconsistently, and so could a body.
///
/// Terminals land ascending by device within each net, because they are filed in
/// device order.
fn transpose_into(graph: &mut Graph, net_count: usize) {
    let terminals = graph.terminal_net.len();
    debug_assert_eq!(
        terminals,
        graph.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );

    // One bucket per net, plus a trash bucket at `net_count` for a terminal on
    // no net. The trash region is filed and then truncated away, which keeps the
    // scatter's write address unconditional — clamping is the branchless form of
    // the skip, and the alternative is a data-dependent `if` per terminal.
    //
    // The column is exactly the `net_count + 1` offsets a caller reads back. It
    // used to be one longer, holding counts shifted up by one so the prefix sum
    // landed on starts, which then needed a whole extra pass over the nets to
    // shift them back down after the scatter had eaten them. Counting in place
    // and scattering *backwards* — the cursor is pre-decremented, so it walks
    // down to its own bucket's start rather than up to its end — leaves the
    // offsets already correct, so that fourth pass is gone rather than turned
    // into a `copy_within`.
    let trash = net_count;
    graph.net_terminal_start.clear();
    graph.net_terminal_start.resize(net_count + 1, 0);

    // A histogram and a prefix sum, and neither vectorises. The histogram's
    // output index is a function of the row's value, so two terminals on one net
    // collide in the same lane; the prefix sum is a chain, row `b` reading what
    // row `b - 1` wrote, which the kernel rule names as the one shape that cannot
    // be a transform at all.
    //
    // The histogram is single-threaded because of the module graph, not because
    // the parallel form is unknown: it is per-thread counts merged in bucket
    // order before the prefix sum, deterministic, and the scatter below is
    // untouched by it. `rayon` is a workspace dependency but not one of
    // `crates/lvs/Cargo.toml`'s, so writing it is a manifest edit and not a body.
    // Stated here and recorded in `docs/SIGNATURE_DEFECTS.md` so the ceiling
    // reads as a dependency edge rather than as a missing idea.
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
    // the total — including whatever landed in the trash bucket.
    let filed = graph.net_terminal_start[net_count] as usize;
    debug_assert_eq!(filed, terminals, "every terminal is filed exactly once");
    graph.net_terminal.clear();
    graph.net_terminal.resize(filed, (0, TerminalRole::Pin(0)));

    // `net_terminal_start[b]` doubles as bucket `b`'s write cursor, so no second
    // offset array is allocated. The outer walk is over device rows because the
    // owning device is what the transpose has to record, and a terminal slot
    // does not carry it.
    //
    // Descending, with the cursor decremented before the store: a bucket is
    // filled from its far end backwards, so the highest device lands last-first
    // and terminals still come out ascending by device, which is what this
    // function's doc comment promises. When the walk finishes every cursor has
    // been driven down to its own bucket's start, which is the offset column.
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

    // The trash bucket's rows sit past the last real net's end, so the offset
    // that used to be the trash bucket's start is now the real terminal count
    // and doubles as the truncation point. `net_terminal_start[net_count]` is
    // therefore both the column's terminator and the length of `net_terminal`.
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
/// One subcircuit, not the whole netlist: hierarchical comparison works cell by
/// cell, and flattening first would discard the structure it needs.
///
/// # Terminal position to role
///
/// `Netlist` stores terminals as bare nets in card order and carries no roles,
/// while [`Graph`] needs one per terminal. The mapping is by
/// [`DeviceKind`] and position, and it is stated here because it is the same
/// table `topology::recognise_into` assigns from a recogniser's terminal
/// layers — the two sides must agree or every comparison is a role mismatch:
///
/// | kind | position 0 | 1 | 2 | 3 |
/// |---|---|---|---|---|
/// | `Mos` | `Gate` | `Source` | `Drain` | `Bulk` |
/// | `Bjt` | `Base` | `Emitter` | `Collector` | — |
/// | `Resistor`, `Capacitor`, `Diode` | `Pin(0)` | `Pin(1)` | — | — |
///
/// A MOS card that names only three nets has no bulk terminal and stops at
/// position 2; a card naming more nets than its family has positions is a
/// structural fault, reported by
/// [`check_topology`](crate::checks::check_topology) rather than guessed at
/// here.
///
/// ## The note `card_role` refers to: the table above is the wrong one
///
/// Written down in the Implementation-Phase, when the crate was first read
/// whole. The table above is `topology::role_at`'s — the *recogniser* order —
/// and this side does not use it. A SPICE `M` card reads `D G S B` and a `Q`
/// card reads `C B E`, so the order here is drain-first and collector-first, and
/// that is what `card_role` implements. `docs/SIGNATURE_DEFECTS.md` carries
/// both, and its `## ingest` entry is the one that holds: the card-order table
/// on `Netlist::terminal_net`, confirmed against
/// `reference/pre-rewrite:crates/lvs/src/spice.rs:112`, "explicitly *not*
/// `DeviceRecognition`'s order — a recogniser lists gate first because geometry
/// names it first, a card lists drain first — and the two meet in `lvs`".
///
/// So the sentence above it — "the two sides must agree or every comparison is
/// a role mismatch" — is false as stated, and reading it as positional
/// agreement is what put a slot-by-slot terminal comparison in
/// `compare::compare_terminals`. The two sides must agree on which *role* a
/// terminal carries, never on which slot carries it; the comparator matches on
/// the role and the refiner folds the roles commutatively. Correcting the frozen
/// table is a `docs/SIGNATURE_DEFECTS.md` entry, not a Phase-4 commit, so it is
/// left standing above with this note under it.
pub fn from_reference_into(
    netlist: &Netlist,
    subckt: SubcktId,
    strings: &StrTable,
    out: &mut RefGraph,
) {
    // `strings` is accepted and unread. Every name this projection moves —
    // `device_model`, `net_name` — is already a `StrId` on both sides, so there
    // is nothing here to intern and nothing to resolve. The parameter keeps its
    // name rather than becoming `_strings`, for the reason
    // `topology::recognise_into` gives: the signature is frozen, and an
    // underscore would read as "this body chose not to bother".
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

    // `rank[reference row] == graph net index`, or `u32::MAX` for a net
    // belonging to another subcircuit. A loop-carried rank is a chain, which is
    // where `/simd-loops` triage stops; the select inside it is arithmetic, so
    // the body still carries no data-dependent branch.
    //
    // The buffer is `graph.net_terminal_start`, borrowed for the length of the
    // projection. The rank column is indexed by *global* reference row — that is
    // what `Netlist::terminal_net` and `Netlist::port_net` name — so it is `rows`
    // long and cannot be narrowed to this subcircuit's nets; hierarchical
    // comparison calls this once per cell, so a `vec![u32::MAX; rows]` here cost
    // one allocation and one memset of the whole netlist's net count per cell.
    // `net_terminal_start` is the one `Vec<u32>` `Graph` already owns whose
    // contents nothing reads before `transpose_into` clears and rebuilds it at
    // the end, so the rank table costs one allocation per `RefGraph` reused
    // across a run rather than one per call, and `push` into reserved capacity
    // drops the memset the old `vec!` paid for a column it overwrote in full.
    //
    // The consequence is stated rather than left to be tripped over: from here
    // until `transpose_into`, `graph` is not a readable `Graph`.
    // `net_terminal_start` holds `rows` ranks and not `net_count + 1` offsets,
    // so `Graph::net_count` and `Graph::terminals_on` would each fail their own
    // assert. Nothing between here and there calls either, and nothing new may.
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

    // The nets of this subcircuit, in ascending reference-row order, which is
    // the order `rank` just ranked them in. Every reference net carries a
    // name, so every projected net is `Some`.
    //
    // The branchless compact: always store, conditionally advance, so the write
    // address never depends on the predicate. It reserves for the whole net
    // column rather than for the survivors — the memory-for-branches trade — and
    // `graph.net_name` is the caller's buffer, so that capacity is paid once
    // across a run rather than once per subcircuit. A scratch `Vec` of picked
    // `(SubcktId, StrId)` pairs used to sit between the compact and this write;
    // fusing the two loops deleted it and the allocation with it.
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
        // `kept <= row` by induction: `kept` starts at zero and `bool` is 0 or 1,
        // so it advances by at most one per iteration. With `row < rows ==
        // out.len()` that gives `kept < out.len()`. Rejected slots are left
        // uninitialised and never read, because `set_len(kept)` truncates them
        // away and `Option<StrId>` is `Copy`, so nothing is dropped.
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

    // A subcircuit's devices are a CSR range over the device columns, so their
    // terminals are one contiguous range too — which is what lets the net column
    // be a single gather rather than a per-device slice.
    debug_assert!(
        device_count == 0 || last < netlist.device_terminal_start.len(),
        "the device terminal CSR column is missing its terminator"
    );
    // The same argument holds for the parameter column, so `span` is written
    // once and read twice.
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
    // filed on no net, exactly as an unconnected layout terminal is. Fail
    // closed: `check_topology` reports it, rather than this body quietly
    // attaching it to net zero.
    //
    // A gather: the load address depends on the row's value, which is not a
    // branch, and the bounds test on `rank` is against a length fixed above
    // the loop.
    graph.terminal_net.clear();
    graph.terminal_net.reserve(tlast - tfirst);
    // Two disjoint fields of one `Graph`, bound together so the rank column can
    // be read while the net column is written.
    let (rank, nets_out) = (&graph.net_terminal_start, &mut graph.terminal_net);
    for &net in &netlist.terminal_net[tfirst..tlast] {
        nets_out.push(rank[net.0 as usize]);
    }

    // Both CSR offset columns are the netlist's own, rebased to the range this
    // projection copied — a subcircuit's devices are contiguous rows, so their
    // terminals and their parameters are each one contiguous span, and the
    // offsets inside a span differ from the graph's only by the span's start.
    // That is one subtraction per offset, not a segmented fold, so it is a loop
    // per column instead of a `push` per device.
    //
    // `wrapping_sub`, not `-`: a subtraction that can underflow is a panic edge,
    // which is a branch in the loop body and blocks vectorisation. A netlist
    // whose offsets ran backwards would wrap to an enormous offset, and the two
    // asserts under each loop are what catch it — they read the rebased column's
    // first and last entries, which is where a wrap would have to show.
    // `first ..= last` and not `first .. last`: a CSR column of `n` rows carries
    // `n + 1` offsets, and the terminator is the entry that makes the graph's own
    // column readable by `csr_run`.
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
    // A netlist with no device column at all still owes the graph a terminator,
    // which is the one thing a loop over an absent span cannot supply. Two
    // guards and not one, because a netlist can be missing either column on its
    // own. Once per call, above every loop, and only reachable for a netlist that
    // declares no devices anywhere.
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

    // `(StrId, f64)` on both sides, already in SI base units — the reader
    // expanded the SPICE scale suffix — so the parameter column moves across
    // unchanged, and across as one span rather than one device at a time.
    graph.param.clear();
    graph.param.extend_from_slice(&netlist.param[qfirst..qlast]);

    // A segmented walk: the role of a terminal is a function of its *position
    // within its device*, so the outer loop is over a per-row range of
    // `device_terminal_start` rather than over a column. The alternatives are
    // both worse — a `partition_point` per terminal to recover its owner turns an
    // `O(terminals)` walk into `O(terminals · log devices)`, and materialising an
    // owner column first is the same walk done twice. The inner walk is over a
    // device's terminals, at most four.
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
    // master's ports by position, and that correspondence is the whole content
    // of the card.
    let (pfirst, plast) = csr_run(&netlist.subckt_port_start, subckt.0 as usize);
    graph.port_net.clear();
    graph.port_net.reserve(plast - pfirst);
    let (rank, ports_out) = (&graph.net_terminal_start, &mut graph.port_net);
    for &net in &netlist.port_net[pfirst..plast] {
        ports_out.push(rank[net.0 as usize]);
    }

    // The last read of the rank column. `transpose_into` clears it and refills it
    // with `net_count + 1` offsets, which is what makes `graph` a readable
    // `Graph` again and what recycles the rank table's capacity into the column
    // it is nominally for.
    transpose_into(graph, net_count);

    debug_assert_eq!(graph.device_count(), device_count, "a device went missing");
    debug_assert_eq!(graph.net_count(), net_count, "a net went missing");
    debug_assert_eq!(
        graph.terminal_role.len(),
        tlast - tfirst,
        "a terminal lost its role"
    );
}

/// A SPICE card position to the [`TerminalRole`] it names.
///
/// **Decision.** The table is [`Netlist::terminal_net`]'s declared card order,
/// *not* the recogniser order [`from_reference_into`]'s own doc comment states —
/// see the note there. A position past its family's row is `Pin(k)`, which is
/// what [`TerminalRole`] documents for one, and a family that has no business
/// with that many terminals is a structural fault
/// [`check_topology`](crate::checks::check_topology) reports.
///
/// The `match` is the surviving data-dependent branch of the projection, and it
/// stays: `kind` is a uniform for the whole of one device's terminal walk and is
/// one value for most of a netlist, so it predicts at well over the ~75% a
/// conditional move would have to beat. The table form — a `[[TerminalRole; 4];
/// 5]` indexed by kind and position — still needs a clamp for the `Pin(k)` tail
/// and buys nothing on four-element inner loops.
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
        // `Pin` numbering is the position, per `TerminalRole`'s table. The
        // saturation is unreachable for any real card and is here so the
        // conversion cannot panic.
        _ => TerminalRole::Pin(u8::try_from(position).unwrap_or(u8::MAX)),
    }
}
