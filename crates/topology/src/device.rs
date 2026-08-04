//! Device recognition and terminal binding.
//!
//! A device is recognised by a *marker polygon* — one polygon on the
//! recogniser's marker layer is exactly one device. That is the rule, and it is
//! stated here because the old tree deduplicated BJTs on the net tuple instead,
//! which silently merged two real devices wired identically.

use crate::csr_run;
use crate::net::{retain_intersecting_into, NetId, NetTable};
use gpurify_core::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_core::ops::area2;
use gpurify_core::{GeometryStore, PolyId};
use gpurify_derived::Evaluator;
use gpurify_ingest::deck::{DeviceKind, DeviceRecognition};
use gpurify_ingest::StrId;
use gpurify_units::{Dbu, DbuArea};

/// Identifies one recognised device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeviceId(pub u32);

/// Which terminal of a device a net is attached to.
///
/// Closed and per-family: a MOS gate and a BJT base are not the same thing, and
/// an enum that pretended otherwise would let a comparison match them.
///
/// # Terminal position to role
///
/// [`DeviceRecognition`] carries terminals as a bare `Vec<LayerId>` with no
/// role column, so the role is a function of the family and the terminal's
/// position in that list. This table is that function, and it is the one place
/// it is written down — `lvs` needs the same mapping from a SPICE card's
/// terminal order, and two crates inferring it separately is how a drain and a
/// source get transposed.
///
/// | [`DeviceKind`] | position 0 | 1 | 2 | 3 |
/// |---|---|---|---|---|
/// | `Mos` | `Gate` | `Source` | `Drain` | `Bulk` |
/// | `Bjt` | `Base` | `Emitter` | `Collector` | — |
/// | `Resistor`, `Capacitor` | `Pin(0)` | `Pin(1)` | — | — |
///
/// A position past the end of its family's row is `Pin(k)` for position `k`.
/// The numbering of `Pin` is the position, not a rank among pins.
///
/// **`Diode` is deliberately absent.** It is two-terminal, but `Pin` asserts
/// the two ends are interchangeable and an anode and a cathode are not — giving
/// a diode pins would let a comparison match one wired backwards, which is
/// fail-open. The fix is an `Anode`/`Cathode` pair of variants, and that is a
/// Definition-Phase decision this table does not make on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalRole {
    Gate,
    Source,
    Drain,
    Bulk,
    Base,
    Emitter,
    Collector,
    /// Either end of a symmetric two-terminal device. Interchangeable by
    /// definition, which the comparator must know.
    Pin(u8),
}

/// Every device recognised from the layout.
///
/// **Five questions.** In: geometry, derived layers, and the deck's
/// recognisers. Out: `SoA` device rows with CSR terminal ranges. How many:
/// thousands to millions. Access pattern: `lvs` walks terminals per device;
/// `erc` walks devices per net — hence the reverse index. Lifetime: whole run.
/// Parallelisable: recognition per marker polygon is independent; the ordering
/// pass at the end is what makes ids canonical.
#[derive(Debug, Default)]
pub struct DeviceTable {
    pub kind: Vec<DeviceKind>,
    /// The marker polygon that identifies this device. One device per marker
    /// polygon, always.
    pub marker: Vec<PolyId>,
    pub model: Vec<StrId>,
    /// Terminals, CSR into `terminal_net` / `terminal_role`.
    pub terminal_start: Vec<u32>,
    pub terminal_net: Vec<NetId>,
    pub terminal_role: Vec<TerminalRole>,
    /// Measured geometry, CSR into `param`. Width, length, area, perimeter —
    /// whatever the family's comparison needs.
    pub param_start: Vec<u32>,
    pub param: Vec<(DeviceParam, DeviceMeasure)>,

    /// Devices attached to each net, CSR. The reverse index `erc` scans.
    net_start: Vec<u32>,
    net_device: Vec<DeviceId>,
}

/// A measured device parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceParam {
    Width,
    Length,
    Area,
    Perimeter,
    Fingers,
}

/// The measurement itself, exact and in layout units.
///
/// Integer, not `f64`: these feed parametric comparison against a reference
/// netlist, where a tolerance is applied deliberately by the comparator rather
/// than accumulated accidentally by the extractor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMeasure {
    Length(Dbu),
    Area(DbuArea),
    Count(u32),
}

impl DeviceTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.marker.len(), self.kind.len(), "one marker per device");
        debug_assert_eq!(self.model.len(), self.kind.len(), "one model per device");
        self.kind.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn terminals_of(&self, device: DeviceId) -> (&[NetId], &[TerminalRole]) {
        let (start, end) = csr_run(&self.terminal_start, device.0 as usize);
        debug_assert_eq!(
            self.terminal_net.len(),
            self.terminal_role.len(),
            "a net column and a role column arrive parallel"
        );
        (
            &self.terminal_net[start..end],
            &self.terminal_role[start..end],
        )
    }
    pub fn params_of(&self, device: DeviceId) -> &[(DeviceParam, DeviceMeasure)] {
        let (start, end) = csr_run(&self.param_start, device.0 as usize);
        &self.param[start..end]
    }
    /// Devices attached to a net, ascending.
    ///
    /// The question `erc` asks constantly: is this net connected to anything,
    /// and if so what. A net with no devices is a floating net.
    pub fn devices_on(&self, net: NetId) -> &[DeviceId] {
        // [`NetId::NONE`] is an absence, not a net, so nothing is attached to
        // it — the same answer `NetTable::polys_of` gives. Not a bulk branch:
        // one compare per query, and the taken side would otherwise index the
        // CSR at `u32::MAX`.
        if net == NetId::NONE {
            return &[];
        }
        // A net id past the table indexes out of bounds and panics in every
        // profile, exactly as `polys_on_layer` does: "this net carries nothing"
        // and "this net does not exist" must not read the same.
        let (start, end) = csr_run(&self.net_start, net.idx());
        debug_assert!(end <= self.net_device.len(), "a reverse-index run leaves its column");
        &self.net_device[start..end]
    }
}

/// One row of [`recognise_into`]'s match list: `(marker polygon, recogniser
/// row, offset into its `bound` buffer)`.
type Match = (PolyId, u32, u32);

/// Recognise every device the deck describes.
///
/// **Transform, dispatcher.** One recogniser per device family, each producing
/// rows into the same table; the families are then run as separate uniform
/// passes rather than a per-polygon branch on kind.
///
/// Device ids are assigned by sorting on the marker polygon, so they are
/// canonical for a given layout.
///
/// `terminal_role` comes from the family and the terminal's position in
/// `recognition.terminal`; the table is on [`TerminalRole`]. Terminals are
/// written in that same order, so `terminals_of` returns them as the recogniser
/// stated them and not sorted by net.
///
/// `derived` is accepted and unread — see the body for why it cannot be read.
/// The parameter keeps its name rather than becoming `_derived`: the signature
/// is frozen, and an underscore would read as "this body chose not to bother"
/// rather than "the two frozen types have no bridge".
#[allow(unused_variables)]
pub fn recognise_into(
    store: &GeometryStore,
    derived: &Evaluator,
    nets: &NetTable,
    recognition: &DeviceRecognition,
    out: &mut DeviceTable,
) {
    // `derived` is unused, and cannot be used: `DeviceRecognition` names its
    // marker and terminal layers as `LayerId`s into the store, while
    // `Evaluator::get` is keyed by the `StrId` the deck named a derived layer
    // with. There is no bridge between the two in either frozen signature, so a
    // recogniser cannot name a derived layer at all. Reported, not worked
    // around: inventing a `LayerId`-to-`StrId` mapping here would be a
    // Definition decision.
    let rows = recognition.kind.len();
    debug_assert_eq!(recognition.marker.len(), rows, "one marker layer per recogniser");
    debug_assert_eq!(recognition.model.len(), rows, "one model per recogniser");
    debug_assert!(
        recognition.terminal_start.len() == rows + 1 || recognition.terminal_start.is_empty(),
        "the recogniser CSR carries one offset per row plus a terminator"
    );

    clear(out);

    // Deck-sized loops from here to the marker scan: tens of recognisers with a
    // handful of terminal layers each, so none of this is bulk.
    debug_assert!(
        (0..rows).all(|row| !terminals_of_recogniser(recognition, row)
            .contains(&recognition.marker[row])),
        "a recogniser's marker layer is also one of its terminal layers"
    );

    // A terminal's role is a function of the family and the position, so it is
    // uniform across every device a recogniser row produces: hoisted here, and
    // indexed by the same CSR offsets `recognition.terminal` uses.
    let mut role: Vec<TerminalRole> = Vec::with_capacity(recognition.terminal.len());
    for row in 0..rows {
        let width = terminals_of_recogniser(recognition, row).len();
        let width = u8::try_from(width).expect("a device family has fewer than 256 terminals");
        role.extend((0..width).map(|position| role_at(recognition.kind[row], position)));
    }
    debug_assert_eq!(role.len(), recognition.terminal.len(), "one role per terminal layer");

    // Scratch. One set for the whole call, cleared per layer, so a deck with a
    // hundred recognisers allocates once.
    let mut marker_index = SpatialIndex::default();
    let mut terminal_index = SpatialIndex::default();
    let mut pairs: Vec<(PolyId, PolyId)> = Vec::new();
    // The survivors of the exact re-test below. A second buffer rather than a
    // retain on `pairs`, because a forward write into a separate destination is
    // what lets the compact's store be unconditional.
    let mut exact: Vec<(PolyId, PolyId)> = Vec::new();
    let mut bind: Vec<NetId> = Vec::new();
    let mut matched: Vec<Match> = Vec::new();
    let mut bound: Vec<NetId> = Vec::new();

    // `within(_, 0)` is `Bbox::overlaps`, which is inclusive — a terminal shape
    // touching the marker's edge counts as being under it. Same direction as
    // every other prune in the tree: over-recognising a device is loud in LVS,
    // dropping one is silent.
    //
    // This distance drives the *prune* only. Every pair it keeps is re-tested
    // exactly by `net::polys_intersect` before it binds a terminal, because a bounding
    // box is a superset of the shape inside it and a box-only hit is not a
    // device.
    let touching = Dbu::new_unchecked(0);

    for row in 0..rows {
        let terminals = terminals_of_recogniser(recognition, row);
        let width = terminals.len();
        let markers = store.polys_on_layer(recognition.marker[row]);
        let marker_count = markers.len();
        if marker_count == 0 {
            continue;
        }
        SpatialIndex::build_into(store, recognition.marker[row], &mut marker_index);

        // `bind[m * width + k]` is the net terminal `k` of marker `m` landed
        // on, or `NetId::NONE` for a terminal layer with nothing under that
        // marker. That sentinel is the whole firing rule: `terminal_net` is a
        // `Vec<NetId>` with no way to spell an absent terminal, so a recogniser
        // whose terminal layers are not all present under a marker has no row
        // it could legally write, and skips it.
        bind.clear();
        bind.resize(marker_count * width, NetId::NONE);

        for (k, &layer) in terminals.iter().enumerate() {
            SpatialIndex::build_into(store, layer, &mut terminal_index);
            cross_layer_pairs_into(store, &marker_index, &terminal_index, touching, &mut pairs);
            debug_assert!(
                pairs.iter().all(|&(m, _)| markers.contains(&m.0)),
                "the cross-layer prune returned a polygon off the marker layer"
            );

            // The prune answers "these two boxes meet"; a box is a superset of
            // the shape inside it. Binding on a box alone does not merely
            // invent a device — the lowest-`PolyId` rule below means a spurious
            // pair with a low id *wins*, and a real device silently comes back
            // wired to a net it does not touch. So every kept pair is re-tested
            // exactly, the same discipline `net::intra_layer_edges_into`
            // applies to a conductor join — through the same predicate, which
            // is why it is `pub(crate)` in `net` rather than written twice —
            // and the branchless compact that applies it is shared for the same
            // reason.
            retain_intersecting_into(store, &pairs, &mut exact);

            // Descending, so the store is unconditional and the *last* write
            // wins: the lowest `PolyId` under the marker is the one that
            // survives, which is what makes the binding independent of how the
            // index bucketed the layer. `exact` is ascending, because the prune
            // emits ascending pairs and a compact preserves order.
            for &(marker, terminal) in exact.iter().rev() {
                bind[(marker.0 - markers.start) as usize * width + k] = nets.net_of(terminal);
            }
        }

        matched.reserve(marker_count);
        for offset in 0..marker_count {
            let slots = &bind[offset * width..offset * width + width];
            // A surviving branch, twice over: it predicts well — a recogniser
            // fires on nearly every polygon of its own marker layer and on none
            // of another's, so selectivity sits at the ends, not at 50% — and
            // the taken side appends a row and copies a slice, which is exactly
            // the expensive side a branch exists to skip.
            if slots.contains(&NetId::NONE) {
                continue;
            }
            let at = narrow(bound.len());
            matched.push((PolyId(markers.start + narrow(offset)), narrow(row), at));
            bound.extend_from_slice(slots);
        }
    }

    // Ids are the rank of the marker polygon, which is what makes a `DeviceId`
    // canonical for a layout. Stable, so two recognisers matching one marker
    // stay in deck order and the dedup below keeps the earlier row: the module
    // comment's rule is one device per marker polygon, always.
    matched.sort_by_key(|&(marker, _, _)| marker);
    matched.dedup_by_key(|&mut (marker, _, _)| marker);

    let devices = matched.len();
    out.kind.reserve(devices);
    out.marker.reserve(devices);
    out.model.reserve(devices);
    out.terminal_start.reserve(devices);
    out.terminal_net.reserve(bound.len());
    out.terminal_role.reserve(bound.len());
    out.param_start.reserve(devices);
    out.param.reserve(devices);

    // `(net, device)` pairs, sorted and deduplicated into the reverse index
    // below. Deduplicated because a device with two terminals on one net is
    // attached to it once, not twice.
    let mut attach: Vec<(NetId, DeviceId)> = Vec::with_capacity(bound.len());

    // One input row writes `width` rows into the two segmented terminal columns
    // and one row into each of the per-device scalar columns, so the whole
    // device is written in a single pass over `matched` rather than in one pass
    // per column.
    for (device, &(marker, row, at)) in matched.iter().enumerate() {
        let row = row as usize;
        let span = recognition.terminal_start[row] as usize
            ..recognition.terminal_start[row + 1] as usize;
        let nets_of_device = &bound[at as usize..at as usize + span.len()];

        out.kind.push(recognition.kind[row]);
        out.marker.push(marker);
        out.model.push(recognition.model[row]);
        out.terminal_net.extend_from_slice(nets_of_device);
        out.terminal_role.extend_from_slice(&role[span]);
        out.terminal_start.push(narrow(out.terminal_net.len()));

        // The one parameter a marker polygon states on its own: its area.
        //
        // It needs no convention to be invented. "One polygon on the marker
        // layer is exactly one device" is this module's rule, so the marker
        // *is* the device's extent — for a MOS recognised on `poly AND active`
        // that region is the channel, and its area is `W × L`, the oxide area
        // `erc::rules::antenna` documents as `DeviceParam::Area`. `Width`,
        // `Length` and `Fingers` are still absent and still blocked: separating
        // `W` from `L` needs a channel direction, which `DeviceRecognition` has
        // no column for. That half stays open in `docs/SIGNATURE_DEFECTS.md`.
        //
        // Signed area doubled, then `abs`: a store polygon carries no winding
        // guarantee — `core::view` establishes one, and a recogniser reads the
        // raw store — so the sign here is the vertex order, not a hole.
        let (marker_x, marker_y) = store.poly_verts(marker);
        let doubled = area2(marker_x, marker_y).raw().abs();
        debug_assert!(doubled % 2 == 0, "twice an area is even");
        out.param
            .push((DeviceParam::Area, DeviceMeasure::Area(DbuArea::new(doubled / 2))));
        out.param_start.push(narrow(out.param.len()));

        let device = DeviceId(narrow(device));
        attach.extend(nets_of_device.iter().map(|&net| (net, device)));
    }
    debug_assert!(
        !out.terminal_net.contains(&NetId::NONE),
        "a device was written with a terminal on no net"
    );

    attach.sort_unstable();
    attach.dedup();

    // A counting sort's histogram scatters at a data-dependent index and its
    // prefix sum is a loop-carried chain — row N reads what row N−1 wrote — so
    // neither pass vectorises and neither has an upgrade path that would change
    // that. Same exception, and same wording, as `NetTable::from_assignment`.
    out.net_start.resize(nets.net_count() + 1, 0);
    for &(net, _) in &attach {
        out.net_start[net.idx() + 1] += 1;
    }
    for index in 1..out.net_start.len() {
        out.net_start[index] += out.net_start[index - 1];
    }
    // `attach` is already sorted by `(net, device)`, so a plain copy of its
    // second column lands every device in its net's run, ascending. No branch
    // in the body and no reserve-and-`set_len` dance: the iterator is
    // `TrustedLen`, so `extend` reserves the exact count once and then writes
    // straight through.
    out.net_device.clear();
    out.net_device.extend(attach.iter().map(|&(_, device)| device));
    debug_assert_eq!(out.net_device.len(), attach.len(), "one device row per attachment");

    debug_assert_eq!(out.len(), devices, "one row per surviving marker polygon");
    debug_assert_eq!(
        out.terminal_start.len(),
        devices + 1,
        "the terminal CSR lost its terminator"
    );
    debug_assert_eq!(out.param_start.len(), devices + 1, "the param CSR lost its terminator");
    debug_assert_eq!(out.param.len(), devices, "one measured area per device");
    debug_assert_eq!(
        out.net_start.last().copied().unwrap_or(0) as usize,
        out.net_device.len(),
        "the reverse index's offsets and its rows disagree"
    );
    debug_assert!(
        out.marker.windows(2).all(|w| w[0] < w[1]),
        "devices come back strictly ascending by marker polygon"
    );
}

/// Every column emptied, and both CSR columns reopened at zero.
///
/// The caller owns `out` and a table handed in twice is refilled, not appended
/// to — so this is the whole of "refilled", in one place, rather than a `clear`
/// per column at the top of a long body.
fn clear(out: &mut DeviceTable) {
    out.kind.clear();
    out.marker.clear();
    out.model.clear();
    out.terminal_start.clear();
    out.terminal_net.clear();
    out.terminal_role.clear();
    out.param_start.clear();
    out.param.clear();
    out.net_start.clear();
    out.net_device.clear();
    out.terminal_start.push(0);
    out.param_start.push(0);
}

/// The terminal layers of one recogniser row.
fn terminals_of_recogniser(recognition: &DeviceRecognition, row: usize) -> &[gpurify_core::LayerId] {
    let (start, end) = csr_run(&recognition.terminal_start, row);
    &recognition.terminal[start..end]
}

/// The role of terminal `position` of a device in family `kind`.
///
/// The table on [`TerminalRole`], and the only place it is written down.
fn role_at(kind: DeviceKind, position: u8) -> TerminalRole {
    const MOS: [TerminalRole; 4] = [
        TerminalRole::Gate,
        TerminalRole::Source,
        TerminalRole::Drain,
        TerminalRole::Bulk,
    ];
    const BJT: [TerminalRole; 3] = [
        TerminalRole::Base,
        TerminalRole::Emitter,
        TerminalRole::Collector,
    ];
    // A closed match over five variants, not a bulk branch: this runs once per
    // terminal layer in the deck, tens of times per run.
    let named: &[TerminalRole] = match kind {
        DeviceKind::Mos => &MOS,
        DeviceKind::Bjt => &BJT,
        // `Diode` rides the fallback with `Resistor` and `Capacitor`, and that
        // is the fail-open [`TerminalRole`] names: `Pin` asserts the two ends
        // are interchangeable, and an anode and a cathode are not. Following
        // the stated table rather than inventing the `Anode`/`Cathode` pair,
        // which is the Definition-Phase decision it says it is.
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode => &[],
    };
    // "A position past the end of its family's row is `Pin(k)` for position
    // `k`" — so `Pin`'s payload is the position, not a rank among pins.
    named
        .get(usize::from(position))
        .copied()
        .unwrap_or(TerminalRole::Pin(position))
}

/// A count narrowed to the `u32` every CSR column in this table is made of.
fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a device table addresses fewer than u32::MAX rows")
}

