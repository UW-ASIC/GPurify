//! Device recognition and terminal binding.
//!
//! One polygon on a recogniser's marker layer is exactly one device, so a MOS
//! marker is the channel, not the implant.
//! Data in: `GeometryStore`, `NetTable`, `DeviceRecognition`. Data out: `DeviceTable`.

use crate::drc::rules::{owners_of, LayerRects};
use crate::topology::csr_run;
use crate::topology::net::{polys_intersect, retain_intersecting_into, Holes, NetId, NetTable};
use gpurify_geom::boolean::{intersection_into, BooleanError};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{area2, isqrt};
use gpurify_geom::view::{validate_layer_with, Angles};
use gpurify_geom::{Dbu, DbuArea};
use gpurify_geom::{GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::deck::{Connectivity, DeviceKind, DeviceRecognition, DeviceValue};
use gpurify_ingest::StrId;

/// Identifies one recognised device: its row in the [`DeviceTable`]. Rows
/// ascend by marker polygon, so ids are the same on every run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeviceId(pub u32);

/// Which terminal of a device a net is attached to, by family and position:
///
/// | [`DeviceKind`] | position 0 | 1 | 2 | 3 |
/// |---|---|---|---|---|
/// | `Mos` | `Gate` | `Source` | `Drain` | `Bulk` |
/// | `Bjt` | `Base` | `Emitter` | `Collector` | — |
/// | `Resistor`, `Capacitor`, `Diode` | `Pin(0)` | `Pin(1)` | — | — |
///
/// A position past its family's row is `Pin(position)`.
///
/// Positions are the deck's `terminals [..]` order. A reference netlist uses
/// SPICE card order instead, which
/// [`from_reference`](crate::lvs::graph::from_reference) maps to the same
/// roles. LVS pairs terminals by role and treats `Source` and `Drain` as one,
/// and a resistor's two ends as one; a diode's anode (`Pin(0)`) and cathode
/// (`Pin(1)`), and a capacitor's plates, stay distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalRole {
    /// A MOS gate.
    Gate,
    /// A MOS source; interchangeable with `Drain` in LVS.
    Source,
    /// A MOS drain; interchangeable with `Source` in LVS.
    Drain,
    /// A MOS bulk. Dropped from the reference when the layout extracts none.
    Bulk,
    /// A BJT base.
    Base,
    /// A BJT emitter; never interchangeable with `Collector`.
    Emitter,
    /// A BJT collector.
    Collector,
    /// A passive's terminal by position: a resistor's end, a capacitor's
    /// plate, a diode's anode (0) or cathode (1). LVS compares a resistor's two
    /// ends as one and keeps every other position distinct.
    Pin(u8),
}

/// Every device recognised from the layout.
///
/// Filled by [`recognise_into`]. Row `k` is `DeviceId(k)`, rows ascend by
/// marker polygon, and every column but `refused` has one row per device.
/// Every terminal is on a real net, never [`NetId::NONE`]: a marker that
/// cannot bind every terminal is not a device, and is listed in `refused`.
#[derive(Debug, Default)]
pub struct DeviceTable {
    /// The family of each device, from its recogniser.
    pub kind: Vec<DeviceKind>,
    /// The marker polygon that identifies this device.
    pub marker: Vec<PolyId>,
    /// The model name of each device, from its recogniser; what LVS compares
    /// against the reference.
    pub model: Vec<StrId>,
    /// Terminals, CSR into `terminal_net` / `terminal_role`.
    pub terminal_start: Vec<u32>,
    /// The net of each terminal, in the recogniser's layer order.
    pub terminal_net: Vec<NetId>,
    /// The role of each terminal, by its position in the recogniser.
    pub terminal_role: Vec<TerminalRole>,
    /// Measured geometry, CSR into `param`.
    pub param_start: Vec<u32>,
    /// `(parameter, measure)` per measured parameter. A MOS gets `Width` and
    /// `Length` when a source or drain polygon fixes its channel direction,
    /// and a resistor when one of its ends does; a MOS gets `Fingers`, 1;
    /// every device gets `Area` and `Perimeter`; a MOS its source's and
    /// drain's, and a bipolar its emitter's, where that terminal is one
    /// polygon.
    pub param: Vec<(DeviceParam, DeviceMeasure)>,
    /// The coefficients each device's recogniser states (`sheet`,
    /// `area_cap`, `fringe_cap`), from which LVS computes a resistor's `r`
    /// and a capacitor's `c`. A table built by hand may leave it short, and
    /// a device past its end has none.
    pub value: Vec<DeviceValue>,
    /// Markers that are no device, ascending: `(marker, bound, listed)` for
    /// each marker polygon no recogniser naming its layer could bind, with
    /// the terminals the first such recogniser in deck order bound and the
    /// count it lists. `lvs.terminal_net` reports each.
    pub refused: Vec<(PolyId, u32, u32)>,

    /// Devices attached to each net, CSR.
    net_start: Vec<u32>,
    net_device: Vec<DeviceId>,
}

/// A measured device parameter, and the SPICE name LVS compares it under:
/// Netgen's and ngspice's (`w`, `l`, `nf`, `area`, `perim`, `as`, `ad`,
/// `ps`, `pd`), and `KLayout`'s for a bipolar's emitter (`ae`, `pe`). LVS
/// also computes a resistor's `r` and a capacitor's `c` from these and the
/// deck's [`DeviceValue`].
///
/// A terminal's area and perimeter are its polygon's, holes taken out of the
/// area and added to the perimeter, and are measured only where the terminal
/// is one polygon under the marker, never where it is drawn in pieces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceParam {
    /// `w`: a MOS or resistor marker's bounding-box extent across the
    /// channel or body. Exact for a straight rectangle.
    Width,
    /// `l`: the marker's bounding-box extent along the channel or body, the
    /// axis on which the first source or drain polygon (a resistor's first
    /// end) sits off the marker's centre (`x` on a diagonal tie).
    Length,
    /// `area`: the marker polygon's area, its holes taken out.
    Area,
    /// `perim`: the length of every ring of the marker polygon, its holes'
    /// included, a diagonal edge rounded down to the database unit.
    Perimeter,
    /// `nf`: 1 per MOS, since one marker polygon is one channel. A parallel
    /// merge sums it, so fingers drawn apart match a card's `nf`.
    Fingers,
    /// `as`: a MOS source's diffusion area, the source polygon's area shared
    /// evenly by every MOS whose source or drain it is, as `KLayout`
    /// distributes it, so fingers sharing a diffusion sum to it.
    SourceArea,
    /// `ad`: the drain's, as `as` is the source's.
    DrainArea,
    /// `ps`: the source polygon's perimeter, its edge along the channel
    /// included, shared as `as` is.
    SourcePerimeter,
    /// `pd`: the drain's, as `ps` is the source's.
    DrainPerimeter,
    /// `ae`: a bipolar's emitter area, the emitter terminal's polygon's.
    EmitterArea,
    /// `pe`: the emitter polygon's perimeter.
    EmitterPerimeter,
}

/// A measurement, exact and in layout units; tolerance is the comparator's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMeasure {
    /// A length in database units.
    Length(Dbu),
    /// An area in square database units.
    Area(DbuArea),
    /// A plain count.
    Count(u32),
    /// An area in square database units shared evenly by this many devices:
    /// each has that fraction of it.
    AreaShare(DbuArea, u32),
    /// A length in database units shared evenly by this many devices.
    LengthShare(Dbu, u32),
}

impl DeviceTable {
    /// The number of devices.
    pub fn len(&self) -> usize {
        self.kind.len()
    }
    /// Whether no device was recognised.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// One device's terminals as parallel `(nets, roles)` slices, in the
    /// recogniser's layer order.
    ///
    /// # Panics
    ///
    /// Panics if `device` is not a row of this table.
    pub fn terminals_of(&self, device: DeviceId) -> (&[NetId], &[TerminalRole]) {
        let (start, end) = csr_run(&self.terminal_start, device.0 as usize);
        (
            &self.terminal_net[start..end],
            &self.terminal_role[start..end],
        )
    }
    /// One device's measured parameters.
    ///
    /// # Panics
    ///
    /// Panics if `device` is not a row of this table.
    pub fn params_of(&self, device: DeviceId) -> &[(DeviceParam, DeviceMeasure)] {
        let (start, end) = csr_run(&self.param_start, device.0 as usize);
        &self.param[start..end]
    }
    /// Devices attached to a net, ascending. Empty for [`NetId::NONE`].
    ///
    /// A device with two terminals on the net is listed once.
    ///
    /// # Panics
    ///
    /// Panics if `net` is not a net of the table this one was recognised
    /// against.
    pub fn devices_on(&self, net: NetId) -> &[DeviceId] {
        if net == NetId::NONE {
            return &[];
        }
        let (start, end) = csr_run(&self.net_start, net.idx());
        &self.net_device[start..end]
    }
}

/// `(marker polygon, recogniser row, offset into `bound`, channel axis)`.
type Match = (PolyId, u32, u32, Axis);

/// No polygon: a terminal drawn in pieces, or not measured.
const NO_POLY: PolyId = PolyId(u32::MAX);

/// Which axis a MOS channel's or a resistor body's current flows along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    /// Neither a MOS nor a resistor, or no source/drain polygon (resistor
    /// end) voted.
    Unknown,
    X,
    Y,
}

/// The axis along which a source/drain polygon's box centre is offset from the
/// marker's; `X` wins a diagonal tie.
fn channel_axis(store: &GeometryStore, marker: PolyId, terminal: PolyId) -> Axis {
    let m = store.poly_bbox(marker);
    let t = store.poly_bbox(terminal);
    // Doubled centres, so no halving rounds.
    let dx = ((t.xlo.raw() + t.xhi.raw()) - (m.xlo.raw() + m.xhi.raw())).abs();
    let dy = ((t.ylo.raw() + t.yhi.raw()) - (m.ylo.raw() + m.yhi.raw())).abs();
    if dx >= dy {
        Axis::X
    } else {
        Axis::Y
    }
}

/// Recognise every device the deck describes. Device ids ascend by marker
/// polygon; terminals come back in the recogniser's stated order.
///
/// Positions naming one layer take that layer's polygons under the marker in
/// ascending [`PolyId`] order.
///
/// Each polygon on a recogniser's marker layer is one candidate device; a
/// hole, which the store keeps as a row of its own, is part of its polygon
/// and never a marker (testing-plan F85). A terminal polygon is under the marker when the two share at least one
/// point, touching included. Polygons under it that touch or overlap each
/// other are one shape: a terminal drawn twice is still one terminal. Each
/// position needs a shape of its own, so too few shapes refuse the marker: a
/// channel with its source drawn twice and no drain is no device, not one
/// with its source and drain shorted (testing-plan F69). More shapes than
/// positions name their layer are terminals drawn apart when their nets are
/// as many as the positions, which then take one net each in the order of
/// each net's lowest shape, or all one net, which then fills every position.
/// Any other surplus refuses the marker, as two gates under one marker do.
/// Which copy of a terminal is numbered first does not matter (testing-plan
/// F33). When two recognisers that share a marker layer both bind a marker,
/// the earlier deck row wins; a marker none binds is listed in
/// [`DeviceTable::refused`].
/// `nets` must have been extracted from `store`; `out` is cleared and
/// refilled.
///
/// # Limits
///
/// - `W` and `L` are the marker's bounding box, exact for a straight
///   rectangle; a bent resistor body reads its box.
/// - A source, drain or emitter is measured only where it is one polygon no
///   other polygon of its layer touches (testing-plan F16).
/// - With three or more positions on one layer, a surplus of shapes on fewer
///   nets than positions refuses the marker, even when each position could
///   have had a shape of its own.
///
/// # Panics
///
/// Panics if a recogniser lists 256 or more terminals, or if `nets` was not
/// extracted from `store`.
pub fn recognise_into(
    store: &GeometryStore,
    nets: &NetTable,
    recognition: &DeviceRecognition,
    out: &mut DeviceTable,
) {
    let rows = recognition.kind.len();
    clear(out);

    // Roles, indexed by the recogniser's terminal offsets.
    let mut role: Vec<TerminalRole> = Vec::with_capacity(recognition.terminal.len());
    for row in 0..rows {
        let width = terminals_of_recogniser(recognition, row).len();
        let width = u8::try_from(width).expect("a device family has fewer than 256 terminals");
        role.extend((0..width).map(|position| role_at(recognition.kind[row], position)));
    }

    let mut marker_index = SpatialIndex::default();
    // One index per terminal layer, shared by every recogniser naming it, and
    // that layer's polygons touching another of it, once a recogniser
    // measures a terminal there.
    let mut terminal_index: Vec<(LayerId, SpatialIndex, Option<Vec<PolyId>>)> = Vec::new();
    let mut pairs: Vec<(PolyId, PolyId)> = Vec::new();
    let mut exact: Vec<(PolyId, PolyId)> = Vec::new();
    let mut bind: Vec<NetId> = Vec::new();
    // `bind`'s polygon: a terminal's one polygon, or `NO_POLY`.
    let mut bind_poly: Vec<PolyId> = Vec::new();
    let mut alone: Vec<bool> = Vec::new();
    let mut bound_poly: Vec<PolyId> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut distinct: Vec<NetId> = Vec::new();
    let mut group: Vec<usize> = Vec::new();
    let mut shapes: Vec<PolyId> = Vec::new();
    let mut matched: Vec<Match> = Vec::new();
    let mut bound: Vec<NetId> = Vec::new();
    let mut sd_axis: Vec<Axis> = Vec::new();

    // Inclusive box prune: a terminal touching the marker's edge counts.
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

        // `bind[m * width + k]`: the net position `k` of marker `m` landed on,
        // `NONE` when unfilled or poisoned.
        bind.clear();
        bind.resize(marker_count * width, NetId::NONE);
        bind_poly.clear();
        bind_poly.resize(marker_count * width, NO_POLY);
        sd_axis.clear();
        sd_axis.resize(marker_count, Axis::Unknown);

        for (k, &layer) in terminals.iter().enumerate() {
            // The first position naming a layer fills them all.
            if terminals[..k].contains(&layer) {
                continue;
            }
            positions.clear();
            positions.extend(
                terminals
                    .iter()
                    .enumerate()
                    .filter(|&(_, &named)| named == layer)
                    .map(|(position, _)| position),
            );

            // Whether this layer carries the MOS source/drain or a resistor's
            // ends, which tells W from L.
            let votes_axis = match recognition.kind[row] {
                DeviceKind::Mos => positions.iter().any(|&position| {
                    let position = u8::try_from(position)
                        .expect("a device family has fewer than 256 terminals");
                    matches!(
                        role_at(DeviceKind::Mos, position),
                        TerminalRole::Source | TerminalRole::Drain
                    )
                }),
                DeviceKind::Resistor => true,
                DeviceKind::Bjt
                | DeviceKind::Capacitor
                | DeviceKind::Diode
                | DeviceKind::Inductor => false,
            };

            let at = terminal_index
                .iter()
                .position(|(built, ..)| *built == layer)
                .unwrap_or_else(|| {
                    let mut index = SpatialIndex::default();
                    SpatialIndex::build_into(store, layer, &mut index);
                    terminal_index.push((layer, index, None));
                    terminal_index.len() - 1
                });
            // A source, drain or emitter is measured where it is one polygon,
            // which no other polygon of its layer touches: a piece is not the
            // terminal (testing-plan F16).
            let measured = positions.iter().any(|&position| {
                let position =
                    u8::try_from(position).expect("a device family has fewer than 256 terminals");
                matches!(
                    (
                        recognition.kind[row],
                        role_at(recognition.kind[row], position)
                    ),
                    (DeviceKind::Mos, TerminalRole::Source | TerminalRole::Drain)
                        | (DeviceKind::Bjt, TerminalRole::Emitter)
                )
            });
            let (_, index, pieced) = &mut terminal_index[at];
            if measured && pieced.is_none() {
                candidate_pairs_into(store, index, touching, &mut pairs);
                retain_intersecting_into(store, &nets.holes, &pairs, &mut exact);
                let mut touched: Vec<PolyId> = exact.iter().flat_map(|&(a, b)| [a, b]).collect();
                touched.sort_unstable();
                touched.dedup();
                *pieced = Some(touched);
            }
            let (index, pieced) = (&*index, pieced.as_deref().unwrap_or_default());
            cross_layer_pairs_into(store, &marker_index, index, touching, &mut pairs);
            // Box-only hits must not bind: a spurious low-id pair would win.
            retain_intersecting_into(store, &nets.holes, &pairs, &mut exact);

            // `exact` ascends by `(marker, terminal)`, so each marker's polygons
            // on this layer are one run, lowest first.
            let mut from = 0;
            while from < exact.len() {
                let marker = exact[from].0;
                let to = from + exact[from..].partition_point(|&(m, _)| m == marker);
                let run = &exact[from..to];
                from = to;
                let offset = (marker.0 - markers.start) as usize;
                let slots = &mut bind[offset * width..(offset + 1) * width];
                let polys = &mut bind_poly[offset * width..(offset + 1) * width];
                // The first source/drain polygon under a marker decides the axis.
                if votes_axis && sd_axis[offset] == Axis::Unknown {
                    sd_axis[offset] = channel_axis(store, marker, run[0].1);
                }
                // Polygons that touch or overlap are one shape, one terminal
                // however often it was drawn (testing-plan F69), named by its
                // lowest polygon.
                // ponytail: pairwise over one marker's polygons on one layer,
                // a handful in practice; sweep them if a marker covers hundreds.
                group.clear();
                group.extend(0..run.len());
                for i in 0..run.len() {
                    for j in 0..i {
                        if polys_intersect(store, &nets.holes, run[i].1, run[j].1) {
                            let (a, b) = (root(&group, i), root(&group, j));
                            group[a.max(b)] = a.min(b);
                        }
                    }
                }
                shapes.clear();
                alone.clear();
                for i in (0..run.len()).filter(|&i| root(&group, i) == i) {
                    shapes.push(run[i].1);
                    alone.push((0..run.len()).all(|j| j == i || root(&group, j) != i));
                }
                if shapes.len() <= positions.len() {
                    // The r-th shape fills the r-th position; too few leave
                    // one with no shape of its own, which refuses the marker.
                    for (r, (&position, &terminal)) in positions.iter().zip(&shapes).enumerate() {
                        slots[position] = nets.net_of(terminal);
                        let whole = alone[r] && pieced.binary_search(&terminal).is_err();
                        polys[position] = if whole { terminal } else { NO_POLY };
                    }
                    continue;
                }
                // More shapes than positions. Their nets, each at its lowest
                // shape, decide whether the surplus is terminals drawn apart
                // on one net (a well beside a well), wherever they are
                // numbered.
                distinct.clear();
                for &terminal in &shapes {
                    let net = nets.net_of(terminal);
                    if !distinct.contains(&net) {
                        distinct.push(net);
                    }
                }
                let unique = distinct.len();
                for (k, &position) in positions.iter().enumerate() {
                    slots[position] = if unique == positions.len() {
                        distinct[k]
                    } else if unique == 1 {
                        distinct[0]
                    } else {
                        // Two gates under one implant: refused.
                        NetId::NONE
                    };
                }
            }
        }

        matched.reserve(marker_count);
        for offset in 0..marker_count {
            let slots = &bind[offset * width..offset * width + width];
            // A hole binds nothing, being no material, and is its outer's.
            if nets.holes.is_hole(PolyId(markers.start + narrow(offset))) {
                continue;
            }
            if slots.contains(&NetId::NONE) {
                let filled = slots.iter().filter(|&&net| net != NetId::NONE).count();
                out.refused.push((
                    PolyId(markers.start + narrow(offset)),
                    narrow(filled),
                    narrow(width),
                ));
                continue;
            }
            let at = narrow(bound.len());
            matched.push((
                PolyId(markers.start + narrow(offset)),
                narrow(row),
                at,
                sd_axis[offset],
            ));
            bound.extend_from_slice(slots);
            bound_poly.extend_from_slice(&bind_poly[offset * width..offset * width + width]);
        }
    }

    // Stable, so of two recognisers matching one marker the earlier wins.
    matched.sort_by_key(|&(marker, ..)| marker);
    matched.dedup_by_key(|&mut (marker, ..)| marker);
    // A marker another recogniser bound is a device; of the rest, each is
    // reported once, as the earliest recogniser refused it.
    out.refused.sort_by_key(|&(marker, ..)| marker);
    out.refused.dedup_by_key(|&mut (marker, ..)| marker);
    out.refused.retain(|&(marker, ..)| {
        matched
            .binary_search_by_key(&marker, |&(bound, ..)| bound)
            .is_err()
    });

    // Every source or drain polygon once per MOS it serves, sorted, so a
    // shared diffusion's count is the length of its run.
    let mut served: Vec<PolyId> = Vec::new();
    for &(_, row, at, _) in &matched {
        let row = row as usize;
        if recognition.kind[row] == DeviceKind::Mos {
            let (from, to) = csr_run(&recognition.terminal_start, row);
            served.extend(
                (from..to)
                    .filter(|&slot| {
                        matches!(role[slot], TerminalRole::Source | TerminalRole::Drain)
                    })
                    .map(|slot| bound_poly[at as usize + slot - from])
                    .filter(|&poly| poly != NO_POLY),
            );
        }
    }
    served.sort_unstable();

    // Deduplicated: a device with two terminals on one net attaches once.
    let mut attach: Vec<(NetId, DeviceId)> = Vec::with_capacity(bound.len());

    for (device, &(marker, row, at, axis)) in matched.iter().enumerate() {
        let row = row as usize;
        let span =
            recognition.terminal_start[row] as usize..recognition.terminal_start[row + 1] as usize;
        let nets_of_device = &bound[at as usize..at as usize + span.len()];

        out.kind.push(recognition.kind[row]);
        out.marker.push(marker);
        out.model.push(recognition.model[row]);
        out.terminal_net.extend_from_slice(nets_of_device);
        out.terminal_role.extend_from_slice(&role[span.clone()]);
        out.terminal_start.push(narrow(out.terminal_net.len()));

        // W/L from the marker's bbox extents: L runs along the channel or
        // the resistor body, W across it. Exact for a straight rectangle.
        // ponytail: a bent resistor reads its bounding box; KLayout's W from
        // the edges the body shares with its terminals, L = area / W, fits it.
        let kind = recognition.kind[row];
        if matches!(kind, DeviceKind::Mos | DeviceKind::Resistor) && axis != Axis::Unknown {
            let bbox = store.poly_bbox(marker);
            let (extent_x, extent_y) = (
                bbox.xhi.raw() - bbox.xlo.raw(),
                bbox.yhi.raw() - bbox.ylo.raw(),
            );
            let (length, width) = match axis {
                Axis::X => (extent_x, extent_y),
                Axis::Y | Axis::Unknown => (extent_y, extent_x),
            };
            out.param.push((
                DeviceParam::Width,
                DeviceMeasure::Length(Dbu::new_unchecked(width)),
            ));
            out.param.push((
                DeviceParam::Length,
                DeviceMeasure::Length(Dbu::new_unchecked(length)),
            ));
        }

        // One channel is one finger; a parallel merge sums them.
        if kind == DeviceKind::Mos {
            out.param
                .push((DeviceParam::Fingers, DeviceMeasure::Count(1)));
        }

        let (area, perimeter) = area_and_perimeter(store, &nets.holes, marker);
        out.param
            .push((DeviceParam::Area, DeviceMeasure::Area(area)));
        out.param
            .push((DeviceParam::Perimeter, DeviceMeasure::Length(perimeter)));

        // A terminal's own area and perimeter: a MOS's source and drain, a
        // bipolar's emitter, each where it is one polygon (testing-plan F16).
        for (slot, &terminal_role) in role[span.clone()].iter().enumerate() {
            let poly = bound_poly[at as usize + slot];
            let names = match (kind, terminal_role) {
                (DeviceKind::Mos, TerminalRole::Source) => {
                    (DeviceParam::SourceArea, DeviceParam::SourcePerimeter)
                }
                (DeviceKind::Mos, TerminalRole::Drain) => {
                    (DeviceParam::DrainArea, DeviceParam::DrainPerimeter)
                }
                (DeviceKind::Bjt, TerminalRole::Emitter) => {
                    (DeviceParam::EmitterArea, DeviceParam::EmitterPerimeter)
                }
                _ => continue,
            };
            if poly == NO_POLY {
                continue;
            }
            let (area, perimeter) = area_and_perimeter(store, &nets.holes, poly);
            let measures = if kind == DeviceKind::Mos {
                let ways =
                    served.partition_point(|&p| p <= poly) - served.partition_point(|&p| p < poly);
                let ways = narrow(ways);
                (
                    DeviceMeasure::AreaShare(area, ways),
                    DeviceMeasure::LengthShare(perimeter, ways),
                )
            } else {
                (DeviceMeasure::Area(area), DeviceMeasure::Length(perimeter))
            };
            out.param.push((names.0, measures.0));
            out.param.push((names.1, measures.1));
        }
        out.param_start.push(narrow(out.param.len()));
        out.value
            .push(recognition.value.get(row).copied().unwrap_or_default());

        let device = DeviceId(narrow(device));
        attach.extend(nets_of_device.iter().map(|&net| (net, device)));
    }

    attach.sort_unstable();
    attach.dedup();
    debug_assert!(
        out.terminal_net
            .iter()
            .all(|&net| net.idx() < nets.net_count()),
        "a recognised device's every terminal is bound to a net of `nets`"
    );

    out.net_start.resize(nets.net_count() + 1, 0);
    for &(net, _) in &attach {
        out.net_start[net.idx() + 1] += 1;
    }
    for index in 1..out.net_start.len() {
        out.net_start[index] += out.net_start[index - 1];
    }
    // Sorted by `(net, device)`, so the device column is already in CSR order.
    out.net_device
        .extend(attach.iter().map(|&(_, device)| device));
    debug_assert!(
        out.terminal_start.last().map(|&end| end as usize) == Some(out.terminal_net.len())
            && out.param_start.last().map(|&end| end as usize) == Some(out.param.len())
            && out.net_start.last().map(|&end| end as usize) == Some(out.net_device.len()),
        "each CSR offset column ends at the length of the column it indexes"
    );
}

/// A polygon's area with its holes taken out, and the length of all its
/// rings, its holes' included: every ring is an edge of the material.
fn area_and_perimeter(store: &GeometryStore, holes: &Holes, poly: PolyId) -> (DbuArea, Dbu) {
    let (mut doubled, mut perimeter) = (0i128, 0i64);
    for (ring, sign) in std::iter::once((poly, 1)).chain(holes.of(poly).map(|hole| (hole, -1))) {
        let (xs, ys) = store.poly_verts(ring);
        // `abs`: a store polygon carries no winding guarantee.
        doubled += sign * area2(xs, ys).raw().abs();
        perimeter += ring_length(xs, ys).raw();
    }
    // Bound holes lie inside their outer and apart from one another.
    debug_assert!(
        doubled >= 0,
        "a polygon's area net of its holes is non-negative"
    );
    (DbuArea::new(doubled / 2), Dbu::new_unchecked(perimeter))
}

/// A ring's length, its closing edge included; a diagonal edge counts its
/// length rounded down to the database unit.
fn ring_length(xs: &[Dbu], ys: &[Dbu]) -> Dbu {
    let n = xs.len();
    let length = (0..n)
        .map(|i| {
            let j = (i + 1) % n;
            let (dx, dy) = (
                i128::from(xs[j].raw() - xs[i].raw()),
                i128::from(ys[j].raw() - ys[i].raw()),
            );
            isqrt(DbuArea::new(dx * dx + dy * dy)).raw()
        })
        .sum();
    Dbu::new_unchecked(length)
}

/// The group of entry `at` in a parent-pointer forest whose roots are their
/// group's lowest entry.
fn root(group: &[usize], mut at: usize) -> usize {
    while group[at] != at {
        at = group[at];
    }
    at
}

/// Every column emptied, both CSR columns reopened at zero.
fn clear(out: &mut DeviceTable) {
    out.kind.clear();
    out.marker.clear();
    out.model.clear();
    out.terminal_start.clear();
    out.terminal_net.clear();
    out.terminal_role.clear();
    out.param_start.clear();
    out.param.clear();
    out.value.clear();
    out.refused.clear();
    out.net_start.clear();
    out.net_device.clear();
    out.terminal_start.push(0);
    out.param_start.push(0);
}

/// Why an extraction was refused before nets were built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// A MOS channel marker overlaps conductor area on its own source/drain
    /// layer, so source and drain would extract as one net.
    #[error(
        "MOS channel marker layer {marker:?} overlaps conductor area on \
         source/drain layer {conductor:?} at polygon {poly:?}: source and \
         drain would extract as one net; derive the source/drain conductor \
         with the channel subtracted (e.g. `diff NOT poly`)"
    )]
    ConductingChannel {
        /// The recogniser's marker layer.
        marker: LayerId,
        /// The source/drain layer the marker overlaps.
        conductor: LayerId,
        /// The lowest store polygon contributing to the first overlap region.
        poly: PolyId,
    },
    /// The marker or source/drain layer could not be validated or intersected.
    #[error(transparent)]
    Geometry(#[from] BooleanError),
}

/// Refuse any MOS recogniser whose channel marker overlaps conductor area on
/// its source/drain layer. Checked in deck order, positions in terminal order.
///
/// Run it before [`extract_nets_into`](crate::topology::extract_nets_into):
/// a drawn diffusion that runs under the gate would join source and drain
/// into one net, and the short would then extract, and compare, as clean.
/// Only area overlap counts, not shapes that merely abut, and only on a
/// source/drain layer that is a conductor. The test is per layer pair over
/// the whole layout, so one bad device refuses the run.
///
/// # Errors
///
/// [`ChannelError::ConductingChannel`] for the first offending
/// `(marker, layer)` pair; [`ChannelError::Geometry`] when either layer fails
/// validation or the intersection fails.
pub fn refuse_conducting_channels(
    store: &GeometryStore,
    connectivity: &Connectivity,
    recognition: &DeviceRecognition,
) -> Result<(), ChannelError> {
    let mut checked: Vec<(LayerId, LayerId)> = Vec::new();
    let mut marker_area = ValidatedLayer::default();
    let mut conductor_area = ValidatedLayer::default();
    let mut overlap = ValidatedLayer::default();

    for row in 0..recognition.kind.len() {
        if recognition.kind[row] != DeviceKind::Mos {
            continue;
        }
        let marker = recognition.marker[row];
        for (position, &layer) in terminals_of_recogniser(recognition, row).iter().enumerate() {
            let position =
                u8::try_from(position).expect("a device family has fewer than 256 terminals");
            // Gate and bulk conduct through the marker on purpose.
            if !matches!(
                role_at(DeviceKind::Mos, position),
                TerminalRole::Source | TerminalRole::Drain
            ) {
                continue;
            }
            if !connectivity.conductors.contains(&layer) || checked.contains(&(marker, layer)) {
                continue;
            }
            checked.push((marker, layer));
            if store.polys_on_layer(marker).is_empty() || store.polys_on_layer(layer).is_empty() {
                continue;
            }

            // Exact area intersection: edge-only abutment intersects to nothing.
            validate_layer_with(store, marker, Angles::Octilinear, &mut marker_area)
                .map_err(BooleanError::from)?;
            validate_layer_with(store, layer, Angles::Octilinear, &mut conductor_area)
                .map_err(BooleanError::from)?;
            intersection_into(&marker_area, &conductor_area, &mut overlap)?;
            if !overlap.is_empty() {
                // The overlap's own rows are the boolean's scratch store's.
                let mut drawn = LayerRects::default();
                let mut owner = PolyId(u32::MAX);
                for (id, area) in [(marker, &marker_area), (layer, &conductor_area)] {
                    owner = owner.min(if area.is_rectilinear() {
                        drawn.build(store, id, area);
                        owners_of(&overlap, &drawn)[0]
                    } else {
                        // ponytail: a 45-degree layer names its lowest row, not
                        // the one under the overlap; cut by point if it matters.
                        (0..u32::try_from(area.len()).expect("a u32 index"))
                            .map(|p| area.get(p).provenance())
                            .min()
                            .unwrap_or(PolyId(u32::MAX))
                    });
                }
                return Err(ChannelError::ConductingChannel {
                    marker,
                    conductor: layer,
                    poly: owner,
                });
            }
        }
    }
    Ok(())
}

/// The terminal layers of one recogniser row.
fn terminals_of_recogniser(recognition: &DeviceRecognition, row: usize) -> &[LayerId] {
    let (start, end) = csr_run(&recognition.terminal_start, row);
    &recognition.terminal[start..end]
}

/// The role of terminal `position` in family `kind`, per [`TerminalRole`].
pub(crate) fn role_at(kind: DeviceKind, position: u8) -> TerminalRole {
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
    let named: &[TerminalRole] = match kind {
        DeviceKind::Mos => &MOS,
        DeviceKind::Bjt => &BJT,
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode | DeviceKind::Inductor => {
            &[]
        }
    };
    named
        .get(usize::from(position))
        .copied()
        .unwrap_or(TerminalRole::Pin(position))
}

/// A count narrowed to the `u32` every CSR column here is made of.
fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a device table addresses fewer than u32::MAX rows")
}
