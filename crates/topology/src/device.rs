//! Device recognition and terminal binding.
//!
//! One polygon on a recogniser's marker layer is exactly one device, which
//! constrains the deck: a MOS marker is the channel, not the implant.

use crate::csr_run;
use crate::net::{retain_intersecting_into, NetId, NetTable};
use gpurify_geom::boolean::{intersection_into, BooleanError};
use gpurify_geom::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::area2;
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_geom::Evaluator;
use gpurify_ingest::deck::{Connectivity, DeviceKind, DeviceRecognition};
use gpurify_ingest::StrId;
use gpurify_geom::{Dbu, DbuArea};

/// Identifies one recognised device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeviceId(pub u32);

/// Which terminal of a device a net is attached to. [`DeviceRecognition`] has
/// no role column, so the role is a function of the family and the position,
/// and this table is the only place it is written down.
///
/// | [`DeviceKind`] | position 0 | 1 | 2 | 3 |
/// |---|---|---|---|---|
/// | `Mos` | `Gate` | `Source` | `Drain` | `Bulk` |
/// | `Bjt` | `Base` | `Emitter` | `Collector` | — |
/// | `Resistor`, `Capacitor` | `Pin(0)` | `Pin(1)` | — | — |
///
/// A position past the end of its family's row is `Pin(k)`: the payload is the
/// position, not a rank among pins. `Diode` has no anode/cathode pair here, so
/// it falls through to `Pin` and a comparison can match one wired backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalRole {
    Gate,
    Source,
    Drain,
    Bulk,
    Base,
    Emitter,
    Collector,
    /// Either end of a symmetric two-terminal device.
    Pin(u8),
}

/// Every device recognised from the layout.
#[derive(Debug, Default)]
pub struct DeviceTable {
    pub kind: Vec<DeviceKind>,
    /// The marker polygon that identifies this device.
    pub marker: Vec<PolyId>,
    pub model: Vec<StrId>,
    /// Terminals, CSR into `terminal_net` / `terminal_role`.
    pub terminal_start: Vec<u32>,
    pub terminal_net: Vec<NetId>,
    pub terminal_role: Vec<TerminalRole>,
    /// Measured geometry, CSR into `param`.
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

/// A measurement, exact and in layout units. Integer, not `f64`: tolerance is
/// the comparator's to apply, not the extractor's to accumulate.
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
    /// Devices attached to a net, ascending. Empty for [`NetId::NONE`].
    pub fn devices_on(&self, net: NetId) -> &[DeviceId] {
        // `NONE`'s index is `u32::MAX`, so falling through would panic rather
        // than return the promised empty slice. Any other id past the table
        // does panic: "carries nothing" and "does not exist" differ.
        if net == NetId::NONE {
            return &[];
        }
        let (start, end) = csr_run(&self.net_start, net.idx());
        debug_assert!(
            end <= self.net_device.len(),
            "a reverse-index run leaves its column"
        );
        &self.net_device[start..end]
    }
}

/// `(marker polygon, recogniser row, offset into `bound`, channel axis)`.
type Match = (PolyId, u32, u32, Axis);

/// Which axis a MOS channel's current flows along, read off where the
/// source/drain geometry sits relative to the channel marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    /// Not a MOS, or no source/drain polygon voted.
    Unknown,
    X,
    Y,
}

/// The channel axis of one `(marker, source/drain polygon)` pair: the axis
/// along which the flanking diffusion is offset from the channel. A perfectly
/// diagonal offset cannot come from a flanking diffusion piece; `X` wins the
/// tie so the answer stays a function of the geometry alone.
fn channel_axis(store: &GeometryStore, marker: PolyId, terminal: PolyId) -> Axis {
    let m = store.poly_bbox(marker);
    let t = store.poly_bbox(terminal);
    // Doubled centres: the sum of two coordinates, so no halving rounds.
    let dx = ((t.xlo.raw() + t.xhi.raw()) - (m.xlo.raw() + m.xhi.raw())).abs();
    let dy = ((t.ylo.raw() + t.yhi.raw()) - (m.ylo.raw() + m.yhi.raw())).abs();
    if dx >= dy {
        Axis::X
    } else {
        Axis::Y
    }
}

/// Recognise every device the deck describes. Device ids are the rank of the
/// marker polygon, so they are canonical for a given layout; terminals come
/// back in the recogniser's stated order.
///
/// Binding is per terminal *position*, not per layer: a MOS declares
/// `[poly, diff_active, diff_active]`, and the positions naming one layer take
/// that layer's polygons under the marker in ascending [`PolyId`] order. A
/// marker carrying too few or too many of them is refused, not half-reported.
///
/// `derived` is accepted and unread — derived layers carry real
/// [`gpurify_geom::LayerId`]s — and keeps its name because the signature is
/// frozen.
#[allow(unused_variables)]
pub fn recognise_into(
    store: &GeometryStore,
    derived: &Evaluator,
    nets: &NetTable,
    recognition: &DeviceRecognition,
    out: &mut DeviceTable,
) {
    let rows = recognition.kind.len();
    debug_assert_eq!(
        recognition.marker.len(),
        rows,
        "one marker layer per recogniser"
    );
    debug_assert_eq!(recognition.model.len(), rows, "one model per recogniser");
    debug_assert!(
        recognition.terminal_start.len() == rows + 1 || recognition.terminal_start.is_empty(),
        "the recogniser CSR carries one offset per row plus a terminator"
    );

    clear(out);

    debug_assert!(
        (0..rows).all(
            |row| !terminals_of_recogniser(recognition, row).contains(&recognition.marker[row])
        ),
        "a recogniser's marker layer is also one of its terminal layers"
    );

    // Uniform per recogniser row, so hoisted and indexed by the same offsets.
    let mut role: Vec<TerminalRole> = Vec::with_capacity(recognition.terminal.len());
    for row in 0..rows {
        let width = terminals_of_recogniser(recognition, row).len();
        let width = u8::try_from(width).expect("a device family has fewer than 256 terminals");
        role.extend((0..width).map(|position| role_at(recognition.kind[row], position)));
    }
    debug_assert_eq!(
        role.len(),
        recognition.terminal.len(),
        "one role per terminal layer"
    );

    // Scratch: one set for the whole call, cleared per layer.
    let mut marker_index = SpatialIndex::default();
    let mut terminal_index = SpatialIndex::default();
    let mut pairs: Vec<(PolyId, PolyId)> = Vec::new();
    // Survivors of the exact re-test; a second buffer, not a retain on `pairs`,
    // so the compact's store can be unconditional.
    let mut exact: Vec<(PolyId, PolyId)> = Vec::new();
    let mut bind: Vec<NetId> = Vec::new();
    // The terminal positions naming one layer, ascending.
    let mut positions: Vec<usize> = Vec::new();
    let mut matched: Vec<Match> = Vec::new();
    let mut bound: Vec<NetId> = Vec::new();
    // Per-marker channel axis, voted by the first source/drain polygon bound
    // under it; `Unknown` for every non-MOS row.
    let mut sd_axis: Vec<Axis> = Vec::new();

    // `within(_, 0)` is `Bbox::overlaps`, inclusive: a terminal touching the
    // marker's edge counts as under it. Prune only; re-tested exactly below.
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

        // `bind[m * width + k]` is the net position `k` of marker `m` landed
        // on, or `NetId::NONE` for a position with nothing under it.
        // `terminal_net` cannot spell an absent terminal, so a marker whose
        // positions are not all filled is skipped.
        bind.clear();
        bind.resize(marker_count * width, NetId::NONE);
        sd_axis.clear();
        sd_axis.resize(marker_count, Axis::Unknown);

        // Strictly above every marker in range, so the scan's first pair reads
        // as a new marker without a flag to test for it.
        let past_markers = PolyId(markers.end);

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
            // Non-empty by construction, which is what makes the
            // `positions.len() - 1` in the bind loop safe.
            debug_assert_eq!(
                positions[0], k,
                "the first position naming a layer fills it"
            );

            // Whether this layer carries the MOS source/drain, which is the
            // geometry that tells the channel's W from its L.
            let votes_axis = recognition.kind[row] == DeviceKind::Mos
                && positions.iter().any(|&position| {
                    let position = u8::try_from(position)
                        .expect("a device family has fewer than 256 terminals");
                    matches!(
                        role_at(DeviceKind::Mos, position),
                        TerminalRole::Source | TerminalRole::Drain
                    )
                });

            SpatialIndex::build_into(store, layer, &mut terminal_index);
            cross_layer_pairs_into(store, &marker_index, &terminal_index, touching, &mut pairs);
            debug_assert!(
                pairs.iter().all(|&(m, _)| markers.contains(&m.0)),
                "the cross-layer prune returned a polygon off the marker layer"
            );

            // Box-only hits must not bind: by the ascending-`PolyId` rule
            // below a spurious low-id pair *wins*, and the real device comes
            // back wired to a net it does not touch.
            retain_intersecting_into(store, &pairs, &mut exact);

            // The r-th of this layer's polygons under a marker fills the r-th
            // position naming it; `exact` is ascending by `(marker, terminal)`,
            // so the rank is ascending `PolyId`.
            let mut previous = past_markers;
            let mut rank = 0usize;
            for &(marker, terminal) in &exact {
                // A new marker resets the rank; the multiply is the reset.
                rank = (rank + 1) * usize::from(marker == previous);
                previous = marker;
                // A rank past the last position naming this layer means the
                // marker carries more of the layer than there are slots for —
                // two gates under one implant. Poisoning the last such position
                // refuses the marker, because reporting the first transistor
                // and dropping the rest is a plausible answer nothing
                // downstream could question. Rank only ascends within a
                // marker's run, so a poisoned slot stays poisoned.
                let surplus = rank >= positions.len();
                let slot = positions[rank.min(positions.len() - 1)];
                let bound = nets.net_of(terminal);
                let offset = (marker.0 - markers.start) as usize;
                bind[offset * width + slot] = if surplus { NetId::NONE } else { bound };
                // The first source/drain polygon under a marker decides the
                // channel axis; later ones agree by construction (they flank
                // the same channel).
                if votes_axis && sd_axis[offset] == Axis::Unknown {
                    sd_axis[offset] = channel_axis(store, marker, terminal);
                }
            }
        }

        matched.reserve(marker_count);
        for offset in 0..marker_count {
            let slots = &bind[offset * width..offset * width + width];
            // A marker with any position unfilled is not one device.
            if slots.contains(&NetId::NONE) {
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
        }
    }

    // Stable, so two recognisers matching one marker stay in deck order and the
    // dedup keeps the earlier: one device per marker polygon, always.
    matched.sort_by_key(|&(marker, ..)| marker);
    matched.dedup_by_key(|&mut (marker, ..)| marker);

    let devices = matched.len();
    out.kind.reserve(devices);
    out.marker.reserve(devices);
    out.model.reserve(devices);
    out.terminal_start.reserve(devices);
    out.terminal_net.reserve(bound.len());
    out.terminal_role.reserve(bound.len());
    out.param_start.reserve(devices);
    out.param.reserve(devices);

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
        out.terminal_role.extend_from_slice(&role[span]);
        out.terminal_start.push(narrow(out.terminal_net.len()));

        // The marker is the device's extent: area is what it states on its
        // own, and for a MOS the source/drain geometry adds the channel axis,
        // which is what separates `W` from `L` — `L` runs along the current,
        // `W` across it. Extents are bbox extents, exact for the rectangular
        // channel a straight gate crossing leaves; a bent gate's W/L is an
        // approximation the comparator's tolerance absorbs. `Fingers` stays
        // absent: one marker is one finger, and the finger count of a
        // multi-finger device is the number of its markers.
        if recognition.kind[row] == DeviceKind::Mos && axis != Axis::Unknown {
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

        // `abs`, because a store polygon carries no winding guarantee: the sign
        // is the vertex order, not a hole.
        let (marker_x, marker_y) = store.poly_verts(marker);
        let doubled = area2(marker_x, marker_y).raw().abs();
        debug_assert!(doubled % 2 == 0, "twice an area is even");
        out.param.push((
            DeviceParam::Area,
            DeviceMeasure::Area(DbuArea::new(doubled / 2)),
        ));
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

    out.net_start.resize(nets.net_count() + 1, 0);
    for &(net, _) in &attach {
        out.net_start[net.idx() + 1] += 1;
    }
    for index in 1..out.net_start.len() {
        out.net_start[index] += out.net_start[index - 1];
    }
    // `attach` is sorted by `(net, device)`, so a plain copy of its second
    // column lands every device in its net's run, ascending.
    out.net_device.clear();
    out.net_device
        .extend(attach.iter().map(|&(_, device)| device));
    debug_assert_eq!(
        out.net_device.len(),
        attach.len(),
        "one device row per attachment"
    );

    debug_assert_eq!(out.len(), devices, "one row per surviving marker polygon");
    debug_assert_eq!(
        out.terminal_start.len(),
        devices + 1,
        "the terminal CSR lost its terminator"
    );
    debug_assert_eq!(
        out.param_start.len(),
        devices + 1,
        "the param CSR lost its terminator"
    );
    debug_assert_eq!(
        out.param_start.last().copied().unwrap_or(0) as usize,
        out.param.len(),
        "the param CSR's terminator and its rows disagree"
    );
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
    out.net_start.clear();
    out.net_device.clear();
    out.terminal_start.push(0);
    out.param_start.push(0);
}

/// Why an extraction was refused before nets were built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// A MOS channel marker overlaps live conductor area on its own
    /// source/drain layer. Extraction joins a conductor polygon into one net
    /// whole, so the channel would conduct laterally and source and drain
    /// would come back as one net — a short through every transistor, reported
    /// by nothing. The deck's fix is to derive the source/drain conductor as
    /// the diffusion minus the channel (`diff NOT poly`, or minus the marker
    /// layers themselves) and recognise on a per-channel marker.
    #[error(
        "MOS channel marker layer {marker:?} overlaps conductor area on \
         source/drain layer {conductor:?} at polygon {poly:?}: source and \
         drain would extract as one net; derive the source/drain conductor \
         with the channel subtracted (e.g. `diff NOT poly`)"
    )]
    ConductingChannel {
        marker: LayerId,
        conductor: LayerId,
        /// The lowest store polygon contributing to the first overlap region,
        /// ascending by construction of the boolean, so the same layout names
        /// the same polygon on every run.
        poly: PolyId,
    },
    /// The marker or source/drain layer could not be validated or intersected
    /// — non-rectilinear or degenerate geometry the splitter cannot represent.
    /// The inner error names the polygon.
    #[error(transparent)]
    Geometry(#[from] BooleanError),
}

/// Refuse any MOS recogniser whose channel marker overlaps conductor area on
/// its source/drain layer — the configuration under which [`recognise_into`]
/// would silently report source and drain on one net.
///
/// Fail-closed and deck-driven: the channel *is* the recogniser's marker
/// region, so the check needs no layer names of its own. Layers are examined
/// in deck order and positions in terminal order, so the first refusal is a
/// function of the deck and the layout alone. A pair of layers where either
/// side holds no geometry is trivially clean and skipped.
pub fn refuse_conducting_channels(
    store: &GeometryStore,
    connectivity: &Connectivity,
    recognition: &DeviceRecognition,
) -> Result<(), ChannelError> {
    let rows = recognition.kind.len();
    // Deduplicated pairs; a deck has a handful of recognisers, so a linear
    // scan beats anything with buckets and stays deterministic.
    let mut checked: Vec<(LayerId, LayerId)> = Vec::new();
    let mut marker_area = ValidatedLayer::default();
    let mut conductor_area = ValidatedLayer::default();
    let mut overlap = ValidatedLayer::default();

    for row in 0..rows {
        // Only a MOS has a channel; a resistor or capacitor marker legally
        // overlaps the conductor its body is drawn on.
        if recognition.kind[row] != DeviceKind::Mos {
            continue;
        }
        let marker = recognition.marker[row];
        for (position, &layer) in terminals_of_recogniser(recognition, row).iter().enumerate() {
            let position =
                u8::try_from(position).expect("a device family has fewer than 256 terminals");
            // Gate and bulk conduct *through* the marker on purpose — the gate
            // poly is one net across the channel. Only the source/drain layer
            // must arrive with the channel subtracted.
            if !matches!(
                role_at(DeviceKind::Mos, position),
                TerminalRole::Source | TerminalRole::Drain
            ) {
                continue;
            }
            // A source/drain layer that is not a conductor binds to no net at
            // all, which recognise_into already refuses per marker.
            if !connectivity.conductors.contains(&layer) || checked.contains(&(marker, layer)) {
                continue;
            }
            checked.push((marker, layer));
            if store.polys_on_layer(marker).is_empty() || store.polys_on_layer(layer).is_empty() {
                continue;
            }

            // Exact area intersection: two regions sharing only an edge — the
            // legal abutment of a channel and its flanking diffusion pieces —
            // intersect to nothing. Validation refuses non-rectilinear or
            // degenerate geometry naming the polygon, which is the fail-closed
            // path for a channel overlap the boolean cannot represent.
            validate_layer_into(store, marker, &mut marker_area).map_err(BooleanError::from)?;
            validate_layer_into(store, layer, &mut conductor_area).map_err(BooleanError::from)?;
            intersection_into(&marker_area, &conductor_area, &mut overlap)?;
            if !overlap.is_empty() {
                return Err(ChannelError::ConductingChannel {
                    marker,
                    conductor: layer,
                    poly: overlap.get(store, 0).provenance(),
                });
            }
        }
    }
    Ok(())
}

/// The terminal layers of one recogniser row.
fn terminals_of_recogniser(
    recognition: &DeviceRecognition,
    row: usize,
) -> &[gpurify_geom::LayerId] {
    let (start, end) = csr_run(&recognition.terminal_start, row);
    &recognition.terminal[start..end]
}

/// The role of terminal `position` in family `kind`, per [`TerminalRole`].
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
    let named: &[TerminalRole] = match kind {
        DeviceKind::Mos => &MOS,
        DeviceKind::Bjt => &BJT,
        // `Diode` rides the fallback and gets `Pin`s, the fail-open
        // [`TerminalRole`] names; fixing it needs `Anode`/`Cathode`.
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode => &[],
    };
    // `Pin`'s payload is the position, not a rank among pins.
    named
        .get(usize::from(position))
        .copied()
        .unwrap_or(TerminalRole::Pin(position))
}

/// A count narrowed to the `u32` every CSR column here is made of.
fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a device table addresses fewer than u32::MAX rows")
}
