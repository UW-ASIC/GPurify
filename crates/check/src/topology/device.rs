//! Device recognition and terminal binding.
//!
//! One polygon on a recogniser's marker layer is exactly one device, so a MOS
//! marker is the channel, not the implant.
//! Data in: `GeometryStore`, `NetTable`, `DeviceRecognition`. Data out: `DeviceTable`.

use crate::topology::csr_run;
use crate::topology::net::{retain_intersecting_into, NetId, NetTable};
use gpurify_geom::boolean::{intersection_into, BooleanError};
use gpurify_geom::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::area2;
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::Evaluator;
use gpurify_geom::{Dbu, DbuArea};
use gpurify_geom::{GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::deck::{Connectivity, DeviceKind, DeviceRecognition};
use gpurify_ingest::StrId;

/// Identifies one recognised device.
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

    /// Devices attached to each net, CSR.
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

/// A measurement, exact and in layout units; tolerance is the comparator's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMeasure {
    Length(Dbu),
    Area(DbuArea),
    Count(u32),
}

impl DeviceTable {
    pub fn len(&self) -> usize {
        self.kind.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn terminals_of(&self, device: DeviceId) -> (&[NetId], &[TerminalRole]) {
        let (start, end) = csr_run(&self.terminal_start, device.0 as usize);
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
        if net == NetId::NONE {
            return &[];
        }
        let (start, end) = csr_run(&self.net_start, net.idx());
        &self.net_device[start..end]
    }
}

/// `(marker polygon, recogniser row, offset into `bound`, channel axis)`.
type Match = (PolyId, u32, u32, Axis);

/// Which axis a MOS channel's current flows along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    /// Not a MOS, or no source/drain polygon voted.
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
/// ascending [`PolyId`] order; a marker with too few or too many is skipped.
pub fn recognise_into(
    store: &GeometryStore,
    _derived: &Evaluator,
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
    let mut terminal_index = SpatialIndex::default();
    let mut pairs: Vec<(PolyId, PolyId)> = Vec::new();
    let mut exact: Vec<(PolyId, PolyId)> = Vec::new();
    let mut bind: Vec<NetId> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
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
        sd_axis.clear();
        sd_axis.resize(marker_count, Axis::Unknown);

        // Above every marker, so the first pair reads as a new marker.
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

            // Whether this layer carries the MOS source/drain, which tells W from L.
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
            // Box-only hits must not bind: a spurious low-id pair would win.
            retain_intersecting_into(store, &pairs, &mut exact);

            // `exact` ascends by `(marker, terminal)`: the r-th polygon under a
            // marker fills the r-th position naming this layer.
            let mut previous = past_markers;
            let mut rank = 0usize;
            for &(marker, terminal) in &exact {
                rank = if marker == previous { rank + 1 } else { 0 };
                previous = marker;
                // More polygons than positions (two gates under one implant):
                // poison the last position so the marker is refused.
                let surplus = rank >= positions.len();
                let slot = positions[rank.min(positions.len() - 1)];
                let offset = (marker.0 - markers.start) as usize;
                bind[offset * width + slot] = if surplus {
                    NetId::NONE
                } else {
                    nets.net_of(terminal)
                };
                // The first source/drain polygon under a marker decides the axis.
                if votes_axis && sd_axis[offset] == Axis::Unknown {
                    sd_axis[offset] = channel_axis(store, marker, terminal);
                }
            }
        }

        matched.reserve(marker_count);
        for offset in 0..marker_count {
            let slots = &bind[offset * width..offset * width + width];
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

    // Stable, so of two recognisers matching one marker the earlier wins.
    matched.sort_by_key(|&(marker, ..)| marker);
    matched.dedup_by_key(|&mut (marker, ..)| marker);

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

        // MOS W/L from the marker's bbox extents: L runs along the channel
        // axis, W across it. Exact for a straight gate crossing.
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

        // `abs`: a store polygon carries no winding guarantee.
        let (marker_x, marker_y) = store.poly_verts(marker);
        let doubled = area2(marker_x, marker_y).raw().abs();
        out.param.push((
            DeviceParam::Area,
            DeviceMeasure::Area(DbuArea::new(doubled / 2)),
        ));
        out.param_start.push(narrow(out.param.len()));

        let device = DeviceId(narrow(device));
        attach.extend(nets_of_device.iter().map(|&net| (net, device)));
    }

    attach.sort_unstable();
    attach.dedup();

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
    /// A MOS channel marker overlaps conductor area on its own source/drain
    /// layer, so source and drain would extract as one net.
    #[error(
        "MOS channel marker layer {marker:?} overlaps conductor area on \
         source/drain layer {conductor:?} at polygon {poly:?}: source and \
         drain would extract as one net; derive the source/drain conductor \
         with the channel subtracted (e.g. `diff NOT poly`)"
    )]
    ConductingChannel {
        marker: LayerId,
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
fn terminals_of_recogniser(recognition: &DeviceRecognition, row: usize) -> &[LayerId] {
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
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Diode => &[],
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
