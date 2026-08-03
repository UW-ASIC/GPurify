//! Layouts emitted from a netlist, so extraction has to give the netlist back.
//!
//! This is the oracle for `topology`, and it is the strongest one available
//! there: there is no closed form for "which shapes are the same conductor",
//! but there is a layout that was *built* from a known answer, and net
//! extraction run over it must reproduce that answer exactly.
//!
//! # The layout it emits
//!
//! A rail-and-stub floorplan, chosen because every adjacency in it is decided
//! by construction rather than by luck:
//!
//! - Net `n` is a horizontal rail on the rail layer, in its own y band. Bands
//!   are pitched far enough apart that no two rails touch, so two nets can
//!   never merge.
//! - A device is a column. Its terminal `k` is a stub on that terminal's own
//!   layer, sitting in the device's column and inside the y band of the net it
//!   belongs to, overlapping the rail there.
//! - A via cut sits where each stub meets its rail, on the cut layer for that
//!   terminal layer. That is the only thing joining the two, so a via-edge bug
//!   splits a net rather than producing a subtly wrong shape.
//! - The device's marker polygon spans the whole column, overlapping every one
//!   of its own stubs and none of any other device's, because columns do not
//!   share x.
//!
//! # One layer per terminal role
//!
//! `DeviceRecognition` names terminals as a list of layers, so terminal `k` of
//! a recogniser is whatever lies on `terminal[start + k]`. A gate and a source
//! therefore have to be on different layers, and this builder gives every
//! distinct [`TerminalRole`] in the spec its own conductor layer and its own
//! cut layer. That is what a real PDK does; it is stated here because it is
//! also the reason the layer table this builder produces is wider than a reader
//! might expect.

use gpurify_core::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, DeviceKind, DeviceRecognition};
use gpurify_ingest::{StrId, StrTable};
use gpurify_topology::TerminalRole;

use crate::shapes::{Handle, Ids, LayoutBuilder};

/// One device to realise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    pub kind: DeviceKind,
    /// Model name, interned into the caller's table.
    pub model: String,
    /// Terminals, in the order the recogniser will report them. The `u32` is a
    /// net index into [`NetlistSpec::nets`].
    pub terminals: Vec<(TerminalRole, u32)>,
}

/// The structure the layout must extract back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlistSpec {
    /// How many nets exist. Every one gets a rail, including nets nothing
    /// attaches to — a floating net is a real extraction result and dropping it
    /// is the bug `erc`'s floating-net rule is looking for.
    pub nets: u32,
    pub devices: Vec<DeviceSpec>,
}

/// Which layer is which in an emitted layout.
///
/// Layer ids are dense and assigned here, so a test reads them from this rather
/// than counting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlistLayers {
    /// The layer every net's rail is on.
    pub rail: LayerId,
    /// The marker layer, one polygon per device.
    pub marker: LayerId,
    /// Terminal roles in assignment order; `terminal[i]` is on `role_layer[i]`
    /// and joined to a rail by a cut on `cut_layer[i]`.
    pub roles: Vec<TerminalRole>,
    pub role_layer: Vec<LayerId>,
    pub cut_layer: Vec<LayerId>,
    /// Total layers in the table, for anything that needs the count.
    pub count: usize,
}

impl NetlistLayers {
    /// The conductor layer carrying a role's stubs.
    ///
    /// # Panics
    ///
    /// When the role was not in the spec.
    #[must_use]
    pub fn layer_of(&self, role: TerminalRole) -> LayerId {
        let index = self
            .roles
            .iter()
            .position(|&r| r == role)
            .expect("that role is not in this layout");
        self.role_layer[index]
    }
}

/// The device the layout says is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDevice {
    pub kind: DeviceKind,
    pub model: StrId,
    /// The marker polygon. `topology::device` assigns one device per marker
    /// polygon and orders devices by it, so this is also what fixes the
    /// expected `DeviceId` ordering.
    pub marker: PolyId,
    /// Terminals in spec order: the role, and the index into
    /// [`NetlistCase::expected_net_polys`] of the net it lands on.
    pub terminals: Vec<(TerminalRole, u32)>,
}

/// A layout, the deck fragments needed to extract it, and the answer.
#[derive(Debug)]
pub struct NetlistCase {
    pub store: GeometryStore,
    pub ids: Ids,
    pub layers: NetlistLayers,
    /// What `topology::extract_nets_into` needs.
    pub connectivity: Connectivity,
    /// What `topology::device::recognise_into` needs.
    pub recognition: DeviceRecognition,
    /// The answer for nets: `expected_net_polys[n]` is every polygon on net
    /// `n`, ascending by [`PolyId`], which is the order `NetTable::polys_of`
    /// states its result in.
    pub expected_net_polys: Vec<Vec<PolyId>>,
    /// The answer for devices, in spec order.
    pub expected_devices: Vec<ExpectedDevice>,
}

/// How far apart the floorplan's features sit.
///
/// Public because a test that wants a dense layout and a test that wants a
/// sparse one are asking different questions of the spatial index, and neither
/// should have to rebuild this module to get it. The defaults are the ones the
/// invariants above were reasoned about with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floorplan {
    /// Height of a net's rail.
    pub rail_height: i64,
    /// Distance between the bottoms of two adjacent rails. Must exceed
    /// `rail_height` or two nets touch and merge.
    pub band_pitch: i64,
    /// Width of a device's column.
    pub column_width: i64,
    /// Distance between the left edges of two adjacent columns. Must exceed
    /// `column_width` or two devices' stubs touch.
    pub column_pitch: i64,
    /// Side of a via cut. Must fit inside a stub and inside the rail height.
    pub cut_size: i64,
}

impl Default for Floorplan {
    fn default() -> Self {
        Self {
            rail_height: 200,
            band_pitch: 1_000,
            column_width: 300,
            column_pitch: 1_000,
            cut_size: 100,
        }
    }
}

/// Emit a layout realising `spec`.
///
/// # Panics
///
/// When the spec names a net index that does not exist, when the floorplan's
/// pitches do not clear its features, or when a device has no terminals.
#[must_use]
pub fn layout_from_netlist(
    spec: &NetlistSpec,
    plan: Floorplan,
    strings: &mut StrTable,
) -> NetlistCase {
    assert!(spec.nets > 0, "a netlist needs at least one net");
    assert!(
        plan.band_pitch > plan.rail_height,
        "band pitch {} does not clear a rail of height {}",
        plan.band_pitch,
        plan.rail_height
    );
    assert!(
        plan.column_pitch > plan.column_width,
        "column pitch {} does not clear a column of width {}",
        plan.column_pitch,
        plan.column_width
    );
    assert!(
        plan.cut_size < plan.rail_height && plan.cut_size < plan.column_width,
        "a cut of {} does not fit inside the rail and column it joins",
        plan.cut_size
    );

    let layers = assign_layers(spec);
    let mut layout = LayoutBuilder::new(layers.count);

    let devices = i64::try_from(spec.devices.len()).expect("a spec written by hand is small");

    // Rails first, one per net, each in its own band.
    let width = plan.column_pitch * (devices + 1);
    let mut net_handles: Vec<Vec<Handle>> = Vec::with_capacity(spec.nets as usize);
    for net in 0..spec.nets {
        let y = i64::from(net) * plan.band_pitch;
        let rail = layout.rect(layers.rail, 0, y, width, y + plan.rail_height);
        net_handles.push(vec![rail]);
    }

    // Then one column per device.
    let mut markers: Vec<Handle> = Vec::with_capacity(spec.devices.len());
    for (index, device) in spec.devices.iter().enumerate() {
        assert!(
            !device.terminals.is_empty(),
            "device {index} has no terminals"
        );
        let column = i64::try_from(index).expect("a spec written by hand is small");
        let x = plan.column_pitch * column + plan.column_pitch / 2;
        emit_column(&mut layout, spec, &layers, plan, x, device, &mut net_handles);

        // The marker spans the column across every band, so it overlaps this
        // device's stubs and, because columns do not share x, no other's.
        let top = i64::from(spec.nets) * plan.band_pitch;
        markers.push(layout.rect(layers.marker, x, 0, x + plan.column_width, top));
    }

    let (store, ids) = layout.finish();

    let expected_net_polys = net_handles
        .iter()
        .map(|handles| ids.sorted(handles))
        .collect();
    let expected_devices = spec
        .devices
        .iter()
        .zip(&markers)
        .map(|(device, &marker)| ExpectedDevice {
            kind: device.kind,
            model: strings.intern(&device.model),
            marker: ids.of(marker),
            terminals: device.terminals.clone(),
        })
        .collect();

    let connectivity = Connectivity {
        conductors: std::iter::once(layers.rail)
            .chain(layers.role_layer.iter().copied())
            .collect(),
        via_cut: layers.cut_layer.clone(),
        via_connects: layers
            .role_layer
            .iter()
            .map(|&role| (layers.rail, role))
            .collect(),
        // Off, deliberately. Every join in this layout is via-mediated, so a
        // broken via edge splits a net instead of being masked by shapes that
        // happen to touch.
        intra_layer_touch: false,
    };

    let recognition = recognition_of(spec, &layers, strings);

    NetlistCase {
        store,
        ids,
        layers,
        connectivity,
        recognition,
        expected_net_polys,
        expected_devices,
    }
}

/// Emit one device's column: a stub per terminal, and the cut joining each stub
/// to the rail it lands on.
///
/// # Panics
///
/// When a terminal names a net the spec does not have.
fn emit_column(
    layout: &mut LayoutBuilder,
    spec: &NetlistSpec,
    layers: &NetlistLayers,
    plan: Floorplan,
    x: i64,
    device: &DeviceSpec,
    net_handles: &mut [Vec<Handle>],
) {
    for &(role, net) in &device.terminals {
        assert!(
            net < spec.nets,
            "a terminal names net {net}, but there are only {} nets",
            spec.nets
        );
        let slot = layers
            .roles
            .iter()
            .position(|&r| r == role)
            .expect("every role in the spec was assigned a layer");
        let y = i64::from(net) * plan.band_pitch;
        // The stub sits inside the rail's band and overlaps the rail, so the
        // cut between them has material on both sides.
        let stub = layout.rect(
            layers.role_layer[slot],
            x,
            y,
            x + plan.column_width,
            y + plan.rail_height,
        );
        net_handles[net as usize].push(stub);
        // The cut, centred in the overlap.
        let cx = x + plan.column_width / 2 - plan.cut_size / 2;
        let cy = y + plan.rail_height / 2 - plan.cut_size / 2;
        layout.rect(
            layers.cut_layer[slot],
            cx,
            cy,
            cx + plan.cut_size,
            cy + plan.cut_size,
        );
    }
}

/// Give every distinct role in the spec a conductor layer and a cut layer.
fn assign_layers(spec: &NetlistSpec) -> NetlistLayers {
    let mut roles: Vec<TerminalRole> = Vec::new();
    for device in &spec.devices {
        for &(role, _) in &device.terminals {
            if !roles.contains(&role) {
                roles.push(role);
            }
        }
    }

    // Rail 0, marker 1, then the roles' conductors and cuts interleaved so a
    // reader can see which cut belongs to which conductor.
    let mut next = 2u16;
    let mut role_layer = Vec::with_capacity(roles.len());
    let mut cut_layer = Vec::with_capacity(roles.len());
    for _ in &roles {
        role_layer.push(LayerId(next));
        cut_layer.push(LayerId(next + 1));
        next += 2;
    }

    NetlistLayers {
        rail: LayerId(0),
        marker: LayerId(1),
        roles,
        role_layer,
        cut_layer,
        count: next as usize,
    }
}

/// The recogniser table for the emitted layout: one row per device, because
/// every device gets its own marker polygon and its own terminal layer set.
fn recognition_of(
    spec: &NetlistSpec,
    layers: &NetlistLayers,
    strings: &mut StrTable,
) -> DeviceRecognition {
    let mut recognition = DeviceRecognition {
        kind: Vec::with_capacity(spec.devices.len()),
        marker: Vec::with_capacity(spec.devices.len()),
        terminal_start: Vec::with_capacity(spec.devices.len() + 1),
        terminal: Vec::new(),
        model: Vec::with_capacity(spec.devices.len()),
    };
    recognition.terminal_start.push(0);
    for device in &spec.devices {
        recognition.kind.push(device.kind);
        recognition.marker.push(layers.marker);
        recognition.model.push(strings.intern(&device.model));
        for &(role, _) in &device.terminals {
            recognition.terminal.push(layers.layer_of(role));
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the terminal list is bounded by the spec, which a test writes by hand"
        )]
        recognition
            .terminal_start
            .push(recognition.terminal.len() as u32);
    }
    recognition
}

#[cfg(test)]
mod tests {
    use super::{assign_layers, DeviceSpec, NetlistSpec};
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_topology::TerminalRole;

    fn two_transistors() -> NetlistSpec {
        NetlistSpec {
            nets: 4,
            devices: vec![
                DeviceSpec {
                    kind: DeviceKind::Mos,
                    model: "nch".to_owned(),
                    terminals: vec![
                        (TerminalRole::Gate, 0),
                        (TerminalRole::Source, 1),
                        (TerminalRole::Drain, 2),
                        (TerminalRole::Bulk, 3),
                    ],
                },
                DeviceSpec {
                    kind: DeviceKind::Resistor,
                    model: "res".to_owned(),
                    terminals: vec![(TerminalRole::Pin(0), 2), (TerminalRole::Pin(1), 3)],
                },
            ],
        }
    }

    /// Oracle: construct-from-answer. Every distinct role gets its own
    /// conductor and its own cut, and no two layers collide. If they did, two
    /// terminals would land on one layer and the recogniser could not tell a
    /// gate from a source — which would make an LVS test pass while the
    /// extraction was scrambled.
    #[test]
    fn every_role_gets_a_distinct_conductor_and_cut_layer() {
        let layers = assign_layers(&two_transistors());
        assert_eq!(layers.roles.len(), 6);

        let mut all = vec![layers.rail, layers.marker];
        all.extend(layers.role_layer.iter().copied());
        all.extend(layers.cut_layer.iter().copied());
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "two layers were assigned the same id");
        assert_eq!(layers.count, all.len());
    }

    /// Oracle: law. Layer ids index a dense table, so the assigned ids must
    /// cover `0..count` with no gaps — a gap means a store built for `count`
    /// layers has a range nothing writes into, and `polys_on_layer` starts
    /// answering about the wrong layer.
    #[test]
    fn assigned_layer_ids_are_dense() {
        let layers = assign_layers(&two_transistors());
        let mut all = vec![layers.rail.0, layers.marker.0];
        all.extend(layers.role_layer.iter().map(|l| l.0));
        all.extend(layers.cut_layer.iter().map(|l| l.0));
        all.sort_unstable();
        let expected: Vec<u16> = (0..u16::try_from(layers.count).expect("small")).collect();
        assert_eq!(all, expected);
    }
}
