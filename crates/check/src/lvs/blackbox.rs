//! Black boxes on the layout side (catalog LVS-033, LVS-067): each
//! placement of a cell the deck's `lvs blackbox` names becomes one device of
//! [`DeviceKind::Cell`] on its pins' nets, and the devices drawn inside it
//! leave the comparison.
//!
//! Data in: the layout graph as [`from_layout`](crate::lvs::graph::from_layout)
//! built it, the extraction it was built from, the placements and their bound
//! pins ([`Provenance::black_boxes`], [`Provenance::black_box_pins`]), and
//! the port names of each subcircuit the reference kept whole
//! ([`Netlist::black_box_ports`]). Data out: the graph, its devices inside a
//! box dropped and one device per box appended.
//!
//! [`Provenance::black_boxes`]: gpurify_ingest::Provenance::black_boxes
//! [`Provenance::black_box_pins`]: gpurify_ingest::Provenance::black_box_pins
//! [`Netlist::black_box_ports`]: gpurify_ingest::netlist::Netlist::black_box_ports

use crate::lvs::controls::retain_devices;
use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::topology::TerminalRole;
use crate::Design;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::{BlackBox, StrId, StrTable};

/// Replaces what each black box holds with one device of
/// [`DeviceKind::Cell`] whose model is the cell's name, as `KLayout`'s
/// `blank_circuit` erases a circuit's content and keeps its pins, and
/// Netgen compares a black box by its pins alone:
///
/// - every device of `layout` (a row of `design.devices`) whose marker lies
///   wholly inside a box's extent is dropped, with every net only such
///   devices reached that is no port;
/// - each box becomes a device with one terminal per distinct `(pin name,
///   net)`, its role `Pin(k)` where `k` is the name's position among the
///   ports the reference states for the cell (`ports`), so a pin pairs only
///   with the port of its name, as both tools match a black box's named
///   pins. A name the reference does not state takes a position past them,
///   in name order, and so pairs with nothing; a pin with no label is not
///   seen, and its port is left unpaired.
///
/// The box's own wiring stays in the nets, as it is drawn: two pins it
/// joins are one net.
///
/// # Errors
///
/// The cell of a box whose pins need a position past 255 (more than
/// [`MAX_CELL_PINS`](gpurify_ingest::netlist::MAX_CELL_PINS) ports and
/// names together), which a device's pin role cannot hold.
///
/// # Panics
///
/// When `layout` was not built from `design`, or `pins` names a box past
/// `boxes` or a polygon not in `design.store`.
pub fn add_black_boxes(
    layout: &mut Graph,
    design: Design<'_>,
    (boxes, pins): (&[BlackBox], &[(u32, gpurify_geom::PolyId, StrId)]),
    ports: &[(StrId, Vec<StrId>)],
    strings: &StrTable,
) -> Result<(), StrId> {
    if boxes.is_empty() {
        return Ok(());
    }
    let drawn = layout.device_count();
    let kept: Vec<u32> = (0..narrow(drawn))
        .filter(|&device| {
            let marker = design.devices.marker[device as usize];
            let extent = design.store.poly_bbox(marker);
            !boxes.iter().any(|b| b.extent.contains(extent))
        })
        .chain((0..narrow(boxes.len())).map(|b| narrow(drawn) + b))
        .collect();

    let mut named: Vec<(StrId, u32)> = Vec::new();
    for (at, black_box) in (0..).zip(boxes) {
        named.clear();
        named.extend(
            pins.iter()
                .filter(|&&(of, ..)| of == at)
                .map(|&(_, poly, name)| (name, design.nets.net_of(poly).0)),
        );
        let stated: &[StrId] = ports
            .iter()
            .find(|(cell, _)| *cell == black_box.cell)
            .map_or(&[], |(_, names)| names);
        let mut extra: Vec<&str> = named
            .iter()
            .filter(|(name, _)| !stated.contains(name))
            .map(|&(name, _)| strings.resolve(name))
            .collect();
        extra.sort_unstable();
        extra.dedup();
        let mut terminals: Vec<(u8, u32)> = Vec::with_capacity(named.len());
        for &(name, net) in &named {
            let position = stated
                .iter()
                .position(|&port| port == name)
                .unwrap_or_else(|| {
                    let rank = extra.binary_search(&strings.resolve(name)).unwrap_or(0);
                    stated.len() + rank
                });
            let role = u8::try_from(position).map_err(|_| black_box.cell)?;
            terminals.push((role, net));
        }
        terminals.sort_unstable();
        terminals.dedup();
        layout.device_kind.push(DeviceKind::Cell);
        layout.device_model.push(black_box.cell);
        for &(role, net) in &terminals {
            layout.terminal_net.push(net);
            layout.terminal_role.push(TerminalRole::Pin(role));
        }
        layout
            .device_terminal_start
            .push(narrow(layout.terminal_net.len()));
        layout.device_param_start.push(narrow(layout.param.len()));
    }
    let nets = layout.net_count();
    transpose_into(layout, nets);
    retain_devices(layout, &kept);
    Ok(())
}
