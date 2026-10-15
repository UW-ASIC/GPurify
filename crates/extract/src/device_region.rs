//! Device-region (MEOL) capacitance (catalog PEX-011): the capacitance
//! inside a transistor's footprint that its SPICE model leaves to
//! extraction, from the gate to the source and drain contacts and to the
//! diffusion beside it.
//!
//! Data in: the recognised devices and the deck's `pex_device` lines, each
//! a MOS model's coefficients per µm of gate width. Data out: coupling
//! capacitances appended to the network, from the gate net's first node to
//! the source net's and to the drain net's.
//!
//! Each side of a gate (source, drain) gets `(gate_contact + gate_diffusion)
//! · W`: a finger has one source side and one drain side of its width, so
//! however the width is split into fingers each net totals `W` of sides.
//! `StarRC` and Quantus extract these terms from the foundry's device
//! cross-section (Synopsys `StarRC` and Cadence Quantus datasheets, public
//! material only, which name gate-to-contact and gate-to-diffusion
//! capacitance); no open PDK publishes the cross-section, so the deck
//! states the coefficients. A side on the gate's own net adds nothing.
//!
//! Not modelled: trench-contact resistance and the gate resistance a gate
//! contact's position sets: the network has no node inside a device to
//! put them between.

use crate::network::{Parasitic, ParasiticNetwork};
use gpurify_check::topology::device::{DeviceMeasure, DeviceParam, TerminalRole};
use gpurify_check::topology::{DeviceTable, NetId};
use gpurify_geom::{Grid, Qty, StrTable};
use gpurify_ingest::deck::{DeviceKind, DeviceParasitics};

/// Appends every MOS device's region capacitances its model's `pex_device`
/// line states, then restores canonical order. A device whose width is not
/// measured, or a side whose net has no node, adds nothing.
pub fn add_into(
    network: &mut ParasiticNetwork,
    devices: &DeviceTable,
    models: &[DeviceParasitics],
    strings: &StrTable,
    grid: Grid,
) {
    if models.is_empty() {
        return;
    }
    let first_node = |net: NetId| network.first_node(net);
    let mut added = Vec::new();
    for d in 0..devices.kind.len() {
        if devices.kind[d] != DeviceKind::Mos {
            continue;
        }
        let model = strings.resolve(devices.model[d]);
        let Some(coefficients) = models.iter().find(|m| m.model == model) else {
            continue;
        };
        let params =
            &devices.param[devices.param_start[d] as usize..devices.param_start[d + 1] as usize];
        let Some(width) = params
            .iter()
            .find_map(|&(param, measure)| match (param, measure) {
                (DeviceParam::Width, DeviceMeasure::Length(w)) => Some(w),
                _ => None,
            })
        else {
            continue;
        };
        #[expect(clippy::cast_precision_loss, reason = "a length in database units")]
        let width_um = width.raw() as f64 / grid.dbu_per_um() as f64;
        let femtofarads = (coefficients.gate_contact_af_um + coefficients.gate_diffusion_af_um)
            * width_um
            / 1000.0;
        let terminals = devices.terminal_start[d] as usize..devices.terminal_start[d + 1] as usize;
        let net_of = |role: TerminalRole| {
            terminals
                .clone()
                .find(|&t| devices.terminal_role[t] == role)
                .map(|t| devices.terminal_net[t])
        };
        let Some(gate) = net_of(TerminalRole::Gate).and_then(first_node) else {
            continue;
        };
        for side in [TerminalRole::Source, TerminalRole::Drain] {
            let Some(net) = net_of(side) else { continue };
            if Some(net) == net_of(TerminalRole::Gate) {
                continue;
            }
            if let Some(node) = first_node(net) {
                added.push((gate, node, femtofarads));
            }
        }
    }
    for (gate, side, femtofarads) in added {
        if femtofarads > 0.0 {
            network.push(
                gate,
                Some(side),
                Parasitic::CouplingCap(Qty::new(femtofarads)),
            );
        }
    }
    network.sort_canonical();
}
