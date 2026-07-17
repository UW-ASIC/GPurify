//! SPICE netlist export from extracted layout + PEX parasitics.
//!
//! Combines LVS extraction (devices + connectivity) with PEX (per-net R/C) into a
//! simulatable SPICE subcircuit. Two modes:
//!   - **Schematic-only**: just the extracted devices (MOS, R, C, diodes).
//!   - **With parasitics**: devices + lumped per-net parasitic R and C elements.

use super::types::*;
use crate::pex::NetParasitics;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

const AF_TO_FARAD: f64 = 1e-18;

/// Which nets are ports (externally visible pins). Maps net_id → port name.
pub type PortMap = HashMap<u32, String>;

pub struct SpiceOpts {
    pub cell_name: String,
    pub ports: PortMap,
    /// When true, include parasitic R/C from PEX. When false, schematic-only.
    pub include_parasitics: bool,
}

/// Generate a SPICE subcircuit string from extracted netlist + optional parasitics.
pub fn to_spice(
    ext: &ExtractedNetlist,
    parasitics: Option<&HashMap<u32, NetParasitics>>,
    opts: &SpiceOpts,
) -> String {
    let mut out = String::new();

    let external_net_name = |id: u32| -> String {
        if let Some(name) = opts.ports.get(&id) {
            name.clone()
        } else {
            format!("n{}", id)
        }
    };

    // A scalar per-net resistance has no physical endpoints. It can only be represented
    // without inventing topology when the net has an external port: put the resistance
    // between that port and one internal lumped node, and remap all extracted terminals to
    // the internal node. Internal-only nets need a distributed terminal map, so their scalar
    // resistance is explicitly omitted below instead of being connected to a dangling node.
    let mut referenced_nets = HashSet::new();
    for d in &ext.devices {
        referenced_nets.extend([d.gate, d.source, d.drain, d.body]);
    }
    for d in &ext.two_terminal {
        referenced_nets.extend([d.terminal_a, d.terminal_b]);
    }
    let split_port_nets: HashSet<u32> = if opts.include_parasitics {
        parasitics
            .into_iter()
            .flat_map(|pex| pex.iter())
            .filter_map(|(&net_id, np)| {
                let has_internal_load = referenced_nets.contains(&net_id) || np.cap_af > 0.0;
                (net_id != u32::MAX
                    && np.r_ohm > 0.0
                    && opts.ports.contains_key(&net_id)
                    && has_internal_load)
                    .then_some(net_id)
            })
            .collect()
    } else {
        HashSet::new()
    };
    let circuit_net_name = |id: u32| -> String {
        let name = external_net_name(id);
        if split_port_nets.contains(&id) {
            format!("{}__pex", name)
        } else {
            name
        }
    };

    // Header
    let port_list: String = {
        let mut ports: Vec<(&u32, &String)> = opts.ports.iter().collect();
        ports.sort_by_key(|(id, _)| *id);
        ports
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let _ = writeln!(out, ".subckt {} {}", opts.cell_name, port_list);

    // MOS devices
    let mut mi = 0u32;
    for d in &ext.devices {
        let prefix = match d.kind {
            DeviceKind::Nmos => "Mn",
            DeviceKind::Pmos => "Mp",
            DeviceKind::Npn | DeviceKind::Pnp => continue,
        };
        let model = match (&d.kind, &d.flavor) {
            (DeviceKind::Nmos, DeviceFlavor::Standard) => "nmos",
            (DeviceKind::Nmos, DeviceFlavor::Lvt) => "nmos_lvt",
            (DeviceKind::Nmos, DeviceFlavor::Hvt) => "nmos_hvt",
            (DeviceKind::Pmos, DeviceFlavor::Standard) => "pmos",
            (DeviceKind::Pmos, DeviceFlavor::Lvt) => "pmos_lvt",
            (DeviceKind::Pmos, DeviceFlavor::Hvt) => "pmos_hvt",
            (DeviceKind::Npn, _) | (DeviceKind::Pnp, _) => continue,
        };
        let _ = writeln!(
            out,
            "{}{} {} {} {} {} {} w={}n l={}n",
            prefix,
            mi,
            circuit_net_name(d.drain),
            circuit_net_name(d.gate),
            circuit_net_name(d.source),
            circuit_net_name(d.body),
            model,
            d.w,
            d.l,
        );
        mi += 1;
    }

    // Two-terminal devices
    let mut ri = 0u32;
    let mut ci = 0u32;
    let mut di = 0u32;
    for d in &ext.two_terminal {
        match d.kind {
            TwoTerminalKind::Resistor => {
                let _ = writeln!(
                    out,
                    "R{} {} {} {:.6}",
                    ri,
                    circuit_net_name(d.terminal_a),
                    circuit_net_name(d.terminal_b),
                    d.value
                );
                ri += 1;
            }
            TwoTerminalKind::Capacitor => {
                // Extracted capacitor values are stored in attofarads. A suffix-free SPICE
                // capacitance is SI farads; using an `f` suffix here would mean femtofarads
                // and inflate the value by 1000x.
                let _ = writeln!(
                    out,
                    "C{} {} {} {:.12e}",
                    ci,
                    circuit_net_name(d.terminal_a),
                    circuit_net_name(d.terminal_b),
                    d.value * AF_TO_FARAD
                );
                ci += 1;
            }
            TwoTerminalKind::Diode => {
                let _ = writeln!(
                    out,
                    "D{} {} {} diode",
                    di,
                    circuit_net_name(d.terminal_a),
                    circuit_net_name(d.terminal_b)
                );
                di += 1;
            }
        }
    }

    // Parasitic R/C (lumped per net)
    if opts.include_parasitics {
        if let Some(pex) = parasitics {
            let mut pex_sorted: Vec<(&u32, &NetParasitics)> = pex.iter().collect();
            pex_sorted.sort_by_key(|(id, _)| *id);
            let mut pri = 0u32;
            let mut pci = 0u32;
            for (&net_id, np) in pex_sorted {
                if net_id == u32::MAX {
                    continue;
                }
                let external = external_net_name(net_id);
                let internal = circuit_net_name(net_id);
                if np.r_ohm > 0.0 {
                    if split_port_nets.contains(&net_id) {
                        let _ =
                            writeln!(out, "Rpar{} {} {} {:.6}", pri, external, internal, np.r_ohm);
                        pri += 1;
                    } else {
                        let reason = if opts.ports.contains_key(&net_id) {
                            "port has no extracted load"
                        } else {
                            "internal net has no explicit resistance endpoints"
                        };
                        let _ =
                            writeln!(out,
                            "* PEX-WARN omitted {:.6} ohm on {}: {}; distributed topology required",
                            np.r_ohm, external, reason);
                    }
                }
                if np.cap_af > 0.0 {
                    // Ground capacitance belongs on the internal side of an inserted port R.
                    // `cap_af` is attofarads; emit suffix-free SI farads.
                    let _ = writeln!(
                        out,
                        "Cpar{} {} 0 {:.12e}",
                        pci,
                        internal,
                        np.cap_af * AF_TO_FARAD
                    );
                    pci += 1;
                }
            }
        }
    }

    let _ = writeln!(out, ".ends {}", opts.cell_name);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spice_inverter() {
        let ext = ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Pmos,
                    gate: 0,
                    source: 1,
                    drain: 2,
                    body: 1,
                    flavor: DeviceFlavor::Standard,
                    w: 1000,
                    l: 180,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 0,
                    source: 3,
                    drain: 2,
                    body: 3,
                    flavor: DeviceFlavor::Standard,
                    w: 500,
                    l: 180,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: vec![TwoTerminalDevice {
                kind: TwoTerminalKind::Capacitor,
                name: "mim".into(),
                terminal_a: 2,
                terminal_b: 1,
                value: 2500.0, // aF = 2.5e-15 F
            }],
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let mut ports = PortMap::new();
        ports.insert(0, "A".into());
        ports.insert(1, "VDD".into());
        ports.insert(2, "Y".into());
        ports.insert(3, "VSS".into());

        let spice = to_spice(
            &ext,
            None,
            &SpiceOpts {
                cell_name: "inv".into(),
                ports: ports.clone(),
                include_parasitics: false,
            },
        );
        assert!(spice.contains(".subckt inv"));
        assert!(spice.contains("Mp0 Y A VDD VDD pmos w=1000n l=180n"));
        assert!(spice.contains("Mn1 Y A VSS VSS nmos w=500n l=180n"));
        assert!(spice.contains("C0 Y VDD 2.500000000000e-15"));
        assert!(!spice.contains("2500.000000f"));
        assert!(spice.contains(".ends inv"));

        // with parasitics
        let mut pex = HashMap::new();
        pex.insert(
            2,
            NetParasitics {
                r_ohm: 0.5,
                cap_af: 100.0,
            },
        );
        let spice = to_spice(
            &ext,
            Some(&pex),
            &SpiceOpts {
                cell_name: "inv".into(),
                ports,
                include_parasitics: true,
            },
        );
        assert!(spice.contains("Mp0 Y__pex A VDD VDD pmos"));
        assert!(spice.contains("Mn1 Y__pex A VSS VSS nmos"));
        assert!(spice.contains("Rpar0 Y Y__pex 0.5"));
        assert!(spice.contains("Cpar0 Y__pex 0 1.000000000000e-16"));
        assert!(!spice.contains("100.000000f"));
        assert!(!spice.contains("Y_par"));
    }

    #[test]
    fn internal_net_resistance_is_flagged_and_not_emitted_to_a_dangling_node() {
        let ext = ExtractedNetlist {
            devices: vec![Device {
                kind: DeviceKind::Nmos,
                gate: 0,
                source: 1,
                drain: 2,
                body: 1,
                flavor: DeviceFlavor::Standard,
                w: 500,
                l: 180,
                device_class: None,
                ..Default::default()
            }],
            net_count: 3,
            used_nets: 3,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let mut ports = PortMap::new();
        ports.insert(0, "A".into());
        ports.insert(1, "VSS".into());
        ports.insert(9, "UNUSED".into());
        let mut pex = HashMap::new();
        pex.insert(
            2,
            NetParasitics {
                r_ohm: 1.25,
                cap_af: 20.0,
            },
        );
        pex.insert(
            9,
            NetParasitics {
                r_ohm: 2.5,
                cap_af: 0.0,
            },
        );

        let spice = to_spice(
            &ext,
            Some(&pex),
            &SpiceOpts {
                cell_name: "internal_r".into(),
                ports,
                include_parasitics: true,
            },
        );
        assert!(spice.contains("PEX-WARN omitted 1.250000 ohm on n2"));
        assert!(
            spice.contains("PEX-WARN omitted 2.500000 ohm on UNUSED: port has no extracted load")
        );
        assert!(!spice.contains("Rpar"));
        assert!(!spice.contains("n2_par"));
        assert!(spice.contains("Cpar0 n2 0 2.000000000000e-17"));
    }
}
