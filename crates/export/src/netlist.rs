//! SPICE netlist export: the extracted circuit, optionally with its parasitics.

use std::fmt::Write as _;

use crate::json::format_f64;
use crate::parasitic::{first_node_of, node_place, spice_card, DELIMITER};
use crate::{narrow, Header, WriteError, INFALLIBLE};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrTable;
use gpurify_pex::ParasiticNetwork;
use gpurify_topology::device::{DeviceId, DeviceMeasure, DeviceParam};
use gpurify_topology::{Extraction, NetId, PortTable, TerminalRole};

/// The subcircuit's name, matching what `engine` hands `gds::write_store`.
/// Never `header.layout_path`: a path in a body is what the [`Header`] keeps out.
const CELL: &str = "TOP";

/// What an anonymous net's fallback name is lengthened by when a label has
/// already taken it — see [`net_name`]. Not a digit, which is what keeps `n7`,
/// `n7_` and `n71` three different names so the fallback stays injective.
const FALLBACK_PAD: char = '_';

/// Where a terminal sits on its family's SPICE card: the inverse of
/// [`TerminalRole`]'s table, because emitting terminals in table order would
/// describe a different transistor.
const fn card_rank(role: TerminalRole) -> u8 {
    match role {
        // `Mname nd ng ns nb`.
        TerminalRole::Drain | TerminalRole::Collector => 0,
        TerminalRole::Gate | TerminalRole::Base => 1,
        TerminalRole::Source | TerminalRole::Emitter => 2,
        TerminalRole::Bulk => 3,
        // Symmetric two-terminal: the position *is* the rank.
        TerminalRole::Pin(position) => position,
    }
}

/// What to include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Devices and their connectivity only.
    Schematic,
    /// Devices plus lumped per-net parasitic R and C.
    WithParasitics,
}

/// Write the extracted circuit as a SPICE subcircuit, appended to `out`.
///
/// Devices go out in ascending `DeviceId` and nets are named through `ports`,
/// or by their `NetId` where they have no name; both are canonical, so the file
/// is a function of the layout alone. `parasitics` is the source and `detail`
/// the decision: a network passed with [`Detail::Schematic`] is not read.
pub fn write_spice(
    extraction: Extraction<'_>,
    parasitics: Option<&ParasiticNetwork>,
    detail: Detail,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    let (nets, devices, ports) = (extraction.nets, extraction.devices, extraction.ports);
    let device_count = devices.len();
    let net_count = nets.net_count();
    debug_assert_eq!(
        devices.terminal_start.len(),
        device_count + 1,
        "the terminal CSR carries one offset per device plus a terminator"
    );
    debug_assert_eq!(
        devices.param_start.len(),
        device_count + 1,
        "the param CSR carries one offset per device plus a terminator"
    );
    debug_assert_eq!(
        devices.terminal_net.len(),
        devices.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );
    // No entry assert that `ports.len() <= net_count`: the pin loop below
    // settles it as a typed error, and a panic here would abort the one path a
    // test of that refusal walks.

    let before = out.len();

    let spliced = parasitics.filter(|_| detail == Detail::WithParasitics);

    writeln!(out, "* {} SPICE netlist", header.tool_version).expect(INFALLIBLE);
    writeln!(out, "* deck: {}", header.deck_path).expect(INFALLIBLE);
    writeln!(out, "* layout: {}", header.layout_path).expect(INFALLIBLE);
    if let Some(stamp) = &header.timestamp {
        writeln!(out, "* written: {stamp}").expect(INFALLIBLE);
    }
    // This signature holds no `Grid`, so it can name no physical unit; saying so
    // keeps a simulator from reading database units as metres.
    writeln!(out, "* lengths below are in database units").expect(INFALLIBLE);

    // ponytail: `O(nets · log ports)`, because `PortTable` publishes none of
    // its four columns and `name_of` — a binary search — is the only way to read
    // one. The port list is the named nets in ascending `NetId`, and named nets
    // are a cell's pins, hundreds against a net count in the millions, so the
    // scan is the wrong way round. Only the `log ports` factor is debt: a merge
    // of the port column against `0 .. net_count` is one linear pass and needs
    // no search at all. The `O(nets)` factor stays either way, because this loop
    // also has to emit nothing for every unnamed net.
    out.push_str(".subckt ");
    out.push_str(CELL);
    let mut pins = 0usize;
    for net in 0..net_count {
        let net = NetId(narrow(net));
        let named = ports.name_of(net).is_some();
        pins += usize::from(named);
        if named {
            out.push(' ');
            // Through the same naming the device cards use, or a pin would be
            // declared on a node nothing inside the subcircuit references —
            // `VDD` here against `VDD:0` on every device — leaving the port
            // floating in a file that still simulates.
            put_terminal_node(net, spliced, ports, strings, out)?;
        }
    }
    out.push('\n');

    debug_assert!(
        pins <= ports.len(),
        "{} nets answered to a name out of {} bindings, so one net is bound twice",
        pins,
        ports.len()
    );
    // Fail closed. A binding whose `NetId` is not in `0..net_count` is never
    // reached by the scan above, so its pin is absent from the `.subckt` line
    // while every device card still names the node — a port demoted to an
    // internal node, in a file that answers a different circuit.
    if pins != ports.len() {
        return Err(WriteError::Unrepresentable(
            "a port bound to a net outside the extraction",
        ));
    }

    // Terminals reordered onto their card positions, hoisted and reused.
    let mut card: Vec<(u8, NetId)> = Vec::new();

    for device in 0..device_count {
        let id = DeviceId(narrow(device));
        let (terminal_net, terminal_role) = devices.terminals_of(id);

        let letter = match devices.kind[device] {
            DeviceKind::Mos => 'M',
            DeviceKind::Bjt => 'Q',
            DeviceKind::Resistor => 'R',
            DeviceKind::Capacitor => 'C',
            DeviceKind::Diode => 'D',
        };
        // Parasitic elements below carry a `p` in the same slot, so an
        // extracted `R0` and a parasitic `Rp0` cannot collide.
        write!(out, "{letter}{device}").expect(INFALLIBLE);

        card.clear();
        card.extend(
            terminal_role
                .iter()
                .zip(terminal_net)
                .map(|(&role, &net)| (card_rank(role), net)),
        );
        // Stable, so two terminals of one rank stay in the order the recogniser
        // stated them and the file stays a function of the tables alone.
        card.sort_by_key(|&(rank, _)| rank);
        debug_assert_eq!(
            card.len(),
            terminal_net.len(),
            "reordering a device's terminals onto its card dropped one"
        );
        for &(_, net) in &card {
            out.push(' ');
            put_terminal_node(net, spliced, ports, strings, out)?;
        }

        out.push(' ');
        out.push_str(strings.resolve(devices.model[device]));

        for &(param, measure) in devices.params_of(id) {
            let key = match param {
                DeviceParam::Width => "w",
                DeviceParam::Length => "l",
                DeviceParam::Area => "area",
                DeviceParam::Perimeter => "perim",
                DeviceParam::Fingers => "nf",
            };
            // Integers, exactly as measured: these are `Dbu` and `DbuArea`, and
            // `format_f64` would round a coordinate into a physical quantity it
            // has no `Grid` to become.
            match measure {
                DeviceMeasure::Length(value) => write!(out, " {key}={}", value.raw()),
                DeviceMeasure::Area(value) => write!(out, " {key}={}", value.raw()),
                DeviceMeasure::Count(value) => write!(out, " {key}={value}"),
            }
            .expect(INFALLIBLE);
        }
        out.push('\n');
    }

    if let Some(network) = spliced {
        let elements = network.element_count();

        for row in 0..elements {
            // Through the same decision `write_dspf` cards an element with, so
            // the two files agree about both the letter and the scale factor.
            let (letter, _, magnitude, suffix) = spice_card(network.value[row]);
            write!(out, "{letter}p{row} ").expect(INFALLIBLE);
            put_node(network, network.from[row], ports, strings, out)?;
            out.push(' ');
            match network.to[row] {
                Some(node) => put_node(network, node, ports, strings, out)?,
                // SPICE's ground: a `None` far end is a capacitance to it, not
                // a node the network forgot to name.
                None => out.push('0'),
            }
            out.push(' ');
            format_f64(magnitude, out);
            out.push_str(suffix);
            out.push('\n');
        }

        debug_assert_eq!(
            network.element_count(),
            elements,
            "a writer transcribes; it does not change the network it was given"
        );
    }

    writeln!(out, ".ends {CELL}").expect(INFALLIBLE);

    debug_assert!(
        out.len() > before,
        "a netlist with a header and a subcircuit cannot be empty"
    );
    Ok(())
}

/// Append the SPICE node a device terminal sits on.
///
/// Without parasitics this is the net's name. With them, the nodes of a net are
/// named `net:index` and the bare net name is not one of them, so terminals
/// attach at their net's *first* node, or every terminal would sit on a node no
/// parasitic element touches. A stated lumping: `ParasiticNetwork` carries no
/// terminal-to-node column.
fn put_terminal_node(
    net: NetId,
    spliced: Option<&ParasiticNetwork>,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    // A net with no parasitics has no node to name; its terminals still meet
    // each other on the plain net name.
    let node = spliced.and_then(|network| Some((network, first_node_of(network, net)?)));
    if let Some((network, node)) = node {
        put_node(network, node, ports, strings, out)
    } else {
        net_name(net, ports, strings, out);
        Ok(())
    }
}

/// Append the name of one parasitic node, under SPICE's naming policy.
///
/// Same `net:index` shape as [`crate::parasitic::node_name`], but the net half
/// goes through [`net_name`], which numbers an anonymous net instead of
/// refusing it. SPEF and DSPF are right to demand a name — their whole purpose
/// is to annotate a netlist someone else wrote, so a net they cannot name is a
/// net they cannot attach to. SPICE carries the netlist *and* the parasitics in
/// one file, so it can name a net itself, and an internal node the generator
/// never declared (a well tie, a routing-only island) is ordinary rather than
/// an error. Sharing `node_name` here made `write_spice` inherit SPEF's
/// strictness and fail on exactly those nets.
fn put_node(
    network: &ParasiticNetwork,
    node: gpurify_pex::network::NodeId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    let before = out.len();
    let (net, index) = node_place(network, node)?;
    net_name(net, ports, strings, out);
    write!(out, "{DELIMITER}{index}").expect(INFALLIBLE);

    debug_assert!(out.len() > before, "a node was named the empty string");
    Ok(())
}

/// The name of one net in the emitted netlist, shared with the parasitic writers.
pub fn net_name(
    net: gpurify_topology::NetId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) {
    // `NetId::NONE` is an absence, not a net. There is no error channel here, so
    // this is the loudest the signature allows.
    debug_assert_ne!(
        net,
        gpurify_topology::NetId::NONE,
        "asked for the name of no net at all"
    );

    let before = out.len();
    // SPICE names an anonymous net by number, unlike SPEF, where an unnamed net
    // is an error rather than a fallback.
    if let Some(name) = ports.name_of(net) {
        out.push_str(strings.resolve(name));
    } else {
        write!(out, "n{}", net.0).expect(INFALLIBLE);
        // A layout whose label is literally `n7` would otherwise be handed the
        // fallback name of net 7 as well, shorting two nets in a file that is
        // still valid SPICE. The label space and the fallback space meet here
        // and nowhere else, so lengthen the fallback until no port carries it.
        while strings
            .get(&out[before..])
            .is_some_and(|taken| ports.net_of(taken).is_some())
        {
            out.push(FALLBACK_PAD);
        }
    }

    debug_assert!(
        out.len() > before,
        "net {} came back with an empty name, which no netlist can carry",
        net.0
    );
    debug_assert!(
        strings
            .get(&out[before..])
            .and_then(|name| ports.net_of(name))
            .is_none_or(|owner| owner == net),
        "net {} was named {:?}, which is net {:?}'s label",
        net.0,
        &out[before..],
        strings.get(&out[before..]).and_then(|n| ports.net_of(n))
    );
}
