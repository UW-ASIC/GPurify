//! SPEF and DSPF: the parasitic network, for a timing tool or a simulator.

use std::fmt::Write as _;
use std::ops::Range;

use crate::json::format_f64;
use crate::{narrow, Header, WriteError, INFALLIBLE};
use gpurify_ingest::StrTable;
use gpurify_extract::network::{NodeId, Parasitic};
use gpurify_extract::ParasiticNetwork;
use gpurify_topology::{NetId, PortTable};

/// Between a net's name and the node's index within it, declared to the reader
/// of both files as `*DELIMITER :`.
///
/// Shared with the SPICE writer, which splits a node name the same way but
/// resolves the net half under its own naming policy — see
/// [`crate::netlist::put_node`].
pub(crate) const DELIMITER: char = ':';

/// SPICE node zero, the far end of a ground capacitance in DSPF.
const GROUND: &str = "0";

/// Is a column non-decreasing?
fn is_non_decreasing<T: Copy + Ord>(column: &[T]) -> bool {
    let n = column.len();
    let mut ok = true;
    for i in 1..n {
        ok &= column[i - 1] <= column[i];
    }
    ok
}

/// Does every element that needs a far node have one?
///
/// A capacitance to ground may omit it: that plate is the substrate, not a node
/// of this network. A resistance or an inductance joins two nodes by definition,
/// so `None` there is a broken row.
fn every_far_node_present(to: &[Option<NodeId>], value: &[Parasitic]) -> bool {
    // `zip` below folds only the shorter column, so the lengths are asserted
    // rather than assumed.
    debug_assert_eq!(to.len(), value.len(), "SoA columns must agree");

    let mut ok = true;
    for (far, kind) in to.iter().zip(value) {
        ok &= far.is_some() | as_farads(*kind).is_some();
    }
    ok
}

/// Refuse a network that is not in the order both writers below read it in.
///
/// Two invariants, stated by `ParasiticNetwork` and enforced by neither its
/// `push` nor a `debug_assert` here: nodes are grouped into one contiguous
/// ascending range per net, and elements are sorted by `from`. Checked in every
/// profile, because an out-of-order network files elements under the wrong net
/// and writes a plausible description of the wrong circuit.
fn check_canonical(network: &ParasiticNetwork) -> Result<(), WriteError> {
    // Checked here so every `narrow` below is a typed error the caller sees
    // rather than a panic reached halfway through a written file.
    if u32::try_from(network.node_count()).is_err() {
        return Err(WriteError::Unrepresentable(
            "a parasitic network with more nodes than a NodeId can address",
        ));
    }
    if !is_non_decreasing(&network.node_net) {
        return Err(WriteError::Unrepresentable(
            "a parasitic network whose nodes are not grouped by net",
        ));
    }
    if !is_non_decreasing(&network.from) {
        return Err(WriteError::Unrepresentable(
            "a parasitic network whose elements are not in canonical order",
        ));
    }
    // `spef_section` refuses a `*RES` or `*INDUC` row with no far node, but DSPF
    // cards every absent far end to node zero, so the same broken resistor would
    // be a typed error in one file and a plausible resistor to ground in the
    // other. Refusing it here makes both writers accept the same networks.
    if !every_far_node_present(&network.to, &network.value) {
        return Err(WriteError::Unrepresentable(
            "a resistance or inductance with no far node",
        ));
    }
    Ok(())
}

/// The first row of a net's node run, or where that run would begin: the single
/// place either writer turns a [`NetId`] into a row, so every sub-node index is
/// measured from the same number.
fn net_start(node_net: &[NetId], net: NetId) -> usize {
    let first = node_net.partition_point(|&other| other < net);
    // The grouping invariant itself: if the run this landed on is the net's,
    // nothing before it may also be the net's.
    debug_assert!(
        first == 0 || node_net[first - 1] < net,
        "the node column is not grouped by net"
    );
    first
}

/// The first node of a net, or `None` where the network holds none for it.
pub(crate) fn first_node_of(network: &ParasiticNetwork, net: NetId) -> Option<NodeId> {
    let nets = &network.node_net[..];
    let first = net_start(nets, net);
    (nets.get(first) == Some(&net)).then(|| NodeId(narrow(first)))
}

/// The net a node sits on, and the node's index within that net's run — a
/// position in a canonically ordered column, so a sub-node name is stable.
pub(crate) fn node_place(
    network: &ParasiticNetwork,
    node: NodeId,
) -> Result<(NetId, usize), WriteError> {
    let nets = &network.node_net[..];
    let row = node.0 as usize;
    // Fail closed. An element pointing past the node columns is a broken
    // network, not a node to invent a name for.
    let net = *nets.get(row).ok_or(WriteError::Unrepresentable(
        "a parasitic element on a node outside the network",
    ))?;
    let first = net_start(nets, net);
    debug_assert!(first <= row, "the node column is not grouped by net");
    Ok((net, row - first))
}

/// The half-open node range of the net that starts at `start`, which must be
/// the first row of a run.
fn net_run(node_net: &[NetId], start: usize) -> (NetId, usize) {
    debug_assert!(start < node_net.len(), "a run starts at a node that exists");
    let net = node_net[start];
    (
        net,
        start + node_net[start..].partition_point(|&other| other == net),
    )
}

/// Append a net's name, or refuse the net for having none.
fn put_net_name(
    net: NetId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    let name = ports.name_of(net).ok_or(WriteError::UnnamedNet(net.0))?;
    out.push_str(strings.resolve(name));
    Ok(())
}

/// Femtofarads on a capacitive element, `None` on any other kind — an `Option`
/// and not zero, because a SPEF section wants "not mine".
const fn as_farads(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => Some(q.raw()),
        Parasitic::Resistance(_) | Parasitic::Inductance(_) => None,
    }
}

/// Ohms on a resistive element, `None` on any other kind.
const fn as_ohms(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::Resistance(q) => Some(q.raw()),
        Parasitic::GroundCap(_) | Parasitic::CouplingCap(_) | Parasitic::Inductance(_) => None,
    }
}

/// Picohenries on an inductive element, `None` on any other kind.
const fn as_henries(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::Inductance(q) => Some(q.raw()),
        Parasitic::Resistance(_) | Parasitic::GroundCap(_) | Parasitic::CouplingCap(_) => None,
    }
}

/// How one parasitic appears as a SPICE card: its prefix letter, which counter
/// numbers it, its magnitude, and the scale factor that magnitude is in. Shared
/// with [`crate::netlist`] so both files describe the same circuit — the suffix
/// is load-bearing, since SPICE reads a bare number as SI and a femtofarad that
/// lost its `f` is off by 10^15.
pub(crate) const fn spice_card(value: Parasitic) -> (char, usize, f64, &'static str) {
    match value {
        Parasitic::Resistance(q) => ('R', 0, q.raw(), ""),
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => ('C', 1, q.raw(), "f"),
        Parasitic::Inductance(q) => ('L', 2, q.raw(), "p"),
    }
}

/// One `*CAP` / `*RES` / `*INDUC` section of one `*D_NET` block.
///
/// `rows` is the element range already narrowed to this net; `select` picks the
/// rows belonging to this section and their magnitude. `far_optional` is the
/// ground-capacitance carve-out: a `*CAP` row may name one node, a `*RES` or
/// `*INDUC` row may not, and breaking that is a typed error, not a short row.
fn spef_section(
    network: &ParasiticNetwork,
    rows: Range<usize>,
    keyword: &str,
    select: fn(Parasitic) -> Option<f64>,
    far_optional: bool,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    debug_assert!(
        rows.end <= network.element_count(),
        "a section was handed rows past the element columns"
    );
    writeln!(out, "{keyword}").expect(INFALLIBLE);

    let mut index = 1usize;
    for row in rows {
        let Some(magnitude) = select(network.value[row]) else {
            continue;
        };

        write!(out, "{index} ").expect(INFALLIBLE);
        node_name(network, network.from[row], ports, strings, out)?;
        match network.to[row] {
            Some(far) => {
                out.push(' ');
                node_name(network, far, ports, strings, out)?;
            }
            None if far_optional => {}
            None => {
                return Err(WriteError::Unrepresentable(
                    "a resistance or inductance with no far node",
                ))
            }
        }
        out.push(' ');
        format_f64(magnitude, out);
        out.push('\n');
        index += 1;
    }

    Ok(())
}

/// Write the network as SPEF. Every net it references must have a name: an
/// anonymous net is [`WriteError::UnnamedNet`], not a generated placeholder.
pub fn write_spef(
    network: &ParasiticNetwork,
    ports: &PortTable,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    let nodes = network.node_count();
    let elements = network.element_count();
    check_canonical(network)?;

    out.push_str("*SPEF \"IEEE 1481-1998\"\n");
    writeln!(out, "*DESIGN \"{}\"", header.layout_path).expect(INFALLIBLE);
    // The clock is never consulted: a timestamp appears here or nowhere.
    if let Some(stamp) = &header.timestamp {
        writeln!(out, "*DATE \"{stamp}\"").expect(INFALLIBLE);
    }
    out.push_str("*VENDOR \"gpurify\"\n*PROGRAM \"gpurify\"\n");
    writeln!(out, "*VERSION \"{}\"", header.tool_version).expect(INFALLIBLE);
    writeln!(out, "// deck {}", header.deck_path).expect(INFALLIBLE);
    out.push_str(
        "*DESIGN_FLOW \"EXTRACTED\"\n\
         *DIVIDER /\n\
         *DELIMITER :\n\
         *BUS_DELIMITER [ ]\n\
         *T_UNIT 1 NS\n\
         *C_UNIT 1 FF\n\
         *R_UNIT 1 OHM\n\
         *L_UNIT 1 PH\n\n",
    );

    // One `*D_NET` block per net. Two monotonic cursors, sound only because
    // `check_canonical` established the grouping and sort above.
    let mut node = 0usize;
    let mut element = 0usize;
    while node < nodes {
        let (net, node_end) = net_run(&network.node_net, node);
        debug_assert!(node_end > node, "a net run is at least one node long");

        out.push_str("*D_NET ");
        put_net_name(net, ports, strings, out)?;
        out.push(' ');
        format_f64(network.net_capacitance(net).raw(), out);
        out.push('\n');

        // Per-terminal direction is not in this writer's inputs, so one
        // bidirectional connection is the whole of what the tables support.
        out.push_str("*CONN\n*P ");
        put_net_name(net, ports, strings, out)?;
        out.push_str(" B\n");

        // This net's elements are the next run of the element columns: `from`
        // ascends and the net owns a contiguous node range.
        let element_end =
            element + network.from[element..].partition_point(|from| (from.0 as usize) < node_end);
        debug_assert!(
            element_end >= element && element_end <= elements,
            "an element run must lie inside the element columns"
        );

        spef_section(
            network,
            element..element_end,
            "*CAP",
            as_farads,
            true,
            ports,
            strings,
            out,
        )?;
        spef_section(
            network,
            element..element_end,
            "*RES",
            as_ohms,
            false,
            ports,
            strings,
            out,
        )?;
        spef_section(
            network,
            element..element_end,
            "*INDUC",
            as_henries,
            false,
            ports,
            strings,
            out,
        )?;
        out.push_str("*END\n\n");

        node = node_end;
        element = element_end;
    }
    debug_assert_eq!(
        node, nodes,
        "the net walk stepped past the node column instead of landing on its end"
    );

    // Fail closed. A row no net claimed points outside the node columns, and a
    // SPEF silently missing a resistor is a timing report confidently fast.
    if element != elements {
        return Err(WriteError::Unrepresentable(
            "a parasitic element on a node outside the network",
        ));
    }
    debug_assert_eq!(network.node_count(), nodes, "a writer mutates nothing");
    debug_assert_eq!(
        network.element_count(),
        elements,
        "a writer mutates nothing"
    );
    Ok(())
}

/// Write the network as DSPF, a flat SPICE-like form. Sub-node names come from
/// the node's index within its net, not from allocation order.
pub fn write_dspf(
    network: &ParasiticNetwork,
    ports: &PortTable,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    let nodes = network.node_count();
    let elements = network.element_count();
    check_canonical(network)?;

    out.push_str("*|DSPF \"1.4\"\n");
    writeln!(out, "*|DESIGN \"{}\"", header.layout_path).expect(INFALLIBLE);
    if let Some(stamp) = &header.timestamp {
        writeln!(out, "*|DATE \"{stamp}\"").expect(INFALLIBLE);
    }
    out.push_str("*|VENDOR \"gpurify\"\n*|PROGRAM \"gpurify\"\n");
    writeln!(out, "*|VERSION \"{}\"", header.tool_version).expect(INFALLIBLE);
    writeln!(out, "* deck {}", header.deck_path).expect(INFALLIBLE);
    out.push_str("*|DIVIDER /\n*|DELIMITER :\n*|GROUND_NET 0\n\n");

    // Per-net declarations first: the net, its total capacitance, and one
    // sub-node record per node, in the order the node column already stands in.
    let mut node = 0usize;
    while node < nodes {
        let (net, node_end) = net_run(&network.node_net, node);

        out.push_str("*|NET ");
        put_net_name(net, ports, strings, out)?;
        out.push(' ');
        format_f64(network.net_capacitance(net).raw(), out);
        out.push_str("f\n");

        // The sub-node record carries the node's layer where DSPF wants its
        // position: `ParasiticNetwork` has `node_layer` and no coordinate
        // column.
        for row in node..node_end {
            out.push_str("*|S (");
            node_name(network, NodeId(narrow(row)), ports, strings, out)?;
            writeln!(out, " L{})", network.node_layer[row].0).expect(INFALLIBLE);
        }
        out.push('\n');

        node = node_end;
    }
    debug_assert_eq!(
        node, nodes,
        "the net walk stepped past the node column instead of landing on its end"
    );

    // Then the elements, flat, one SPICE card each, in canonical element order.
    // Numbered per prefix, so `R1` and `C1` are two different cards.
    let mut next = [1usize; 3];
    for row in 0..elements {
        let (prefix, slot, magnitude, suffix) = spice_card(network.value[row]);

        write!(out, "{prefix}{} ", next[slot]).expect(INFALLIBLE);
        node_name(network, network.from[row], ports, strings, out)?;
        out.push(' ');
        // The far end of a ground capacitance is node zero. That only a
        // capacitance reaches this arm is `check_canonical`'s
        // `every_far_node_present`; without it a resistance with no far node
        // would become a plausible resistor to ground.
        if let Some(far) = network.to[row] {
            node_name(network, far, ports, strings, out)?;
        } else {
            debug_assert!(
                as_farads(network.value[row]).is_some(),
                "check_canonical let a non-capacitive element reach ground"
            );
            out.push_str(GROUND);
        }
        out.push(' ');
        format_f64(magnitude, out);
        writeln!(out, "{suffix}").expect(INFALLIBLE);
        next[slot] += 1;
    }

    debug_assert_eq!(
        next[0] + next[1] + next[2] - 3,
        elements,
        "every element is written exactly once"
    );
    debug_assert_eq!(network.node_count(), nodes, "a writer mutates nothing");
    Ok(())
}

/// The name of one parasitic node, shared by both writers so the two formats
/// agree about what a node is called.
pub fn node_name(
    network: &ParasiticNetwork,
    node: gpurify_extract::network::NodeId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    let before = out.len();
    let (net, index) = node_place(network, node)?;
    put_net_name(net, ports, strings, out)?;
    write!(out, "{DELIMITER}{index}").expect(INFALLIBLE);

    debug_assert!(out.len() > before, "a node was named the empty string");
    Ok(())
}
