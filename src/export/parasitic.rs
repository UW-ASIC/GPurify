//! SPEF and DSPF: the parasitic network, for a timing tool or a simulator.
//!
//! Data in: a canonical [`ParasiticNetwork`] plus the ports that name its nets.
//! Data out: text appended to a `String`; an unnamed net is refused, not invented.
//!
//! Both formats name node `i` of a net `net:i`, counting from the net's first
//! node, and both write in the network's canonical order. Units are fF, Ω
//! and pH, with six decimals.
//!
//! A mutual inductance between two field-solved nets is a SPICE `K` card in
//! DSPF, naming the two series inductances it couples and their coefficient
//! `k = M / √(L₁L₂)`. SPEF (IEEE 1481) has no mutual inductance, so SPEF
//! carries it as a comment in the first net's `*D_NET` block, in pH.
//!
//! A label on several disconnected nets would write one `*D_NET` per piece
//! under one name, so the pieces read as one net: both writers refuse it
//! ([`WriteError::SplitLabel`]). A net with several labels, a short, would
//! be written under one of them and lose the rest, since neither format can
//! give a net two names: both refuse that too ([`WriteError::ShortedLabels`]).

use std::fmt::Write as _;
use std::ops::Range;

use crate::export::json::format_f64;
use crate::export::{check_labels_one_to_one, narrow, Header, WriteError};
use gpurify_check::topology::{NetId, PortTable};
use gpurify_extract::network::{NodeId, Parasitic};
use gpurify_extract::ParasiticNetwork;
use gpurify_ingest::StrTable;

/// Between a net's name and the node's index within it (`*DELIMITER :`).
pub(crate) const DELIMITER: char = ':';

/// SPICE node zero, the far end of a ground capacitance in DSPF.
const GROUND: &str = "0";

/// Refuse a network not in the order both writers read it in: nodes grouped
/// by ascending net, elements sorted by `from`. Checked in every profile, since
/// an out-of-order network writes a plausible description of the wrong circuit.
fn check_canonical(network: &ParasiticNetwork) -> Result<(), WriteError> {
    if u32::try_from(network.node_count()).is_err() {
        return Err(WriteError::Unrepresentable(
            "a parasitic network with more nodes than a NodeId can address",
        ));
    }
    if !network.node_net.is_sorted() {
        return Err(WriteError::Unrepresentable(
            "a parasitic network whose nodes are not grouped by net",
        ));
    }
    if !network.from.is_sorted() {
        return Err(WriteError::Unrepresentable(
            "a parasitic network whose elements are not in canonical order",
        ));
    }
    // Only a capacitance to ground may omit its far node; DSPF would otherwise
    // write a broken resistor as a plausible one to ground.
    let far_ok = network
        .to
        .iter()
        .zip(&network.value)
        .all(|(far, kind)| far.is_some() || as_farads(*kind).is_some());
    if !far_ok {
        return Err(WriteError::Unrepresentable(
            "a resistance or inductance with no far node",
        ));
    }
    check_finite(network)
}

/// Refuse a NaN or infinite element: it prints as a number no reader parses,
/// or as one no simulator should believe.
pub(crate) fn check_finite(network: &ParasiticNetwork) -> Result<(), WriteError> {
    if network
        .value
        .iter()
        .all(|&value| spice_card(value).2.is_finite())
    {
        Ok(())
    } else {
        Err(WriteError::Unrepresentable("a non-finite parasitic value"))
    }
}

/// The net a node sits on, and the node's index within that net's run.
pub(crate) fn node_place(
    network: &ParasiticNetwork,
    node: NodeId,
) -> Result<(NetId, usize), WriteError> {
    let nets = &network.node_net[..];
    let row = node.0 as usize;
    let net = *nets.get(row).ok_or(WriteError::Unrepresentable(
        "a parasitic element on a node outside the network",
    ))?;
    let first = nets.partition_point(|&other| other < net);
    Ok((net, row - first))
}

/// The net whose node run starts at `start`, and the end of that run.
fn net_run(node_net: &[NetId], start: usize) -> (NetId, usize) {
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

/// Femtofarads on a capacitive element, `None` on any other kind.
const fn as_farads(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => Some(q.raw()),
        Parasitic::Resistance(_) | Parasitic::Inductance(_) | Parasitic::MutualInductance(_) => {
            None
        }
    }
}

/// Ohms on a resistive element, `None` on any other kind.
const fn as_ohms(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::Resistance(q) => Some(q.raw()),
        Parasitic::GroundCap(_)
        | Parasitic::CouplingCap(_)
        | Parasitic::Inductance(_)
        | Parasitic::MutualInductance(_) => None,
    }
}

/// Picohenries on an inductive element, `None` on any other kind.
const fn as_henries(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::Inductance(q) => Some(q.raw()),
        Parasitic::Resistance(_)
        | Parasitic::GroundCap(_)
        | Parasitic::CouplingCap(_)
        | Parasitic::MutualInductance(_) => None,
    }
}

/// Picohenries on a mutual inductance, `None` on any other kind.
const fn as_mutual_henries(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::MutualInductance(q) => Some(q.raw()),
        Parasitic::Resistance(_)
        | Parasitic::GroundCap(_)
        | Parasitic::CouplingCap(_)
        | Parasitic::Inductance(_) => None,
    }
}

/// A SPICE card's prefix letter, counter slot, magnitude and unit suffix. The
/// suffix matters: SPICE reads a bare number as SI.
///
/// A mutual inductance's magnitude here is its value in pH; its `K` card
/// states the coefficient instead ([`mutual_couplings`]).
pub(crate) const fn spice_card(value: Parasitic) -> (char, usize, f64, &'static str) {
    match value {
        Parasitic::Resistance(q) => ('R', 0, q.raw(), ""),
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => ('C', 1, q.raw(), "f"),
        Parasitic::Inductance(q) => ('L', 2, q.raw(), "p"),
        Parasitic::MutualInductance(q) => ('K', 3, q.raw(), ""),
    }
}

/// A mutual inductance as SPICE's `K` card states it: the rows of the two
/// series inductances it couples, and their coupling coefficient.
pub(crate) type Coupling = (usize, usize, f64);

/// Each element's [`Coupling`], `None` for any element but a
/// [`Parasitic::MutualInductance`]: the rows of the
/// [`Parasitic::Inductance`] elements whose near nodes are its own two nodes
/// (the first such row of each node), and `k = M / √(L_a L_b)`.
///
/// # Errors
///
/// [`WriteError::Unrepresentable`] for a mutual inductance on a node no
/// inductance starts at, and for one whose coefficient is not within
/// `[−1, 1]`: larger than the two inductances it couples allow, which no
/// passive pair is (NaN included).
pub(crate) fn mutual_couplings(
    network: &ParasiticNetwork,
) -> Result<Vec<Option<Coupling>>, WriteError> {
    let mut inductor: Vec<Option<usize>> = vec![None; network.node_count()];
    for (row, value) in network.value.iter().enumerate() {
        if matches!(value, Parasitic::Inductance(_)) {
            if let Some(slot) = inductor.get_mut(network.from[row].0 as usize) {
                slot.get_or_insert(row);
            }
        }
    }
    let inductor_at = |node: NodeId| inductor.get(node.0 as usize).copied().flatten();
    let henries = |row: usize| as_henries(network.value[row]).unwrap_or(f64::NAN);
    network
        .value
        .iter()
        .enumerate()
        .map(|(row, &value)| {
            let Some(mutual) = as_mutual_henries(value) else {
                return Ok(None);
            };
            let (Some(a), Some(b)) = (
                inductor_at(network.from[row]),
                network.to[row].and_then(inductor_at),
            ) else {
                return Err(WriteError::Unrepresentable(
                    "a mutual inductance on a node no inductance starts at",
                ));
            };
            let k = mutual / (henries(a) * henries(b)).sqrt();
            if !(k.abs() <= 1.0) {
                return Err(WriteError::Unrepresentable(
                    "a mutual inductance larger than the two inductances it couples allow",
                ));
            }
            Ok(Some((a, b, k)))
        })
        .collect()
}

/// One `*CAP` / `*RES` / `*INDUC` section of one `*D_NET` block.
///
/// `rows` is this net's element range; `select` picks this section's rows and
/// magnitudes. Only a `*CAP` row (`far_optional`) may name a single node.
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
    let _ = writeln!(out, "{keyword}");

    let mut index = 1usize;
    for row in rows {
        let Some(magnitude) = select(network.value[row]) else {
            continue;
        };

        let _ = write!(out, "{index} ");
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
///
/// IEEE 1481-1998, units `1 FF`, `1 OHM` and `0.000001 UH`, which is one
/// picohenry: the standard's inductance units are `HENRY`, `MH` and `UH`
/// only (its `induc_unit`), so the scale carries the pico. The header has
/// every field the standard's `header_def` requires, in its order:
/// `*DESIGN` (the layout path), `*DATE` (the header's timestamp, an empty
/// string without one, since `*DATE qstring` is required), `*VERSION`, and
/// the deck path as a comment. Then one `*D_NET`
/// per net, in ascending net order, with the net's total capacitance
/// (coupling included), one bidirectional `*CONN` port, and `*CAP`, `*RES`
/// and `*INDUC` sections. A coupling capacitance is listed once, in the
/// section of the net that holds its near node. A mutual inductance, which
/// the standard has no element for, is a comment after `*INDUC` in the same
/// net's block: `// mutual <node> <node> <pH>`.
///
/// # Errors
///
/// [`WriteError::Unrepresentable`] for a network out of canonical order, a
/// resistance or inductance with no far node, or a NaN or infinite value,
/// checked before anything is written, and for an element on a node outside
/// the network, found while writing. [`WriteError::SplitLabel`] for a net
/// whose label also names another net, and [`WriteError::ShortedLabels`]
/// for a net with several labels, checked before anything is written.
/// [`WriteError::UnnamedNet`] for a net with no label, found while writing.
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
    check_labels_one_to_one(
        network.node_net.chunk_by(|a, b| a == b).map(|run| run[0]),
        ports,
        strings,
    )?;

    out.push_str("*SPEF \"IEEE 1481-1998\"\n");
    let _ = writeln!(out, "*DESIGN \"{}\"", header.layout_path);
    let stamp = header.timestamp.as_deref().unwrap_or_default();
    let _ = writeln!(out, "*DATE \"{stamp}\"");
    out.push_str("*VENDOR \"gpurify\"\n*PROGRAM \"gpurify\"\n");
    let _ = writeln!(out, "*VERSION \"{}\"", header.tool_version);
    let _ = writeln!(out, "// deck {}", header.deck_path);
    out.push_str(
        "*DESIGN_FLOW \"EXTRACTED\"\n\
         *DIVIDER /\n\
         *DELIMITER :\n\
         *BUS_DELIMITER [ ]\n\
         *T_UNIT 1 NS\n\
         *C_UNIT 1 FF\n\
         *R_UNIT 1 OHM\n\
         *L_UNIT 0.000001 UH\n\n",
    );

    let capacitance = network.capacitance_per_net();
    // One `*D_NET` block per net; two cursors, sound after `check_canonical`.
    let mut node = 0usize;
    let mut element = 0usize;
    while node < nodes {
        let (net, node_end) = net_run(&network.node_net, node);

        out.push_str("*D_NET ");
        put_net_name(net, ports, strings, out)?;
        out.push(' ');
        format_f64(capacitance[net.0 as usize], out);
        out.push('\n');

        // No per-terminal direction is known, so one bidirectional connection.
        out.push_str("*CONN\n*P ");
        put_net_name(net, ports, strings, out)?;
        out.push_str(" B\n");

        let element_end =
            element + network.from[element..].partition_point(|from| (from.0 as usize) < node_end);

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
        // IEEE 1481 has no mutual inductance; a comment keeps it in the file.
        for row in element..element_end {
            let Some(henries) = as_mutual_henries(network.value[row]) else {
                continue;
            };
            out.push_str("// mutual ");
            node_name(network, network.from[row], ports, strings, out)?;
            out.push(' ');
            let far = network.to[row].ok_or(WriteError::Unrepresentable(
                "a resistance or inductance with no far node",
            ))?;
            node_name(network, far, ports, strings, out)?;
            out.push(' ');
            format_f64(henries, out);
            out.push('\n');
        }
        out.push_str("*END\n\n");

        node = node_end;
        element = element_end;
    }
    // A row no net claimed points outside the node columns.
    if element != elements {
        return Err(WriteError::Unrepresentable(
            "a parasitic element on a node outside the network",
        ));
    }
    Ok(())
}

/// Write the network as DSPF, a flat SPICE-like form. Sub-node names come from
/// the node's index within its net, not from allocation order.
///
/// DSPF 1.4 with ground net `0`. The header carries `*|DESIGN` (the layout
/// path), `*|DATE` only when the header has a timestamp, `*|VERSION`, and
/// the deck path as a comment. Then, per net, `*|NET` with its total
/// capacitance and one `*|S` line per node, with the node's layer standing
/// in for its position. Then every element as a card, `R`, `C`, `L` and `K`
/// numbered separately from 1, capacitances in `f` and inductances in `p`. A
/// mutual inductance is a `K` card naming the two `L` cards it couples and
/// their coefficient `M / √(L₁L₂)`.
///
/// # Errors
///
/// As [`write_spef`], and [`WriteError::Unrepresentable`] for a mutual
/// inductance on a node no inductance starts at or larger than its two
/// inductances allow, checked before anything is written.
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
    check_labels_one_to_one(
        network.node_net.chunk_by(|a, b| a == b).map(|run| run[0]),
        ports,
        strings,
    )?;
    let couplings = mutual_couplings(network)?;

    out.push_str("*|DSPF \"1.4\"\n");
    let _ = writeln!(out, "*|DESIGN \"{}\"", header.layout_path);
    if let Some(stamp) = &header.timestamp {
        let _ = writeln!(out, "*|DATE \"{stamp}\"");
    }
    out.push_str("*|VENDOR \"gpurify\"\n*|PROGRAM \"gpurify\"\n");
    let _ = writeln!(out, "*|VERSION \"{}\"", header.tool_version);
    let _ = writeln!(out, "* deck {}", header.deck_path);
    out.push_str("*|DIVIDER /\n*|DELIMITER :\n*|GROUND_NET 0\n\n");

    let capacitance = network.capacitance_per_net();
    // Per-net declarations first, then the element cards.
    let mut node = 0usize;
    while node < nodes {
        let (net, node_end) = net_run(&network.node_net, node);

        out.push_str("*|NET ");
        put_net_name(net, ports, strings, out)?;
        out.push(' ');
        format_f64(capacitance[net.0 as usize], out);
        out.push_str("f\n");

        // The node's layer stands in for a position the network does not carry.
        for row in node..node_end {
            out.push_str("*|S (");
            node_name(network, NodeId(narrow(row)), ports, strings, out)?;
            let _ = writeln!(out, " L{})", network.node_layer[row].0);
        }
        out.push('\n');

        node = node_end;
    }
    // Numbered per prefix, so `R1` and `C1` are two different cards; numbered
    // first, so a `K` card can name an `L` card written after it.
    let mut next = [1usize; 4];
    let card: Vec<usize> = network
        .value
        .iter()
        .map(|&value| {
            let slot = spice_card(value).1;
            next[slot] += 1;
            next[slot] - 1
        })
        .collect();
    for row in 0..elements {
        let (prefix, _, magnitude, suffix) = spice_card(network.value[row]);

        if let Some((a, b, k)) = couplings[row] {
            let _ = write!(out, "K{} L{} L{} ", card[row], card[a], card[b]);
            format_f64(k, out);
            out.push('\n');
            continue;
        }
        let _ = write!(out, "{prefix}{} ", card[row]);
        node_name(network, network.from[row], ports, strings, out)?;
        out.push(' ');
        // A missing far end is ground; `check_canonical` allows it only on a capacitance.
        if let Some(far) = network.to[row] {
            node_name(network, far, ports, strings, out)?;
        } else {
            out.push_str(GROUND);
        }
        out.push(' ');
        format_f64(magnitude, out);
        let _ = writeln!(out, "{suffix}");
    }
    Ok(())
}

/// `net:index`, the name both writers give a node.
///
/// `index` counts from the first node of the node's net, so it needs the
/// network's nodes grouped by net.
///
/// # Errors
///
/// [`WriteError::Unrepresentable`] for a node outside the network, and
/// [`WriteError::UnnamedNet`] for a net with no label.
pub fn node_name(
    network: &ParasiticNetwork,
    node: gpurify_extract::network::NodeId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    let (net, index) = node_place(network, node)?;
    put_net_name(net, ports, strings, out)?;
    let _ = write!(out, "{DELIMITER}{index}");
    Ok(())
}
