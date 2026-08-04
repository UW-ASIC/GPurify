//! SPEF and DSPF: the parasitic network, for a timing tool or a simulator.
//!
//! These two writers are the ones with history. The old implementation's
//! interlayer-capacitance rows carried their layer pair in whichever order a
//! `HashMap` happened to yield, so **8 of 27 parasitic outputs differed between
//! runs of the same binary on the same input**. The magnitudes were right; the
//! file was not reproducible, which means it could not be diffed and a
//! regression in it could not be seen.
//!
//! The fix is upstream — `ParasiticNetwork` is `SoA` and canonically ordered —
//! and the job here is to not undo it.

use std::fmt::Write as _;
use std::ops::Range;

use crate::json::format_f64;
use crate::{narrow, Header, WriteError, INFALLIBLE};
use gpurify_ingest::StrTable;
use gpurify_pex::network::{NodeId, Parasitic};
use gpurify_pex::ParasiticNetwork;
use gpurify_topology::{NetId, PortTable};

/// Between a net's name and the node's index within it. Declared to the reader
/// of both files as `*DELIMITER :`, so the two agree by construction rather
/// than by both happening to use a colon.
const DELIMITER: char = ':';

/// SPICE node zero. What a ground capacitance's far end is called in DSPF,
/// where every element is a card and a card has two nodes.
const GROUND: &str = "0";

/// Is a column non-decreasing?
///
/// **Decision** — pure, one column in, one bool out. An adjacent-pair scan over
/// two offset views of the same column. `&=` and not `&&`: both sides are a
/// compare on a loaded value, so short-circuiting would only buy a branch, and
/// the fold stays a strict left-to-right one over the whole column.
fn is_non_decreasing<T: Copy + Ord>(column: &[T]) -> bool {
    // One column, so the two offset views agree by construction and the
    // columns-must-agree check has nothing to compare. A length under two
    // gives an empty range rather than a guard branch.
    let n = column.len();
    let mut ok = true;
    for i in 1..n {
        ok &= column[i - 1] <= column[i];
    }
    ok
}

/// Does every element that needs a far node have one?
///
/// **Decision** — pure, two columns in, one bool out. `to` names the element's
/// other end, and a capacitance to ground is the one kind entitled to omit it:
/// that plate is the substrate, which is not a node of this network. A
/// resistance or an inductance joins two nodes by definition, so `None` there is
/// a broken row and not a grounded one.
///
/// The kind test is [`as_farads`], not a second `matches!`, so a fifth
/// capacitive [`Parasitic`] variant cannot be groundable in one place and not in
/// the other. `&=` and `|` and not `&&` / `||`: both sides are a tag compare on
/// a loaded value, so short-circuiting would only buy a branch, and the fold
/// stays a strict left-to-right one over the whole column.
fn every_far_node_present(to: &[Option<NodeId>], value: &[Parasitic]) -> bool {
    // The two columns are one `SoA` row split in two, and `zip` would silently
    // fold only the shorter of them — the fail-open shape that once let a
    // release build check 999 of 1000 rows and report success.
    debug_assert_eq!(to.len(), value.len(), "SoA columns must agree");

    let mut ok = true;
    for (far, kind) in to.iter().zip(value) {
        ok &= far.is_some() | as_farads(*kind).is_some();
    }
    ok
}

/// Refuse a network that is not in the order both writers below read it in.
///
/// Two invariants, both stated by `ParasiticNetwork` and neither enforced by its
/// `push`: nodes are grouped into one contiguous ascending range per net, and
/// elements are sorted by `from`. Together they are what lets a writer walk both
/// columns once with a forward cursor instead of scanning every element per net.
///
/// Checked in **every** profile, not `debug_assert`ed. A network handed over out
/// of order would otherwise file elements under the wrong net and write a
/// perfectly plausible description of the wrong circuit — and this crate's whole
/// reason to exist is that a wrong-but-plausible parasitic file is the defect
/// nobody sees. `export` never sorts; if the order is wrong it is wrong at the
/// source, and saying so is the only honest thing a writer can do about it.
fn check_canonical(network: &ParasiticNetwork) -> Result<(), WriteError> {
    // Not an ordering claim, but the same kind of precondition and the same one
    // place to state it: a node the writers cannot address by [`NodeId`] cannot
    // be named, and this is what makes every `narrow` below a typed error the
    // caller sees rather than a panic reached halfway through a written file.
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
    // Not an ordering claim either, and here for the same reason as the node
    // count: it is the one precondition the two formats disagreed about.
    // `spef_section` refuses a `*RES` or `*INDUC` row with no far node, but DSPF
    // cards every absent far end to node zero — so the same broken resistor was
    // a typed error in one file and a plausible resistor to ground in the other.
    // A reader diffing the two would have believed the DSPF. Refusing it once,
    // here, is what makes the two writers accept exactly the same networks.
    if !every_far_node_present(&network.to, &network.value) {
        return Err(WriteError::Unrepresentable(
            "a resistance or inductance with no far node",
        ));
    }
    Ok(())
}

/// The first row of a net's node run, or where that run would begin.
///
/// **Decision** — pure. One contiguous ascending range per net, so a run's start
/// is a binary search rather than a walk backwards. The single place either
/// writer turns a [`NetId`] into a row: [`node_place`]'s sub-node index and
/// [`first_node_of`]'s terminal attachment are measured from the same number,
/// and a netlist that disagreed with its own DSPF about where a net's nodes
/// begin would name the same node two things.
fn net_start(node_net: &[NetId], net: NetId) -> usize {
    let first = node_net.partition_point(|&other| other < net);
    // O(1), and it is the grouping invariant itself: if the run this landed on
    // is the net's, nothing before it may also be the net's.
    debug_assert!(
        first == 0 || node_net[first - 1] < net,
        "the node column is not grouped by net"
    );
    first
}

/// The first node of a net, or `None` where the network holds none for it.
///
/// **Decision** — pure, one net in, one optional node out. Lives here rather
/// than beside its caller in [`crate::netlist`] because it reads the grouping
/// invariant [`check_canonical`] enforces, and an invariant is worth stating in
/// one file.
pub(crate) fn first_node_of(network: &ParasiticNetwork, net: NetId) -> Option<NodeId> {
    let nets = &network.node_net[..];
    let first = net_start(nets, net);
    (nets.get(first) == Some(&net)).then(|| NodeId(narrow(first)))
}

/// The net a node sits on, and the node's index within that net's run.
///
/// **Decision** — pure. The index is a position in a canonically ordered column,
/// which is why a sub-node name is stable across runs where an allocation
/// counter would not be.
fn node_place(network: &ParasiticNetwork, node: NodeId) -> Result<(NetId, usize), WriteError> {
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

/// The half-open node range of the net that starts at `start`.
///
/// **Decision** — pure. `start` is the first row of a run because the caller
/// walks run to run, and the run's end is a binary search over the suffix: the
/// column is ascending, so `== net` is true for a prefix of it and false after.
fn net_run(node_net: &[NetId], start: usize) -> (NetId, usize) {
    debug_assert!(start < node_net.len(), "a run starts at a node that exists");
    let net = node_net[start];
    (net, start + node_net[start..].partition_point(|&other| other == net))
}

/// Append a net's name, or refuse the net.
///
/// The single place either format turns a [`NetId`] into text, so "every net a
/// SPEF references must have a name" is one `ok_or` and not a rule repeated at
/// every call site.
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
///
/// **Decision** — pure. `pex`'s own `cap_ff` is `pub(crate)` there, so this is
/// the same select restated at the one site outside that crate that needs it —
/// and as an `Option`, because a SPEF section wants "not mine" and not "zero".
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
/// numbers it, its magnitude, and the scale factor that magnitude is in.
///
/// **Decision** — pure. The single place a [`Parasitic`] becomes a card, shared
/// with [`crate::netlist`] so a netlist and a DSPF of the same network describe
/// the same circuit. The suffix is the load-bearing part: SPICE reads a bare
/// number as SI, so a femtofarad that kept its `f` in one file and lost it in
/// the other is the same capacitor written 10^15 apart — and both files parse.
///
/// The `slot` is the card counter to number this kind from, so `R1` and `C1`
/// are two different cards and adding a kind does not renumber another.
pub(crate) const fn spice_card(value: Parasitic) -> (char, usize, f64, &'static str) {
    match value {
        Parasitic::Resistance(q) => ('R', 0, q.raw(), ""),
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => ('C', 1, q.raw(), "f"),
        Parasitic::Inductance(q) => ('L', 2, q.raw(), "p"),
    }
}

/// One `*CAP` / `*RES` / `*INDUC` section of one `*D_NET` block.
///
/// **Transform.** Caller owns `out`, appended to. `rows` is the element range
/// already narrowed to this net; `select` decides which of those rows belong to
/// this section and what magnitude each contributes. Rows are numbered from 1
/// within the section, as IEEE 1481 asks, and the numbering is a position in a
/// canonical order rather than a discovery counter.
///
/// `far_optional` is the ground-capacitance carve-out: a `*CAP` row may name one
/// node, a `*RES` or `*INDUC` row may not. An element that breaks that is a
/// typed error rather than a short row, because a short row is a file that
/// parses into a different circuit.
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
    // Emitting text is a scatter with a data-dependent output index: each row
    // appends its own number of bytes, so where row N lands is read out of the
    // data rather than computed from N.
    for row in rows {
        // Data-dependent `if`, and it stays: SPEF puts each kind of element in
        // its own section, so this is a section filter and not arithmetic to
        // predicate — and the taken side is a float format plus two name
        // lookups, which is exactly the "taken side is expensive" escape valve.
        let Some(magnitude) = select(network.value[row]) else {
            continue;
        };

        write!(out, "{index} ").expect(INFALLIBLE);
        node_name(network, network.from[row], ports, strings, out)?;
        // Data-dependent `if` on the far end. Same escape valve: the taken side
        // is a second name lookup, and the two arms write different row shapes
        // rather than different values, so there is nothing to blend.
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

/// SPEF.
///
/// Names are emitted through the port table, and every net a SPEF references
/// must have one — an anonymous net is [`WriteError::UnnamedNet`], not a
/// generated placeholder, because a placeholder is a name that changes between
/// runs.
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
    // A branch on a uniform — one header field, constant across the whole write
    // — so the predictor has it before the first net. The clock is never
    // consulted: a timestamp appears here or nowhere.
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

    // One `*D_NET` block per net, nets in ascending `NetId`, elements in the
    // canonical order the network guarantees. Two cursors, both monotonic: the
    // node column is grouped by net and the element column is sorted by `from`,
    // which `check_canonical` established above. The stride is a run length
    // read out of the data, so the trip count is not the column length.
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

        // `*CONN` names the net's own port. Per-terminal direction is not in
        // this writer's inputs — `PortTable` is net-to-name — so declaring one
        // bidirectional connection is the whole of what the tables support.
        out.push_str("*CONN\n*P ");
        put_net_name(net, ports, strings, out)?;
        out.push_str(" B\n");

        // This net's elements are the next run of the element columns: `from`
        // ascends and the net owns a contiguous node range, so a single
        // binary search on the unconsumed suffix bounds them.
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

    // Fail closed. Every element belongs to the net of its `from` node, so a row
    // no net claimed is a row pointing outside the node columns — and a SPEF
    // silently missing a resistor is a timing report that is confidently fast.
    if element != elements {
        return Err(WriteError::Unrepresentable(
            "a parasitic element on a node outside the network",
        ));
    }
    debug_assert_eq!(network.node_count(), nodes, "a writer mutates nothing");
    debug_assert_eq!(network.element_count(), elements, "a writer mutates nothing");
    Ok(())
}

/// DSPF.
///
/// A flat SPICE-like form. Sub-node names are derived from the node's index
/// within its net, which is canonical, rather than from allocation order, which
/// is not.
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
    // Same uniform branch, same reason, as `write_spef`.
    if let Some(stamp) = &header.timestamp {
        writeln!(out, "*|DATE \"{stamp}\"").expect(INFALLIBLE);
    }
    out.push_str("*|VENDOR \"gpurify\"\n*|PROGRAM \"gpurify\"\n");
    writeln!(out, "*|VERSION \"{}\"", header.tool_version).expect(INFALLIBLE);
    writeln!(out, "* deck {}", header.deck_path).expect(INFALLIBLE);
    out.push_str("*|DIVIDER /\n*|DELIMITER :\n*|GROUND_NET 0\n\n");

    // Per-net declarations first: the net, its total capacitance, and one
    // sub-node record per node, in the order the node column already stands in.
    // Run-length stride, as `write_spef`'s node walk.
    let mut node = 0usize;
    while node < nodes {
        let (net, node_end) = net_run(&network.node_net, node);

        out.push_str("*|NET ");
        put_net_name(net, ports, strings, out)?;
        out.push(' ');
        format_f64(network.net_capacitance(net).raw(), out);
        out.push_str("f\n");

        // The sub-node record carries the node's layer where DSPF wants its
        // position — `*|S (name L3)` against the `*|S (name x y)` the format
        // asks for, which the old tree emitted from a node that had an `x` and a
        // `y` (`reference/pre-rewrite:crates/pex/src/analytical/dspf.rs:69`).
        //
        // Not fixable in this writer. `ParasiticNetwork` has `node_layer` and no
        // coordinate column, and `write_dspf` is handed no geometry to recover
        // one from, so the choices here are a wrong token, a short record, or
        // refusing every DSPF outright. Filed as a frozen-signature defect —
        // `docs/SIGNATURE_DEFECTS.md`, `## export` — because the fix is a node
        // position column upstream in `pex`, not a body in `export`.
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
    // Cards are numbered per prefix, so `R1` and `C1` are two different cards
    // and the numbering of one kind does not move when another kind is added.
    let mut next = [1usize; 3];
    // Serial by construction: `next[slot]` is what row N-1 wrote, so this loop
    // does not partition by index range the way the kernel rule wants.
    for row in 0..elements {
        // A `match` over a closed enum, not a data-dependent branch: every arm
        // produces the same four uniforms and the body below is common.
        let (prefix, slot, magnitude, suffix) = spice_card(network.value[row]);

        write!(out, "{prefix}{} ", next[slot]).expect(INFALLIBLE);
        node_name(network, network.from[row], ports, strings, out)?;
        out.push(' ');
        // The far end of a ground capacitance is node zero, which is a name
        // DSPF already defines — so there is no shape difference between a
        // grounded card and a coupled one. That this arm is only ever reached
        // by a capacitance is `check_canonical`'s `every_far_node_present`,
        // above: without it, a resistance with no far node became a plausible
        // resistor to ground here while `spef_section` refused the same row.
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

/// The name of one parasitic node.
///
/// **Decision** — pure, and shared by both writers so the two formats agree
/// about what a node is called. Two writers naming the same node differently is
/// the kind of thing nobody notices until two tools disagree.
pub fn node_name(
    network: &ParasiticNetwork,
    node: gpurify_pex::network::NodeId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    let before = out.len();
    let (net, index) = node_place(network, node)?;
    put_net_name(net, ports, strings, out)?;
    write!(out, "{DELIMITER}{index}").expect(INFALLIBLE);

    // Two nodes never share a name: the net name is a function of the net and
    // the index is the node's unique position within that net's run, so the
    // pair is injective over the node column.
    debug_assert!(out.len() > before, "a node was named the empty string");
    Ok(())
}
