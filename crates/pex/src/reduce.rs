//! Network reduction to a requested [`Order`].
//!
//! Invariant across every order: total capacitance on each net, and the driving
//! point resistance between any two terminals.

use gpurify_geom::Qty;

use crate::network::{cap_ff, NodeId, Parasitic, ParasiticNetwork};

/// How far to reduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Keep every node; reduction is a no-op.
    Full,
    /// One lumped R and C per net.
    Lumped,
    /// Keep terminals and branch points, collapse series and parallel chains.
    Reduced,
}

/// One element as a row: [`ParasiticNetwork`]'s three element columns zipped.
type Row = (NodeId, Option<NodeId>, Parasitic);

/// Ohms on a resistive element, zero on any other kind.
#[inline]
fn ohms(value: Parasitic) -> f64 {
    match value {
        Parasitic::Resistance(q) => q.raw(),
        Parasitic::GroundCap(_) | Parasitic::CouplingCap(_) | Parasitic::Inductance(_) => 0.0,
    }
}

/// A resistive element with two nodes, the one kind reduction rewrites.
#[inline]
fn is_resistor(row: Row) -> bool {
    row.1.is_some() & matches!(row.2, Parasitic::Resistance(_))
}

/// A capacitance to ground.
#[inline]
fn is_ground_cap(row: Row) -> bool {
    row.1.is_none() & matches!(row.2, Parasitic::GroundCap(_))
}

/// The unordered node pair an element stands between: a resistor is symmetric,
/// so `(a, b)` and `(b, a)` must land in one merge group.
#[inline]
fn pair_key(from: NodeId, to: Option<NodeId>) -> (u32, u32) {
    let far = to.map_or(from.0, |node| node.0);
    (from.0.min(far), from.0.max(far))
}

/// The end of `row` that is not `node`; a self-loop returns `node` itself, which
/// is what the caller's `near == far` guard catches.
#[inline]
fn far_end(row: Row, node: u32) -> u32 {
    let near = row.0 .0;
    let far = row.1.map_or(near, |other| other.0);
    [near, far][usize::from(near == node)]
}

/// The element columns as rows.
fn rows_of(network: &ParasiticNetwork) -> Vec<Row> {
    let n = network.value.len();
    debug_assert_eq!(
        network.from.len(),
        n,
        "the element columns must stay parallel"
    );
    debug_assert_eq!(
        network.to.len(),
        n,
        "the element columns must stay parallel"
    );

    let mut rows = Vec::with_capacity(n);
    for ((&from, &to), &value) in network.from.iter().zip(&network.to).zip(&network.value) {
        rows.push((from, to, value));
    }
    debug_assert_eq!(rows.len(), n);
    rows
}

/// Write `rows` into `out`'s element columns, carrying `src`'s node columns
/// across unchanged.
///
/// Node ids are stable by contract: nodes are copied, never renumbered, so a
/// collapsed node survives with no element on it. [`reduce_into`] takes
/// `terminals: &[NodeId]` from the caller and the result is read back through
/// those same ids, so renumbering would redirect every terminal a simulator
/// connects to — and it preserves [`ParasiticNetwork`]'s node-order invariant.
fn fill_from_rows(src: &ParasiticNetwork, rows: &[Row], out: &mut ParasiticNetwork) {
    debug_assert_eq!(
        src.node_net.len(),
        src.node_layer.len(),
        "the node columns must stay parallel"
    );

    out.node_net.clear();
    out.node_net.extend_from_slice(&src.node_net);
    out.node_layer.clear();
    out.node_layer.extend_from_slice(&src.node_layer);

    out.from.clear();
    out.from.reserve(rows.len());
    out.to.clear();
    out.to.reserve(rows.len());
    out.value.clear();
    out.value.reserve(rows.len());
    for &(from, to, value) in rows {
        out.from.push(from);
        out.to.push(to);
        out.value.push(value);
    }

    debug_assert_eq!(out.from.len(), rows.len());
    debug_assert_eq!(out.to.len(), rows.len());
    debug_assert_eq!(out.value.len(), rows.len());
    debug_assert_eq!(out.node_net.len(), src.node_net.len());
}

/// How many node slots the element columns can address: the max of declared and
/// reached, so a malformed network is a diagnosable assert rather than an
/// out-of-bounds index in release.
fn node_span(network: &ParasiticNetwork) -> usize {
    let declared = network.node_net.len();
    debug_assert_eq!(
        network.from.len(),
        network.to.len(),
        "the element columns must stay parallel"
    );

    let mut reached = 0_usize;
    for (&from, &to) in network.from.iter().zip(&network.to) {
        let near = from.0 as usize + 1;
        let far = to.map_or(0, |node| node.0 as usize + 1);
        reached = reached.max(near).max(far);
    }
    debug_assert!(
        reached <= declared,
        "an element names node {reached} of {declared} declared"
    );
    declared.max(reached)
}

/// Copy `src` into `out`, keeping only what `decide` marks live, in order.
///
/// `decide` returns the payload *and* the predicate: the store is unconditional
/// and the write index carries the decision. `T` and `U` are `Copy` because
/// rejected slots are left uninitialised, and a droppable `U` would leak them.
fn compact_into<T: Copy, U: Copy>(
    src: &[T],
    out: &mut Vec<U>,
    decide: impl Fn(usize, T) -> (U, bool),
) {
    let n = src.len();
    // Reserved for the whole input rather than the survivors, which is what
    // lets the store below be unconditional.
    out.clear();
    out.reserve(n);
    let dst = &mut out.spare_capacity_mut()[..n];

    let mut w = 0_usize;
    for (i, &row) in src.iter().enumerate() {
        let (value, live) = decide(i, row);
        // `w <= i` by induction: `w` starts at zero and `bool` is 0 or 1, so one
        // iteration advances it by at most one.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < n == dst.len()` from the induction above. Rejected
        // slots stay uninitialised and the `set_len(w)` below truncates them
        // away; `U: Copy`, so nothing there needs dropping.
        unsafe { dst.get_unchecked_mut(w) }.write(value);
        w += usize::from(live);
    }

    // SAFETY: slot `j` was written while `w` held `j`, for every `j < w`, and
    // `w <= n <= out.capacity()`.
    unsafe { out.set_len(w) };
    debug_assert!(out.len() <= n, "a compact cannot grow its input");
}

/// Drop the rows `keep` marks dead, preserving order.
fn compact_rows(rows: &[Row], keep: &[bool], out: &mut Vec<Row>) {
    debug_assert_eq!(
        rows.len(),
        keep.len(),
        "the row and keep columns must agree"
    );
    // Sliced rather than zipped: a short `keep` would make `zip` stop early and
    // emit a silently-short result. The slice panics instead, in every profile.
    let keep = &keep[..rows.len()];
    compact_into(rows, out, |i, row| (row, keep[i]));
}

/// Merge every group of resistors sharing a node pair into one, conductances
/// added; pass every other element through untouched.
fn merge_parallel_rows(rows: &[Row], out: &mut Vec<Row>) {
    let mut keyed: Vec<((u32, u32), Row)> = Vec::new();
    compact_into(rows, &mut keyed, |_, row| {
        ((pair_key(row.0, row.1), row), is_resistor(row))
    });
    let resistive = keyed.len();

    // Stable, so equal pairs stay in element order and the conductance sum below
    // is the same `f64` on every run.
    keyed.sort_by_key(|&(key, _)| key);

    out.clear();
    out.reserve(rows.len());

    let mut start = 0;
    while start < keyed.len() {
        let key = keyed[start].0;
        let mut end = start;
        while end < keyed.len() && keyed[end].0 == key {
            end += 1;
        }
        debug_assert!(end > start);

        // Ascending index order, deliberately: a reassociated `f64` sum is a
        // different `f64`, and the reduced network is compared bit for bit.
        let mut conductance = 0.0_f64;
        for &(_, row) in &keyed[start..end] {
            conductance += 1.0 / ohms(row.2);
        }

        // A group of one keeps its exact value: `1.0 / (1.0 / r)` is not the
        // identity on every `f64`, and a merge that perturbs a resistor it did
        // not merge is not idempotent.
        let value = if end - start == 1 {
            keyed[start].1 .2
        } else {
            Parasitic::Resistance(Qty::new(1.0 / conductance))
        };
        out.push((NodeId(key.0), Some(NodeId(key.1)), value));
        start = end;
    }

    let mut others: Vec<Row> = Vec::new();
    compact_into(rows, &mut others, |_, row| (row, !is_resistor(row)));
    debug_assert_eq!(others.len() + resistive, rows.len());
    out.extend_from_slice(&others);

    debug_assert!(out.len() <= rows.len());
}

/// Collapse every eliminable node, rewriting the surviving resistor of each pair
/// in place and marking the absorbed one dead in `keep`.
///
/// Eliminable means exactly two resistive incidences, nothing else, and not in
/// `protected`: capacitance makes a node electrically observable, and a terminal
/// is what a simulator connects to.
fn collapse_series_rows(rows: &mut [Row], keep: &mut [bool], nodes: usize, protected: &[NodeId]) {
    debug_assert_eq!(rows.len(), keep.len());
    debug_assert!(keep.iter().all(|&live| live), "keep starts all-live");

    let mut res_degree = vec![0_u32; nodes];
    let mut blocked = vec![false; nodes];
    // Two incidence slots per node, plus one dump slot for stores that must not
    // land anywhere real.
    let dump = 2 * nodes;
    let mut incidence = vec![u32::MAX; dump + 1];

    // An incidence slot holds a row index as a `u32` and reserves `u32::MAX` as
    // its empty sentinel, so the element column must be *shorter* than
    // `u32::MAX` — at exactly that length the last row is indistinguishable from
    // an unfilled slot.
    let element_count = u32::try_from(rows.len()).expect("element counts fit in u32");
    assert!(
        element_count < u32::MAX,
        "an element column must be shorter than the u32::MAX incidence sentinel"
    );

    for (index, &row) in (0..element_count).zip(rows.iter()) {
        let (from, to, _) = row;
        let resistive = is_resistor(row);
        let near = from.0 as usize;
        // A ground element has no far node; aiming the second update at the near
        // node keeps both stores unconditional, and that node is blocked by this
        // same element anyway.
        let far = to.unwrap_or(from).0 as usize;

        let step = u32::from(resistive);
        res_degree[near] += step;
        res_degree[far] += step;
        // A self-loop fills only one of its node's two slots, so it would leave
        // a degree-two node with slot zero still `u32::MAX` — an out-of-bounds
        // index in release. It is also electrically nothing, so blocking the
        // node is the right answer as well as the fix.
        let loop_back = near == far;
        blocked[near] |= !resistive | loop_back;
        blocked[far] |= !resistive | loop_back;

        // Only a degree-exactly-two node is ever eliminated, so only its two
        // slots are ever read; a third incidence overwrites slot one of a node
        // nobody will look at. Non-resistive rows go to the dump slot.
        let near_slot = 2 * near + usize::from(res_degree[near] >= 2);
        let far_slot = 2 * far + usize::from(res_degree[far] >= 2);
        incidence[[dump, near_slot][usize::from(resistive)]] = index;
        incidence[[dump, far_slot][usize::from(resistive)]] = index;
    }

    let mut is_terminal = vec![false; nodes];
    for &NodeId(node) in protected {
        // A terminal naming a node the element columns never reach is a caller
        // error, not something to index on.
        if let Some(slot) = is_terminal.get_mut(node as usize) {
            *slot = true;
        }
    }

    // One pass suffices: the rewrite replaces two edges at a node with one, so
    // every node's degree is invariant under it, and a node eliminable at the
    // start stays eliminable until it is peeled.
    for node in 0..nodes {
        let node_id = NodeId(u32::try_from(node).expect("node counts fit in u32"));
        let eliminable = res_degree[node] == 2 && !blocked[node] && !is_terminal[node];
        if !eliminable {
            continue;
        }

        // Kept in both widths: `u32` is what the incidence slots store and what
        // the fixup below writes back, `usize` is what indexes `rows`/`keep`.
        let (first_slot, second_slot) = (incidence[2 * node], incidence[2 * node + 1]);
        let first = first_slot as usize;
        let second = second_slot as usize;
        debug_assert!(first < rows.len() && second < rows.len());
        debug_assert!(
            keep[first] && keep[second],
            "a live degree-two node kept a dead incidence"
        );

        let near = far_end(rows[first], node_id.0);
        let far = far_end(rows[second], node_id.0);
        // Two resistors closing a loop back onto one node would collapse to a
        // self-loop, which no simulator can read; the parallel merge finishes
        // the job.
        if near == far {
            continue;
        }

        let total = ohms(rows[first].2) + ohms(rows[second].2);
        debug_assert!(total.is_finite());
        rows[first] = (
            NodeId(near),
            Some(NodeId(far)),
            Parasitic::Resistance(Qty::new(total)),
        );
        keep[second] = false;

        // `far` reached this node through `second`; it now reaches `near`
        // through `first`. A node of degree above two holds stale slots that are
        // never read, so a miss here is correct.
        let base = 2 * far as usize;
        let (dead, live) = (second_slot, first_slot);
        for slot in [base, base + 1] {
            incidence[slot] = [incidence[slot], live][usize::from(incidence[slot] == dead)];
        }
    }
}

/// One resistor and one ground capacitance per net: the total series resistance
/// between the first and last node, the total ground capacitance on the first.
///
/// Coupling is not a per-net quantity, so it passes through untouched — which is
/// what keeps total capacitance invariant across this order.
fn lump_rows(network: &ParasiticNetwork, out: &mut Vec<Row>) {
    let nodes = network.node_net.len();
    if nodes == 0 {
        // No node column, so no net to lump onto: an element here would name a
        // node that does not exist.
        debug_assert!(
            network.value.is_empty(),
            "{} elements over an empty node column",
            network.value.len()
        );
        out.clear();
        return;
    }

    // Rests on the node-order invariant (see `ParasiticNetwork`): every net
    // occupies one contiguous ascending range of `node_net`, so an adjacent-pair
    // scan finds the run boundaries.
    let mut fresh: Vec<bool> = Vec::with_capacity(nodes - 1);
    for (previous, current) in network.node_net[..nodes - 1]
        .iter()
        .zip(&network.node_net[1..])
    {
        fresh.push(previous != current);
    }
    debug_assert_eq!(fresh.len(), nodes - 1);

    // Node zero opens the first run, so the run count is one more than the
    // number of boundaries.
    let mut boundaries = 0_usize;
    for &boundary in &fresh {
        boundaries += usize::from(boundary);
    }
    let nets = 1 + boundaries;
    debug_assert!(nets <= nodes);

    let mut slot_of_node = vec![0_u32; nodes];
    let mut first_node = vec![NodeId(0); nets];
    let mut last_node = vec![NodeId(0); nets];

    let mut rank = 0_u32;
    for index in 1..nodes {
        let boundary = fresh[index - 1];
        rank += u32::from(boundary);
        slot_of_node[index] = rank;

        let id = NodeId(u32::try_from(index).expect("node counts fit in u32"));
        let slot = rank as usize;
        // Runs are contiguous and ascending, so the node that opens a run is its
        // first and every later store into the same slot lands on its last.
        first_node[slot] = [first_node[slot], id][usize::from(boundary)];
        last_node[slot] = id;
    }
    debug_assert_eq!(
        usize::try_from(rank).expect("net counts fit in usize") + 1,
        nets
    );
    debug_assert_eq!(first_node[0], NodeId(0), "node zero opens the first run");

    let mut cap_sum = vec![0.0_f64; nets];
    let mut res_sum = vec![0.0_f64; nets];

    for ((&from, &to), &value) in network.from.iter().zip(&network.to).zip(&network.value) {
        let row = (from, to, value);
        let slot = slot_of_node[from.0 as usize] as usize;
        cap_sum[slot] += f64::from(u8::from(is_ground_cap(row))) * cap_ff(value);
        res_sum[slot] += f64::from(u8::from(is_resistor(row))) * ohms(value);
    }

    let all = rows_of(network);
    let mut others: Vec<Row> = Vec::new();
    compact_into(&all, &mut others, |_, row| {
        (row, !(is_resistor(row) | is_ground_cap(row)))
    });
    debug_assert!(others.len() <= all.len());

    // A payload-carrying compact: `out` is sized for every candidate up front
    // and the store is unconditional, so the write index carries the decision.
    out.clear();
    out.resize(
        2 * nets,
        (NodeId(0), None, Parasitic::GroundCap(Qty::new(0.0))),
    );
    let mut written = 0_usize;
    for slot in 0..nets {
        // Zero is not an element: a zero-ohm resistor is a short and a zero
        // capacitor is absent, and either would read to a simulator as a fault.
        let resistive = (res_sum[slot] > 0.0) & (first_node[slot] != last_node[slot]);
        out[written] = (
            first_node[slot],
            Some(last_node[slot]),
            Parasitic::Resistance(Qty::new(res_sum[slot])),
        );
        written += usize::from(resistive);

        let capacitive = cap_sum[slot] > 0.0;
        out[written] = (
            first_node[slot],
            None,
            Parasitic::GroundCap(Qty::new(cap_sum[slot])),
        );
        written += usize::from(capacitive);
    }
    debug_assert!(written <= 2 * nets);
    out.truncate(written);
    out.extend_from_slice(&others);
}

/// Reduce a network to `order`, leaving `network` intact.
pub fn reduce_into(
    network: &ParasiticNetwork,
    terminals: &[NodeId],
    order: Order,
    out: &mut ParasiticNetwork,
) {
    debug_assert_eq!(
        network.node_net.len(),
        network.node_layer.len(),
        "the node columns must stay parallel"
    );
    debug_assert_eq!(network.from.len(), network.to.len());
    debug_assert_eq!(network.from.len(), network.value.len());

    let before = total_capacitance(network).raw();

    match order {
        // Identity, byte for byte, including element order.
        Order::Full => {
            let rows = rows_of(network);
            fill_from_rows(network, &rows, out);
        }
        Order::Reduced => {
            let rows = rows_of(network);
            let mut merged = Vec::new();
            merge_parallel_rows(&rows, &mut merged);

            let mut keep = vec![true; merged.len()];
            collapse_series_rows(&mut merged, &mut keep, node_span(network), terminals);
            let mut survivors = Vec::new();
            compact_rows(&merged, &keep, &mut survivors);

            // A collapse can leave two chains ending on the same pair, so the
            // merge runs again on its output; it is idempotent.
            merge_parallel_rows(&survivors, &mut merged);
            fill_from_rows(network, &merged, out);
            out.sort_canonical();
        }
        Order::Lumped => {
            let mut rows = Vec::new();
            lump_rows(network, &mut rows);
            fill_from_rows(network, &rows, out);
            out.sort_canonical();
        }
    }

    let after = total_capacitance(out).raw();
    debug_assert!(
        (after - before).abs() <= 1e-9 * before.abs().max(1.0),
        "reduction changed total capacitance from {before} fF to {after} fF"
    );
    debug_assert_eq!(out.node_net.len(), network.node_net.len());
}

/// Collapse chains of resistors in series, resistances adding.
///
/// Only a node with exactly two resistive neighbours and no capacitance, which
/// would make it electrically observable.
pub fn collapse_series_into(network: &ParasiticNetwork, out: &mut ParasiticNetwork) {
    debug_assert_eq!(network.from.len(), network.value.len());

    let mut rows = rows_of(network);
    let mut keep = vec![true; rows.len()];
    collapse_series_rows(&mut rows, &mut keep, node_span(network), &[]);

    let mut survivors = Vec::new();
    compact_rows(&rows, &keep, &mut survivors);
    debug_assert!(survivors.len() <= network.from.len());
    fill_from_rows(network, &survivors, out);
}

/// Merge resistors in parallel between the same node pair, conductances adding.
///
/// Emitted once per node pair, ordered by `(from, to)`, so the sum reproduces.
pub fn merge_parallel_into(network: &ParasiticNetwork, out: &mut ParasiticNetwork) {
    debug_assert_eq!(network.from.len(), network.value.len());

    let rows = rows_of(network);
    let mut merged = Vec::new();
    merge_parallel_rows(&rows, &mut merged);
    debug_assert!(merged.len() <= network.from.len());
    fill_from_rows(network, &merged, out);
}

/// Total capacitance over every element of a network.
pub fn total_capacitance(
    network: &ParasiticNetwork,
) -> gpurify_geom::Qty<gpurify_geom::Capacitance, { gpurify_geom::prefix::FEMTO }> {
    debug_assert_eq!(
        network.from.len(),
        network.value.len(),
        "the element columns must stay parallel"
    );

    // A strict left fold in canonical element order, which is what makes this
    // sum the same `f64` on every run. Coupling counts once here, however many
    // nets it touches; `net_capacitance` is the per-net view that counts both.
    let mut femtofarads = 0.0_f64;
    for &value in &network.value {
        femtofarads += cap_ff(value);
    }

    debug_assert!(
        femtofarads.is_finite() && femtofarads >= 0.0,
        "total capacitance is {femtofarads} fF"
    );
    Qty::new(femtofarads)
}

#[cfg(test)]
mod tests {
    use super::compact_into;

    /// The two ends of the write-index induction the unchecked store rests on:
    /// reject-everything pins `w` at 0, accept-everything pins `w == i`.
    #[test]
    fn a_compact_that_rejects_all_and_one_that_accepts_all_bound_the_write_index() {
        let mut out: Vec<u32> = Vec::new();

        for n in 0_u32..=64 {
            let src: Vec<u32> = (0..n).collect();

            compact_into(&src, &mut out, |_, row| (row, false));
            assert!(
                out.is_empty(),
                "rejecting every one of {n} rows must leave the cursor at zero, got {out:?}"
            );

            compact_into(&src, &mut out, |_, row| (row, true));
            assert_eq!(
                out, src,
                "accepting every one of {n} rows must reproduce the input in order"
            );
        }
    }
}
