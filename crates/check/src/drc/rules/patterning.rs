//! Multi-patterning: can a layer be split across `colors` masks?
//!
//! Data in: one layer; touching rows merge into one figure (node), figures
//! closer than `color_spacing` conflict (edge), and a figure whose own notch
//! is narrower conflicts with itself (a loop). Data out: graph colouring —
//! two masks by bipartiteness (never gives up), three or more by DSATUR with
//! backtracking under a budget. Running out of budget is `Refused`, never clean.

use super::{
    centre, gap_midpoint, join_nested, label_pairs_into, owners_of, pair_distances_into, Verdict,
};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, SkipReason, Violation, Violations};
use gpurify_geom::boolean::union_into;
use gpurify_geom::derive::overlapping_flags;
use gpurify_geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify_geom::view::ValidatedLayer;
use gpurify_geom::width::narrowest_facing;
use gpurify_geom::{Dbu, GeometryStore, LayerId, PolyId};
use gpurify_ingest::StrId;

/// Search-step floor; a call gets `max(this, nodes × BUDGET_STEPS_PER_NODE)`.
const COLOR_SEARCH_BUDGET: u32 = 1 << 20;
const BUDGET_STEPS_PER_NODE: u32 = 64;

/// How a colouring attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coloring {
    /// Every node has a colour, in `out`.
    Complete,
    /// Proved uncolourable. `node` is canonical: the lowest root of an
    /// odd-cycle component (2 colours); otherwise the lowest node conflicting
    /// with itself, else the lowest node the search could not place.
    Infeasible {
        /// The node to report the failure on; the same for the same graph.
        node: u32,
    },
    /// The budget ran out with no answer either way. Only three or more
    /// colours can run out.
    Exhausted,
}

/// Colours a conflict graph over `0 .. node_count` with at most `colors`
/// colours, so that no conflict joins two nodes of one colour.
/// `out` holds the colouring on `Complete` and is left empty otherwise.
///
/// Exact either way it answers. Two colours is a bipartiteness test, linear in
/// the graph. Three or more is a DSATUR search with backtracking, capped at
/// `max(2^20, 64 * node_count)` placements, past which it returns
/// [`Coloring::Exhausted`]. Zero colours is infeasible for any non-empty graph.
/// A conflict `(a, a)` makes any graph infeasible, under any palette.
///
/// # Panics
///
/// When a conflict names a node at or above `node_count`.
pub fn color_into(
    node_count: u32,
    conflicts: &[(u32, u32)],
    colors: u8,
    out: &mut Vec<u8>,
) -> Coloring {
    out.clear();
    let n = node_count as usize;
    if n == 0 {
        return Coloring::Complete;
    }
    if colors == 0 {
        return Coloring::Infeasible { node: 0 };
    }
    let k = usize::from(colors);

    // CSR adjacency, one entry per endpoint.
    let mut adj_start = vec![0u32; n + 1];
    for &(a, b) in conflicts {
        adj_start[a as usize + 1] += 1;
        adj_start[b as usize + 1] += 1;
    }
    for node in 1..=n {
        adj_start[node] += adj_start[node - 1];
    }
    let mut cursor = adj_start.clone();
    let mut adj = vec![0u32; 2 * conflicts.len()];
    for &(a, b) in conflicts {
        adj[cursor[a as usize] as usize] = b;
        cursor[a as usize] += 1;
        adj[cursor[b as usize] as usize] = a;
        cursor[b as usize] += 1;
    }

    out.resize(n, UNCOLORED);
    if colors == 2 {
        return two_color_into(&adj_start, &adj, out);
    }
    // A node conflicting with itself takes no colour; the search below never
    // checks a placed node against itself.
    if let Some(node) = conflicts
        .iter()
        .filter(|(a, b)| a == b)
        .map(|&(a, _)| a)
        .min()
    {
        out.clear();
        return Coloring::Infeasible { node };
    }

    // `adjacent[node * k + c]`: neighbours of `node` holding colour `c`.
    let mut adjacent = vec![0u32; n * k];
    let mut sat = vec![0u32; n];
    // The search stack: node placed at each depth, next colour to try, and
    // distinct colours used above it.
    let mut pick = vec![0u32; n];
    let mut next = vec![0u8; n];
    let mut used = vec![0u8; n + 1];
    let mut queue = SatQueue::new(n, k, &adj_start);

    let mut budget = COLOR_SEARCH_BUDGET.max(node_count.saturating_mul(BUDGET_STEPS_PER_NODE));
    let mut unplaceable = u32::MAX;
    let mut depth = 0usize;
    pick[0] = queue.pick();

    while depth < n {
        let node = pick[depth] as usize;
        // Symmetry breaking: a colour past the ones used is a rename of the
        // first unused one.
        let limit = colors.min(used[depth].saturating_add(1));
        let mut color = next[depth];
        while color < limit && adjacent[node * k + usize::from(color)] > 0 {
            color += 1;
        }

        if color < limit {
            if budget == 0 {
                out.clear();
                return Coloring::Exhausted;
            }
            budget -= 1;
            next[depth] = color + 1;
            used[depth + 1] = used[depth].max(color + 1);
            out[node] = color;
            queue.remove(pick[depth], sat[node]);
            for &neighbour in &adj[adj_start[node] as usize..adj_start[node + 1] as usize] {
                let nb = neighbour as usize;
                let slot = nb * k + usize::from(color);
                let bump = u32::from(adjacent[slot] == 0);
                adjacent[slot] += 1;
                if bump == 1 && out[nb] == UNCOLORED {
                    queue.shift(neighbour, sat[nb], sat[nb] + 1);
                }
                sat[nb] += bump;
            }
            depth += 1;
            if depth < n {
                pick[depth] = queue.pick();
                next[depth] = 0;
            }
        } else {
            // Only a node that failed before trying any colour is unplaceable.
            if next[depth] == 0 {
                unplaceable = unplaceable.min(pick[depth]);
            }
            if depth == 0 {
                out.clear();
                return Coloring::Infeasible {
                    node: unplaceable.min(node_count - 1),
                };
            }
            depth -= 1;
            let placed = pick[depth] as usize;
            let color = out[placed];
            for &neighbour in &adj[adj_start[placed] as usize..adj_start[placed + 1] as usize] {
                let nb = neighbour as usize;
                let slot = nb * k + usize::from(color);
                adjacent[slot] -= 1;
                let drop = u32::from(adjacent[slot] == 0);
                if drop == 1 && out[nb] == UNCOLORED {
                    queue.shift(neighbour, sat[nb], sat[nb] - 1);
                }
                sat[nb] -= drop;
            }
            out[placed] = UNCOLORED;
            queue.insert(pick[depth], sat[placed]);
        }
    }
    Coloring::Complete
}

const UNCOLORED: u8 = u8::MAX;

/// Two colours by BFS from each component's lowest node; the reported node is
/// the root of the first odd-cycle component.
fn two_color_into(adj_start: &[u32], adj: &[u32], out: &mut Vec<u8>) -> Coloring {
    let n = out.len();
    let mut frontier: Vec<u32> = Vec::with_capacity(n);
    let mut head = 0usize;
    for root_id in 0..u32::try_from(n).expect("node ids are u32") {
        let root = root_id as usize;
        if out[root] != UNCOLORED {
            continue;
        }
        out[root] = 0;
        frontier.push(root_id);
        let mut odd = false;
        while head < frontier.len() {
            let node = frontier[head] as usize;
            head += 1;
            let here = out[node];
            for &neighbour in &adj[adj_start[node] as usize..adj_start[node + 1] as usize] {
                let nb = neighbour as usize;
                odd |= out[nb] == here;
                if out[nb] == UNCOLORED {
                    out[nb] = here ^ 1;
                    frontier.push(neighbour);
                }
            }
        }
        if odd {
            out.clear();
            return Coloring::Infeasible { node: root_id };
        }
    }
    Coloring::Complete
}

/// The uncoloured nodes bucketed by saturation. Within a bucket the order is
/// static (highest degree, then lowest index), so a bucket is a bitset over ranks.
#[derive(Debug)]
struct SatQueue {
    /// `by_rank[r]` is the node at rank `r`; `rank` is the inverse.
    by_rank: Vec<u32>,
    rank: Vec<u32>,
    /// One rank bitset per saturation level, `words` words each.
    bits: Vec<u64>,
    /// One bit per non-zero word of `bits`.
    summary: Vec<u64>,
    /// Live nodes per bucket.
    count: Vec<u32>,
    words: usize,
    summary_words: usize,
}

impl SatQueue {
    /// Every node uncoloured at saturation zero.
    fn new(n: usize, k: usize, adj_start: &[u32]) -> Self {
        let words = n.div_ceil(64);
        let summary_words = words.div_ceil(64);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "a layer's shapes fit a u32"
        )]
        let mut by_rank: Vec<u32> = (0..n as u32).collect();
        by_rank.sort_unstable_by_key(|&node| {
            let degree = adj_start[node as usize + 1] - adj_start[node as usize];
            (u64::from(!degree) << 32) | u64::from(node)
        });
        let mut rank = vec![0u32; n];
        for (r, &node) in (0u32..).zip(&by_rank) {
            rank[node as usize] = r;
        }
        let mut bits = vec![0u64; (k + 1) * words];
        let mut summary = vec![0u64; (k + 1) * summary_words];
        let mut count = vec![0u32; k + 1];
        // Bucket zero starts full; tail words are masked so no bit past node
        // `n - 1` is live.
        bits[..words].fill(!0);
        bits[words - 1] >>= (64 - n % 64) % 64;
        summary[..summary_words].fill(!0);
        summary[summary_words - 1] >>= (64 - words % 64) % 64;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "a layer's shapes fit a u32"
        )]
        {
            count[0] = n as u32;
        }
        Self {
            by_rank,
            rank,
            bits,
            summary,
            count,
            words,
            summary_words,
        }
    }

    fn insert(&mut self, node: u32, sat: u32) {
        let (word, bit, sword, sbit) = self.slots(node, sat);
        self.bits[word] |= 1 << bit;
        self.summary[sword] |= 1 << sbit;
        self.count[sat as usize] += 1;
    }

    fn remove(&mut self, node: u32, sat: u32) {
        let (word, bit, sword, sbit) = self.slots(node, sat);
        self.bits[word] &= !(1 << bit);
        if self.bits[word] == 0 {
            self.summary[sword] &= !(1 << sbit);
        }
        self.count[sat as usize] -= 1;
    }

    fn shift(&mut self, node: u32, from: u32, to: u32) {
        self.remove(node, from);
        self.insert(node, to);
    }

    fn slots(&self, node: u32, sat: u32) -> (usize, usize, usize, usize) {
        let r = self.rank[node as usize] as usize;
        let s = sat as usize;
        (
            s * self.words + r / 64,
            r % 64,
            s * self.summary_words + r / 64 / 64,
            r / 64 % 64,
        )
    }

    /// The next DSATUR node: highest saturation, then highest degree, then
    /// lowest index.
    fn pick(&self) -> u32 {
        let sat = (0..self.count.len())
            .rev()
            .find(|&s| self.count[s] != 0)
            .expect("the queue was asked for a node with none left");
        let sbase = sat * self.summary_words;
        let sword = self.summary[sbase..sbase + self.summary_words]
            .iter()
            .position(|&w| w != 0)
            .expect("a bucket with a live count has a set summary word");
        let word = sword * 64 + self.summary[sbase + sword].trailing_zeros() as usize;
        let live = self.bits[sat * self.words + word];
        self.by_rank[word * 64 + live.trailing_zeros() as usize]
    }
}

/// One layer's conflict graph: its figures (touching rows merged, a figure
/// named by its lowest row, node `row - first_row`) into `s.labels`, an edge
/// per pair of figures closer than `spacing` and a loop per figure whose own
/// notch is narrower into `s.edges`, and the merged figures into
/// `s.layer_out`. Returns each merged figure's node, in `s.layer_out` order;
/// `None` when the layer fails validation or will not merge.
fn conflict_graph(
    store: &GeometryStore,
    layer: LayerId,
    spacing: Dbu,
    s: &mut Scratch,
) -> Option<Vec<u32>> {
    let shapes = store.polys_on_layer(layer);
    let (first_row, node_count) = (shapes.start, shapes.end - shapes.start);
    s.validated.get(store, layer)?;
    SpatialIndex::build_into(store, layer, &mut s.index_a);
    candidate_pairs_into(store, &s.index_a, spacing, &mut s.pairs);
    pair_distances_into(store, &s.pairs, spacing, &mut s.dists);
    s.holes.build(store, [layer]);
    join_nested(store, &s.holes, &s.pairs, &mut s.dists);
    // Touching rows print as one shape: merge them (skipping this could create
    // an odd cycle). A figure is named by its lowest row.
    label_pairs_into(
        first_row,
        node_count,
        &s.pairs,
        &s.dists,
        |d2| d2.raw() == 0,
        &mut s.edges,
        &mut s.labels,
    );

    // Conflict edges between distinct figures closer than `spacing`.
    let limit2 = spacing.mul_wide(spacing);
    let labels = &s.labels;
    s.edges.clear();
    s.edges
        .extend(s.pairs.iter().zip(&s.dists).filter_map(|(&(a, b), &d2)| {
            let fa = labels[(a.0 - first_row) as usize].0;
            let fb = labels[(b.0 - first_row) as usize].0;
            (d2 < limit2 && fa != fb).then_some((fa, fb))
        }));
    // A figure whose own notch is narrower than `spacing` holds two parts
    // closer than one mask allows (Calibre's self-conflict, "an odd cycle
    // of one"): a loop on its node, which no palette colours.
    let drawn = s.validated.get(store, layer)?;
    union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).ok()?;
    s.rects_a.build(store, layer, drawn);
    let mut figure_node = Vec::with_capacity(s.layer_out.len());
    for (idx, owner) in (0..).zip(owners_of(&s.layer_out, &s.rects_a)) {
        let node = s.labels[(owner.0 - first_row) as usize].0;
        figure_node.push(node);
        let notch = narrowest_facing(s.layer_out.get(idx), false, &mut s.facing);
        if notch.is_some_and(|(gap, _)| gap < spacing) {
            s.edges.push((node, node));
        }
    }
    Some(figure_node)
}

/// Colourability of one layer's merged figures. One violation (on the node
/// `Infeasible` names, measured `colors + 1`) per uncolourable layer.
/// `examined` counts shapes, also when `Refused`; an empty layer is skipped.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn multi_patterning(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    colors: u8,
    spacing: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let shapes = store.polys_on_layer(layer);
    let examined = u64::from(shapes.end - shapes.start);
    if examined == 0 {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    if conflict_graph(store, layer, spacing, s).is_none() {
        return (Outcome::Refused, examined);
    }
    let (first_row, node_count) = (shapes.start, shapes.end - shapes.start);
    let outcome = match color_into(node_count, &s.edges, colors, &mut s.bytes) {
        Coloring::Complete => Outcome::Ran,
        Coloring::Exhausted => Outcome::Refused,
        Coloring::Infeasible { node } => {
            let poly = PolyId(first_row + node);
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(store.poly_bbox(poly)),
                measured: Measurement::Count(u32::from(colors) + 1),
                limit: Measurement::Count(u32::from(colors)),
                shapes: (poly, None),
            });
            Outcome::Ran
        }
    };
    (outcome, examined)
}

/// Anchor conflicts of one layer: per component of its conflict graph that
/// `colors` masks can split, but not with every anchored figure on its
/// anchor's mask, one violation. Figure `f` is anchored to mask `i + 1` when
/// it shares area with a shape of `anchors[i]`. Two masks name the pair whose
/// parity contradicts their anchors (Calibre's anchor path), or a figure on
/// two masks' anchors (anchor self-conflict); more masks decide by colouring
/// the component with one node per mask joined as a clique, each anchored
/// figure joined to every mask node but its own, and name the lowest anchored
/// figure. A component no colouring splits is `multi_patterning`'s, not
/// reported here. `examined` counts the layer's shapes.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn anchored_patterning(
    store: &GeometryStore,
    rule: StrId,
    (layer, anchors): (LayerId, &[LayerId]),
    colors: u8,
    spacing: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let shapes = store.polys_on_layer(layer);
    let examined = u64::from(shapes.end - shapes.start);
    if examined == 0 {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    let Some(figure_node) = conflict_graph(store, layer, spacing, s) else {
        return (Outcome::Refused, examined);
    };
    let (first_row, n) = (shapes.start, (shapes.end - shapes.start) as usize);

    // Anchor bits per node, bit `i` for `anchors[i]`.
    let mut anchor = vec![0u8; n];
    for (bit, &marker) in anchors.iter().enumerate() {
        let Some(drawn) = s.validated.get(store, marker) else {
            return (Outcome::Refused, examined);
        };
        let mut merged = ValidatedLayer::default();
        let Ok(hit) = union_into(drawn, &ValidatedLayer::default(), &mut merged)
            .and_then(|()| overlapping_flags(&s.layer_out, &merged))
        else {
            return (Outcome::Refused, examined);
        };
        for (&node, _) in figure_node.iter().zip(hit).filter(|(_, hit)| *hit) {
            anchor[node as usize] |= 1 << bit;
        }
    }

    // Components by union-find over the conflicts, each listed in node order.
    let mut parent: Vec<u32> = (0..u32::try_from(n).expect("a layer's rows fit a u32")).collect();
    for &(a, b) in &s.edges {
        let (ra, rb) = (root_of(&mut parent, a), root_of(&mut parent, b));
        parent[ra.max(rb) as usize] = ra.min(rb);
    }
    let mut members: Vec<(u32, u32)> = (0..u32::try_from(n).expect("fits"))
        .map(|node| (root_of(&mut parent, node), node))
        .collect();
    members.sort_unstable();
    let mut component_edges: Vec<Vec<(u32, u32)>> = vec![Vec::new(); n];
    for &(a, b) in &s.edges {
        component_edges[root_of(&mut parent, a) as usize].push((a, b));
    }

    let k = u32::from(colors);
    let mut outcome = Outcome::Ran;
    let mut local = vec![u32::MAX; n];
    let (mut edges, mut held) = (Vec::new(), Vec::new());
    for group in members.chunk_by(|x, y| x.0 == y.0) {
        if group.iter().all(|&(_, node)| anchor[node as usize] == 0) {
            continue;
        }
        for (i, &(_, node)) in (0..).zip(group) {
            local[node as usize] = i;
        }
        edges.clear();
        edges.extend(
            component_edges[group[0].0 as usize]
                .iter()
                .map(|&(a, b)| (local[a as usize], local[b as usize])),
        );
        held.clear();
        held.extend(group.iter().map(|&(_, node)| anchor[node as usize]));
        let m = u32::try_from(group.len()).expect("a layer's rows fit a u32");
        let (a, b) = match anchor_conflict(m, &edges, &held, colors, &mut s.bytes) {
            Anchoring::Honoured | Anchoring::Unsplittable => continue,
            Anchoring::Exhausted => {
                outcome = Outcome::Refused;
                continue;
            }
            Anchoring::Conflict { node, other } => (
                group[node as usize].1,
                other.map(|other| group[other as usize].1),
            ),
        };
        let (pa, pb) = (PolyId(first_row + a), b.map(|b| PolyId(first_row + b)));
        let at = match pb {
            Some(pb) => gap_midpoint(store.poly_bbox(pa), store.poly_bbox(pb)),
            None => centre(store.poly_bbox(pa)),
        };
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at,
            measured: Measurement::Count(k + 1),
            limit: Measurement::Count(k),
            shapes: (pa, pb),
        });
    }
    (outcome, examined)
}

/// How honouring pre-coloured nodes ended, on one connected conflict graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchoring {
    /// A colouring gives every anchored node its anchor's colour.
    Honoured,
    /// No colouring exists, anchors aside ([`color_into`] proves it).
    Unsplittable,
    /// Colourings exist, and none honours the anchors. `node` is anchored.
    /// With two colours `other` is the first anchored node whose anchor the
    /// colouring through `node`'s contradicts (an anchor path), and `None`
    /// means `node` holds two anchors (an anchor self-conflict); with more,
    /// `node` is the lowest anchored node and `other` is `None`.
    Conflict {
        /// An anchored node of the conflict.
        node: u32,
        /// The other end of an anchor path.
        other: Option<u32>,
    },
    /// The colouring search ran out of budget (three or more colours).
    Exhausted,
}

/// Whether a connected conflict graph over `0 .. node_count` can be coloured
/// with `colors` colours so that each anchored node takes its anchor's colour:
/// node `i` is anchored to colour `c` when bit `c` of `anchors[i]` is set
/// (`0` is unanchored, two bits can never both be honoured). `out` is
/// scratch.
///
/// Exact. Two colours: a connected graph's two-colouring is unique up to
/// swapping the colours, so two anchored nodes take one colour exactly when
/// they take one in [`color_into`]'s. More: colour the graph plus one node
/// per colour, the colour nodes a clique, each anchored node joined to every
/// colour node but its anchor's (to all of them when it holds two), with the
/// same search and budget as [`color_into`].
///
/// # Panics
///
/// When `anchors` is shorter than `node_count`, or a conflict names a node at
/// or above it.
pub fn anchor_conflict(
    node_count: u32,
    conflicts: &[(u32, u32)],
    anchors: &[u8],
    colors: u8,
    out: &mut Vec<u8>,
) -> Anchoring {
    match color_into(node_count, conflicts, colors, out) {
        Coloring::Complete => {}
        Coloring::Infeasible { .. } => return Anchoring::Unsplittable,
        Coloring::Exhausted => return Anchoring::Exhausted,
    }
    let bits = |node: u32| anchors[node as usize].count_ones();
    let mut anchored = (0..node_count).filter(|&node| anchors[node as usize] != 0);
    let Some(u) = anchored.next() else {
        return Anchoring::Honoured;
    };
    if bits(u) > 1 {
        return Anchoring::Conflict {
            node: u,
            other: None,
        };
    }
    if colors == 2 {
        let colour = |node: u32| out[node as usize];
        return anchored
            .find_map(|v| {
                if bits(v) > 1 {
                    Some(Anchoring::Conflict {
                        node: v,
                        other: None,
                    })
                } else {
                    let same_anchor = anchors[v as usize] == anchors[u as usize];
                    (same_anchor != (colour(v) == colour(u))).then_some(Anchoring::Conflict {
                        node: u,
                        other: Some(v),
                    })
                }
            })
            .unwrap_or(Anchoring::Honoured);
    }
    let k = u32::from(colors);
    let mut edges = conflicts.to_vec();
    for a in 0..k {
        for b in a + 1..k {
            edges.push((node_count + a, node_count + b));
        }
    }
    for node in 0..node_count {
        let held = anchors[node as usize];
        if held == 0 {
            continue;
        }
        let own = if bits(node) > 1 {
            u32::MAX
        } else {
            held.trailing_zeros()
        };
        edges.extend((0..k).filter(|&c| c != own).map(|c| (node, node_count + c)));
    }
    match color_into(node_count + k, &edges, colors, out) {
        Coloring::Complete => Anchoring::Honoured,
        Coloring::Infeasible { .. } => Anchoring::Conflict {
            node: u,
            other: None,
        },
        Coloring::Exhausted => Anchoring::Exhausted,
    }
}

/// The root of `x`'s set in a union-find forest, halving the path on the way.
fn root_of(parent: &mut [u32], mut x: u32) -> u32 {
    while parent[x as usize] != x {
        parent[x as usize] = parent[parent[x as usize] as usize];
        x = parent[x as usize];
    }
    x
}
