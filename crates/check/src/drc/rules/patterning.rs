//! Multi-patterning: can a layer be split across `colors` masks, or decomposed
//! for self-aligned double patterning?
//!
//! Data in: one layer; touching rows merge into one figure (node), figures
//! closer than `color_spacing` conflict (edge), and a figure whose own notch
//! is narrower conflicts with itself (a loop). Data out: graph colouring —
//! two masks by bipartiteness (never gives up), three or more by DSATUR with
//! backtracking under a budget. Running out of budget is `Refused`, never clean.

use super::facing::merged_owners;
use super::spacing::prepare;
use super::{centre, gap_midpoint, Verdict};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, SkipReason, Violation, Violations};
use gpurify_geom::boolean::union_into;
use gpurify_geom::derive::overlapping_flags;
use gpurify_geom::view::ValidatedLayer;
use gpurify_geom::width::{narrowest_facing, narrowest_width};
use gpurify_geom::{Bbox, Dbu, GeometryStore, LayerId, PolyId};
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
    let first_row = shapes.start;
    // Touching rows print as one shape: merge them (skipping this could create
    // an odd cycle). A figure is named by its lowest row.
    if !prepare(store, layer, spacing, s) {
        return None;
    }

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
    let owners = merged_owners(store, layer, s)?;
    let mut figure_node = Vec::with_capacity(s.layer_out.len());
    for (idx, owner) in (0..).zip(owners) {
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

/// Self-aligned double patterning decomposability of one layer: the
/// colour-band graph and, with `track`, the odd-track width rule.
///
/// Figures are [`conflict_graph`]'s (touching rows merged). Two figures
/// closer than `bands.0` must take different colours, and two at least that
/// far apart but closer than `bands.1` the same colour: a different-colour
/// edge has parity 1 and a same-colour edge parity 0, so a layer splits
/// exactly when every cycle has an even number of different-colour edges.
/// Union-find with parity finds each contradiction; the first edge, in
/// ascending `(figure, figure)` order, that closes an odd cycle of a
/// component is reported, once per component, between its two figures, at
/// the middle of their boxes' gap. A figure whose own notch is under
/// `bands.0` is a different-colour edge to itself, reported at its centre.
/// Each measures 1 odd cycle against 0.
///
/// With `track = (w, s)`, a figure whose narrowest width is over `w` and not
/// `(2k + 1) w + 2k s` for a whole `k` spans an even number of tracks; it is
/// reported at its centre, measuring its width against the largest legal
/// width under it. `examined` counts the layer's rows.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn sadp(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    bands: (Dbu, Dbu),
    track: Option<(Dbu, Dbu)>,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let shapes = store.polys_on_layer(layer);
    let examined = u64::from(shapes.end - shapes.start);
    if examined == 0 {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    let (different, same) = bands;
    let Some(figure_node) = conflict_graph(store, layer, same.max(different), s) else {
        return (Outcome::Refused, examined);
    };
    let (first_row, n) = (shapes.start, (shapes.end - shapes.start) as usize);
    let poly = |node: u32| PolyId(first_row + node);
    let different2 = different.mul_wide(different);
    let same2 = same.mul_wide(same);

    // One edge per pair of figures, at their least distance: parity 1 under
    // `different`, 0 under `same`.
    let mut edges: Vec<(u32, u32, bool)> = Vec::new();
    for (&(a, b), &d2) in s.pairs.iter().zip(&s.dists) {
        let fa = s.labels[(a.0 - first_row) as usize].0;
        let fb = s.labels[(b.0 - first_row) as usize].0;
        if fa != fb && d2 < same2.max(different2) {
            edges.push((fa.min(fb), fa.max(fb), d2 < different2));
        }
    }
    // The least distance decides a pair's band.
    edges.sort_unstable_by_key(|&(a, b, odd)| (a, b, !odd));
    edges.dedup_by_key(|&mut (a, b, _)| (a, b));

    let mut parent: Vec<u32> = (0..u32::try_from(n).expect("a layer's rows fit a u32")).collect();
    let mut parity = vec![false; n];
    let mut reported = vec![false; n];
    // The root of `x` and `x`'s parity to it, pointing the path at the root.
    fn find(parent: &mut [u32], parity: &mut [bool], x: u32) -> (u32, bool) {
        let (mut root, mut to_root) = (x, false);
        while parent[root as usize] != root {
            to_root ^= parity[root as usize];
            root = parent[root as usize];
        }
        let (mut at, mut here) = (x, to_root);
        while at != root && parent[at as usize] != root {
            let (next, up) = (parent[at as usize], parity[at as usize]);
            parent[at as usize] = root;
            parity[at as usize] = here;
            here ^= up;
            at = next;
        }
        (root, to_root)
    }
    for &(a, b, odd) in &edges {
        let ((ra, pa), (rb, pb)) = (
            find(&mut parent, &mut parity, a),
            find(&mut parent, &mut parity, b),
        );
        if ra != rb {
            let (lo, hi) = (ra.min(rb), ra.max(rb));
            parent[hi as usize] = lo;
            parity[hi as usize] = pa ^ pb ^ odd;
            reported[lo as usize] |= reported[hi as usize];
            continue;
        }
        if pa ^ pb != odd && !reported[ra as usize] {
            reported[ra as usize] = true;
            let (sa, sb) = (poly(a), poly(b));
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: gap_midpoint(store.poly_bbox(sa), store.poly_bbox(sb)),
                measured: Measurement::Count(1),
                limit: Measurement::Count(0),
                shapes: (sa, Some(sb)),
            });
        }
    }

    // Per merged figure: a notch under `different` (a self-conflict) and,
    // with a track, its width.
    let mut figures: Vec<(u32, u32)> = figure_node.iter().copied().zip(0..).collect();
    figures.sort_unstable();
    for &(node, idx) in &figures {
        let figure = s.layer_out.get(idx);
        let notch = narrowest_facing(figure, false, &mut s.facing);
        if notch.is_some_and(|(gap, _)| gap < different) {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(store.poly_bbox(poly(node))),
                measured: Measurement::Count(1),
                limit: Measurement::Count(0),
                shapes: (poly(node), None),
            });
        }
        let Some((w, space)) = track else {
            continue;
        };
        let width = narrowest_width(figure, &mut s.facing);
        let step = 2 * (w.raw() + space.raw());
        let over = width.raw() - w.raw();
        if over > 0 && over % step != 0 {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(store.poly_bbox(poly(node))),
                measured: Measurement::Length(width),
                limit: Measurement::Length(Dbu::new_unchecked(w.raw() + over / step * step)),
                shapes: (poly(node), None),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// The limits of [`sadp_line_end`]: Xu et al.'s rules 1 to 4, and the gap at
/// which two lines sit on adjacent tracks.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LineEnds {
    /// Lines whose sides are at most this far apart are on adjacent tracks.
    pub adjacent: Dbu,
    /// Rule 1, OnTrackSpace: the least end-to-end gap on one track.
    pub tip: Dbu,
    /// Rule 2, OffTrackOverlap: the least overlap of anti-parallel ends.
    pub overlap: Dbu,
    /// Rule 3, OffTrackSpace: the least along-track gap between
    /// anti-parallel ends that do not overlap.
    pub corner: Dbu,
    /// Rule 4, OffTrackOffset: same-facing ends are flush or this far apart.
    pub offset: Dbu,
}

/// Line ends of one gridded SADP layer (`sadp_line_end`). Each merged
/// figure that is a rectangle longer than wide is a line along its long
/// side; other figures are not lines and are not examined. For two lines
/// along one axis, with `across` the gap between their sides (negative when
/// they share a track's span) and `[a0, a1]`, `[b0, b1]` their spans along
/// it, `a` before `b`:
///
/// - on one track (`across < 0`), an end-to-end gap `b0 - a1` under `tip`;
/// - on adjacent tracks (`0 < across <= adjacent`): ends facing apart that
///   overlap (`a0 < b0 < a1 < b1`) by less than `overlap`; ends facing apart
///   that do not (`b0 >= a1`) closer than `corner` along the track; and
///   same-facing ends (`a0, b0` or `a1, b1`) offset by more than 0 and less
///   than `offset`.
///
/// Each finding is between the two lines, at the middle of their boxes' gap,
/// measuring the gap, overlap or offset against its limit. `examined`
/// counts the layer's rows.
pub(crate) fn sadp_line_end(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limits: LineEnds,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let shapes = store.polys_on_layer(layer);
    let examined = u64::from(shapes.end - shapes.start);
    if examined == 0 {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    let corner_reach = limits.adjacent.raw().max(limits.corner.raw());
    let reach = Dbu::new_unchecked(
        1 + limits
            .tip
            .raw()
            .max(limits.adjacent.raw() + corner_reach)
            .max(limits.offset.raw()),
    );
    let Some(figure_node) = conflict_graph(store, layer, reach, s) else {
        return (Outcome::Refused, examined);
    };
    let first_row = shapes.start;
    // Per node: its line as `(horizontal, box)`, when its figure is one.
    let mut line: Vec<Option<(bool, Bbox)>> = vec![None; (shapes.end - shapes.start) as usize];
    for (idx, &node) in (0u32..).zip(&figure_node) {
        let figure = s.layer_out.get(idx);
        let b = figure.bbox();
        let (w, h) = (b.xhi.raw() - b.xlo.raw(), b.yhi.raw() - b.ylo.raw());
        let rectangle = figure.holes().next().is_none()
            && figure.outer().area2().raw() == 2 * i128::from(w) * i128::from(h);
        if rectangle && w != h {
            line[node as usize] = Some((w > h, b));
        }
    }
    let mut pairs: Vec<(u32, u32)> = s
        .pairs
        .iter()
        .map(|&(a, b)| {
            let fa = s.labels[(a.0 - first_row) as usize].0;
            let fb = s.labels[(b.0 - first_row) as usize].0;
            (fa.min(fb), fa.max(fb))
        })
        .filter(|&(a, b)| a != b)
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    for (a, b) in pairs {
        let (Some((ha, ba)), Some((hb, bb))) = (line[a as usize], line[b as usize]) else {
            continue;
        };
        if ha != hb {
            continue;
        }
        // Spans along the line and across it, `a` before `b` along it.
        let along = |b: Bbox| if ha { (b.xlo, b.xhi) } else { (b.ylo, b.yhi) };
        let cross = |b: Bbox| if ha { (b.ylo, b.yhi) } else { (b.xlo, b.xhi) };
        let ((mut a0, mut a1), (mut b0, mut b1)) = (along(ba), along(bb));
        if (b0, b1) < (a0, a1) {
            std::mem::swap(&mut a0, &mut b0);
            std::mem::swap(&mut a1, &mut b1);
        }
        let ((c0, c1), (d0, d1)) = (cross(ba), cross(bb));
        let across = c0.raw().max(d0.raw()) - c1.raw().min(d1.raw());
        let mut found = |measured: i64, limit: Dbu| {
            let (pa, pb) = (PolyId(first_row + a), PolyId(first_row + b));
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: gap_midpoint(store.poly_bbox(pa), store.poly_bbox(pb)),
                measured: Measurement::Length(Dbu::new_unchecked(measured)),
                limit: Measurement::Length(limit),
                shapes: (pa, Some(pb)),
            });
        };
        let gap = b0.raw() - a1.raw();
        if across < 0 {
            if gap >= 0 && gap < limits.tip.raw() {
                found(gap, limits.tip);
            }
            continue;
        }
        if across == 0 || across > limits.adjacent.raw() {
            continue;
        }
        if gap >= 0 {
            if gap < limits.corner.raw() {
                found(gap, limits.corner);
            }
        } else if a0 < b0 && a1 < b1 && -gap < limits.overlap.raw() {
            found(-gap, limits.overlap);
        }
        for shift in [b0.raw() - a0.raw(), (b1.raw() - a1.raw()).abs()] {
            if shift > 0 && shift < limits.offset.raw() {
                found(shift, limits.offset);
            }
        }
    }
    (Outcome::Ran, examined)
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
