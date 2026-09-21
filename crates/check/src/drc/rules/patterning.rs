//! Multi-patterning: can this layer be split across the masks the process has?
//!
//! Two shapes closer than `color_spacing` cannot share a mask, so the question
//! is graph colouring: nodes are shapes, edges are too-close pairs, colours are
//! masks.
//!
//! This is the only rule in the crate that can give up, which is why
//! [`Coloring`] has three variants rather than being a `bool`:
//! [`Coloring::Exhausted`] is **not** a violation and **not** clean — it becomes
//! `Outcome::Refused`, because a checker that reports "colourable" after giving
//! up is worse than one that reports nothing. Collapsing it into either other
//! variant is the single defect this module exists to avoid.
//!
//! Two masks are not NP-hard and are not searched: two-colourability is
//! bipartiteness, which [`color_into`] settles in one pass, so double
//! patterning never comes back `Exhausted`.

use super::{centre, poly_dist2, row_columns, COLUMNS_DIVERGED};
use crate::drc::{record_run, Design, Scratch};
use crate::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
use gpurify_geom::connectivity::components_into;
use gpurify_geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Dbu, MAX_ABS_DBU};
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::StrId;

/// Floor on the backtracking budget, in search steps.
///
/// A call gets `max(COLOR_SEARCH_BUDGET, node_count × BUDGET_STEPS_PER_NODE)`.
/// Not a parameter: a caller that could raise it would be tempted to raise it
/// until the answer came out clean.
pub const COLOR_SEARCH_BUDGET: u32 = 1 << 20;

/// Search steps granted per node, on top of [`COLOR_SEARCH_BUDGET`].
const BUDGET_STEPS_PER_NODE: u32 = 64;

/// Multi-patterning colourability.
#[derive(Debug, Default)]
pub struct MultiPatterningTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Masks available.
    pub colors: Vec<u8>,
    /// Two shapes closer than this cannot share a mask. Also the radius the
    /// candidate prune is built at: narrowing it drops conflict edges and makes
    /// an uncolourable layer look colourable, which is fail-open.
    pub color_spacing: Vec<Dbu>,
}

row_columns! {
    MultiPatterningTable { rule, layer, colors, color_spacing },
}

/// How a colouring attempt ended.
///
/// A sum type rather than `Option<Vec<u8>>`: "no assignment exists" and "we did
/// not find one" are different claims and only the first is a layout defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coloring {
    /// Every node has a colour, in `out`.
    Complete,
    /// Proved uncolourable within the budget.
    ///
    /// `node` is a function of the graph, not of the path taken through it:
    /// three masks or more names the lowest-indexed node the search could not
    /// place, two masks the lowest-indexed node of the lowest-indexed component
    /// carrying an odd cycle.
    Infeasible { node: u32 },
    /// The budget ran out with no answer either way. Fail closed.
    Exhausted,
}

/// Colour a conflict graph with at most `colors` colours.
///
/// `out` is cleared and refilled to `node_count` entries on
/// [`Coloring::Complete`] and left **empty** otherwise: a partial colouring is
/// not a result anyone can use.
///
/// `conflicts` is a flat pair list over `0 .. node_count`. An edge naming a
/// node at or beyond `node_count` is asserted, not ignored: ignoring it drops a
/// constraint and makes an uncolourable graph look fine.
///
/// Two masks are decided exactly in one pass; three or more runs DSATUR with
/// backtracking, tie-broken by node index so the result is canonical.
///
/// Allocates its search buffers per call; the crate-internal `color_into_with`
/// takes a set the caller owns.
pub fn color_into(
    node_count: u32,
    conflicts: &[(u32, u32)],
    colors: u8,
    out: &mut Vec<u8>,
) -> Coloring {
    color_into_with(
        &mut ColorScratch::default(),
        node_count,
        conflicts,
        colors,
        out,
    )
}

/// Every buffer the colouring search needs, sized by the graph and reusable
/// across graphs.
///
/// Every field a call reads is cleared and refilled before it is read, so no
/// state crosses a call and the answer stays a function of the arguments.
#[derive(Debug, Default)]
pub(crate) struct ColorScratch {
    /// CSR row starts over the conflict graph, `node_count + 1` entries.
    adj_start: Vec<u32>,
    /// Write cursor per row while the counting sort fills `adj`.
    cursor: Vec<u32>,
    /// CSR neighbours, one entry per endpoint, so `2 × conflicts.len()`.
    adj: Vec<u32>,
    /// Neighbours of each node holding each colour, `node_count × colors`.
    adjacent: Vec<u32>,
    /// Saturation degree per node: how many colours its neighbours occupy.
    sat: Vec<u32>,
    /// The search stack: which node was placed at each depth, the next colour
    /// to try for it, and how many distinct colours the assignment above used.
    pick: Vec<u32>,
    next: Vec<u8>,
    used: Vec<u8>,
    /// The bipartite pass's breadth-first frontier, on the `colors == 2` path.
    frontier: Vec<u32>,
    /// The uncoloured nodes in DSATUR order, on the search path.
    queue: SatQueue,
}

/// [`color_into`] against a caller-owned [`ColorScratch`].
///
/// `scratch`'s contents on entry are irrelevant and on exit are not an output;
/// the result is a function of `node_count`, `conflicts` and `colors` alone.
pub(crate) fn color_into_with(
    scratch: &mut ColorScratch,
    node_count: u32,
    conflicts: &[(u32, u32)],
    colors: u8,
    out: &mut Vec<u8>,
) -> Coloring {
    debug_assert!(
        conflicts
            .iter()
            .all(|&(a, b)| a < node_count && b < node_count),
        "a conflict edge names a node outside 0..{node_count}; ignoring it would \
         drop a constraint and make an uncolourable graph look fine"
    );
    debug_assert!(
        conflicts.iter().all(|&(a, b)| a != b),
        "a shape does not conflict with itself"
    );
    debug_assert!(
        u64::from(node_count) <= IDX_MASK,
        "the DSATUR key packs the node index into {IDX_BITS} bits; a layer of \
         {node_count} shapes is past this tool's scale"
    );

    out.clear();
    let n = node_count as usize;
    // An empty graph is coloured, vacuously. A palette of nothing leaves the
    // first node unplaceable — fail closed rather than `Complete`.
    if n == 0 {
        return Coloring::Complete;
    }
    if colors == 0 {
        return Coloring::Infeasible { node: 0 };
    }
    let k = usize::from(colors);

    // Disjoint borrows out of one `ColorScratch`.
    let ColorScratch {
        adj_start,
        cursor,
        adj,
        adjacent,
        sat,
        pick,
        next,
        used,
        frontier,
        queue,
    } = scratch;

    // Every buffer is `clear` then `resize`, never `resize` alone: resizing a
    // longer buffer down would keep the head of the previous graph's answer.
    adj_start.clear();
    adj_start.resize(n + 1, 0);
    for &(a, b) in conflicts {
        adj_start[a as usize + 1] += 1;
        adj_start[b as usize + 1] += 1;
    }
    for node in 1..=n {
        adj_start[node] += adj_start[node - 1];
    }
    cursor.clear();
    cursor.extend_from_slice(adj_start);
    adj.clear();
    adj.resize(2 * conflicts.len(), 0);
    for &(a, b) in conflicts {
        adj[cursor[a as usize] as usize] = b;
        cursor[a as usize] += 1;
        adj[cursor[b as usize] as usize] = a;
        cursor[b as usize] += 1;
    }
    debug_assert_eq!(
        adj_start[n] as usize,
        adj.len(),
        "every edge was filed from both of its ends"
    );

    // `out` doubles as the colour column.
    out.resize(n, UNCOLORED);

    // Two masks is bipartiteness, answered exactly in one pass, so double
    // patterning can never come back `Exhausted`.
    if colors == 2 {
        return two_color_into(adj_start, adj, frontier, out);
    }

    adjacent.clear();
    adjacent.resize(n * k, 0);
    sat.clear();
    sat.resize(n, 0);
    pick.clear();
    pick.resize(n, 0);
    next.clear();
    next.resize(n, 0);
    used.clear();
    used.resize(n + 1, 0);
    queue.reset(n, k, adj_start);

    let mut budget = COLOR_SEARCH_BUDGET.max(node_count.saturating_mul(BUDGET_STEPS_PER_NODE));
    let mut unplaceable = u32::MAX;
    let mut depth = 0usize;
    pick[0] = queue.pick_checked(out, sat, adj_start);

    loop {
        if depth == n {
            break;
        }
        let node = pick[depth] as usize;
        // Symmetry breaking: colours are interchangeable names, so a colour
        // past the ones already used is a rename of the first unused one.
        // `used[depth]` counts the distinct colours placed above this depth,
        // which is the highest plus one because they are handed out
        // contiguously. The saturation and tie-breaks are invariant under
        // renaming, so the search order is the same in every branch this
        // prunes — which is what keeps it complete.
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
            // The node leaves the queue before its neighbours are touched: it
            // has no self-loop, so its own saturation is still what it was when
            // it was picked and the undo below can restore that level.
            queue.remove(pick[depth], sat[node]);
            for &neighbour in &adj[adj_start[node] as usize..adj_start[node + 1] as usize] {
                let nb = neighbour as usize;
                let slot = nb * k + usize::from(color);
                let bump = u32::from(adjacent[slot] == 0);
                adjacent[slot] += 1;
                // A coloured neighbour is in no bucket, and a saturation that
                // did not move needs no move.
                if bump == 1 && out[nb] == UNCOLORED {
                    queue.shift(neighbour, sat[nb], sat[nb] + 1);
                }
                sat[nb] += bump;
            }
            depth += 1;
            if depth < n {
                pick[depth] = queue.pick_checked(out, sat, adj_start);
                next[depth] = 0;
            }
        } else {
            // A node that ran out of colours *before* trying one is a node the
            // search could not place; one that exhausted its palette after
            // placing it is not. `wrapping_sub` turns the second case into
            // `u32::MAX`, which loses every `min`.
            let virgin = u32::from(next[depth] == 0);
            unplaceable = unplaceable.min(pick[depth] | virgin.wrapping_sub(1));
            if depth == 0 {
                out.clear();
                debug_assert!(
                    unplaceable < node_count,
                    "an exhausted search bottoms out on a node with no colour left"
                );
                return Coloring::Infeasible {
                    node: unplaceable.min(node_count - 1),
                };
            }
            depth -= 1;
            let placed = pick[depth] as usize;
            let color = out[placed];
            debug_assert!(color < colors, "backtracking over an unplaced node");
            for &neighbour in &adj[adj_start[placed] as usize..adj_start[placed + 1] as usize] {
                let nb = neighbour as usize;
                let slot = nb * k + usize::from(color);
                adjacent[slot] -= 1;
                let drop = u32::from(adjacent[slot] == 0);
                // Mirror of the placement branch.
                if drop == 1 && out[nb] == UNCOLORED {
                    queue.shift(neighbour, sat[nb], sat[nb] - 1);
                }
                sat[nb] -= drop;
            }
            out[placed] = UNCOLORED;
            queue.insert(pick[depth], sat[placed]);
        }
    }

    debug_assert_eq!(out.len(), n, "a complete colouring names every node");
    debug_assert!(
        out.iter().all(|&color| color < colors),
        "a complete colouring stays inside the palette"
    );
    debug_assert!(
        conflicts
            .iter()
            .all(|&(a, b)| out[a as usize] != out[b as usize]),
        "a complete colouring puts no conflicting pair on one mask"
    );
    Coloring::Complete
}

/// Not a colour. The palette is at most `u8::MAX` wide and colours run
/// `0 .. colors`, so the top value is free to mean "unassigned".
const UNCOLORED: u8 = u8::MAX;

/// Bits the DSATUR key spends on the node index, and on the degree beside it.
const IDX_BITS: u32 = 28;
const IDX_MASK: u64 = (1 << IDX_BITS) - 1;

/// The next node DSATUR would colour: highest saturation, then highest degree,
/// then lowest index.
///
/// **The reference implementation, not the production path.** [`SatQueue`]
/// answers the same question incrementally and
/// [`SatQueue::pick_checked`] asserts the two agree under `debug_assertions`.
fn dsatur_pick(color: &[u8], sat: &[u32], adj_start: &[u32]) -> u32 {
    debug_assert_eq!(color.len(), sat.len(), "one saturation per node");
    debug_assert_eq!(
        adj_start.len(),
        color.len() + 1,
        "adjacency is CSR over nodes"
    );

    // The three tie-breaks packed into one key: saturation on top, then degree,
    // then the index complemented so a lower one sorts higher. An assigned node
    // keys to zero and a real key never is.
    let mut best = 0u64;
    for node in 0..color.len() {
        let free = u64::from(color[node] == UNCOLORED);
        let degree = u64::from(adj_start[node + 1] - adj_start[node]) & IDX_MASK;
        let key = (u64::from(sat[node]) << (2 * IDX_BITS))
            | (degree << IDX_BITS)
            | (!(node as u64) & IDX_MASK);
        best = best.max(key * free);
    }
    debug_assert!(best != 0, "dsatur_pick was asked for a node with none left");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked to IDX_BITS, and color_into asserts the node count fits in them"
    )]
    let node = (!best & IDX_MASK) as u32;
    debug_assert!(
        color[node as usize] == UNCOLORED,
        "dsatur_pick returned a node that is already coloured"
    );
    node
}

/// Two masks, decided exactly and without search, under [`color_into`]'s
/// contract on `out`.
///
/// Every component is visited from its lowest-indexed member, which is what
/// makes the reported node canonical. [`Coloring::Exhausted`] is unreachable.
fn two_color_into(
    adj_start: &[u32],
    adj: &[u32],
    frontier: &mut Vec<u32>,
    out: &mut Vec<u8>,
) -> Coloring {
    let n = out.len();
    debug_assert_eq!(adj_start.len(), n + 1, "adjacency is CSR over nodes");
    debug_assert!(
        out.iter().all(|&color| color == UNCOLORED),
        "the bipartite pass starts from a blank colour column"
    );

    // One frontier for the whole layer: a node enters it once, so the cursor
    // never rewinds and the buffer is sized by the node count in total.
    frontier.clear();
    frontier.reserve(n);
    let mut head = 0usize;

    #[allow(
        clippy::cast_possible_truncation,
        reason = "color_into asserts the node count fits in 28 bits"
    )]
    let node_count = n as u32;
    for root_id in 0..node_count {
        let root = root_id as usize;
        if out[root] != UNCOLORED {
            continue;
        }
        out[root] = 0;
        frontier.push(root_id);

        // Accumulated rather than returned early: an early exit would make the
        // answer depend on which edge the walk happened to reach first.
        let mut odd = false;
        while head < frontier.len() {
            let node = frontier[head] as usize;
            head += 1;
            let here = out[node];
            let other = here ^ 1;
            for &neighbour in &adj[adj_start[node] as usize..adj_start[node + 1] as usize] {
                let nb = neighbour as usize;
                odd |= out[nb] == here;
                // `UNCOLORED` can never equal `here`, so the two tests cannot
                // both fire.
                if out[nb] == UNCOLORED {
                    out[nb] = other;
                    frontier.push(neighbour);
                }
            }
        }

        if odd {
            out.clear();
            return Coloring::Infeasible { node: root_id };
        }
    }

    debug_assert_eq!(frontier.len(), n, "every node was reached exactly once");
    debug_assert!(
        out.iter().all(|&color| color < 2),
        "a two-colouring stays inside a palette of two"
    );
    Coloring::Complete
}

/// The uncoloured nodes, bucketed by saturation and ranked by the remaining
/// DSATUR tie-breaks.
///
/// Within a bucket the order is *static* — degree and index do not change — so
/// nodes are ranked once and a bucket is a bitset over ranks.
///
/// [`Default`] is storage, not a usable queue; [`SatQueue::reset`] sizes it.
#[derive(Debug, Default)]
struct SatQueue {
    /// Nodes in DSATUR tie-break order: highest degree first, and among equal
    /// degrees the lowest index first. `by_rank[r]` is the node at rank `r`.
    by_rank: Vec<u32>,
    /// The inverse permutation: `rank[node]` is that node's slot in `by_rank`.
    rank: Vec<u32>,
    /// One rank bitset per saturation level, `words` words each. Bit `r` of
    /// bucket `s` is set exactly when `by_rank[r]` is uncoloured with
    /// saturation `s`.
    bits: Vec<u64>,
    /// One bit per word of `bits`, set when that word is non-zero.
    summary: Vec<u64>,
    /// Live nodes per bucket, so the top non-empty level is a counter read
    /// rather than a scan.
    count: Vec<u32>,
    words: usize,
    summary_words: usize,
}

impl SatQueue {
    /// Every node uncoloured at saturation zero, ranked by the static
    /// tie-breaks.
    ///
    /// Nothing is carried over: a live bit past rank `n - 1` would make
    /// [`lowest_rank`](Self::lowest_rank) name a node this graph does not have,
    /// which is what the exit assertions check.
    fn reset(&mut self, n: usize, k: usize, adj_start: &[u32]) {
        debug_assert!(n > 0, "an empty graph never reaches the search");
        debug_assert_eq!(adj_start.len(), n + 1, "adjacency is CSR over nodes");

        self.words = n.div_ceil(64);
        self.summary_words = self.words.div_ceil(64);
        let (words, summary_words) = (self.words, self.summary_words);

        self.by_rank.clear();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "color_into asserts the node count fits in 28 bits"
        )]
        self.by_rank.extend(0..n as u32);
        // One packed key: the degree complemented so the highest sorts first,
        // then the index so the lowest does. The keys are distinct, so the
        // order is total and the search stays canonical.
        self.by_rank.sort_unstable_by_key(|&node| {
            let degree = adj_start[node as usize + 1] - adj_start[node as usize];
            (u64::from(!degree) << 32) | u64::from(node)
        });

        self.rank.clear();
        self.rank.resize(n, 0);
        // Inverting a permutation is a scatter: the output index is the value.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "r < n, and color_into asserts n fits in 28 bits"
        )]
        for (r, &node) in self.by_rank.iter().enumerate() {
            self.rank[node as usize] = r as u32;
        }

        self.bits.clear();
        self.bits.resize((k + 1) * words, 0);
        self.summary.clear();
        self.summary.resize((k + 1) * summary_words, 0);
        self.count.clear();
        self.count.resize(k + 1, 0);
        // Bucket zero starts full, and the tail word is masked so no bit past
        // node `n - 1` is ever live — `lowest_rank` would otherwise hand back a
        // rank that indexes nothing.
        self.bits[..words].fill(!0);
        self.bits[words - 1] >>= (64 - n % 64) % 64;
        self.summary[..summary_words].fill(!0);
        self.summary[summary_words - 1] >>= (64 - words % 64) % 64;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "color_into asserts the node count fits in 28 bits"
        )]
        let full = n as u32;
        self.count[0] = full;

        debug_assert_eq!(
            self.bits.iter().map(|w| w.count_ones()).sum::<u32>(),
            full,
            "a reset queue holds every node exactly once: a different population \
             means a bit survived the previous graph"
        );
        debug_assert_eq!(
            self.count.iter().sum::<u32>(),
            full,
            "the bucket counters agree with the bitsets they summarise"
        );
    }

    /// Add an uncoloured node at saturation `sat`.
    fn insert(&mut self, node: u32, sat: u32) {
        let (word, bit, sword, sbit) = self.slots(node, sat);
        debug_assert_eq!(
            self.bits[word] >> bit & 1,
            0,
            "a node was inserted into a bucket it is already in"
        );
        self.bits[word] |= 1 << bit;
        self.summary[sword] |= 1 << sbit;
        self.count[sat as usize] += 1;
    }

    /// Take a node out of saturation level `sat`.
    fn remove(&mut self, node: u32, sat: u32) {
        let (word, bit, sword, sbit) = self.slots(node, sat);
        debug_assert_eq!(
            self.bits[word] >> bit & 1,
            1,
            "a node was removed from a bucket it is not in"
        );
        self.bits[word] &= !(1 << bit);
        // The summary bit goes only when the word empties.
        let emptied = u64::from(self.bits[word] == 0);
        self.summary[sword] &= !(emptied << sbit);
        self.count[sat as usize] -= 1;
    }

    /// Move a node between two saturation levels.
    fn shift(&mut self, node: u32, from: u32, to: u32) {
        debug_assert_ne!(from, to, "a shift that moves nothing is a caller bug");
        self.remove(node, from);
        self.insert(node, to);
    }

    /// The four indices one node's bit lives at.
    fn slots(&self, node: u32, sat: u32) -> (usize, usize, usize, usize) {
        debug_assert!(
            (sat as usize) < self.count.len(),
            "saturation cannot exceed the palette size"
        );
        let r = self.rank[node as usize] as usize;
        let s = sat as usize;
        (
            s * self.words + r / 64,
            r % 64,
            s * self.summary_words + r / 64 / 64,
            r / 64 % 64,
        )
    }

    /// The node DSATUR would colour next.
    fn pick(&self) -> u32 {
        let sat = (0..self.count.len())
            .rev()
            .find(|&s| self.count[s] != 0)
            .expect("the queue was asked for a node with none left");
        self.lowest_rank(sat)
    }

    /// [`pick`](Self::pick), differenced against [`dsatur_pick`] in debug
    /// builds.
    fn pick_checked(&self, color: &[u8], sat: &[u32], adj_start: &[u32]) -> u32 {
        let node = self.pick();
        debug_assert_eq!(
            node,
            dsatur_pick(color, sat, adj_start),
            "the saturation queue and the reference argmax chose different nodes"
        );
        node
    }

    /// The lowest live rank in one bucket, through the summary level.
    fn lowest_rank(&self, sat: usize) -> u32 {
        let sbase = sat * self.summary_words;
        let sword = self.summary[sbase..sbase + self.summary_words]
            .iter()
            .position(|&w| w != 0)
            .expect("a bucket with a live count has a set summary word");
        let word = sword * 64 + self.summary[sbase + sword].trailing_zeros() as usize;
        let live = self.bits[sat * self.words + word];
        debug_assert_ne!(live, 0, "a set summary bit names a non-empty word");
        self.by_rank[word * 64 + live.trailing_zeros() as usize]
    }
}

/// Check every multi-patterning rule.
///
/// **A node is a figure, not a row.** Two rows that touch print as one shape
/// and go on one mask, so they are merged before colouring. Skipping the merge
/// is fail-open rather than merely coarse: contracting a touching pair can
/// *create* an odd cycle the uncontracted graph does not carry, so an
/// unmanufacturable layer would read as two-colourable. A figure is named by
/// the lowest row in it, so an [`Coloring::Infeasible`] node is still a store
/// row; non-representative rows stay as isolated nodes and change no verdict.
///
/// One violation per uncolourable layer, on the shape
/// [`Coloring::Infeasible`] names — the defect is the cycle, not any member of
/// it — at the centre of that shape's box, with no partner shape. `measured` is
/// `Count(colors + 1)`: infeasibility proves the layer needs more masks than
/// the process has, and one more is the smallest count that claim licences.
///
/// `examined` counts shapes on the layer, including on a budget exhaustion, so
/// a report can tell "checked 40 000 shapes, colourable" from "gave up after
/// 40 000 shapes".
pub fn check_multi_patterning(
    design: Design<'_>,
    table: &MultiPatterningTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Disjoint borrows out of one `Scratch`.
    let Scratch {
        layer_a,
        index_a,
        pairs,
        edges,
        labels,
        areas,
        colors: colouring,
        ..
    } = scratch;

    // Hoisted out of the row loop so the search buffers grow to the largest
    // layer once rather than once per layer.
    let mut coloring_scratch = ColorScratch::default();

    for row in 0..table.len() {
        let rule = table.rule[row];
        let layer = table.layer[row];
        let colors = table.colors[row];
        let spacing = table.color_spacing[row];
        let before = out.len();
        debug_assert!(
            spacing.raw() >= 0 && spacing.raw() <= MAX_ABS_DBU,
            "a colour spacing outside the coordinate domain is a deck error"
        );

        let shapes = design.store.polys_on_layer(layer);
        let examined = u64::from(shapes.end - shapes.start);
        if examined == 0 {
            record_run(
                runs,
                out,
                before,
                rule,
                Outcome::Skipped(SkipReason::EmptyLayer),
                0,
            );
            continue;
        }

        // Geometry this tool cannot represent exactly is a refusal, never a
        // clean answer. The nodes below are store rows rather than validated
        // polygons because a violation names a `PolyId` and a validated index
        // cannot be resolved back to one.
        if validate_layer_into(design.store, layer, layer_a).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, examined);
            continue;
        }

        let first_row = shapes.start;
        let node_count = shapes.end - shapes.start;
        SpatialIndex::build_into(design.store, layer, index_a);
        candidate_pairs_into(design.store, index_a, spacing, pairs);
        debug_assert!(
            pairs
                .iter()
                .all(|&(a, b)| shapes.contains(&a.0) && shapes.contains(&b.0) && a.0 < b.0),
            "the same-layer prune emits pairs of rows on the layer, low row first"
        );

        // 1. Exact separation per candidate pair, measured once for both steps.
        let pair_count = pairs.len();
        areas.clear();
        areas.reserve(pair_count);
        areas.extend(
            pairs[..pair_count]
                .iter()
                .map(|&(a, b)| poly_dist2(design.store, a, b)),
        );

        // 2. Merged figures. A touching pair is one wire, not two shapes racing
        //    for two masks; a pair that does not touch becomes a self-edge,
        //    which the union-find treats as the no-op it is.
        debug_assert_eq!(pairs.len(), areas.len(), "SoA columns must agree");
        edges.clear();
        edges.reserve(pair_count);
        for i in 0..pair_count {
            let (a, b) = pairs[i];
            let d2 = areas[i];
            let (ra, rb) = (a.0 - first_row, b.0 - first_row);
            let touching = u32::from(d2.raw() == 0);
            edges.push((ra, ra + touching * (rb - ra)));
        }
        components_into(node_count, edges, labels);
        debug_assert_eq!(labels.len(), node_count as usize, "one label per row");

        // 3. Conflict edges between distinct figures. The prune is inclusive
        //    and built at the same radius, so every conflicting pair is already
        //    in `pairs` and this only ever removes. A non-conflict becomes a
        //    self-edge, which the compact below drops.
        let limit2 = spacing.mul_wide(spacing);
        debug_assert_eq!(pairs.len(), areas.len(), "SoA columns must agree");
        edges.clear();
        edges.reserve(pair_count);
        for i in 0..pair_count {
            let (a, b) = pairs[i];
            let d2 = areas[i];
            let fa = labels[(a.0 - first_row) as usize].0;
            let fb = labels[(b.0 - first_row) as usize].0;
            // Blend rather than `fa + close * (fb - fa)`: a figure label is the
            // minimum row of its component, so the subtraction would underflow.
            let close = u32::from(d2 < limit2).wrapping_neg();
            edges.push((fa, (fb & close) | (fa & !close)));
        }

        // Drop the self-edges step 3 marked a non-conflict with. `kept <= i`
        // throughout — `bool` is 0 or 1, so the cursor advances by at most one
        // per iteration — which is why the in-place store can never clobber a
        // row this pass has not read yet.
        let mut kept = 0usize;
        for i in 0..edges.len() {
            let (u, v) = edges[i];
            debug_assert!(kept <= i);
            edges[kept] = (u, v);
            kept += usize::from(u != v);
        }
        debug_assert!(
            kept <= pairs.len(),
            "the conflict graph is a subset of the prune"
        );
        edges.truncate(kept);

        let coloring = color_into_with(&mut coloring_scratch, node_count, edges, colors, colouring);
        debug_assert_eq!(
            colouring.len(),
            usize::from(coloring == Coloring::Complete) * node_count as usize,
            "a colouring buffer is full on Complete and empty on anything else"
        );

        let outcome = match coloring {
            Coloring::Complete => Outcome::Ran,
            // Not a violation and not clean: the search gave up.
            Coloring::Exhausted => Outcome::Refused,
            Coloring::Infeasible { node } => {
                debug_assert!(node < node_count, "the named node is a shape on this layer");
                let poly = PolyId(shapes.start + node);
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: centre(design.store.poly_bbox(poly)),
                    measured: Measurement::Count(u32::from(colors) + 1),
                    limit: Measurement::Count(u32::from(colors)),
                    shapes: (poly, None),
                });
                Outcome::Ran
            }
        };
        record_run(runs, out, before, rule, outcome, examined);
    }
}

#[cfg(test)]
mod tests {
    use super::{color_into, color_into_with, ColorScratch, Coloring};

    /// A reused scratch answers exactly what a fresh one does.
    ///
    /// The graphs are ordered largest first: a shrinking node count is where a
    /// `resize` without a `clear` would leave the previous answer's tail.
    #[test]
    fn a_reused_color_scratch_answers_what_a_fresh_one_does() {
        /// One case: node count, palette size, and the conflict edges.
        type Graph<'e> = (u32, u8, &'e [(u32, u32)]);

        // An odd cycle, a four-clique, a path, a triangle, an edgeless graph.
        let graphs: [Graph<'_>; 5] = [
            (
                7,
                3,
                &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 0)],
            ),
            (4, 3, &[(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]),
            (6, 2, &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]),
            (3, 2, &[(0, 1), (1, 2), (2, 0)]),
            (5, 3, &[]),
        ];

        let mut shared = ColorScratch::default();
        let mut reused = Vec::new();
        let mut fresh = Vec::new();
        for &(nodes, palette, edges) in &graphs {
            let a = color_into_with(&mut shared, nodes, edges, palette, &mut reused);
            let b = color_into(nodes, edges, palette, &mut fresh);
            assert_eq!(
                a, b,
                "a reused scratch changed the verdict for {nodes} nodes"
            );
            assert_eq!(
                reused, fresh,
                "a reused scratch changed the colouring for {nodes} nodes"
            );
            assert_eq!(
                reused.len(),
                usize::from(a == Coloring::Complete) * nodes as usize,
                "the buffer contract survives reuse: full on Complete, empty otherwise"
            );
        }
    }
}
