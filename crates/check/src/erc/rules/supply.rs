//! Supply, substrate and pad integrity: topological but geometry-aware, and
//! independent of design intent (a supply short is an n-tie and a p-tie on one
//! conductor, provable from the deck's tap markers).
//!
//! Data in: the store, nets, devices, [`NetFacts`]. Data out: violations and
//! one run per row.

use crate::erc::facts::{NetFacts, RoleMask};
use crate::erc::ruleset::RuleHead;
use crate::erc::{first_vertex, push_net_violations, record_run, Design, Scratch};
use crate::report::{Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::NetId;
use gpurify_geom::connectivity::components_into;
use gpurify_geom::ops::{isqrt, point_seg_dist2, segments_intersect, Point, Seg};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, RingRef};
use gpurify_geom::{Dbu, DbuArea};

/// One conductor carrying both tap layers.
#[derive(Debug, Default)]
pub struct SupplyShortTable {
    pub head: RuleHead,
    pub tap_a: Vec<LayerId>,
    pub tap_b: Vec<LayerId>,
}

/// A net that falls into several components once its resistive (soft) layers
/// are removed.
#[derive(Debug, Default)]
pub struct SoftConnectionTable {
    pub head: RuleHead,
    /// `soft[soft_start[i] .. soft_start[i + 1]]` are row `i`'s soft layers.
    pub soft_start: Vec<u32>,
    pub soft: Vec<LayerId>,
}

/// A point of a region further than `max_distance` from every tap.
#[derive(Debug, Default)]
pub struct MissingTieTable {
    pub head: RuleHead,
    pub region: Vec<LayerId>,
    pub tap: Vec<LayerId>,
    pub max_distance: Vec<Dbu>,
}

/// A net carrying a gate and a source terminal but no drain.
#[derive(Debug, Default)]
pub struct TieHighLowTable {
    pub head: RuleHead,
}

/// A pad net reaching no protection device. A deck cannot name a clamp model,
/// so every pad net is flagged.
#[derive(Debug, Default)]
pub struct EsdTopologicalTable {
    pub head: RuleHead,
    /// Marker layer whose polygons are pads.
    pub pad: Vec<LayerId>,
}

/// One bit-or of `bit` per polygon on `layers` into its net's slot of
/// `marks` (sized `nets + 1`; `NetId::NONE` lands in the trash slot). Skipped
/// on an unextracted design, where `net_of` would panic.
fn mark_nets(design: Design<'_>, layer: LayerId, bit: u32, marks: &mut [u32]) {
    let nets = marks.len() - 1;
    if nets == 0 {
        return;
    }
    for poly in design.store.polys_on_layer(layer) {
        let slot = design.nets.net_of(PolyId(poly)).idx().min(nets);
        marks[slot] |= bit;
    }
}

/// The nets (ascending) whose mark equals `want`, ignoring the trash slot.
fn nets_marked(marks: &[u32], want: u32) -> Vec<u32> {
    (0u32..)
        .zip(&marks[..marks.len() - 1])
        .filter(|&(_, &mark)| mark == want)
        .map(|(net, _)| net)
        .collect()
}

/// Flag every net carrying both taps.
pub fn check_supply_short(
    design: Design<'_>,
    table: &SupplyShortTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let nets = design.nets.net_count();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let (tap_a, tap_b) = (table.tap_a[row], table.tap_b[row]);

        scratch.net_marks.clear();
        scratch.net_marks.resize(nets + 1, 0);
        mark_nets(design, tap_a, 1, &mut scratch.net_marks);
        mark_nets(design, tap_b, 2, &mut scratch.net_marks);
        let (a_rows, b_rows) = (
            design.store.polys_on_layer(tap_a),
            design.store.polys_on_layer(tap_b),
        );
        let examined = u64::from(a_rows.end - a_rows.start) + u64::from(b_rows.end - b_rows.start);

        push_net_violations(
            design,
            &nets_marked(&scratch.net_marks, 3),
            rule,
            table.head.severity[row],
            Measurement::Count(2),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every net that falls apart once the soft layers are removed, naming a
/// shape on each side of the bridge.
pub fn check_soft_connection(
    design: Design<'_>,
    table: &SoftConnectionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let nets = design.nets.net_count();
    let mut is_soft: Vec<bool> = Vec::new();
    let mut hard: Vec<PolyId> = Vec::new();
    let mut order: Vec<u32> = Vec::new();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let span = table.soft_start[row] as usize..table.soft_start[row + 1] as usize;

        // A layer named twice is marked once.
        is_soft.clear();
        is_soft.resize(design.store.layer_count(), false);
        scratch.net_marks.clear();
        scratch.net_marks.resize(nets + 1, 0);
        for &layer in &table.soft[span] {
            if !is_soft[layer.idx()] {
                is_soft[layer.idx()] = true;
                mark_nets(design, layer, 1, &mut scratch.net_marks);
            }
        }
        let soft_nets = nets_marked(&scratch.net_marks, 1);

        for &net in &soft_nets {
            // What is left without the resistive body is what one potential holds.
            hard.clear();
            hard.extend(
                design
                    .nets
                    .polys_of(NetId(net))
                    .iter()
                    .copied()
                    .filter(|&poly| !is_soft[design.store.poly_layer(poly).idx()]),
            );
            let Some(&first_poly) = hard.first() else {
                continue;
            };
            scratch.boxes.clear();
            scratch
                .boxes
                .extend(hard.iter().map(|&p| design.store.poly_bbox(p)));

            // Join conductors that share a point (not just a box); the box test
            // and an x-order sweep prune in front of the exact one.
            let node_count = u32::try_from(hard.len()).expect("a net's polygons fit a u32");
            order.clear();
            order.extend(0..node_count);
            order.sort_unstable_by_key(|&i| scratch.boxes[i as usize].xlo);
            scratch.edges.clear();
            for i in 0..order.len() {
                let a = order[i];
                let box_a = scratch.boxes[a as usize];
                for &b in &order[i + 1..] {
                    let box_b = scratch.boxes[b as usize];
                    if box_b.xlo > box_a.xhi {
                        break;
                    }
                    if box_a.overlaps(box_b)
                        && polys_meet(design.store, hard[a as usize], hard[b as usize])
                    {
                        scratch.edges.push((a, b));
                    }
                }
            }
            components_into(node_count, &scratch.edges, &mut scratch.labels);

            // The lowest-numbered conductor not in the first one's component.
            let near = scratch.labels[0];
            let Some(far) = scratch.labels.iter().position(|&label| label != near) else {
                continue;
            };
            out.push(Violation {
                rule,
                layer: design.store.poly_layer(first_poly),
                severity: table.head.severity[row],
                at: first_vertex(design.store, first_poly),
                measured: Measurement::Count(2),
                limit: Measurement::Count(1),
                shapes: (first_poly, Some(hard[far])),
            });
        }

        let examined = u64::try_from(soft_nets.len()).expect("a net count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every region polygon whose furthest point is more than `max_distance`
/// from a tap, reporting that exact furthest point. Distances are compared
/// squared, in integers.
pub fn check_missing_tie(
    design: Design<'_>,
    table: &MissingTieTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let mut taps: Vec<Seg> = Vec::new();
    let mut grid = TapGrid::default();
    let mut stack: Vec<Cell> = Vec::new();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        // A tap layer that will not validate is refused, never read as empty.
        if validate_layer_into(design.store, table.tap[row], &mut scratch.layer_b).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let tap = &scratch.layer_b;

        let limit = table.max_distance[row];
        let limit2 = limit.mul_wide(limit);

        // Holes too: a ring-shaped tap ties along its inner boundary.
        taps.clear();
        for idx in 0..tap.len() {
            let idx = u32::try_from(idx).expect("a validated layer's polygons fit a u32");
            let poly = tap.get(idx);
            push_ring_edges(poly.outer(), &mut taps);
            for hole in poly.holes() {
                push_ring_edges(hole, &mut taps);
            }
        }
        // Coincident edges measure alike; keyed undirected because abutting
        // taps run a shared edge in opposite directions.
        taps.sort_unstable_by_key(undirected);
        taps.dedup_by_key(|s| undirected(s));
        TapGrid::build_into(&taps, &mut grid);

        let region_rows = design.store.polys_on_layer(table.region[row]);
        let examined = u64::from(region_rows.end - region_rows.start);
        for poly in region_rows {
            let poly = PolyId(poly);
            let (xs, ys) = design.store.poly_verts(poly);
            let Some((&x0, &y0)) = xs.first().zip(ys.first()) else {
                continue;
            };
            // No taps at all: the sentinel, whose root is `MAX_ABS_DBU`.
            let (at, worst) = if taps.is_empty() {
                (Point { x: x0, y: y0 }, NO_TAP_IN_RANGE)
            } else {
                // `limit2` is the search's floor, so a region under the limit
                // prunes without descending.
                furthest_from_taps(
                    xs,
                    ys,
                    design.store.poly_bbox(poly),
                    limit2,
                    &grid,
                    &mut stack,
                )
            };
            if worst > limit2 {
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(poly),
                    severity: table.head.severity[row],
                    at,
                    measured: Measurement::Length(isqrt(worst)),
                    limit: Measurement::Length(limit),
                    shapes: (poly, None),
                });
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every net that is a gate and a source and not a drain. `examined`
/// counts gate nets.
pub fn check_tie_high_low(
    design: Design<'_>,
    facts: &NetFacts,
    table: &TieHighLowTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let held = RoleMask::GATE.union(RoleMask::SOURCE);
    let examined = facts
        .role
        .iter()
        .filter(|mask| mask.contains(RoleMask::GATE))
        .count() as u64;
    let flagged: Vec<u32> = (0u32..)
        .zip(&facts.role)
        .filter(|&(_, &mask)| mask.contains(held) & !mask.intersects(RoleMask::DRAIN))
        .map(|(net, _)| net)
        .collect();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every pad net: a deck cannot list a clamp model, so none is protected.
pub fn check_esd_topological(
    design: Design<'_>,
    table: &EsdTopologicalTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let nets = design.nets.net_count();
    let mut on_a_pad: Vec<u32> = Vec::new();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        on_a_pad.clear();
        on_a_pad.resize(nets + 1, 0);
        mark_nets(design, table.pad[row], 1, &mut on_a_pad);
        let pad_nets = nets_marked(&on_a_pad, 1);
        push_net_violations(
            design,
            &pad_nets,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        let examined = u64::try_from(pad_nets.len()).expect("a net count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// One segment's endpoints in ascending order — its identity ignoring which way
/// round it was drawn.
fn undirected(s: &Seg) -> (i64, i64, i64, i64) {
    let (p, q) = ((s.a.x.raw(), s.a.y.raw()), (s.b.x.raw(), s.b.y.raw()));
    let (lo, hi) = (p.min(q), p.max(q));
    (lo.0, lo.1, hi.0, hi.1)
}

/// Append one ring's closed edges to a segment column.
fn push_ring_edges(ring: RingRef<'_>, out: &mut Vec<Seg>) {
    let (xs, ys) = ring.coords();
    out.reserve(xs.len());
    for vertex in 0..xs.len() {
        out.push(ring_edge(xs, ys, vertex));
    }
}

/// The closed edge from vertex `i` of a ring to the next one, wrapping.
#[inline]
fn ring_edge(xs: &[Dbu], ys: &[Dbu], i: usize) -> Seg {
    let next = (i + 1) - xs.len() * usize::from(i + 1 == xs.len());
    Seg {
        a: Point { x: xs[i], y: ys[i] },
        b: Point {
            x: xs[next],
            y: ys[next],
        },
    }
}

/// Whether two polygons share at least one point. Rings whose boundaries do
/// not meet are nested or disjoint, so one vertex of each decides the rest.
fn polys_meet(store: &GeometryStore, a: PolyId, b: PolyId) -> bool {
    let (ax, ay) = store.poly_verts(a);
    let (bx, by) = store.poly_verts(b);

    // `ingest` may carry a degenerate run, which bounds no area.
    if ax.len() < 3 || bx.len() < 3 {
        return false;
    }

    rings_meet(ax, ay, bx, by)
        || point_in_region(bx, by, Point { x: ax[0], y: ay[0] })
        || point_in_region(ax, ay, Point { x: bx[0], y: by[0] })
}

/// Whether any edge of one ring meets any edge of the other, touching included.
fn rings_meet(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    for i in 0..ax.len() {
        let edge = ring_edge(ax, ay, i);
        for j in 0..bx.len() {
            if segments_intersect(edge, ring_edge(bx, by, j)) {
                return true;
            }
        }
    }
    false
}

/// Whether a point lies in a ring, boundary included (the missing-tie maximum
/// often sits on an edge). Even-odd ray cast toward +x, exact in `i128`.
/// Deliberately not folded with `topology::inside_ring`, which excludes the
/// boundary.
fn point_in_region(xs: &[Dbu], ys: &[Dbu], p: Point) -> bool {
    if xs.len() < 3 {
        return false;
    }

    let zero = DbuArea::new(0);
    let mut inside = false;
    for i in 0..xs.len() {
        let edge = ring_edge(xs, ys, i);
        if point_seg_dist2(p, edge) == zero {
            return true;
        }

        // Half-open crossing rule, then the side test.
        let dy = i128::from(edge.b.y.raw() - edge.a.y.raw());
        let dx = i128::from(edge.b.x.raw() - edge.a.x.raw());
        let lhs = i128::from(p.x.raw() - edge.a.x.raw()) * dy;
        let rhs = i128::from(p.y.raw() - edge.a.y.raw()) * dx;
        let straddles = (edge.a.y > p.y) != (edge.b.y > p.y);
        inside ^= straddles & ((lhs - rhs) * dy.signum() < 0);
    }
    inside
}

/// The square root of a non-negative area, rounded up: an upper bound rounded
/// down (as `ops::isqrt` does) would prune away the maximum.
fn isqrt_ceil(area: i128) -> i64 {
    let root = area.isqrt();
    let root = root + i128::from(root * root != area);
    i64::try_from(root).expect("the root of an in-domain area is a length")
}

/// Target segments per [`TapGrid`] bucket. Tuned by measurement.
const BUCKET_TARGET: i64 = 16;

/// Whether no point of a cell can be further from a tap than the best found:
/// `sqrt(d2) + reach <= worst_root`, squared. `worst_root` is floored, so this
/// prunes slightly too rarely, never too often. The sign test is required.
#[inline]
fn prunes(worst_root: i64, reach: i64, d2: DbuArea) -> bool {
    let slack = i128::from(worst_root - reach);
    (slack >= 0) & (d2.raw() <= slack * slack)
}

/// A closed block of integer points in [`furthest_from_taps`]'s search.
#[derive(Debug, Clone, Copy)]
struct Cell {
    xlo: i64,
    ylo: i64,
    xhi: i64,
    yhi: i64,
    /// Index into [`TapGrid::segs`] of the tap nearest the parent's probe.
    hint: u32,
}

/// The nearest tap to some point: how far, and which one.
#[derive(Debug, Clone, Copy)]
struct Nearest {
    dist2: DbuArea,
    /// Index into [`TapGrid::segs`], or [`u32::MAX`] when nothing was scanned.
    tap: u32,
}

impl Nearest {
    const NONE: Self = Self {
        dist2: NO_TAP_IN_RANGE,
        tap: u32::MAX,
    };

    /// Keep whichever is nearer; the earlier wins a tie.
    #[inline]
    fn keep(&mut self, other: Self) {
        let mask = u32::from(other.dist2 < self.dist2).wrapping_neg();
        self.tap = (self.tap & !mask) | (other.tap & mask);
        self.dist2 = self.dist2.min(other.dist2);
    }
}

/// A uniform grid over one row's tap edges. A segment is filed under every
/// cell its bounding box overlaps, which makes the ring search's stop sound.
#[derive(Debug)]
struct TapGrid {
    origin: Point,
    cell: i64,
    nx: i64,
    ny: i64,
    /// `start[b] .. start[b + 1]` indexes `segs`.
    start: Vec<u32>,
    segs: Vec<Seg>,
    /// Build scratch.
    extents: Vec<i64>,
    cursor: Vec<u32>,
}

impl Default for TapGrid {
    fn default() -> Self {
        Self {
            origin: Point {
                x: Dbu::new_unchecked(0),
                y: Dbu::new_unchecked(0),
            },
            cell: 1,
            nx: 0,
            ny: 0,
            start: Vec::new(),
            segs: Vec::new(),
            extents: Vec::new(),
            cursor: Vec::new(),
        }
    }
}

impl TapGrid {
    /// Build over one row's tap edges; an empty column leaves an empty grid
    /// that must not be probed.
    fn build_into(taps: &[Seg], out: &mut Self) {
        out.start.clear();
        out.segs.clear();
        out.cursor.clear();
        out.cell = 1;
        out.nx = 0;
        out.ny = 0;
        out.origin = Point {
            x: Dbu::new_unchecked(0),
            y: Dbu::new_unchecked(0),
        };
        if taps.is_empty() {
            return;
        }

        let mut extent = Bbox::EMPTY;
        for s in taps {
            extent = extent.include(s.a.x, s.a.y).include(s.b.x, s.b.y);
        }
        let span_x = extent.xhi.raw() - extent.xlo.raw() + 1;
        let span_y = extent.yhi.raw() - extent.ylo.raw() + 1;

        // Cell: the median segment extent, widened until there are about
        // `taps.len() / BUCKET_TARGET` buckets.
        out.extents.clear();
        out.extents.reserve(taps.len());
        out.extents.extend(taps.iter().map(|s| {
            (s.b.x.raw() - s.a.x.raw())
                .abs()
                .max((s.b.y.raw() - s.a.y.raw()).abs())
        }));
        let mid = out.extents.len() / 2;
        out.extents.select_nth_unstable(mid);
        let side = (i64::try_from(taps.len()).expect("a tap edge count fits an i64")
            / BUCKET_TARGET)
            .isqrt()
            .max(1);
        let cell = out.extents[mid]
            .max(1)
            .max((span_x + side - 1) / side)
            .max((span_y + side - 1) / side);

        out.cell = cell;
        out.origin = Point {
            x: extent.xlo,
            y: extent.ylo,
        };
        out.nx = (span_x + cell - 1) / cell;
        out.ny = (span_y + cell - 1) / cell;

        let buckets = usize::try_from(out.nx * out.ny).expect("a bucket count fits a usize");
        out.start.clear();
        out.start.resize(buckets + 1, 0);

        // A counting sort: scatter-accumulate, prefix sum, scatter.
        for seg in taps {
            let (x0, y0, x1, y1) = out.cells_of(*seg);
            for cy in y0..=y1 {
                for cx in x0..=x1 {
                    let b = out.bucket(cx, cy);
                    out.start[b + 1] += 1;
                }
            }
        }
        for b in 0..buckets {
            out.start[b + 1] += out.start[b];
        }
        let total =
            usize::try_from(out.start[buckets]).expect("a filed-segment count fits a usize");
        out.segs.clear();
        out.segs
            .resize(total, *taps.first().expect("the column is not empty"));
        out.cursor.clear();
        out.cursor.extend_from_slice(&out.start[..buckets]);
        for seg in taps {
            let (x0, y0, x1, y1) = out.cells_of(*seg);
            for cy in y0..=y1 {
                for cx in x0..=x1 {
                    let b = out.bucket(cx, cy);
                    let at = usize::try_from(out.cursor[b]).expect("a write cursor fits a usize");
                    out.segs[at] = *seg;
                    out.cursor[b] += 1;
                }
            }
        }
    }

    /// The flat bucket index of one in-range cell.
    #[inline]
    fn bucket(&self, cx: i64, cy: i64) -> usize {
        usize::try_from(cy * self.nx + cx).expect("a cell inside the grid has a non-negative index")
    }

    /// The inclusive cell range one segment's bounding box covers, clamped.
    #[inline]
    fn cells_of(&self, seg: Seg) -> (i64, i64, i64, i64) {
        let (x0, x1) = (
            seg.a.x.raw().min(seg.b.x.raw()),
            seg.a.x.raw().max(seg.b.x.raw()),
        );
        let (y0, y1) = (
            seg.a.y.raw().min(seg.b.y.raw()),
            seg.a.y.raw().max(seg.b.y.raw()),
        );
        (
            self.axis_x(x0).clamp(0, self.nx - 1),
            self.axis_y(y0).clamp(0, self.ny - 1),
            self.axis_x(x1).clamp(0, self.nx - 1),
            self.axis_y(y1).clamp(0, self.ny - 1),
        )
    }

    #[inline]
    fn axis_x(&self, x: i64) -> i64 {
        (x - self.origin.x.raw()).div_euclid(self.cell)
    }

    #[inline]
    fn axis_y(&self, y: i64) -> i64 {
        (y - self.origin.y.raw()).div_euclid(self.cell)
    }

    /// One filed tap edge.
    #[inline]
    fn tap(&self, at: u32) -> Seg {
        self.segs[usize::try_from(at).expect("a filed-segment index fits a usize")]
    }

    /// The nearest tap in one cell, or [`Nearest::NONE`] when it is empty.
    #[inline]
    fn nybucket(&self, cx: i64, cy: i64, p: Point) -> Nearest {
        let b = self.bucket(cx, cy);
        let (lo, hi) = (
            usize::try_from(self.start[b]).expect("a bucket offset fits a usize"),
            usize::try_from(self.start[b + 1]).expect("a bucket offset fits a usize"),
        );
        let bucket = &self.segs[lo..hi];
        let mut best = Nearest::NONE;
        for (tap, &seg) in (self.start[b]..).zip(bucket) {
            best.keep(Nearest {
                dist2: point_seg_dist2(p, seg),
                tap,
            });
        }
        best
    }

    /// The nearest tap edge to `p`, exactly: rings of cells outward from `p`'s
    /// cell until nothing unscanned (at least `r * cell` away) can be nearer.
    fn nearest2(&self, p: Point) -> Nearest {
        let (px, py) = (self.axis_x(p.x.raw()), self.axis_y(p.y.raw()));
        let rmax = px
            .abs()
            .max((px - (self.nx - 1)).abs())
            .max(py.abs())
            .max((py - (self.ny - 1)).abs());

        let mut best = Nearest::NONE;
        let mut r = 0;
        while r <= rmax {
            let (x0, x1) = (px - r, px + r);
            let (y0, y1) = (py - r, py + r);
            for cy in y0.max(0)..=y1.min(self.ny - 1) {
                // Top and bottom rows whole; the rows between, their two ends.
                if (cy == y0) | (cy == y1) {
                    for cx in x0.max(0)..=x1.min(self.nx - 1) {
                        best.keep(self.nybucket(cx, cy, p));
                    }
                } else {
                    if (0..self.nx).contains(&x0) {
                        best.keep(self.nybucket(x0, cy, p));
                    }
                    if (0..self.nx).contains(&x1) && x1 != x0 {
                        best.keep(self.nybucket(x1, cy, p));
                    }
                }
            }

            let gap = i128::from(r) * i128::from(self.cell);
            if best.dist2.raw() <= gap * gap {
                break;
            }
            r += 1;
        }

        best
    }
}

/// The point of a region polygon furthest from any tap, and that distance
/// squared: exact whenever it exceeds `floor`, otherwise `floor` itself.
///
/// Branch and bound over the region's integer points (vertices alone miss the
/// maximum), seeded from the vertices. A cell is pruned when its probe's
/// distance plus its reach cannot beat the best; each cell inherits its
/// parent's nearest tap as a cheap upper bound, and only the exact query
/// writes `worst`.
fn furthest_from_taps(
    xs: &[Dbu],
    ys: &[Dbu],
    bbox: Bbox,
    floor: DbuArea,
    grid: &TapGrid,
    stack: &mut Vec<Cell>,
) -> (Point, DbuArea) {
    // Vertices are in the region, so need no containment test.
    let mut best = Nearest {
        dist2: DbuArea::new(-1),
        tap: 0,
    };
    let mut at = Point { x: xs[0], y: ys[0] };
    for vertex in 0..xs.len() {
        let here = Point {
            x: xs[vertex],
            y: ys[vertex],
        };
        let found = grid.nearest2(here);
        if found.dist2 > best.dist2 {
            best = found;
            at = here;
        }
    }

    // Starting at the floor prunes a region under it without descending; `at`
    // is read only when `worst` ends above the floor.
    let mut worst = best.dist2.max(floor);
    let mut worst_root = isqrt(worst).raw();

    stack.clear();
    stack.push(Cell {
        xlo: bbox.xlo.raw(),
        ylo: bbox.ylo.raw(),
        xhi: bbox.xhi.raw(),
        yhi: bbox.yhi.raw(),
        hint: best.tap,
    });
    while let Some(cell) = stack.pop() {
        let cx = cell.xlo + (cell.xhi - cell.xlo) / 2;
        let cy = cell.ylo + (cell.yhi - cell.ylo) / 2;
        let here = Point {
            x: Dbu::new_unchecked(cx),
            y: Dbu::new_unchecked(cy),
        };

        // The inherited tap is a real tap: an upper bound.
        let mut probe = Nearest {
            dist2: point_seg_dist2(here, grid.tap(cell.hint)),
            tap: cell.hint,
        };

        let rx = i128::from((cell.xhi - cx).max(cx - cell.xlo));
        let ry = i128::from((cell.yhi - cy).max(cy - cell.ylo));
        let reach = isqrt_ceil(rx * rx + ry * ry);

        if !prunes(worst_root, reach, probe.dist2) {
            let exact = grid.nearest2(here);
            probe = exact;

            if exact.dist2 > worst && point_in_region(xs, ys, here) {
                worst = exact.dist2;
                worst_root = isqrt(worst).raw();
                at = here;
            }
        }

        // Exact whenever the first test failed, so survival ignores the hint.
        if prunes(worst_root, reach, probe.dist2) {
            continue;
        }

        // A single point was just probed and cannot split.
        let splits_x = cx < cell.xhi;
        let splits_y = cy < cell.yhi;
        if !splits_x && !splits_y {
            continue;
        }

        stack.push(Cell {
            xlo: cell.xlo,
            ylo: cell.ylo,
            xhi: cx,
            yhi: cy,
            hint: probe.tap,
        });
        if splits_x {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cell.ylo,
                xhi: cell.xhi,
                yhi: cy,
                hint: probe.tap,
            });
        }
        if splits_y {
            stack.push(Cell {
                xlo: cell.xlo,
                ylo: cy + 1,
                xhi: cx,
                yhi: cell.yhi,
                hint: probe.tap,
            });
        }
        if splits_x && splits_y {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cy + 1,
                xhi: cell.xhi,
                yhi: cell.yhi,
                hint: probe.tap,
            });
        }
    }

    (at, worst)
}

/// "No tap in range": the largest area `ops::isqrt` accepts, so an untapped
/// region measures `MAX_ABS_DBU` and is reported.
const NO_TAP_IN_RANGE: DbuArea = DbuArea::new(1i128 << 80);
