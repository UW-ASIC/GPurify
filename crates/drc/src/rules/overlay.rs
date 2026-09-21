//! Overlay family: how two layers must sit relative to each other.
//!
//! **Best host, not first host.** An inner shape may sit inside several outer
//! shapes at once; the rule is satisfied if the *best* host satisfies it,
//! because after the layers are merged there is only one host and it is the
//! union. Taking the first host also depends on polygon order, so it is
//! nondeterministic as well as wrong.
//!
//! **An unhosted inner shape is zero enclosure, not skipped.** A via with no
//! metal under it violates every enclosure rule; skipping it is fail-open.

use super::{centre, mid, ring_segs, row_columns, COLUMNS_DIVERGED};
use crate::{record_run, Design, Scratch};
use gpurify_geom::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, Point};
use gpurify_geom::view::{validate_layer_into, ValidityError};
use gpurify_geom::{Bbox, LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{
    LimitSense, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use std::cmp::Reverse;

/// Minimum enclosure: the outer layer must surround the inner one by at least
/// the limit on **every** side.
#[derive(Debug, Default)]
pub struct MinEnclosureTable {
    pub rule: Vec<StrId>,
    /// The surrounding layer — metal under a via, implant around diffusion.
    pub outer: Vec<LayerId>,
    /// The surrounded layer.
    pub inner: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Asymmetric enclosure: at least the limit on **one** side of each axis.
///
/// Passes when `max(left, right) >= limit && max(top, bottom) >= limit`.
#[derive(Debug, Default)]
pub struct AsymmetricEnclosureTable {
    pub rule: Vec<StrId>,
    pub outer: Vec<LayerId>,
    pub inner: Vec<LayerId>,
    /// Required on one side of each axis. Deliberately *not* named `limit`: it
    /// means something weaker than [`MinEnclosureTable`]'s.
    pub min_one_side: Vec<Dbu>,
}

/// Minimum extension: one layer must run past another by at least the limit.
///
/// Measured only where the two shapes actually overlap, and on each side the
/// layer protrudes.
#[derive(Debug, Default)]
pub struct MinExtensionTable {
    pub rule: Vec<StrId>,
    /// The layer that must stick out.
    pub layer: Vec<LayerId>,
    /// The layer it must stick out past.
    pub reference: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Minimum overlap: two layers that meet must share at least this much.
///
/// Distinct from enclosure: a wire crossing a strap satisfies it without either
/// shape containing the other.
#[derive(Debug, Default)]
pub struct OverlapTable {
    pub rule: Vec<StrId>,
    pub a: Vec<LayerId>,
    pub b: Vec<LayerId>,
    /// The smaller side of the intersection rectangle must be at least this; a
    /// limit on *area* would pass a long thin sliver, which does not conduct.
    pub limit: Vec<Dbu>,
}

/// Maximum distance to a well tie: every point of a well must be within reach
/// of a tap.
///
/// The constraint is on the *farthest* point of the well, not on the average.
#[derive(Debug, Default)]
pub struct MaxDistanceToTapTable {
    pub rule: Vec<StrId>,
    /// The region that needs tying — well or diffusion.
    pub well: Vec<LayerId>,
    /// The tie layer.
    pub tap: Vec<LayerId>,
    /// Violated above.
    pub limit: Vec<Dbu>,
}

row_columns! {
    MinEnclosureTable { rule, outer, inner, limit },
    AsymmetricEnclosureTable { rule, outer, inner, min_one_side },
    MinExtensionTable { rule, layer, reference, limit },
    OverlapTable { rule, a, b, limit },
    MaxDistanceToTapTable { rule, well, tap, limit },
}

/// How far an outer shape extends past an inner one, per side.
///
/// The one place the sign convention is written down: positive when the outer
/// shape extends past the inner on that side, negative when the inner sticks
/// out. Negative is not an error — it is what an unhosted or overhanging shape
/// measures, and clamping it to zero would hide how badly the rule failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Margins {
    pub left: Dbu,
    pub right: Dbu,
    pub bottom: Dbu,
    pub top: Dbu,
}

/// Which of the four margins a reduction named.
///
/// Carried out of the reduction rather than re-derived: re-deriving "which side
/// was that" from the value alone ties on a symmetric shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
    Bottom,
    Top,
}

/// The smaller of two sides, the first of them on a tie.
const fn lesser(a: (Dbu, Side), b: (Dbu, Side)) -> (Dbu, Side) {
    if a.0.raw() <= b.0.raw() {
        a
    } else {
        b
    }
}

/// The larger of two sides, the first of them on a tie.
const fn greater(a: (Dbu, Side), b: (Dbu, Side)) -> (Dbu, Side) {
    if a.0.raw() >= b.0.raw() {
        a
    } else {
        b
    }
}

impl Margins {
    /// The worst side — what [`check_min_enclosure`] compares.
    pub const fn worst(self) -> Dbu {
        self.worst_sided().0
    }

    /// `min(max(left, right), max(bottom, top))` — what
    /// [`check_asymmetric_enclosure`] compares.
    pub const fn worst_axis_best_side(self) -> Dbu {
        self.worst_axis_best_side_sided().0
    }

    /// [`Margins::worst`], and which side it was.
    const fn worst_sided(self) -> (Dbu, Side) {
        lesser(
            lesser((self.left, Side::Left), (self.right, Side::Right)),
            lesser((self.bottom, Side::Bottom), (self.top, Side::Top)),
        )
    }

    /// [`Margins::worst_axis_best_side`], and which side it was.
    const fn worst_axis_best_side_sided(self) -> (Dbu, Side) {
        lesser(
            greater((self.left, Side::Left), (self.right, Side::Right)),
            greater((self.bottom, Side::Bottom), (self.top, Side::Top)),
        )
    }
}

/// The midpoint of the strip between the two boxes on one side — this family's
/// report point.
///
/// Along the named axis, the middle of the gap between the two edges; across
/// it, the range the two boxes share.
fn strip_midpoint(inner: Bbox, outer: Bbox, side: Side) -> Point {
    let cross_x = mid(inner.xlo.max(outer.xlo), inner.xhi.min(outer.xhi));
    let cross_y = mid(inner.ylo.max(outer.ylo), inner.yhi.min(outer.yhi));
    match side {
        Side::Left => Point {
            x: mid(outer.xlo, inner.xlo),
            y: cross_y,
        },
        Side::Right => Point {
            x: mid(inner.xhi, outer.xhi),
            y: cross_y,
        },
        Side::Bottom => Point {
            x: cross_x,
            y: mid(outer.ylo, inner.ylo),
        },
        Side::Top => Point {
            x: cross_x,
            y: mid(inner.yhi, outer.yhi),
        },
    }
}

/// A margin no real host can produce, and the seed of every host reduction.
///
/// Below `-2 * MAX_ABS_DBU`, the most negative margin two in-domain boxes can
/// have, so it loses to every real host without a special case. A
/// *non-containing* host folds in as this too.
const UNHOSTED: i64 = -(1 << 42);

/// A squared distance that stands for "no tap in reach".
///
/// `MAX_ABS_DBU` squared — a perfect square, so [`ceil_sqrt`] returns
/// `MAX_ABS_DBU` exactly rather than one past the domain. Fail **closed**: the
/// rule is violated *above* its limit, so a saturating distance over-reports
/// rather than silently passing an untied well.
const OUT_OF_REACH: i128 = 1 << 80;

/// Squared distance from a point to the nearest point of a box.
///
/// No assert: every operand is a `Dbu`, so the differences reach `2^41` and the
/// sum of their squares `2^83`, which `i128` holds with room.
fn point_box_dist2(x: Dbu, y: Dbu, b: Bbox) -> i128 {
    let dx = i128::from((b.xlo.raw() - x.raw()).max(x.raw() - b.xhi.raw()).max(0));
    let dy = i128::from((b.ylo.raw() - y.raw()).max(y.raw() - b.yhi.raw()).max(0));
    dx * dx + dy * dy
}

/// The distance whose square is `d2`, rounded **up**.
///
/// Up, not toward zero as [`isqrt`] alone would: an exceeded limit has to read
/// as exceeded in the report a human acts on. For an integer limit
/// `d2 > limit²` iff `ceil(sqrt(d2)) > limit`, so the comparison can happen on
/// the number that is printed.
fn ceil_sqrt(d2: i128) -> Dbu {
    debug_assert!(
        (0..=OUT_OF_REACH).contains(&d2),
        "a squared distance past the domain MAX_ABS_DBU bounds"
    );
    let root = isqrt(DbuArea::new(d2));
    let exact = root.mul_wide(root).raw() == d2;
    debug_assert!(
        root.raw() < MAX_ABS_DBU || exact,
        "only the out-of-reach sentinel reaches the domain edge, and it is a square"
    );
    Dbu::new_unchecked(root.raw() + i64::from(!exact))
}

/// The half-open range of `pairs` whose first element is `a`.
///
/// `pairs` is strictly ascending and `a` walks the same layer ascending, so the
/// cursor only ever moves forward and survives across calls: one pass over the
/// pair list per layer, amortised O(1) here.
fn run_of(pairs: &[(PolyId, PolyId)], cursor: &mut usize, a: PolyId) -> (usize, usize) {
    debug_assert!(*cursor <= pairs.len(), "the cursor is inside the pair list");
    while *cursor < pairs.len() && pairs[*cursor].0 < a {
        *cursor += 1;
    }
    let lo = *cursor;
    while *cursor < pairs.len() && pairs[*cursor].0 == a {
        *cursor += 1;
    }
    debug_assert!(
        lo <= *cursor && *cursor <= pairs.len(),
        "the run is a range"
    );
    (lo, *cursor)
}

/// Validate both operands, then prune their cross-layer pairs into `scratch`.
///
/// Validation is the fail-closed gate: geometry this tool does not represent
/// exactly is a refusal for the rule row, never a clean one.
///
/// **Known fail-open:** the measurements
/// are taken on bounding boxes. A box margin *overstates* the enclosure a
/// non-convex host gives, so an L-shaped pad leaving a via's corner uncovered
/// reads as clean. Closing it needs
/// `ValidatedLayer::provenance(&self) -> &[PolyId]` in `core` to map a pair's
/// [`PolyId`] to a validated index; that is a widened interface.
fn pair_layers(
    design: Design<'_>,
    a: LayerId,
    b: LayerId,
    distance: Dbu,
    scratch: &mut Scratch,
) -> Result<(), ValidityError> {
    debug_assert_ne!(a, b, "an overlay rule relates two different layers");
    debug_assert!(distance.raw() >= 0, "a prune distance is never negative");
    debug_assert!(
        distance.raw() <= MAX_ABS_DBU,
        "a limit past the coordinate domain is a deck error, not a query"
    );

    validate_layer_into(design.store, a, &mut scratch.layer_a)?;
    validate_layer_into(design.store, b, &mut scratch.layer_b)?;
    SpatialIndex::build_into(design.store, a, &mut scratch.index_a);
    SpatialIndex::build_into(design.store, b, &mut scratch.index_b);
    cross_layer_pairs_into(
        design.store,
        &scratch.index_a,
        &scratch.index_b,
        distance,
        &mut scratch.pairs,
    );

    debug_assert!(
        scratch.pairs.windows(2).all(|w| w[0] < w[1]),
        "the pair list is strictly ascending, which is what makes the walks above one pass"
    );
    Ok(())
}

/// Whether two axis-aligned segments cross at a point interior to both.
///
/// *Proper* crossing: a T-junction, collinear overlap and a shared endpoint are
/// all boundary contact, which is what an inner shape touching its host's edge
/// from the inside looks like.
fn segments_cross(a: (Point, Point), b: (Point, Point)) -> bool {
    // Both orderings are tested; the one that is not horizontal-and-vertical
    // fails its own guard.
    crosses_hv(a, b) | crosses_hv(b, a)
}

/// [`segments_cross`] with the roles fixed: `h` horizontal, `v` vertical.
fn crosses_hv(h: (Point, Point), v: (Point, Point)) -> bool {
    let shaped = (h.0.y == h.1.y) & (v.0.x == v.1.x);
    let (xlo, xhi) = (h.0.x.min(h.1.x), h.0.x.max(h.1.x));
    let (ylo, yhi) = (v.0.y.min(v.1.y), v.0.y.max(v.1.y));
    // Strict on all four: touching is not crossing.
    shaped & (v.0.x > xlo) & (v.0.x < xhi) & (h.0.y > ylo) & (h.0.y < yhi)
}

/// Whether the ring of `inner` lies entirely within the ring of `host`.
///
/// Two conditions, and both are needed: one vertex of `inner` is inside or on
/// `host`, and no edge of `inner` properly crosses an edge of `host`. A vertex
/// test alone is not enough — a bar whose two ends sit in the two arms of a U
/// has every vertex inside the host and spans the opening.
///
/// **Does not see holes**, since a store row is one ring: a host hole lying
/// strictly inside `inner` crosses nothing and reads as contained. Fail-open,
/// and the same missing provenance route `pair_layers` records.
fn ring_contains_ring(store: &gpurify_geom::GeometryStore, host: PolyId, inner: PolyId) -> bool {
    let (xs, ys) = store.poly_verts(inner);
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(xs.len() >= 3, "a stored ring has at least three vertices");

    // Boundary-inclusive: an inner shape flush against its host's edge is
    // contained, not unhosted.
    let anchor = Point { x: xs[0], y: ys[0] };
    if !store.poly_contains_point(host, anchor) {
        return false;
    }

    let (hxs, hys) = store.poly_verts(host);
    for si in ring_segs(xs, ys) {
        for sh in ring_segs(hxs, hys) {
            if segments_cross((si.a, si.b), (sh.a, sh.b)) {
                return false;
            }
        }
    }
    true
}

/// Enclosure margins of `inner` within `outer`, on bounding boxes.
///
/// Exact when the host is a rectangle, optimistic otherwise:
/// [`ring_contains_ring`] confirms containment before a candidate may host, but
/// the *margin* of a genuinely contained shape in a concave host can still
/// overstate.
pub fn margins(inner: Bbox, outer: Bbox) -> Margins {
    // `Sub` rather than a checked constructor: a margin legally reaches
    // `+/-2^41`, one bit past the coordinate domain, which `Sub` documents as
    // legal and `Dbu::new_unchecked` would assert on.
    Margins {
        left: inner.xlo - outer.xlo,
        right: outer.xhi - inner.xhi,
        bottom: inner.ylo - outer.ylo,
        top: outer.yhi - inner.yhi,
    }
}

/// One enclosure rule row, under whichever reduction the table's rule uses.
///
/// Generic rather than a `fn` pointer: the reduction is called once per
/// candidate host, inside the fold.
fn check_enclosure_rows<R>(
    design: Design<'_>,
    rules: &[StrId],
    outers: &[LayerId],
    inners: &[LayerId],
    limits: &[Dbu],
    worst_of: R,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) where
    R: Fn(Margins) -> (Dbu, Side) + Copy,
{
    debug_assert_eq!(rules.len(), outers.len(), "one outer layer per rule row");
    debug_assert_eq!(rules.len(), inners.len(), "one inner layer per rule row");
    debug_assert_eq!(rules.len(), limits.len(), "one limit per rule row");

    for row in 0..rules.len() {
        let rule = rules[row];
        let inner_layer = inners[row];
        let limit = Measurement::Length(limits[row]);
        let before = out.len();

        // The inner layer is the `a` operand, so the pair list comes back
        // grouped by inner shape and the walk below is a merge, not a search.
        if pair_layers(
            design,
            inner_layer,
            outers[row],
            Dbu::new_unchecked(0),
            scratch,
        )
        .is_err()
        {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let shapes = design.store.polys_on_layer(inner_layer);
        let examined = u64::from(shapes.end - shapes.start);
        let mut cursor = 0usize;

        // One fold per inner shape over that shape's own run of the pair list,
        // cut out by a cursor that carries from row N-1 into row N.
        for shape in shapes {
            let inner = PolyId(shape);
            let inner_box = design.store.poly_bbox(inner);
            let (lo, hi) = run_of(&scratch.pairs, &mut cursor, inner);

            // Best host, not first host. `Reverse` on the row breaks a tie
            // toward the lowest, so the reported host does not depend on
            // polygon order.
            let candidates = &scratch.pairs[lo..hi];
            let mut acc = (UNHOSTED, Reverse(u32::MAX));
            for &(_, candidate) in candidates {
                let host_box = design.store.poly_bbox(candidate);
                // A candidate that does not contain the inner shape folds in as
                // the sentinel and loses to every real host: a margin measured
                // against a host that clips the shape is not an enclosure.
                // The box test is a *prune* — box containment is necessary for
                // real containment, so `&&` short-circuits the ring scan away.
                let keep = i64::from(
                    host_box.contains(inner_box)
                        && ring_contains_ring(design.store, candidate, inner),
                );
                let value = worst_of(margins(inner_box, host_box)).0.raw();
                acc = acc.max((UNHOSTED + (value - UNHOSTED) * keep, Reverse(candidate.0)));
            }
            let (best, Reverse(host)) = acc;

            // An unhosted inner shape is zero enclosure, not skipped, and the
            // clamp's lower bound is the whole of that rule: a containing
            // host's reduction is never negative and the sentinel is far below.
            let measured = Measurement::Length(Dbu::new_unchecked(best.clamp(0, MAX_ABS_DBU)));

            if measured.violates(limit, LimitSense::Minimum) {
                let hosted = best >= 0;
                let at = if hosted {
                    let host_box = design.store.poly_bbox(PolyId(host));
                    strip_midpoint(
                        inner_box,
                        host_box,
                        worst_of(margins(inner_box, host_box)).1,
                    )
                } else {
                    centre(inner_box)
                };
                out.push(Violation {
                    rule,
                    layer: inner_layer,
                    severity: Severity::Error,
                    at,
                    measured,
                    limit,
                    shapes: (inner, hosted.then_some(PolyId(host))),
                });
            }
        }

        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|reported| reported <= examined),
            "an enclosure rule reports at most one violation per inner shape"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Check every minimum-enclosure rule.
///
/// One violation per offending inner shape, with the best achievable margin as
/// the measurement, reported at the midpoint of the strip on the side
/// [`Margins::worst`] named. `examined` counts inner shapes.
pub fn check_min_enclosure(
    design: Design<'_>,
    table: &MinEnclosureTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();
    check_enclosure_rows(
        design,
        &table.rule,
        &table.outer,
        &table.inner,
        &table.limit,
        Margins::worst_sided,
        scratch,
        out,
        runs,
    );
    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever each row found"
    );
}

/// Check every asymmetric-enclosure rule.
///
/// Same pairing as [`check_min_enclosure`], reduced with
/// [`Margins::worst_axis_best_side`]. `examined` counts inner shapes.
pub fn check_asymmetric_enclosure(
    design: Design<'_>,
    table: &AsymmetricEnclosureTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();
    check_enclosure_rows(
        design,
        &table.rule,
        &table.outer,
        &table.inner,
        &table.min_one_side,
        Margins::worst_axis_best_side_sided,
        scratch,
        out,
        runs,
    );
    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever each row found"
    );
}

/// Check every minimum-extension rule.
///
/// Only pairs that overlap are judged — a layer that does not meet the
/// reference is not failing to extend past it. `examined` counts overlapping
/// shape pairs.
pub fn check_min_extension(
    design: Design<'_>,
    table: &MinExtensionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Hoisted above the row loop: one allocation for the whole call.
    let mut failing: Vec<(PolyId, PolyId)> = Vec::new();

    for row in 0..table.len() {
        let rule = table.rule[row];
        let layer = table.layer[row];
        let limit = Measurement::Length(table.limit[row]);
        let before = out.len();

        if pair_layers(
            design,
            layer,
            table.reference[row],
            Dbu::new_unchecked(0),
            scratch,
        )
        .is_err()
        {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        // The prune at distance zero is `Bbox::overlaps` exactly, so the pair
        // list *is* the overlapping pairs and nothing further has to filter it.
        let examined = scratch.pairs.len() as u64;

        // Two passes: a branchless compact, then a report over the survivors.
        // The buffer is reserved for the whole input rather than for the
        // survivors, which is what lets the commit below be unconditional.
        let pairs = &scratch.pairs[..];
        let n = pairs.len();
        failing.clear();
        failing.reserve(n);
        debug_assert!(
            failing.capacity() >= n,
            "the compact reserves for the input, not the survivors"
        );
        let slots = &mut failing.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for (i, &(line, reference)) in pairs.iter().enumerate() {
            // Roles reversed against enclosure: the reference plays the inner
            // shape and the extending layer the outer one, so a positive margin
            // is exactly a protrusion.
            let (protrusion, _) = smallest_protrusion(margins(
                design.store.poly_bbox(reference),
                design.store.poly_bbox(line),
            ));
            let p = Measurement::Length(protrusion).violates(limit, LimitSense::Minimum);
            // `w <= i` holds by induction: `w` starts at `0`, and `bool` is `0`
            // or `1`, so it advances by at most one per iteration. Rejected
            // slots stay uninit and are never read, because `set_len(w)`
            // truncates them away; `(PolyId, PolyId)` is `Copy`, so nothing has
            // a `Drop` to run on them.
            debug_assert!(w <= i);
            // Unchecked, and slicing to `[..n]` is not enough to earn it here:
            // `w`'s step is data-dependent, so LLVM cannot prove `w <= i` and
            // emits a live panic edge instead. Measured 1.19x at 8k.
            //
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write((line, reference));
            w += usize::from(p);
        }

        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { failing.set_len(w) };
        let kept = w;
        debug_assert_eq!(kept, failing.len(), "the compact reports what it kept");
        debug_assert!(
            kept <= scratch.pairs.len(),
            "a filter over the pair list keeps a subset of it"
        );

        // Pass two, over the survivors only. The compact preserves input order,
        // so the violation order is the pair order.
        for &(line, reference) in &failing {
            let line_box = design.store.poly_bbox(line);
            let ref_box = design.store.poly_bbox(reference);
            let (protrusion, side) = smallest_protrusion(margins(ref_box, line_box));
            let measured = Measurement::Length(protrusion);
            debug_assert!(
                measured.violates(limit, LimitSense::Minimum),
                "a survivor of the compact violates the limit its predicate tested"
            );
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: strip_midpoint(ref_box, line_box, side),
                measured,
                limit,
                shapes: (line, Some(reference)),
            });
        }

        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|reported| reported <= examined),
            "an extension rule reports at most one violation per overlapping pair"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The smallest side the layer actually protrudes on, and which side that is.
///
/// A margin of zero or less is not a side the layer sticks out on, so it does
/// not bound the extension. A shape that protrudes nowhere extends by zero and
/// violates every positive limit — the fail-closed answer for a poly endcap
/// swallowed by its own diffusion.
fn smallest_protrusion(m: Margins) -> (Dbu, Side) {
    // `min_by_key` keeps the first of a tie, so the reported side is a function
    // of the geometry and of nothing else.
    [
        (m.left, Side::Left),
        (m.right, Side::Right),
        (m.bottom, Side::Bottom),
        (m.top, Side::Top),
    ]
    .into_iter()
    .filter(|&(value, _)| value.raw() > 0)
    .min_by_key(|&(value, _)| value.raw())
    .unwrap_or((Dbu::new_unchecked(0), Side::Left))
}

/// Check every overlap rule: the smaller dimension of each intersection figure
/// against the limit, reported inside that figure.
///
/// `examined` counts intersection figures. `Outcome::Refused` if either operand
/// will not merge exactly.
pub fn check_overlap(
    design: Design<'_>,
    table: &OverlapTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    for row in 0..table.len() {
        let rule = table.rule[row];
        let layer = table.a[row];
        let limit = Measurement::Length(table.limit[row]);
        let before = out.len();

        if pair_layers(design, layer, table.b[row], Dbu::new_unchecked(0), scratch).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        // One figure per overlapping pair, and every pair here overlaps.
        //
        // **Known fail-open:** the figure
        // is the pair's box intersection, not the exact boolean one. For a
        // non-convex operand the box meet is larger, so a too-small overlap
        // reads as passing. The exact route needs
        // `ValidatedLayer::provenance(&self) -> &[PolyId]` in `core` so a figure
        // can still name the two shapes `Violation::shapes` promises.
        let examined = scratch.pairs.len() as u64;
        for &(a, b) in &scratch.pairs {
            let Some(figure) = design
                .store
                .poly_bbox(a)
                .intersection(design.store.poly_bbox(b))
            else {
                // Unreachable: the prune at distance zero is `Bbox::overlaps`.
                debug_assert!(false, "a pruned pair has a non-empty box intersection");
                continue;
            };

            // The *smaller side*, not the area: a limit on area passes a long
            // thin sliver, and a sliver does not conduct.
            let smaller = figure.width().raw().min(figure.height().raw());
            debug_assert!(smaller >= 0, "a non-empty figure has non-negative sides");
            let measured = Measurement::Length(Dbu::new_unchecked(smaller.min(MAX_ABS_DBU)));

            if measured.violates(limit, LimitSense::Minimum) {
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: centre(figure),
                    measured,
                    limit,
                    shapes: (a, Some(b)),
                });
            }
        }

        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|reported| reported <= examined),
            "an overlap rule reports at most one violation per intersection figure"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Check every maximum-distance-to-tap rule.
///
/// Measures from the *corners* of each well shape, since the farthest point of
/// a rectilinear region from any finite point set is always a vertex. Distance
/// is to the nearest point of the tap shape, not to its centre.
///
/// `examined` counts well shapes. `Outcome::Skipped(SkipReason::EmptyLayer)`
/// when the well layer is empty; a well layer with no taps at all is **not**
/// skipped, it is a violation on every well shape.
pub fn check_max_distance_to_tap(
    design: Design<'_>,
    table: &MaxDistanceToTapTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    for row in 0..table.len() {
        let rule = table.rule[row];
        let well_layer = table.well[row];
        let reach = table.limit[row];
        let limit = Measurement::Length(reach);
        let before = out.len();

        let wells = design.store.polys_on_layer(well_layer);
        let examined = u64::from(wells.end - wells.start);
        if examined == 0 {
            // Nothing to judge, which is a different claim from judged-and-
            // clean. A layer with no *taps* is not this case.
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

        // Pruned at the limit, so a well with no tap in reach measures the
        // out-of-reach sentinel — over-reporting, which is the fail-closed
        // direction for a rule violated *above* its limit.
        if pair_layers(design, well_layer, table.tap[row], reach, scratch).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let mut cursor = 0usize;
        for well_row in wells {
            let well = PolyId(well_row);
            let (lo, hi) = run_of(&scratch.pairs, &mut cursor, well);
            let (xs, ys) = design.store.poly_verts(well);
            debug_assert_eq!(xs.len(), ys.len(), "a polygon's columns are parallel");

            // The run of taps in reach is the same for every corner of this
            // well.
            let taps = &scratch.pairs[lo..hi];

            let mut worst = (i128::MIN, 0usize);
            for (vertex, (&x, &y)) in xs.iter().zip(ys).enumerate() {
                // To the nearest point of the tap, not to its centre: a centre
                // measurement understates the reach of a wide tap strap.
                let mut nearest = OUT_OF_REACH;
                for &(_, tap) in taps {
                    nearest = nearest.min(point_box_dist2(x, y, design.store.poly_bbox(tap)));
                }
                // Strict, so a tie keeps the first vertex and the reported
                // corner does not depend on the fold.
                if nearest > worst.0 {
                    worst = (nearest, vertex);
                }
            }
            debug_assert!(worst.1 < xs.len(), "the farthest corner is one of them");

            let measured = Measurement::Length(ceil_sqrt(worst.0));
            if measured.violates(limit, LimitSense::Maximum) {
                out.push(Violation {
                    rule,
                    layer: well_layer,
                    severity: Severity::Error,
                    at: Point {
                        x: xs[worst.1],
                        y: ys[worst.1],
                    },
                    measured,
                    limit,
                    // No second shape: the violation is that *no* tap is in
                    // reach, so naming one of them would name the wrong thing.
                    shapes: (well, None),
                });
            }
        }

        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|reported| reported <= examined),
            "a tap rule reports at most one violation per well shape"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}
