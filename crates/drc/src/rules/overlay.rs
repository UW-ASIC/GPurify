//! Overlay family: how two layers must sit relative to each other.
//!
//! Enclosure, extension and overlap are all the same question asked from
//! different sides — given a shape on layer A and a shape on layer B that
//! interact, is there enough of A around, past, or under B. They share a file
//! because they share the pairing step and the failure mode that goes with it.
//!
//! # Best host, not first host
//!
//! An inner shape may sit inside several outer shapes at once: a via under a
//! wide pad that a narrow wire also clips the corner of. The rule is satisfied
//! if the *best* host satisfies it, because after the layers are merged there
//! is only one host and it is the union. Taking the first host found, or the
//! worst, fails a via whose pad encloses it perfectly — and which host is
//! "first" depends on polygon order, so that variant is also nondeterministic.
//!
//! # An unhosted inner shape is zero enclosure, not skipped
//!
//! A via with no metal under it at all has an enclosure of zero and violates
//! every enclosure rule. Skipping it because no host was found is fail-open,
//! and it is the case that matters most.

use super::{centre, mid, ring_segs};
use crate::{record_run, Design, Scratch};
use gpurify_core::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_core::ops::{isqrt, Point};
use gpurify_core::view::{validate_layer_into, ValidityError};
use gpurify_core::{Bbox, LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{
    LimitSense, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use gpurify_units::{Dbu, DbuArea, MAX_ABS_DBU};
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
/// The relaxed form a foundry allows where lithographic overlay error is
/// directional: a via needs a landing pad on one side of each axis, not a
/// symmetric collar. Passes when
/// `max(left, right) >= limit && max(top, bottom) >= limit`.
#[derive(Debug, Default)]
pub struct AsymmetricEnclosureTable {
    pub rule: Vec<StrId>,
    pub outer: Vec<LayerId>,
    pub inner: Vec<LayerId>,
    /// Required on one side of each axis. Deliberately *not* named `limit`: the
    /// number means something weaker than the one in [`MinEnclosureTable`], and
    /// a reader who transposes the two rules should notice.
    pub min_one_side: Vec<Dbu>,
}

/// Minimum extension: one layer must run past another by at least the limit.
///
/// The poly endcap over diffusion is the canonical case — the gate must extend
/// beyond the channel or the transistor leaks around its end. Measured only
/// where the two shapes actually overlap, and on each side the layer protrudes.
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
/// Distinct from enclosure, which requires containment. Overlap only requires a
/// large enough intersection, so a wire crossing a strap satisfies it without
/// either shape containing the other. Measured on the exact boolean
/// intersection, not on bounding boxes — a bounding-box intersection
/// over-reports for any non-convex shape, and the old tree's `lvs` evaluator
/// did exactly that on the path feeding device recognition.
#[derive(Debug, Default)]
pub struct OverlapTable {
    pub rule: Vec<StrId>,
    pub a: Vec<LayerId>,
    pub b: Vec<LayerId>,
    /// The smaller side of the intersection rectangle must be at least this.
    /// A limit on *area* would pass a long thin sliver, which does not conduct.
    pub limit: Vec<Dbu>,
}

/// Maximum distance to a well tie: every point of a well must be within reach
/// of a tap.
///
/// A latch-up rule rather than a lithographic one. An untied well floats, its
/// junction forward-biases, and the parasitic thyristor fires — so the
/// constraint is on the *farthest* point of the well, not on the average.
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

impl MinEnclosureTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.outer.len(), "one outer layer per row");
        debug_assert_eq!(self.rule.len(), self.inner.len(), "one inner layer per row");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "one limit per row");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsymmetricEnclosureTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.outer.len(), "one outer layer per row");
        debug_assert_eq!(self.rule.len(), self.inner.len(), "one inner layer per row");
        debug_assert_eq!(
            self.rule.len(),
            self.min_one_side.len(),
            "one requirement per row"
        );
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MinExtensionTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "one layer per row");
        debug_assert_eq!(
            self.rule.len(),
            self.reference.len(),
            "one reference layer per row"
        );
        debug_assert_eq!(self.rule.len(), self.limit.len(), "one limit per row");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl OverlapTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.a.len(), "one first layer per row");
        debug_assert_eq!(self.rule.len(), self.b.len(), "one second layer per row");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "one limit per row");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MaxDistanceToTapTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.well.len(), "one well layer per row");
        debug_assert_eq!(self.rule.len(), self.tap.len(), "one tap layer per row");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "one limit per row");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How far an outer shape extends past an inner one, per side.
///
/// **Decision** — two boxes in, four distances out, pure and table-testable,
/// and the one place the sign convention is written down: each field is
/// positive when the outer shape extends past the inner on that side, negative
/// when the inner sticks out. Negative is not an error here; it is what an
/// unhosted or overhanging shape measures, and clamping it to zero would hide
/// how badly the rule failed.
///
/// `AoS` because all four are read together by both enclosure rules and never
/// scanned one at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Margins {
    pub left: Dbu,
    pub right: Dbu,
    pub bottom: Dbu,
    pub top: Dbu,
}

/// Which of the four margins a reduction named.
///
/// Not in any frozen signature: it exists so a transform can report *at* the
/// side its reduction chose, which is the crate's midpoint convention applied
/// to a margin. Carrying it out of the reduction is what keeps the choice and
/// the number from drifting — re-deriving "which side was that" from the value
/// alone ties on a symmetric shape and picks by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
    Bottom,
    Top,
}

/// The smaller of two sides, the first of them on a tie.
///
/// Surviving `if`: two scalars in a decision, not a loop body, and the two arms
/// are whole tuples rather than blendable values — LLVM builds it as a pair of
/// `cmov`s. Same call [`Bbox::intersection`] makes for the same reason.
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
    /// The worst side. What [`check_min_enclosure`] compares.
    pub const fn worst(self) -> Dbu {
        self.worst_sided().0
    }

    /// The better side of each axis, then the worse of those two. What
    /// [`check_asymmetric_enclosure`] compares:
    /// `min(max(left, right), max(bottom, top))`.
    pub const fn worst_axis_best_side(self) -> Dbu {
        self.worst_axis_best_side_sided().0
    }

    /// [`Margins::worst`], and which side it was.
    ///
    /// The public reduction is this one's first field, so the value a rule
    /// compares and the side it reports at cannot disagree.
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

/// The midpoint of the strip between the two boxes on one side.
///
/// **Decision** — two boxes and a side in, one coordinate out, and the one
/// place this family's report point is written down. Along the named axis it is
/// the middle of the gap between the two edges, which is `rules`' midpoint
/// convention. Across it, the range the two boxes share: for an enclosure that
/// is the inner shape's own span, for an extension it is the overhanging stub's.
/// Either way it is a point a viewer can jump to and see the defect, rather than
/// a corner that may be fine.
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
/// Below `-2 * MAX_ABS_DBU`, which is the most negative margin two in-domain
/// boxes can have, so it loses to every real host without a special case. It is
/// also what a *non-containing* host folds in as, which is what makes that
/// rejection branchless.
const UNHOSTED: i64 = -(1 << 42);

/// A squared distance that stands for "no tap in reach".
///
/// `MAX_ABS_DBU` squared: the largest distance the coordinate domain can
/// express, and a perfect square, so [`ceil_sqrt`] returns `MAX_ABS_DBU`
/// exactly rather than one past the domain. Fail **closed** — this rule is
/// violated *above* its limit, so a saturating distance over-reports rather
/// than silently passing an untied well.
const OUT_OF_REACH: i128 = 1 << 80;

/// Squared distance from a point to the nearest point of a box.
///
/// No assert: this is called from inside the nearest-tap fold, where a panic
/// edge would pin the loop to one element per iteration and block
/// vectorisation. Every operand is a `Dbu` and so already inside
/// the domain the `i128` product is bounded by — the differences reach `2^41`
/// and the sum of their squares `2^83`, which `i128` holds with room.
fn point_box_dist2(x: Dbu, y: Dbu, b: Bbox) -> i128 {
    // Branchless: the larger of the two one-sided overhangs and zero is the
    // whole clamp, with no branch on which side of the box the point falls.
    let dx = i128::from((b.xlo.raw() - x.raw()).max(x.raw() - b.xhi.raw()).max(0));
    let dy = i128::from((b.ylo.raw() - y.raw()).max(y.raw() - b.yhi.raw()).max(0));
    dx * dx + dy * dy
}

/// The distance whose square is `d2`, rounded **up**.
///
/// Up, not toward zero as [`isqrt`] alone would: an exceeded limit has to read
/// as exceeded in the report a human acts on. For an integer limit the two
/// agree exactly — `d2 > limit²` iff `ceil(sqrt(d2)) > limit` — so rounding
/// this way is what lets the comparison happen on the number that is printed
/// instead of on a square nobody sees.
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
/// **Decision.** `pairs` is strictly ascending and `a` walks the same layer
/// ascending, so the cursor only moves forward: the whole walk over a layer is
/// one pass over the pair list rather than a binary search per shape.
///
/// The cursor survives across calls, so the two loops here are one merge cut
/// into per-shape slices. Every step of either loop consumes a pair, so the two
/// of them together cost one pass over `pairs` per layer however the calls are
/// cut up: amortised O(1) here, O(pairs) over the walk. A binary search per
/// shape would be the slower rewrite, not the faster one.
fn run_of(pairs: &[(PolyId, PolyId)], cursor: &mut usize, a: PolyId) -> (usize, usize) {
    debug_assert!(*cursor <= pairs.len(), "the cursor is inside the pair list");
    while *cursor < pairs.len() && pairs[*cursor].0 < a {
        *cursor += 1;
    }
    let lo = *cursor;
    while *cursor < pairs.len() && pairs[*cursor].0 == a {
        *cursor += 1;
    }
    debug_assert!(lo <= *cursor && *cursor <= pairs.len(), "the run is a range");
    (lo, *cursor)
}

/// Validate both operands, then prune their cross-layer pairs into `scratch`.
///
/// **Transform, gatherer**, shared by all five rules in this file: they differ
/// in what they measure, not in how they reach the pairs.
///
/// Validation is the fail-closed gate and its result is deliberately not read
/// afterwards — geometry this tool does not represent exactly is a refusal for
/// the rule row, never a clean one, and that is the whole of what the two
/// `ValidatedLayer` buffers are for here.
///
/// # Known fail-open: the measurements are taken on bounding boxes
///
/// **This is a correctness gap, not a simplification, and it is filed in
/// `docs/SIGNATURE_DEFECTS.md`.** A box margin is exact for the rectangles a
/// real via, pad, tap or endcap is, and it *overstates* the enclosure a
/// non-convex host gives — so an L-shaped pad that leaves a via's corner
/// uncovered reads as a clean enclosure. Overstating a minimum is the fail-open
/// direction, which is the defect class `docs/VOCABULARY.md` §3 names.
///
/// It is not fixed here because it cannot be. The exact confirmation is
/// `ops::point_in_ring` against the host's rings, `point_in_ring` takes a
/// `core::view::RingRef`, and the only route to one is
/// `ValidatedLayer::get(store, idx)` on a *validated* index. Nothing maps the
/// [`PolyId`] a pair carries — a store row — to that index, and `RingRef`'s
/// fields are private with no constructor, so neither half can be reached from
/// this crate. Closing it is `ValidatedLayer::provenance(&self) -> &[PolyId]`
/// in `core`, which is a widened interface and therefore a bug report rather
/// than a commit.
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
/// **Decision** — pure, two segments in, one `bool` out.
///
/// *Proper* crossing, and the strictness is the whole content: a T-junction,
/// two collinear overlapping segments and two segments sharing an endpoint are
/// all boundary contact, which is what an inner shape touching its host's edge
/// from the inside looks like. Only a genuine transversal crossing says one
/// shape's boundary passes through the other's.
///
/// Rectilinear only, which is this crate's whole input domain: a crossing needs
/// one horizontal segment and one vertical one, so two parallel segments return
/// `false` and no arbitrary-angle arithmetic is reachable from here.
fn segments_cross(a: (Point, Point), b: (Point, Point)) -> bool {
    // Branchless: both orderings are tested and the pair that is not
    // horizontal-and-vertical fails its own guard, so there is no jump and no
    // question of which operand came in which role.
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
/// **Decision** — two store rows in, one `bool` out, pure.
///
/// Two conditions, and both are needed:
///
///  - one vertex of `inner` is inside or on `host`, and
///  - no edge of `inner` properly crosses an edge of `host`.
///
/// Together they are exact for rings that do not cross: if the boundaries never
/// pass through each other then `inner` is wholly inside `host` or wholly
/// outside it, and the anchor vertex says which. A vertex test alone is not
/// enough — a bar whose two ends sit in the two arms of a U has every vertex
/// inside the host and spans the opening, which is the case
/// `a_bar_bridging_a_hosts_opening_is_not_enclosed_though_its_corners_are` is
/// written for.
///
/// # What it does not see
///
/// Holes. A store row is one ring, and a polygon-with-hole is several rows that
/// `validate_layer_into` binds together — so a host hole lying strictly inside
/// `inner` crosses nothing, puts no vertex outside, and reads as contained. That
/// is an inner shape sitting over a void in its host, and it is still fail-open.
/// Closing it needs the *validated* host rather than its outer ring, and the
/// route from a store [`PolyId`] to a `PolygonRef` does not exist — the same gap
/// `pair_layers` records. Narrower than the bounding box it replaces by every
/// shape that is not a rectangle, and filed rather than papered over.
fn ring_contains_ring(store: &gpurify_core::GeometryStore, host: PolyId, inner: PolyId) -> bool {
    let (xs, ys) = store.poly_verts(inner);
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(xs.len() >= 3, "a stored ring has at least three vertices");

    // Boundary-inclusive, which is what makes an inner shape flush against its
    // host's edge contained rather than unhosted.
    let anchor = Point { x: xs[0], y: ys[0] };
    if !store.poly_contains_point(host, anchor) {
        return false;
    }

    let (hxs, hys) = store.poly_verts(host);
    // Not a bulk loop: one candidate pair's two rings, single-digit vertex
    // counts on real geometry. The early return is the escape valve — the
    // taken side is the rest of a quadratic scan, and skipping it is exactly
    // what a branch is for.
    for si in ring_segs(xs, ys) {
        for sh in ring_segs(hxs, hys) {
            if segments_cross((si.a, si.b), (sh.a, sh.b)) {
                return false;
            }
        }
    }
    true
}

/// Enclosure margins of `inner` within `outer`.
///
/// **Decision.** Bounding boxes, which is exact when the host is a rectangle
/// and optimistic otherwise — a non-convex host's box is larger than the host,
/// so this can *overstate* the enclosure.
///
/// The transforms below no longer trust that on its own:
/// [`ring_contains_ring`] confirms containment exactly before a candidate is
/// allowed to host, so a shape stranded in a concave host's notch now measures
/// zero rather than a comfortable pass. What is *not* yet exact is the margin of
/// a genuinely contained shape in a concave host — the box's far side may be
/// further away than the host's material is — and that remains optimistic. See
/// `docs/SIGNATURE_DEFECTS.md`.
pub fn margins(inner: Bbox, outer: Bbox) -> Margins {
    // No assert, and by decision rather than omission: this runs once per
    // candidate host inside the best-host fold, where a panic edge would pin
    // the loop to one element per iteration, and there is nothing left to check
    // that the operands' own type does not already guarantee. `Sub` is the
    // same reason — a margin legally reaches `+/-2^41`, one bit past the
    // coordinate domain, and `Sub` documents that difference as legal where
    // `Dbu::new_unchecked` would assert on it.
    Margins {
        left: inner.xlo - outer.xlo,
        right: outer.xhi - inner.xhi,
        bottom: inner.ylo - outer.ylo,
        top: outer.yhi - inner.yhi,
    }
}

/// One enclosure rule row, under whichever reduction the table's rule uses.
///
/// **Transform**, and the whole of both enclosure rules: they differ in one
/// function — [`Margins::worst`] against [`Margins::worst_axis_best_side`] —
/// and in nothing else, so this is compression of two identical bodies rather
/// than an abstraction invented for a third that might arrive. Generic and not
/// a `fn` pointer: the reduction is called once per candidate host, inside the
/// fold, and an indirect call there would block inlining on the hot path.
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

    // Tens of rows, read once each: cold, and not the bulk loop. Every value
    // pulled out of a row here is a uniform over the shape loop below.
    for row in 0..rules.len() {
        let rule = rules[row];
        let inner_layer = inners[row];
        let limit = Measurement::Length(limits[row]);
        let before = out.len();

        // The inner layer is the `a` operand, so the pair list comes back
        // grouped by inner shape and the walk below is a merge, not a search.
        if pair_layers(design, inner_layer, outers[row], Dbu::new_unchecked(0), scratch).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let shapes = design.store.polys_on_layer(inner_layer);
        let examined = u64::from(shapes.end - shapes.start);
        let mut cursor = 0usize;

        // One fold per inner shape over that shape's own run of the pair list,
        // cut out by a cursor that carries from row N-1 into row N. Not a
        // scatter: at most one violation per inner shape, asserted below.
        for shape in shapes {
            let inner = PolyId(shape);
            let inner_box = design.store.poly_bbox(inner);
            let (lo, hi) = run_of(&scratch.pairs, &mut cursor, inner);

            // Best host, not first host: after the outer layer is merged there
            // is only one host and it is the union, so the rule is satisfied by
            // whichever candidate gives the most. `Reverse` on the row breaks a
            // tie toward the lowest, so the reported host does not depend on
            // polygon order.
            //
            // A single column, so there is no column agreement to assert. The
            // trip count is the slice's own length, hoisted above the loop, so
            // the indexed read carries no panic edge; the fold runs strictly
            // left to right, as every reduction in this tree does.
            let candidates = &scratch.pairs[lo..hi];
            let mut acc = (UNHOSTED, Reverse(u32::MAX));
            for &(_, candidate) in candidates {
                let host_box = design.store.poly_bbox(candidate);
                // A candidate that does not contain the inner shape folds in as
                // the sentinel and loses to every real host. Only containing
                // hosts count — a margin measured against a host that clips the
                // shape is not an enclosure.
                //
                // The box test is a *prune*, not the answer: box containment is
                // necessary for real containment, so a candidate it rejects
                // cannot host, and `&&` short-circuits the ring scan away for
                // it. The surviving branch is the expensive-taken-side valve —
                // the taken side is a ring-against-ring scan, and skipping it on
                // a candidate whose box already misses is what a branch is for.
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
            // host's reduction is never negative, and the sentinel is far below
            // zero. `clamp` rather than `max(0).min(..)`: both bounds are
            // constants with `0 <= MAX_ABS_DBU`, so its ordering assert folds
            // away and it lowers to the same `smax`/`smin` pair.
            let measured = Measurement::Length(Dbu::new_unchecked(best.clamp(0, MAX_ABS_DBU)));

            // Surviving `if`: the taken side pushes eight columns and
            // re-derives a coordinate, and on a design under signoff it is
            // taken on a fraction of a percent of shapes. Skipping expensive
            // work is what a branch is for.
            if measured.violates(limit, LimitSense::Minimum) {
                let hosted = best >= 0;
                let at = if hosted {
                    let host_box = design.store.poly_bbox(PolyId(host));
                    strip_midpoint(inner_box, host_box, worst_of(margins(inner_box, host_box)).1)
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
/// **Transform.** For each inner shape, finds every containing outer shape,
/// takes the best [`Margins::worst`] among them, and compares. One violation
/// per offending inner shape, with the best achievable margin as the
/// measurement — so the number in the report is what the layout actually has,
/// not what the first candidate host happened to give.
///
/// Reported at the midpoint of the deficient margin: the middle of the strip
/// between the inner shape's edge and the host's on the side [`Margins::worst`]
/// named. That is the crate's convention (module doc), and it points at the
/// side that failed rather than at a corner that may be fine.
///
/// `examined` counts inner shapes.
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
/// [`Margins::worst_axis_best_side`], and reported the same way: at the
/// midpoint of the margin that reduction named — the better side of the worse
/// axis, which is the one side a designer has to widen. `examined` counts inner
/// shapes.
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
/// reference at all is not failing to extend past it, it is somewhere else. The
/// measurement is the smallest protrusion across the sides where the layer does
/// protrude.
///
/// `examined` counts overlapping shape pairs.
pub fn check_min_extension(
    design: Design<'_>,
    table: &MinExtensionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Hoisted above the row loop and cleared per row by `compact_into` itself:
    // one allocation for the whole call, whatever the row count, which is the
    // "nothing allocates per iteration" rule applied to the only buffer this
    // transform needs and `Scratch` does not carry.
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
        // A layer that never meets the reference contributes no pair and is not
        // failing to extend past it — it is somewhere else.
        let examined = scratch.pairs.len() as u64;

        // Two passes over the pair list, and splitting them is what lets the
        // bulk one be branchless. Unlike the two segmented rules in this file
        // there is nothing per-shape to fold here — one pair measures one
        // protrusion — so the whole measurement is a filter over bulk data.
        //
        // The body reads two `poly_bbox` rows, which are gathers and so
        // addresses rather than branches; the selects inside
        // `smallest_protrusion` and `Measurement::violates` are over four sides
        // and two enum tags, both uniform across the run, and lower to `cmov`.
        // `violates`' two `debug_assert`s are the only tolerated panic edge in
        // this body: they ask `Measurement::is_finite`, which is `true` by
        // construction for the `Length` variant both operands are, and they are
        // compiled out of every profile where the store being unconditional is
        // worth anything.
        //
        // A single column, so there is no column agreement to assert. The
        // buffer is reserved for the whole input rather than for the survivors:
        // that over-reservation is the memory-for-branches trade, and it is
        // what lets the commit below be unconditional.
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
            // is exactly a protrusion and the sign convention is reused rather
            // than restated.
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
            // `w`'s step is data-dependent, so LLVM gets no affine recurrence
            // for it and cannot prove `w <= i`. It emits a live `cmp/jae` to a
            // panic edge instead, which pins the loop to one element per
            // iteration. Measured 1.19x at 8k, 1.18x at 200k, 1.06x at 4M —
            // `docs/BULK_MEASUREMENTS.md` §4.
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

        // Pass two, over the survivors only: eight columns and a re-derived
        // coordinate per row, on a fraction of a percent of the pairs under
        // signoff. `compact_into` preserves input order, so the violation order
        // is the pair order it always was — which is what `export` reproduces
        // byte for byte.
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
/// **Decision.** A margin of zero or less is not a side the layer sticks out
/// on, so it does not bound the extension. A shape that protrudes nowhere
/// extends by zero and violates every positive limit, which is the fail-closed
/// answer for a poly endcap swallowed by its own diffusion.
fn smallest_protrusion(m: Margins) -> (Dbu, Side) {
    // Four sides is not bulk data. `min_by_key` keeps the first of a tie, so
    // the reported side is a function of the geometry and of nothing else.
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

/// Check every overlap rule.
///
/// The exact intersection of the two merged layers, then the smaller dimension
/// of each resulting figure against the limit. One violation per insufficient
/// intersection, reported inside it.
///
/// `examined` counts intersection figures. `Outcome::Refused` if either
/// operand will not merge exactly.
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

        // `Outcome::Refused` if either operand will not merge exactly: that is
        // what `pair_layers`' validation decides, and it is the only reading
        // under which an empty violation table means "clean" here.
        if pair_layers(design, layer, table.b[row], Dbu::new_unchecked(0), scratch).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        // One figure per overlapping pair, and every pair here overlaps.
        //
        // **Known fail-open, filed in `docs/SIGNATURE_DEFECTS.md`.** The figure
        // is the pair's box intersection, not the exact boolean one
        // [`OverlapTable`]'s own doc promises. Exact for the rectangles a wire
        // crossing a strap is; for a non-convex operand the box meet is larger
        // than the real one, so a too-small overlap reads as a passing one.
        // That is the same over-reporting the doc on `OverlapTable` says the old
        // tree's `lvs` evaluator did on the path feeding device recognition.
        //
        // It is not fixed here because it cannot be. The exact route is
        // `boolean::intersection_into` over the two merged layers; its output is
        // a `ValidatedLayer` whose `ring_poly` provenance is private, so a figure
        // could not name the two shapes `Violation::shapes` promises. Closing it
        // is `ValidatedLayer::provenance(&self) -> &[PolyId]` in `core` — a
        // widened interface, and so a bug report rather than a commit.
        let examined = scratch.pairs.len() as u64;
        for &(a, b) in &scratch.pairs {
            let Some(figure) = design
                .store
                .poly_bbox(a)
                .intersection(design.store.poly_bbox(b))
            else {
                // Unreachable: the prune at distance zero is `Bbox::overlaps`,
                // which is exactly the pairs whose meet is non-empty.
                debug_assert!(false, "a pruned pair has a non-empty box intersection");
                continue;
            };

            // The *smaller side*, not the area: a limit on area passes a long
            // thin sliver, and a sliver does not conduct.
            let smaller = figure.width().raw().min(figure.height().raw());
            debug_assert!(smaller >= 0, "a non-empty figure has non-negative sides");
            let measured = Measurement::Length(Dbu::new_unchecked(smaller.min(MAX_ABS_DBU)));

            // Surviving `if`: same escape valve as the rules above.
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
/// a rectilinear region from any finite point set is always a vertex. A well
/// violates if any of its corners is farther than the limit from every tap.
///
/// Distance is to the nearest point of the tap shape, not to its centre. The
/// old tree used the centre, which understates reach for a large tap strap and
/// therefore *over*-reports — a rare direction for a bug in this tree, but
/// still a wrong number in a report a human acts on.
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
            // clean. A well layer with no *taps* is not this case: that is
            // every well untied, and it is reported below on every one of them.
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

        // Pruned at the limit, so a well with no tap in reach comes back with
        // an empty run and measures the out-of-reach sentinel. That
        // over-reports the distance, and over-reporting is the fail-closed
        // direction for a rule violated *above* its limit.
        if pair_layers(design, well_layer, table.tap[row], reach, scratch).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let mut cursor = 0usize;
        // One nearest-tap fold per well over that well's own run of the pair
        // list, cut out by a cursor that carries from row N-1 into row N. Not a
        // scatter: at most one violation per well shape, asserted below.
        for well_row in wells {
            let well = PolyId(well_row);
            let (lo, hi) = run_of(&scratch.pairs, &mut cursor, well);
            let (xs, ys) = design.store.poly_verts(well);
            debug_assert_eq!(xs.len(), ys.len(), "a polygon's columns are parallel");

            // Hoisted above the vertex loop: the run of taps in reach is the
            // same for every corner of this well. A single column, so there is
            // no column agreement to assert.
            let taps = &scratch.pairs[lo..hi];

            // From the *corners*: the farthest point of a rectilinear region
            // from any finite point set is always a vertex, so a handful of
            // vertices decide the answer and the interior never has to be
            // sampled. Not bulk — the row count is in the tap fold inside.
            let mut worst = (i128::MIN, 0usize);
            for (vertex, (&x, &y)) in xs.iter().zip(ys).enumerate() {
                // To the nearest point of the tap, not to its centre: a centre
                // measurement understates the reach of a wide tap strap and
                // therefore over-reports, which is a wrong number in a report a
                // human acts on even though it errs the safe way.
                //
                // Strictly left to right, and the trip count is the slice's own
                // length, so the indexed read carries no panic edge.
                let mut nearest = OUT_OF_REACH;
                for &(_, tap) in taps {
                    nearest = nearest.min(point_box_dist2(x, y, design.store.poly_bbox(tap)));
                }
                // Surviving `if`: four to twenty iterations over one polygon's
                // vertices, not a bulk loop, and the arms are a tuple rather
                // than a blendable value. Strict, so a tie keeps the first
                // vertex and the reported corner does not depend on the fold.
                if nearest > worst.0 {
                    worst = (nearest, vertex);
                }
            }
            debug_assert!(worst.1 < xs.len(), "the farthest corner is one of them");

            let measured = Measurement::Length(ceil_sqrt(worst.0));
            // Surviving `if`: same escape valve as the rules above.
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
