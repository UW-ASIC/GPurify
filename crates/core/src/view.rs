//! Borrowed validated geometry.
//!
//! Exact boolean operations need guarantees the raw store does not make: rings
//! are simple, holes lie inside their outer boundary, winding is canonical.
//! Establishing those is a pass; re-establishing them per rule was 43% of a
//! signoff run in the old implementation.
//!
//! So validation happens once per layer into a [`ValidatedLayer`], and
//! [`PolygonRef`] is a *borrowed* handle into it. There is no owned polygon
//! type.
//!
//! # Why the coordinates are copied
//!
//! A [`ValidatedLayer`] carries its own coordinate columns rather than spans
//! into the [`GeometryStore`] it was validated from. Spans were the original
//! design and they cannot express the output of a boolean: two rectangles that
//! partially overlap union into an L whose vertices exist in no store row, so
//! `union_into` had no legal value to write. Owning the columns is what makes
//! `core::boolean`'s four transforms — and therefore every derived layer —
//! representable at all.
//!
//! The cost is one copy of one layer's coordinates per validation. It is paid
//! once into a buffer the caller hoists and refills, and it buys back locality:
//! a validated layer's rings are contiguous in validation order rather than
//! scattered across the store's per-layer range.
//!
//! # The weakness, stated plainly
//!
//! An owned refined type cannot exist without having been validated. A borrowed
//! view can, if someone constructs one over rows that were never checked. The
//! only defence is that [`PolygonRef`]'s fields are private and its sole
//! constructors are [`validate_layer_into`] and `core::boolean`.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId, RingId};
use crate::index::{candidate_pairs_into, SpatialIndex};
use crate::ops::{point_in_ring, self_intersects, winding_of, Point, Winding};
use crate::store::GeometryStore;
use gpurify_units::{Dbu, DbuArea};

/// Why a polygon could not be validated.
///
/// Fail closed: an unvalidatable shape is an error, never a silently skipped
/// row. The old implementation dropped a hole with no containing outer ring
/// without a word, which removes area from a verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidityError {
    #[error("polygon {0:?} has fewer than three distinct vertices")]
    Degenerate(PolyId),
    #[error("polygon {0:?} has self-intersecting boundary")]
    SelfIntersecting(PolyId),
    #[error("polygon {0:?} is a hole with no containing outer ring")]
    OrphanHole(PolyId),
    #[error("polygon {0:?} is not rectilinear")]
    NotRectilinear(PolyId),
}

/// One layer's geometry, validated and grouped into outer-plus-holes polygons.
///
/// **Five questions.** In: a [`GeometryStore`] and a [`LayerId`], or the result
/// of a boolean. Out: coordinate columns plus ring and polygon spans over them.
/// How many: one per layer per run, reused across every rule on that layer.
/// Access pattern: `SoA`; a boolean walks rings, a containment test walks
/// polygons, a prune walks `poly_bbox` alone. Lifetime: phase — this is a
/// reusable buffer, cleared and refilled per layer, never reallocated.
/// Parallelisable: validation of distinct polygons is independent.
///
/// # Equality
///
/// [`PartialEq`] is **structural**: same layer tag, same coordinates, same
/// rings, in the same order. That is stronger than region equality — the same
/// region decomposed into different polygons compares unequal — so it is the
/// right tool for determinism and for "these two runs agree", and the wrong one
/// for "these two layers cover the same area". Region equality has no canonical
/// form to compare against and goes through area and per-polygon fingerprints.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ValidatedLayer {
    /// Which layer this was built from, or `None` for a boolean result, which
    /// belongs to no single input layer. A mismatched pairing is catchable.
    layer: Option<LayerId>,
    /// Validated vertex coordinates, one contiguous run per ring. Owned rather
    /// than borrowed from the store because a boolean produces vertices no
    /// store row holds — see the module doc.
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,
    /// One row per ring: its coordinate run, its winding, and the store row it
    /// came from.
    ///
    /// `ring_poly` is provenance, not identity. For a ring a boolean produced
    /// it is the lowest [`PolyId`] among the input polygons that contributed an
    /// edge to it, which is deterministic and lets a rule on a derived layer
    /// still blame a violation on real geometry.
    ring_vert_start: Vec<u32>,
    ring_vert_len: Vec<u32>,
    ring_poly: Vec<PolyId>,
    ring_winding: Vec<Winding>,
    /// One row per validated polygon: `ring_start .. ring_start + ring_len`
    /// into the ring columns. Ring 0 of every span is the outer boundary.
    poly_ring_start: Vec<u32>,
    poly_ring_len: Vec<u32>,
    /// Precomputed per polygon, for the same reason
    /// [`GeometryStore::poly_bbox`] is: a pairwise prune reads nothing else,
    /// and a derived layer has no store column to read it from.
    poly_bbox: Vec<Bbox>,
}

impl ValidatedLayer {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.poly_ring_start.len(), self.poly_ring_len.len());
        debug_assert_eq!(self.poly_ring_start.len(), self.poly_bbox.len());
        self.poly_ring_start.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrow one validated polygon.
    ///
    /// Takes the store as a parameter rather than holding a reference, so
    /// `ValidatedLayer` stays a plain owned buffer the caller can keep across
    /// runs and refill. The coordinates come from this layer's own columns; the
    /// store is what resolves `ring_poly` provenance and catches a layer paired
    /// with the wrong store.
    pub fn get<'a>(&'a self, store: &'a GeometryStore, idx: u32) -> PolygonRef<'a> {
        debug_assert!(
            (idx as usize) < self.len(),
            "polygon {idx} is past the end of a {}-polygon layer",
            self.len()
        );
        // The pairing check the `store` parameter exists for: a ring's
        // provenance names a row of *this* store, so a layer validated from a
        // different one is caught here rather than by a wrong report later.
        debug_assert!(
            self.ring_poly[self.poly_ring_start[idx as usize] as usize].idx() < store.poly_count(),
            "this layer's provenance does not name a row of this store"
        );
        PolygonRef { layer: self, idx }
    }

    /// The bounding-box column, one row per polygon, in `get` index order.
    ///
    /// The slice a pairwise prune actually scans — the counterpart of
    /// [`GeometryStore::layer_bboxes`] for a layer that may have been produced
    /// by a boolean and so has no rows in any store.
    pub fn bboxes(&self) -> &[Bbox] {
        debug_assert_eq!(self.poly_bbox.len(), self.poly_ring_start.len());
        &self.poly_bbox
    }

    /// Every ring of one polygon, outer first, without a store.
    ///
    /// `pub(crate)`, for `core::boolean` alone. [`get`](Self::get)'s `store`
    /// parameter is vestigial for coordinates — `docs/SIGNATURE_DEFECTS.md`
    /// records it as surviving only for provenance and pairing — and a boolean
    /// reads neither. Handing `get` an empty scratch store to satisfy the frozen
    /// signature would defeat the pairing check for every real caller, so the
    /// one caller that has no store takes this route instead.
    pub(crate) fn poly_rings(&self, idx: u32) -> impl Iterator<Item = RingRef<'_>> + '_ {
        debug_assert!(
            (idx as usize) < self.len(),
            "polygon {idx} is past the end of a {}-polygon layer",
            self.len()
        );
        let start = self.poly_ring_start[idx as usize];
        let len = self.poly_ring_len[idx as usize];
        debug_assert!(len >= 1, "every validated polygon has an outer boundary");
        (start..start + len).map(move |ring| self.ring(ring))
    }

    /// Borrow one ring by its index into this layer's ring columns.
    ///
    /// Private: a ring index is meaningless outside the polygon that owns it,
    /// and [`PolygonRef::outer`] / [`PolygonRef::holes`] are the two ways a
    /// caller reaches one.
    fn ring(&self, ring: u32) -> RingRef<'_> {
        let start = self.ring_vert_start[ring as usize] as usize;
        let len = self.ring_vert_len[ring as usize] as usize;
        debug_assert!(len >= 3, "a validated ring has at least three vertices");
        debug_assert!(start + len <= self.verts_x.len(), "ring run past the column");
        RingRef {
            xs: &self.verts_x[start..start + len],
            ys: &self.verts_y[start..start + len],
            winding: self.ring_winding[ring as usize],
        }
    }
}

/// A polygon that is known valid: simple rings, canonical winding, holes
/// contained by their outer boundary.
///
/// Downstream takes this and never re-derives what it guarantees. Constructible
/// only through [`ValidatedLayer::get`].
///
/// No store reference is kept. Every coordinate this hands out comes from the
/// layer's own columns, so holding one would be a borrow nothing reads — the
/// store `get` takes is spent on the pairing check there and goes no further.
#[derive(Debug, Clone, Copy)]
pub struct PolygonRef<'a> {
    layer: &'a ValidatedLayer,
    idx: u32,
}

impl<'a> PolygonRef<'a> {
    /// The outer boundary. Always present.
    pub fn outer(self) -> RingRef<'a> {
        let ring = self.layer.poly_ring_start[self.idx as usize];
        debug_assert!(
            is_outer(RingId(0)),
            "ring zero of a span is the outer boundary"
        );
        self.layer.ring(ring)
    }

    /// The holes. Empty for a simply-connected polygon, which is most of them.
    pub fn holes(self) -> impl Iterator<Item = RingRef<'a>> + 'a {
        let layer = self.layer;
        let start = layer.poly_ring_start[self.idx as usize];
        let len = layer.poly_ring_len[self.idx as usize];
        debug_assert!(len >= 1, "every validated polygon has an outer boundary");
        (start + 1..start + len).map(move |ring| layer.ring(ring))
    }

    /// O(1): read out of the layer's own `poly_bbox` column, not recomputed
    /// from the vertices.
    pub fn bbox(self) -> Bbox {
        self.layer.poly_bbox[self.idx as usize]
    }

    /// Signed area of the outer boundary minus the holes.
    ///
    /// `DbuArea` and exact: this feeds `min_area` and density, where a rounded
    /// answer changes a verdict.
    pub fn area(self) -> gpurify_units::DbuArea {
        // A hole winds clockwise, so its doubled area is already negative and
        // the subtraction is a sum. A polygon's ring count is a handful, not
        // bulk data.
        let doubled = self
            .holes()
            .fold(self.outer().area2(), |total, hole| total + hole.area2());
        debug_assert!(
            doubled.raw() >= 0,
            "holes are contained, so they cannot outweigh the outer boundary"
        );
        debug_assert!(
            doubled.raw() % 2 == 0,
            "a rectilinear polygon has integer area, so its doubled area is even"
        );
        DbuArea::new(doubled.raw() / 2)
    }
}

/// One validated closed ring.
#[derive(Debug, Clone, Copy)]
pub struct RingRef<'a> {
    xs: &'a [gpurify_units::Dbu],
    ys: &'a [gpurify_units::Dbu],
    winding: Winding,
}

impl<'a> RingRef<'a> {
    /// The two coordinate columns, parallel and of equal length.
    ///
    /// Slices, not points, so an edge scan can vectorise.
    pub fn coords(self) -> (&'a [gpurify_units::Dbu], &'a [gpurify_units::Dbu]) {
        debug_assert_eq!(self.xs.len(), self.ys.len(), "columns are parallel");
        (self.xs, self.ys)
    }

    pub fn winding(self) -> Winding {
        self.winding
    }

    /// Twice the signed area. Doubled to stay exact in integers — the halving
    /// is the only place a rounding could enter, so it does not happen here.
    pub fn area2(self) -> gpurify_units::DbuArea {
        let doubled = crate::ops::area2(self.xs, self.ys);
        debug_assert_eq!(
            doubled.raw() > 0,
            matches!(self.winding, Winding::CounterClockwise),
            "a ring's stored winding disagrees with the sign of its own area"
        );
        doubled
    }
}

/// This layer row holds a hole, so it has no slot in `outers`.
///
/// `u32::MAX` is unreachable as a slot: the outers are a subset of a layer's
/// rows and a store's rows are `u32`-indexed, so a real slot is strictly below
/// the row count.
const NOT_OUTER: u32 = u32::MAX;

/// Validate every polygon on one layer.
///
/// **Transform, A-to-B.** Caller owns `out`, which is cleared and refilled;
/// hoisting it above a per-layer loop is the point. All data flow is in the
/// signature.
///
/// The layer's coordinates are copied into `out`'s own columns, so a
/// `ValidatedLayer` is readable without the store and a boolean over one can
/// write vertices the store does not hold. `out.bboxes()` is filled here too.
///
/// Fails on the first invalid polygon rather than accumulating: a deck run
/// against geometry the tool cannot represent is not partially meaningful.
///
/// Rectilinear only. Arbitrary-angle input is [`ValidityError::NotRectilinear`],
/// not an approximation — the previous general-angle path failed open in three
/// places and silently dropped area.
pub fn validate_layer_into(
    store: &GeometryStore,
    layer: LayerId,
    out: &mut ValidatedLayer,
) -> Result<(), ValidityError> {
    let rows = store.polys_on_layer(layer);
    debug_assert!(rows.start <= rows.end, "a layer's row range runs forwards");
    debug_assert!(
        rows.end as usize <= store.poly_count(),
        "a layer's row range is inside the store"
    );

    out.reset(Some(layer));

    // Pass one: shape validation, splitting the layer's rows by winding.
    //
    // Every `if` inside `classify_ring` is a rejection that is not taken on
    // valid input, so all of them predict at ~100%.
    let rows_len = (rows.end - rows.start) as usize;
    let first = rows.start as usize;
    let mut outers: Vec<PolyId> = Vec::with_capacity(rows_len);
    let mut holes: Vec<PolyId> = Vec::with_capacity(rows_len);
    // Dense over the layer's rows, so pass two can read a row's role with a
    // load instead of a search: an outer's slot in `outers`, or `NOT_OUTER`.
    let mut outer_slot: Vec<u32> = Vec::with_capacity(rows_len);
    for row in rows.clone() {
        let poly = PolyId(row);
        let (xs, ys) = store.poly_verts(poly);
        match classify_ring(xs, ys, poly)? {
            Winding::CounterClockwise => {
                outer_slot.push(u32::try_from(outers.len()).expect("outers fit a u32"));
                outers.push(poly);
            }
            Winding::Clockwise => {
                outer_slot.push(NOT_OUTER);
                holes.push(poly);
            }
        }
    }
    debug_assert_eq!(
        outers.len() + holes.len(),
        rows_len,
        "every row on the layer was classified exactly once"
    );
    debug_assert_eq!(outer_slot.len(), rows_len, "one role per row on the layer");

    // Pass two: bind each hole to the innermost outer boundary containing it.
    //
    // Indexed rather than pairwise. `index::candidate_pairs_into` at a distance
    // of zero is every pair on this layer whose boxes touch, and containment
    // implies touching, so every (hole, outer) pair a full scan would have
    // considered is in that list. A pair the index somehow lost surfaces as
    // `OrphanHole` or as a wider container, both of which the assertions below
    // catch — the direction this can fail in is closed.
    let mut owned: Vec<(usize, PolyId)> = Vec::with_capacity(holes.len());
    // A layer of outer boundaries only is the common case, and it pays nothing:
    // no holes, no index, no pairs.
    if !holes.is_empty() {
        let mut index = SpatialIndex::default();
        SpatialIndex::build_into(store, layer, &mut index);
        let mut pairs: Vec<(PolyId, PolyId)> = Vec::new();
        candidate_pairs_into(store, &index, Dbu::new_unchecked(0), &mut pairs);

        // Drop every pair that cannot be a containment: two outers, two holes,
        // or an outer whose box does not enclose the other's. Both `contains`
        // calls are evaluated and blended rather than selected on `a_outer` —
        // eight integer compares are cheaper than the branch they replace, and
        // the blend is what leaves the store below unconditional.
        //
        // `nested` is reserved for the whole input, not for the survivors: that
        // over-reservation is the memory-for-branches trade that lets `w` carry
        // the predicate instead of a jump.
        let mut nested: Vec<(PolyId, PolyId)> = Vec::with_capacity(pairs.len());
        let out = &mut nested.spare_capacity_mut()[..pairs.len()];
        let mut w = 0usize;
        for (i, &(a, b)) in pairs.iter().enumerate() {
            let a_outer = outer_slot[a.idx() - first] != NOT_OUTER;
            let b_outer = outer_slot[b.idx() - first] != NOT_OUTER;
            let a_in_b = store.poly_bbox(b).contains(store.poly_bbox(a));
            let b_in_a = store.poly_bbox(a).contains(store.poly_bbox(b));
            let keep = (a_outer != b_outer) & ((a_outer & b_in_a) | (b_outer & a_in_b));
            // `w <= i` by induction. Base: both are zero on the first
            // iteration. Step: `i` advances by exactly one, and `w` advances by
            // `usize::from(keep)`, which is zero or one because Rust guarantees
            // a `bool` is 0 or 1. So `w` can never outrun `i`.
            debug_assert!(w <= i);
            // The store must be *unchecked*: `w`'s step is data-dependent, so
            // LLVM gets no affine recurrence for it, cannot prove `w <= i`, and
            // emits a live `cmp/jae` to a panic edge — an implicit branch in
            // the loop. Measured 1.19x at 8k / 1.18x at 200k / 1.06x at 4M,
            // `docs/BULK_MEASUREMENTS.md` §4.
            //
            // SAFETY: `w <= i < pairs.len() == out.len()`, from the induction
            // above. Slots the predicate rejected stay uninitialised and are
            // never read, because `set_len(w)` truncates them away, and
            // `(PolyId, PolyId)` is `Copy`, so none of them has a `Drop` to run.
            unsafe { out.get_unchecked_mut(w) }.write((a, b));
            w += usize::from(keep);
        }
        // SAFETY: for every `k < w`, slot `k` was written on the iteration
        // where `w` held `k`, and `w <= pairs.len()`, which is the capacity
        // reserved above.
        unsafe { nested.set_len(w) };
        debug_assert!(
            nested.len() <= pairs.len(),
            "the containment candidates are a subset of the touching pairs"
        );

        // A scatter: the write index is the hole's row, a function of the
        // pair's contents, so this is neither elementwise nor a fold and the
        // rows are not independent.
        //
        // `best_area` starts above any real box area — the whole coordinate
        // domain squared is `2^82` — so "no container yet" and "a wider
        // container" are the same comparison and there is no second sentinel to
        // test in the hot path.
        let mut best_area = vec![DbuArea::new(i128::MAX); rows_len];
        let mut best_slot = vec![NOT_OUTER; rows_len];
        for &(a, b) in &nested {
            // Which of the pair is the outer. Both slots are loaded
            // unconditionally so neither side of the choice hides a load, which
            // leaves three register selects LLVM lowers to `cmov`.
            let a_slot = outer_slot[a.idx() - first];
            let b_slot = outer_slot[b.idx() - first];
            let a_is_hole = a_slot == NOT_OUTER;
            let (outer, hole, slot) = if a_is_hole {
                (b, a, b_slot)
            } else {
                (a, b, a_slot)
            };
            debug_assert_ne!(slot, NOT_OUTER, "a survivor pairs one outer with one hole");

            let (hole_xs, hole_ys) = store.poly_verts(hole);
            let (outer_xs, outer_ys) = store.poly_verts(outer);
            let ring = RingRef {
                xs: outer_xs,
                ys: outer_ys,
                winding: Winding::CounterClockwise,
            };
            let probe = Point {
                x: hole_xs[0],
                y: hole_ys[0],
            };
            // Guards the expensive side: a point-in-ring walk costs a pass over
            // the outer's vertices, and the box test in the compact above is
            // what keeps it off nearly every pair.
            if !point_in_ring(ring, probe) {
                continue;
            }
            // Innermost wins: under nesting, the smallest containing box is the
            // boundary the hole actually punctures. Strict `<`, and the pairs
            // arrive ascending, so a tie keeps the lower store row — the same
            // choice the pairwise scan made.
            let area = store.poly_bbox(outer).area();
            let row = hole.idx() - first;
            if area < best_area[row] {
                best_area[row] = area;
                best_slot[row] = slot;
            }
        }

        for &hole in &holes {
            let slot = best_slot[hole.idx() - first];
            // Fail closed. Dropping the hole would remove area from a
            // verification result without saying so.
            if slot == NOT_OUTER {
                return Err(ValidityError::OrphanHole(hole));
            }
            owned.push((slot as usize, hole));
        }
    }
    // Deterministic ring order: holes follow their outer, ascending by store
    // row. Two validations of one store must agree ring for ring.
    owned.sort_unstable();
    debug_assert_eq!(owned.len(), holes.len(), "every hole found a container");
    debug_assert!(
        owned.iter().all(|&(slot, hole)| {
            store.poly_bbox(outers[slot]).contains(store.poly_bbox(hole))
        }),
        "a hole was bound to an outer boundary whose box does not enclose it"
    );

    // Pass three: emit, one contiguous ring span per polygon, outer first.
    //
    // Each iteration appends a data-dependent *number* of rings, and the inner
    // walk over `owned` is a merge against a cursor that carries across
    // iterations — a chain, so this neither vectorises nor partitions.
    let mut cursor = 0usize;
    for (slot, &outer) in outers.iter().enumerate() {
        let span_start = u32::try_from(out.ring_vert_start.len()).expect("rings fit a u32");
        let (outer_xs, outer_ys) = store.poly_verts(outer);
        out.push_ring(outer_xs, outer_ys, outer, Winding::CounterClockwise);
        while cursor < owned.len() && owned[cursor].0 == slot {
            let hole = owned[cursor].1;
            let (hole_xs, hole_ys) = store.poly_verts(hole);
            out.push_ring(hole_xs, hole_ys, hole, Winding::Clockwise);
            cursor += 1;
        }
        let span_len = u32::try_from(out.ring_vert_start.len()).expect("rings fit a u32");
        out.poly_ring_start.push(span_start);
        out.poly_ring_len.push(span_len - span_start);
        out.poly_bbox.push(store.poly_bbox(outer));
    }

    debug_assert_eq!(cursor, owned.len(), "every hole landed in a ring span");
    debug_assert_eq!(out.len(), outers.len(), "one polygon per outer boundary");
    debug_assert_eq!(
        out.ring_vert_start.len(),
        outers.len() + holes.len(),
        "one ring per validated row"
    );
    debug_assert_eq!(
        out.verts_x.len(),
        out.verts_y.len(),
        "the coordinate columns are parallel"
    );
    Ok(())
}

impl ValidatedLayer {
    /// Empty the buffer for reuse, keeping every column's capacity.
    ///
    /// `clear`, never a fresh `Vec`: hoisting one `ValidatedLayer` above a loop
    /// over layers is the reason this type is caller-owned.
    fn reset(&mut self, layer: Option<LayerId>) {
        self.layer = layer;
        self.verts_x.clear();
        self.verts_y.clear();
        self.ring_vert_start.clear();
        self.ring_vert_len.clear();
        self.ring_poly.clear();
        self.ring_winding.clear();
        self.poly_ring_start.clear();
        self.poly_ring_len.clear();
        self.poly_bbox.clear();
    }

    /// Copy one ring's coordinates into this layer's own columns and append its
    /// ring row.
    fn push_ring(&mut self, xs: &[Dbu], ys: &[Dbu], poly: PolyId, winding: Winding) {
        debug_assert_eq!(xs.len(), ys.len(), "the source columns are parallel");
        debug_assert!(xs.len() >= 3, "a validated ring has at least three vertices");
        let start = u32::try_from(self.verts_x.len()).expect("a layer's vertices fit a u32");
        let len = u32::try_from(xs.len()).expect("a ring's vertices fit a u32");
        self.verts_x.extend_from_slice(xs);
        self.verts_y.extend_from_slice(ys);
        self.ring_vert_start.push(start);
        self.ring_vert_len.push(len);
        self.ring_poly.push(poly);
        self.ring_winding.push(winding);
    }
}

/// Validate one coordinate run and report the direction it winds.
///
/// **Decision** — one ring in, one winding or one typed refusal out. The check
/// order is part of the answer, not an implementation detail: a bowtie is both
/// non-simple and non-rectilinear, and "it crosses itself" is the finding that
/// names what is actually wrong with it.
fn classify_ring(xs: &[Dbu], ys: &[Dbu], poly: PolyId) -> Result<Winding, ValidityError> {
    debug_assert_eq!(xs.len(), ys.len(), "the store's columns are parallel");
    let n = xs.len();
    if n < 3 {
        return Err(ValidityError::Degenerate(poly));
    }

    // One pass over the ring's edges, strictly ascending. Seeding with the last
    // vertex is what puts the closing edge in the same pass with no fixup
    // outside it, and the body carries two independent flags rather than a
    // branch: `distinct` fails on a zero-length edge, `rectilinear` on a
    // diagonal one. `&=` on `bool` is `BitAndAssign`, not `&&`, so neither flag
    // short-circuits into a jump. The columns were asserted parallel above, so
    // `n` drives both.
    let (mut px, mut py) = (xs[n - 1], ys[n - 1]);
    let (mut distinct, mut rectilinear) = (true, true);
    for i in 0..n {
        let (x, y) = (xs[i], ys[i]);
        let same_x = px == x;
        let same_y = py == y;
        distinct &= !(same_x & same_y);
        rectilinear &= same_x | same_y;
        px = x;
        py = y;
    }

    if !distinct {
        return Err(ValidityError::Degenerate(poly));
    }
    if self_intersects(xs, ys) {
        return Err(ValidityError::SelfIntersecting(poly));
    }
    if !rectilinear {
        return Err(ValidityError::NotRectilinear(poly));
    }
    // A simple rectilinear run with no zero-length edge can still fold to zero
    // signed area by doubling back on itself. That has no interior, so it is
    // degenerate rather than a ring wound in some third direction.
    winding_of(xs, ys).ok_or(ValidityError::Degenerate(poly))
}

/// Which ring of a polygon a [`RingId`] refers to.
///
/// `RingId(0)` is always the outer boundary. Kept as a free function rather
/// than a method so it reads at the call site without borrowing anything.
pub const fn is_outer(ring: RingId) -> bool {
    ring.0 == 0
}
