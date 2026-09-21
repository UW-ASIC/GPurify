//! Grid family: rules about where vertices may sit and which way edges may
//! point.
//!
//! No tolerance band: an allowed angle is an exact integer [`Direction`] and
//! the test is a cross product that is zero or is not. The cost is that only
//! multiples of 45 degrees can be expressed, so a deck asking for 30 degrees is
//! [`DrcError::UnrepresentableAngle`](crate::drc::DrcError::UnrepresentableAngle) at
//! load rather than approximated.

use super::COLUMNS_DIVERGED;
use crate::drc::{record_run, Design, Scratch};
use crate::report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::PolyId;
use gpurify_ingest::StrId;

/// Off-grid: every vertex must land on a manufacturing pitch.
///
/// No layer column — one pitch for the whole design. Per-layer pitches need a
/// `layer` column here.
#[derive(Debug, Default)]
pub struct OffGridTable {
    pub rule: Vec<StrId>,
    /// The pitch every coordinate must be a multiple of, in database units —
    /// a coarser lattice on top of `Grid`, which is what the file is written in.
    pub pitch: Vec<Dbu>,
}

/// Angle: every edge must point in one of the allowed directions.
///
/// The allowed set is CSR: `allowed[start .. start + len]`.
#[derive(Debug, Default)]
pub struct AngleTable {
    pub rule: Vec<StrId>,
    pub allowed_start: Vec<u32>,
    pub allowed_len: Vec<u32>,
    /// Every allowed direction of every row, concatenated.
    pub allowed: Vec<Direction>,
}

/// A primitive edge direction, as an exact integer vector with components in
/// `-1 ..= 1`.
///
/// An edge and its reverse point along the same line and both match; see
/// [`Direction::parallel_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Direction {
    pub dx: i8,
    pub dy: i8,
}

impl Direction {
    /// The direction an angle in whole degrees names, or `None` when no
    /// integer vector expresses it.
    pub const fn from_degrees(degrees: i32) -> Option<Self> {
        // The four lines a whole-degree angle can name, indexed by
        // `degrees / 45` after folding onto `0 .. 180`.
        const LINES: [Direction; 4] = [
            Direction { dx: 1, dy: 0 },
            Direction { dx: 1, dy: 1 },
            Direction { dx: 0, dy: 1 },
            Direction { dx: -1, dy: 1 },
        ];

        // `rem_euclid`, not `%`: a negative angle is a legal way to name a
        // direction, and the truncating remainder is wrong on it.
        if degrees.rem_euclid(45) != 0 {
            return None;
        }
        // Modulo 180 because a direction and its reverse are the same line.
        #[allow(
            clippy::cast_sign_loss,
            reason = "rem_euclid is non-negative, so the quotient is 0..=3"
        )]
        let line = (degrees.rem_euclid(180) / 45) as usize;
        Some(LINES[line])
    }

    /// Whether an edge vector lies along this direction — the cross product in
    /// `i128`, zero exactly when parallel.
    ///
    /// A zero-length edge is parallel to everything and is not an edge; callers
    /// drop it before asking.
    pub const fn parallel_to(self, dx: Dbu, dy: Dbu) -> bool {
        // Not `Dbu::mul_wide`: it `debug_assert`s both operands are inside
        // `±MAX_ABS_DBU`, and an edge vector is a *difference* of two
        // coordinates, which is legally outside it. Hence the spelled-out
        // widening.
        dx.raw() as i128 * self.dy as i128 - dy.raw() as i128 * self.dx as i128 == 0
    }
}

/// Chebyshev distance from `(x, y)` to the nearest point of the `pitch`
/// lattice.
///
/// Chebyshev, not Euclidean: a violation carries a [`Dbu`] and the Euclidean
/// distance to a lattice point is a square root. Zero exactly when the vertex
/// is on the lattice, which makes it both the predicate and the measurement.
#[inline]
fn lattice_offset(x: Dbu, y: Dbu, pitch: i64) -> i64 {
    let rx = x.raw().rem_euclid(pitch);
    let ry = y.raw().rem_euclid(pitch);
    rx.min(pitch - rx).max(ry.min(pitch - ry))
}

/// The vector spanned by two consecutive ring vertices.
///
/// A difference of two coordinates, so legally outside `±MAX_ABS_DBU` — which
/// is why [`Direction::parallel_to`] widens by hand.
#[inline]
fn edge_delta(a: Point, b: Point) -> (Dbu, Dbu) {
    (b.x - a.x, b.y - a.y)
}

/// Whether two consecutive ring vertices span a real edge.
///
/// A repeated vertex is not an edge: it is parallel to every direction, so
/// counting it would make a degenerate polygon look clean.
#[inline]
fn is_edge(a: Point, b: Point) -> bool {
    let (dx, dy) = edge_delta(a, b);
    (dx.raw() | dy.raw()) != 0
}

/// How many of `allowed` the edge `a -> b` lies along.
#[inline]
fn directions_matched(allowed: &[Direction], a: Point, b: Point) -> u32 {
    let (dx, dy) = edge_delta(a, b);
    allowed.iter().fold(0u32, |n, direction| {
        n + u32::from(direction.parallel_to(dx, dy))
    })
}

impl OffGridTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.pitch.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.rule.len(), self.pitch.len(), "{COLUMNS_DIVERGED}");
        self.rule.is_empty()
    }
}

impl AngleTable {
    pub fn len(&self) -> usize {
        debug_assert!(self.columns_agree(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        debug_assert!(self.columns_agree(), "{COLUMNS_DIVERGED}");
        self.rule.is_empty()
    }

    /// The directions one row allows.
    pub fn allowed_of(&self, row: usize) -> &[Direction] {
        debug_assert!(self.columns_agree(), "{COLUMNS_DIVERGED}");
        debug_assert!(row < self.rule.len(), "allowed_of({row}) past the table");
        let start = self.allowed_start[row] as usize;
        let end = start + self.allowed_len[row] as usize;
        // Fail closed: a run past the end panics on the slice below, in every
        // profile. Clamping would silently hand the rule a rule nobody wrote.
        debug_assert!(
            end <= self.allowed.len(),
            "an allowed run leaves the column"
        );
        &self.allowed[start..end]
    }

    /// The three row-indexed columns hold the same number of rows; `allowed` is
    /// not among them, being the concatenation the other two index into.
    fn columns_agree(&self) -> bool {
        self.allowed_start.len() == self.rule.len() && self.allowed_len.len() == self.rule.len()
    }
}

/// Check every off-grid rule.
///
/// One violation per offending vertex, at that vertex, measuring its distance
/// from the nearest lattice point. `examined` counts vertices, not polygons.
pub fn check_off_grid(
    design: Design<'_>,
    table: &OffGridTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // No validation, no index, no pairing: this rule reads the coordinate
    // columns and nothing else, so it borrows no scratch buffer.
    let _ = scratch;
    let store = design.store;
    let polys = u32::try_from(store.poly_count()).expect("a store indexes polygons with a u32");

    // One buffer for the whole call, grown once to the largest ring.
    let mut offending: Vec<(Dbu, Dbu)> = Vec::new();

    for row in 0..table.len() {
        let rule = table.rule[row];
        let pitch = table.pitch[row].raw();
        // Every profile, not `debug_assert`: a pitch of zero divides by zero and
        // a negative one reads as a rule nobody wrote. This is also what proves
        // the divisor non-zero for the loop below.
        assert!(pitch > 0, "an off-grid pitch must be positive, not {pitch}");

        let before = out.len();
        let mut examined = 0usize;

        // Collapsing this into a single flat scan needs a `verts_layer` column
        // on `GeometryStore`.
        for index in 0..polys {
            let poly = PolyId(index);
            let (xs, ys) = store.poly_verts(poly);
            debug_assert_eq!(
                xs.len(),
                ys.len(),
                "a polygon's coordinate columns disagree"
            );
            examined += xs.len();

            // One branchless compact over the polygon's two coordinate columns,
            // so the reporting loop below walks the survivors rather than every
            // vertex again.
            let verts = xs.len();
            offending.clear();
            // The whole polygon, not the survivors: over-reserving is what
            // lets the store below be unconditional.
            offending.reserve(verts);
            let slots = &mut offending.spare_capacity_mut()[..verts];

            let mut offenders = 0usize;
            for (&x, &y) in xs.iter().zip(ys) {
                let p = lattice_offset(x, y, pitch) != 0;
                // SAFETY: the zip runs at most `verts` times — exactly `verts`
                // once the `debug_assert_eq!` above holds — and `offenders`
                // advances by `usize::from(p)`, which `bool`'s 0-or-1
                // guarantee caps at one per iteration. So by induction
                // `offenders <= i < verts == slots.len()` at every store. The
                // rejected slots stay uninit and `set_len(offenders)` below
                // truncates them away; `(Dbu, Dbu)` is `Copy`, so nothing has
                // a `Drop` that would run over them.
                unsafe { slots.get_unchecked_mut(offenders) }.write((x, y));
                offenders += usize::from(p);
            }
            // SAFETY: slots `0 .. offenders` were each written when the cursor
            // held that value, and `offenders <= verts <= capacity`.
            unsafe { offending.set_len(offenders) };
            debug_assert!(
                offenders <= verts,
                "the scan kept more offending vertices than the polygon has"
            );

            if offenders != 0 {
                let layer = store.poly_layer(poly);
                let poly_before = out.len();
                for &(x, y) in &offending {
                    let offset = lattice_offset(x, y, pitch);
                    debug_assert_ne!(offset, 0, "the compact kept an on-grid vertex");
                    out.push(Violation {
                        rule,
                        layer,
                        severity: Severity::Error,
                        at: Point { x, y },
                        measured: Measurement::Length(Dbu::new_unchecked(offset)),
                        limit: Measurement::Length(Dbu::new_unchecked(0)),
                        shapes: (poly, None),
                    });
                }
                debug_assert_eq!(
                    out.len() - poly_before,
                    offenders,
                    "the compact and the reporting pass disagreed about this polygon"
                );
            }
        }

        debug_assert!(
            out.len() - before <= examined,
            "more off-grid vertices reported than vertices scanned"
        );
        record_run(
            runs,
            out,
            before,
            rule,
            Outcome::Ran,
            u64::try_from(examined).expect("a vertex count fits a u64"),
        );
    }
}

/// Check every angle rule.
///
/// Reported at the edge's first vertex, measuring how many allowed directions
/// the edge matched — zero — against a limit of one. Not an angle in degrees:
/// this crate cannot produce "37.2" exactly.
///
/// `examined` counts edges. Zero-length edges are not counted and not checked.
pub fn check_angle(
    design: Design<'_>,
    table: &AngleTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Borrows no scratch buffer, for the same reason `check_off_grid` does not.
    let _ = scratch;
    let store = design.store;
    let polys = u32::try_from(store.poly_count()).expect("a store indexes polygons with a u32");

    // Two buffers for the whole call, both grown once to the largest ring.
    // `ring` packs the two coordinate columns into the single column an
    // adjacent-pair scan can zip against itself.
    let mut ring: Vec<Point> = Vec::new();
    let mut offending: Vec<(Point, Point)> = Vec::new();

    for row in 0..table.len() {
        let rule = table.rule[row];
        let allowed = table.allowed_of(row);
        let allowed_count =
            u32::try_from(allowed.len()).expect("a rule allows a handful of directions");

        let before = out.len();
        let mut examined = 0usize;

        for index in 0..polys {
            let poly = PolyId(index);
            let (xs, ys) = store.poly_verts(poly);
            debug_assert_eq!(
                xs.len(),
                ys.len(),
                "a polygon's coordinate columns disagree"
            );
            let verts = xs.len();
            // A polygon with no coordinates has no ring to close; this is also
            // the guard that keeps `verts - 1` below from wrapping.
            if verts == 0 {
                continue;
            }
            let layer = store.poly_layer(poly);

            // Pack the two coordinate columns into one, so the ring can be
            // zipped against a one-vertex-shifted view of itself.
            ring.clear();
            ring.extend(xs.iter().zip(ys).map(|(&x, &y)| Point { x, y }));
            // A `zip` truncates to the shorter side rather than complaining, so
            // this is what catches a release build where the columns disagreed.
            debug_assert_eq!(ring.len(), verts, "the packed ring lost a vertex");

            // The ring's `verts - 1` interior edges, as two offset views of the
            // same column. The wrap edge is the scalar fixup below.
            let (tail, head) = (&ring[..verts - 1], &ring[1..]);
            debug_assert_eq!(tail.len(), head.len(), "the offset views disagree");

            let mut edges = 0usize;
            for (&a, &b) in tail.iter().zip(head) {
                edges += usize::from(is_edge(a, b));
            }
            examined += edges;

            let interior = tail.len();
            offending.clear();
            // Every interior edge, not the offending ones: the over-reserve is
            // what pays for the unconditional store.
            offending.reserve(interior);
            let slots = &mut offending.spare_capacity_mut()[..interior];

            let mut offenders = 0usize;
            for (&a, &b) in tail.iter().zip(head) {
                // `&`, not `&&`: both sides are cheap and side-effect free.
                let p = is_edge(a, b) & (directions_matched(allowed, a, b) == 0);
                // SAFETY: the zip runs exactly `interior` times — the two
                // views are slices of one ring and the `debug_assert_eq!`
                // above states they agree — and `offenders` advances by
                // `usize::from(p)`, which `bool`'s 0-or-1 guarantee caps at
                // one per iteration. So `offenders <= i < interior ==
                // slots.len()` at every store. Rejected slots stay uninit and
                // `set_len(offenders)` truncates them away; `(Point, Point)`
                // is `Copy`, so none of them has a `Drop` to run.
                unsafe { slots.get_unchecked_mut(offenders) }.write((a, b));
                offenders += usize::from(p);
            }
            // SAFETY: slots `0 .. offenders` were each written when the cursor
            // held that value, and `offenders <= interior <= capacity`.
            unsafe { offending.set_len(offenders) };
            debug_assert!(
                offenders <= interior,
                "the scan kept more offending edges than the ring has interior edges"
            );

            if offenders != 0 {
                let poly_before = out.len();
                for &(a, b) in &offending {
                    let matched = directions_matched(allowed, a, b);
                    debug_assert_eq!(matched, 0, "the compact kept a legal edge");
                    debug_assert!(
                        matched <= allowed_count,
                        "an edge matched more directions than the rule allows"
                    );
                    out.push(Violation {
                        rule,
                        layer,
                        severity: Severity::Error,
                        // The edge is reported at the vertex it leaves.
                        at: a,
                        measured: Measurement::Count(matched),
                        limit: Measurement::Count(1),
                        shapes: (poly, None),
                    });
                }
                debug_assert_eq!(
                    out.len() - poly_before,
                    offenders,
                    "the compact and the reporting pass disagreed about this polygon"
                );
            }

            // The wrap edge closes the ring, reported last. A one-vertex
            // polygon's wrap edge is degenerate and `is_edge` drops it.
            let (last, first) = (ring[verts - 1], ring[0]);
            let wrap_is_edge = is_edge(last, first);
            let wrap_matched = directions_matched(allowed, last, first);
            debug_assert!(
                wrap_matched <= allowed_count,
                "an edge matched more directions than the rule allows"
            );
            examined += usize::from(wrap_is_edge);
            if wrap_is_edge & (wrap_matched == 0) {
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: last,
                    measured: Measurement::Count(wrap_matched),
                    limit: Measurement::Count(1),
                    shapes: (poly, None),
                });
            }
        }

        debug_assert!(
            out.len() - before <= examined,
            "more offending edges reported than edges scanned"
        );
        record_run(
            runs,
            out,
            before,
            rule,
            Outcome::Ran,
            u64::try_from(examined).expect("an edge count fits a u64"),
        );
    }
}
