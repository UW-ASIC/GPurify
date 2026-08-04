//! Grid family: rules about where vertices may sit and which way edges may
//! point.
//!
//! Two rules, and both are exact integer arithmetic over the coordinate columns
//! with no geometry at all — no pairing, no index, no validation. That is why
//! they share a file and why they are the cheapest rules in the crate: a
//! remainder and a cross product, over two contiguous `Dbu` columns, with no
//! loop-carried dependency. The shape a SIMD reduction wants.
//!
//! # No tolerance band
//!
//! The old tree's angle check took `atan2` in `f64`, normalised to degrees, and
//! accepted anything within 0.5°. That band is fail-open by construction: an
//! edge 0.4° off a legal direction is *not* on that direction, and no
//! manufacturable geometry needs the slack. Here an allowed angle is an exact
//! integer [`Direction`] and the test is a cross product that is zero or is
//! not.
//!
//! The cost is that only multiples of 45° can be expressed, so a deck asking
//! for 30° is [`DrcError::UnrepresentableAngle`](crate::DrcError::UnrepresentableAngle)
//! at load. That is the right answer: this tool's boolean engine refuses
//! non-rectilinear geometry anyway, so a 30° deck was never going to get an
//! exact verdict.

use super::COLUMNS_DIVERGED;
use crate::{record_run, Design, Scratch};
use gpurify_core::ops::Point;
use gpurify_core::PolyId;
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_units::Dbu;

/// Off-grid: every vertex must land on a manufacturing pitch.
///
/// No layer column. The mask grid is a property of the process, not of a layer,
/// and a vertex off it is unmanufacturable wherever it is.
///
/// One pitch for the whole design. Some nodes grid metal and poly differently,
/// and expressing that needs a `layer: Vec<LayerId>` column here plus one row
/// per layer — a new public field on a frozen table and a new column for
/// `RuleSet::from_deck` to fill. Filed in `docs/SIGNATURE_DEFECTS.md` rather
/// than worked around; the transform below already scans per row, so the row
/// gaining a layer is the whole change.
#[derive(Debug, Default)]
pub struct OffGridTable {
    pub rule: Vec<StrId>,
    /// The pitch every coordinate must be a multiple of, in database units.
    /// Distinct from `Grid`, which is the units the file is *written* in; this
    /// is a coarser lattice on top of it.
    pub pitch: Vec<Dbu>,
}

/// Angle: every edge must point in one of the allowed directions.
///
/// The allowed set is CSR — `allowed[start .. start + len]` — rather than a
/// `Vec<Vec<Direction>>`. Two or three directions per rule and a handful of
/// rules per deck, so the nested form would be a dozen allocations of two bytes
/// each.
#[derive(Debug, Default)]
pub struct AngleTable {
    pub rule: Vec<StrId>,
    pub allowed_start: Vec<u32>,
    pub allowed_len: Vec<u32>,
    /// Every allowed direction of every row, concatenated.
    pub allowed: Vec<Direction>,
}

/// A primitive edge direction, as an exact integer vector.
///
/// Components are in `-1 ..= 1`, so `i8` — and a whole allowed-set for a rule
/// fits in one cache line several times over. Stored as a direction rather than
/// as degrees because the *test* is a cross product against an edge vector, and
/// converting an edge to degrees to compare it back is where the floating point
/// crept in.
///
/// Direction is unsigned in the sense that matters: an edge and its reverse
/// point along the same line, and both match. [`Direction::parallel_to`] is
/// what encodes that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Direction {
    pub dx: i8,
    pub dy: i8,
}

impl Direction {
    /// The direction an angle in whole degrees names, or `None` when no
    /// integer vector expresses it.
    ///
    /// **Decision** — one integer in, one value out, pure, and the test plan
    /// names it: the four representable angles modulo 180°, and a rejection for
    /// everything else.
    pub const fn from_degrees(degrees: i32) -> Option<Self> {
        // The four lines a whole-degree angle can name, indexed by
        // `degrees / 45` after folding onto `0 .. 180`. Components are the
        // signs of the cosine and the sine, which is what makes each entry the
        // shortest integer vector along that line.
        const LINES: [Direction; 4] = [
            Direction { dx: 1, dy: 0 },
            Direction { dx: 1, dy: 1 },
            Direction { dx: 0, dy: 1 },
            Direction { dx: -1, dy: 1 },
        ];

        // `rem_euclid`, not `%`: a negative angle is a legal way to name a
        // direction, and `-45 % 45` is `0` while `-30 % 45` is `-30` — the
        // truncating remainder answers the first correctly and the second only
        // by accident of the comparison.
        if degrees.rem_euclid(45) != 0 {
            return None;
        }
        // Modulo 180 because a direction and its reverse are the same line —
        // the `parallel_to` cross product cannot tell them apart, so offering
        // eight answers where there are four would be a lie.
        #[allow(
            clippy::cast_sign_loss,
            reason = "rem_euclid is non-negative, so the quotient is 0..=3"
        )]
        let line = (degrees.rem_euclid(180) / 45) as usize;
        Some(LINES[line])
    }

    /// Whether an edge vector lies along this direction.
    ///
    /// **Decision.** The cross product `dx * self.dy - dy * self.dx` in `i128`,
    /// zero exactly when the two are parallel. No trigonometry, no tolerance,
    /// and therefore no band of edges that are neither accepted nor rejected.
    ///
    /// A zero-length edge is parallel to everything and is not an edge; callers
    /// drop it before asking.
    pub const fn parallel_to(self, dx: Dbu, dy: Dbu) -> bool {
        // `Dbu::mul_wide` is not the route: it `debug_assert`s both operands
        // are inside `±MAX_ABS_DBU`, and an edge vector is a *difference* of
        // two coordinates, which `Dbu::sub` documents as legally outside it.
        // So the widening is spelled out here. `i128` matches the doc above and
        // leaves the bound uninteresting — with components in `-1 ..= 1` the
        // product cannot exceed `2^41` — rather than resting the exactness of
        // the whole rule on a width argument nobody rechecks.
        dx.raw() as i128 * self.dy as i128 - dy.raw() as i128 * self.dx as i128 == 0
    }
}

/// Distance from `(x, y)` to the nearest point of the `pitch` lattice.
///
/// Chebyshev, not Euclidean: the measurement a violation carries is a [`Dbu`],
/// and the Euclidean distance from a vertex to a lattice point is a square
/// root. Reporting a rounded one would be the tolerance band this file exists
/// to refuse, wearing a different hat.
///
/// Per axis it is `min(r, pitch - r)` over the Euclidean remainder, so a
/// coordinate one unit *below* a lattice line measures one rather than
/// `pitch - 1`. Zero exactly when the vertex is on the lattice, which is what
/// makes it both the predicate and the measurement.
#[inline]
fn lattice_offset(x: Dbu, y: Dbu, pitch: i64) -> i64 {
    let rx = x.raw().rem_euclid(pitch);
    let ry = y.raw().rem_euclid(pitch);
    // `min`/`max` builtins, not three `if`s: the sides are equally likely on
    // real geometry and each lowers to one `cmov`.
    rx.min(pitch - rx).max(ry.min(pitch - ry))
}

/// The vector spanned by two consecutive ring vertices.
///
/// A difference of two coordinates, so it is legally outside `±MAX_ABS_DBU` —
/// which is exactly why [`Direction::parallel_to`] widens to `i128` rather than
/// going through `Dbu::mul_wide`.
#[inline]
fn edge_delta(a: Point, b: Point) -> (Dbu, Dbu) {
    (b.x - a.x, b.y - a.y)
}

/// Whether two consecutive ring vertices span a real edge.
///
/// A repeated vertex is not an edge: it is parallel to every direction, so
/// counting it would make a degenerate polygon look clean rather than look
/// degenerate. The `or` of the two components rather than two comparisons —
/// one test, no branch, and it is the same predicate the count and the report
/// both need.
#[inline]
fn is_edge(a: Point, b: Point) -> bool {
    let (dx, dy) = edge_delta(a, b);
    (dx.raw() | dy.raw()) != 0
}

/// How many of `allowed` the edge `a -> b` lies along.
///
/// A fold over two or three directions closed over as a uniform, not a loop
/// over bulk data — so it is cheap enough to call from inside the per-edge
/// scan below, and it carries no data-dependent branch of its own.
#[inline]
fn directions_matched(allowed: &[Direction], a: Point, b: Point) -> u32 {
    let (dx, dy) = edge_delta(a, b);
    allowed
        .iter()
        .fold(0u32, |n, direction| n + u32::from(direction.parallel_to(dx, dy)))
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
        // Fail closed: a run past the end of the concatenated column panics on
        // the slice below, in every profile. Clamping it would silently hand
        // the rule a rule nobody wrote.
        debug_assert!(end <= self.allowed.len(), "an allowed run leaves the column");
        &self.allowed[start..end]
    }

    /// The three row-indexed columns hold the same number of rows.
    ///
    /// `allowed` is not among them: it is the concatenation the other two index
    /// into, and its length is unrelated to the row count.
    fn columns_agree(&self) -> bool {
        self.allowed_start.len() == self.rule.len() && self.allowed_len.len() == self.rule.len()
    }
}

/// Check every off-grid rule.
///
/// **Transform, and the closest thing in the crate to a pure vector loop.**
/// Scans the store's two coordinate columns, testing `x % pitch != 0 ||
/// y % pitch != 0`. Each vertex is independent of every other, the pitch is a
/// uniform, and the only loop-carried value is the compact's write cursor — an
/// accumulator, not a chain.
///
/// One violation per offending vertex, at that vertex, with its distance from
/// the nearest lattice point as the measurement. Per vertex rather than per
/// polygon because a mask-prep tool needs each coordinate, and a polygon with
/// twelve off-grid vertices is twelve edits.
///
/// `examined` counts vertices, not polygons — the only rule in the crate for
/// which those differ by two orders of magnitude, and the number that shows
/// this rule really did sweep the whole design.
pub fn check_off_grid(
    design: Design<'_>,
    table: &OffGridTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // No validation, no index, no pairing: this rule reads the coordinate
    // columns and nothing else, so it borrows no scratch buffer. Named rather
    // than left unused so the parameter still reads as deliberate once the
    // crate's `allow(unused_variables)` goes.
    let _ = scratch;
    let store = design.store;
    let polys = u32::try_from(store.poly_count()).expect("a store indexes polygons with a u32");

    // One buffer for the whole call. `compact_into` reserves for its input, and
    // a reserve costs nothing once the capacity already covers the largest ring
    // in the design — so this is one allocation per call, not one per polygon.
    // It would live in `Scratch` if `Scratch`'s fields were reachable from a
    // pass that may only touch this file.
    let mut offending: Vec<(Dbu, Dbu)> = Vec::new();

    // Tens of rows, read once each: not bulk, and the row's parameters are the
    // uniforms hoisted above the two loops below.
    for row in 0..table.len() {
        let rule = table.rule[row];
        let pitch = table.pitch[row].raw();
        // Every profile, not `debug_assert`. A pitch of zero divides by zero;
        // a negative one makes `rem_euclid` answer for `|pitch|` and reads as a
        // rule nobody wrote. `ingest` refuses both as `NonPositiveLimit`, so
        // reaching here is a programming error, and the surviving assert is
        // also what proves the divisor non-zero for the loop below.
        assert!(pitch > 0, "an off-grid pitch must be positive, not {pitch}");

        let before = out.len();
        // `usize` while it accumulates, widened once at the bottom: the cast is
        // then one instruction per rule row rather than one per polygon.
        let mut examined = 0usize;

        // A raw loop over *polygons*, which is not bulk data by this crate's
        // definition: every violation names its own `PolyId` and layer, and
        // `GeometryStore` hands out coordinates one polygon at a time, so
        // there is no whole-design coordinate column to sweep in one pass. The
        // bulk loop is the per-vertex scan inside. Collapsing this into a
        // single flat scan needs a
        // `verts_layer` column on `GeometryStore` — a widened interface in
        // `gpurify-core`, filed in `docs/SIGNATURE_DEFECTS.md`.
        for index in 0..polys {
            let poly = PolyId(index);
            let (xs, ys) = store.poly_verts(poly);
            debug_assert_eq!(xs.len(), ys.len(), "a polygon's coordinate columns disagree");
            examined += xs.len();

            // One branchless compact over the polygon's two contiguous `Dbu`
            // columns, and it yields both numbers this rule needs: the count,
            // and the offending coordinates themselves, so the reporting loop
            // below is over the *survivors* rather than over every vertex
            // again. A compact that carried the offset its predicate already
            // computed would save recomputing it per survivor — as written
            // that is one division per *reported* violation rather than a
            // second division per *scanned* vertex, which is the cheaper side
            // of the trade on any design worth taping out.
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

            // The taken side pushes eight columns per offending vertex, and on
            // any design worth taping out it is not taken at all. Skipping
            // expensive work is what a branch is for.
            if offenders != 0 {
                let layer = store.poly_layer(poly);
                let poly_before = out.len();
                // Not a loop over bulk data: `offending` holds only the
                // vertices already found off-grid, and the body writes eight
                // `Violations` columns from one input row.
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
/// Scans every edge of every polygon and rejects those parallel to none of the
/// row's allowed directions. Reported at the edge's first vertex, measuring the
/// number of allowed directions the edge matched — zero — against a limit of
/// one. Not an angle in degrees: "37.2°" is not a quantity this crate can
/// produce exactly, and reporting an inexact one would be the same mistake the
/// tolerance band was.
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

    // Two buffers for the whole call, both grown once to the largest ring the
    // design holds. `ring` packs a polygon's two coordinate columns into the
    // single column an adjacent-pair scan can zip against itself — `Cols` stops
    // at three columns and `(xs[..n-1], xs[1..], ys[..n-1], ys[1..])` is four,
    // so the pairing is done on a packed `Point` instead of on a fourth impl.
    // `offending` takes the compacted edges.
    let mut ring: Vec<Point> = Vec::new();
    let mut offending: Vec<(Point, Point)> = Vec::new();

    for row in 0..table.len() {
        let rule = table.rule[row];
        // Two or three entries, hoisted above both loops as the uniform.
        let allowed = table.allowed_of(row);
        let allowed_count =
            u32::try_from(allowed.len()).expect("a rule allows a handful of directions");

        let before = out.len();
        // `usize` while it accumulates, widened once at the bottom.
        let mut examined = 0usize;

        // A raw loop over polygons, not over bulk data, for the same reason as
        // `check_off_grid`: a violation names its polygon, and vertices arrive
        // one polygon at a time. The same `verts_layer` column on
        // `GeometryStore` would flatten it; filed in
        // `docs/SIGNATURE_DEFECTS.md`.
        for index in 0..polys {
            let poly = PolyId(index);
            let (xs, ys) = store.poly_verts(poly);
            debug_assert_eq!(xs.len(), ys.len(), "a polygon's coordinate columns disagree");
            let verts = xs.len();
            // A polygon with no coordinates has no ring to close. Once per
            // polygon and outside every inner loop: this is the guard that
            // keeps `verts - 1` below from wrapping, not a per-element branch.
            if verts == 0 {
                continue;
            }
            let layer = store.poly_layer(poly);

            // Pack the two coordinate columns into one, so the ring can be
            // zipped against a one-vertex-shifted view of itself. `clear` then
            // `extend`: `clear` keeps the capacity, and the zip of two slice
            // iterators is `TrustedLen`, so `extend` reserves the exact count
            // once and the loop reallocates nothing. Spelling out a
            // reserve-and-`set_len` here would buy nothing over that.
            ring.clear();
            ring.extend(xs.iter().zip(ys).map(|(&x, &y)| Point { x, y }));
            // The columns were asserted equal above; this is what catches a
            // release build where they were not, since a `zip` truncates to
            // the shorter one rather than complaining.
            debug_assert_eq!(ring.len(), verts, "the packed ring lost a vertex");

            // The ring's `verts - 1` interior edges, as two offset views of the
            // same column. The wrap edge is the scalar fixup below, which is
            // what keeps its branch out of both inner loop bodies.
            let (tail, head) = (&ring[..verts - 1], &ring[1..]);
            debug_assert_eq!(tail.len(), head.len(), "the offset views disagree");

            // A strict left-to-right fold over the interior edges. The order
            // is free here — this accumulator is a `usize` and integer
            // addition reassociates exactly — but it is written in index order
            // anyway, because that is the order every fold in this tree keeps.
            let mut edges = 0usize;
            for (&a, &b) in tail.iter().zip(head) {
                // Branchless: the flag is arithmetic on the running count, not
                // control flow.
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
                // `&`, not `&&`: both sides are cheap and side-effect free, so
                // short-circuiting would only buy a branch this body may not
                // have.
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

            // The taken side pushes eight columns and is not taken on
            // rectilinear geometry, which is what this tool represents.
            if offenders != 0 {
                let poly_before = out.len();
                // Not a loop over bulk data: `offending` holds only the edges
                // already found illegal, and the body writes eight `Violations`
                // columns from one input row.
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
                        // The count of allowed directions the edge lay along —
                        // zero — against a requirement of one. Not degrees:
                        // this crate cannot produce "37.2" exactly, and an
                        // inexact measurement is the tolerance band again.
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

            // The wrap edge closes the ring, and it is reported last because
            // that is the order the vertex sweep it replaced produced. A closed
            // ring has as many edges as vertices; a one-vertex polygon's wrap
            // edge is degenerate and `is_edge` drops it, which is the same
            // answer the sweep gave.
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
