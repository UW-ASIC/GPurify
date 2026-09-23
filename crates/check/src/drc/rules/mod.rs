//! The twenty-four rule kinds, one function per kind, grouped by what they measure.
//!
//! Data in: one rule row's parameters, the store and a `Scratch`.
//! Data out: violations appended to `out`, and the row's [`Verdict`].
//! `Violation::at` is the midpoint of the thing measured (a vertex for off-grid
//! and angle). A layer that fails to validate is `Refused`, never a clean `Ran`.

pub mod area;
pub mod grid;
pub mod overlay;
pub mod patterning;
pub mod spacing;
pub mod via;
pub mod width;

use crate::report::Outcome;
use fearless_simd::{dispatch, f64x4, Level, Simd, SimdBase};
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::ops::{seg_seg_dist2, Point, Seg};
use gpurify_geom::{Bbox, GeometryStore, PolyId};
use gpurify_geom::{Dbu, DbuArea};

/// How one rule row ended, and how many of its primitives it examined.
pub(crate) type Verdict = (Outcome, u64);

pub(crate) const REFUSED: Verdict = (Outcome::Refused, 0);

/// Midpoint of two coordinates, floored (`div_euclid`) on both sides of the origin.
pub(crate) const fn mid(a: Dbu, b: Dbu) -> Dbu {
    Dbu::new_unchecked((a.raw() + b.raw()).div_euclid(2))
}

/// The middle of the interval two boxes share, or of the gap between them when
/// they share none — the report point for a pairwise violation.
pub(crate) const fn gap_midpoint(a: Bbox, b: Bbox) -> Point {
    Point {
        x: span_mid(a.xlo, a.xhi, b.xlo, b.xhi),
        y: span_mid(a.ylo, a.yhi, b.ylo, b.yhi),
    }
}

const fn span_mid(alo: Dbu, ahi: Dbu, blo: Dbu, bhi: Dbu) -> Dbu {
    let lo = if alo.raw() >= blo.raw() { alo } else { blo };
    let hi = if ahi.raw() <= bhi.raw() { ahi } else { bhi };
    mid(lo, hi)
}

pub(crate) const fn centre(b: Bbox) -> Point {
    gap_midpoint(b, b)
}

/// One closed ring's edges, in vertex order, closing edge last.
pub(crate) fn ring_segs<'a>(xs: &'a [Dbu], ys: &'a [Dbu]) -> impl Iterator<Item = Seg> + 'a {
    let n = xs.len();
    (0..n).map(move |i| {
        let j = if i + 1 < n { i + 1 } else { 0 };
        Seg {
            a: Point { x: xs[i], y: ys[i] },
            b: Point { x: xs[j], y: ys[j] },
        }
    })
}

pub(crate) const fn seg_bbox(s: Seg) -> Bbox {
    Bbox::point(s.a.x, s.a.y).include(s.b.x, s.b.y)
}

/// Squared distance between two boxes, zero where they touch or overlap; a
/// lower bound on the distance between anything they contain.
const fn bbox_gap2(a: Bbox, b: Bbox) -> DbuArea {
    let dx = axis_gap(a.xlo, a.xhi, b.xlo, b.xhi);
    let dy = axis_gap(a.ylo, a.yhi, b.ylo, b.yhi);
    DbuArea::new(dx * dx + dy * dy)
}

const fn axis_gap(alo: Dbu, ahi: Dbu, blo: Dbu, bhi: Dbu) -> i128 {
    let lo = if alo.raw() >= blo.raw() {
        alo.raw()
    } else {
        blo.raw()
    };
    let hi = if ahi.raw() <= bhi.raw() {
        ahi.raw()
    } else {
        bhi.raw()
    };
    let d = lo - hi;
    if d > 0 {
        d as i128
    } else {
        0
    }
}

/// Exact squared distance between two store polygons' *boundaries*; zero exactly
/// when they touch or cross. Quadratic in the two ring sizes.
pub(crate) fn poly_dist2(store: &GeometryStore, a: PolyId, b: PolyId) -> DbuArea {
    let (axs, ays) = store.poly_verts(a);
    let (bxs, bys) = store.poly_verts(b);
    let box_b = Bbox::of_points(bxs, bys);

    let mut best = DbuArea::new(i128::MAX);
    for sa in ring_segs(axs, ays) {
        let box_a = seg_bbox(sa);
        if bbox_gap2(box_a, box_b) >= best {
            continue;
        }
        for sb in ring_segs(bxs, bys) {
            if bbox_gap2(box_a, seg_bbox(sb)) < best {
                best = best.min(seg_seg_dist2(sa, sb));
            }
        }
    }
    best
}

/// Squared boundary distance for every pair, into `dists`: exact wherever it is
/// below `limit²`, and never below `limit²` where the exact value is not.
/// Rectilinear pairs under a limit below `GAP_CAP` take the capped f64 kernel.
pub(crate) fn pair_distances_into(
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    limit: Dbu,
    dists: &mut Vec<DbuArea>,
) {
    dists.clear();
    if limit.raw() >= GAP_CAP {
        dists.extend(pairs.iter().map(|&(a, b)| poly_dist2(store, a, b)));
        return;
    }
    dispatch!(Level::new(), simd => capped_distances(simd, store, pairs, dists));
}

/// Gaps are capped here so `gx² + gy²` is exact in f64 (at most 2^53).
const GAP_CAP: i64 = 1 << 26;

/// Squared distance per pair, exact below `GAP_CAP²` and at least `GAP_CAP²`
/// otherwise. Callers compare only against `limit²` with `limit < GAP_CAP`,
/// and report `isqrt` only below it, so this is as good as exact for them.
#[allow(
    clippy::inline_always,
    reason = "a fearless_simd kernel inlines into its dispatch"
)]
#[inline(always)]
fn capped_distances<S: Simd>(
    s: S,
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    dists: &mut Vec<DbuArea>,
) {
    let mut far = EdgeBoxes::default();
    for &(a, b) in pairs {
        let (axs, ays) = store.poly_verts(a);
        let (bxs, bys) = store.poly_verts(b);
        let d2 = if rectilinear(axs, ays) && rectilinear(bxs, bys) {
            far.fill(bxs, bys);
            DbuArea::new(capped_dist2_simd(s, axs, ays, &far))
        } else {
            poly_dist2(store, a, b)
        };
        dists.push(d2);
    }
}

/// Every edge axis-aligned (or zero-length).
fn rectilinear(xs: &[Dbu], ys: &[Dbu]) -> bool {
    ring_segs(xs, ys).all(|e| e.a.x == e.b.x || e.a.y == e.b.y)
}

/// One ring's edge boxes as f64 columns (exact: |coordinate| <= 2^40).
#[derive(Debug, Default)]
struct EdgeBoxes {
    xlo: Vec<f64>,
    xhi: Vec<f64>,
    ylo: Vec<f64>,
    yhi: Vec<f64>,
}

impl EdgeBoxes {
    fn fill(&mut self, xs: &[Dbu], ys: &[Dbu]) {
        self.xlo.clear();
        self.xhi.clear();
        self.ylo.clear();
        self.yhi.clear();
        for e in ring_segs(xs, ys) {
            let b = seg_bbox(e);
            self.xlo.push(to_f64(b.xlo));
            self.xhi.push(to_f64(b.xhi));
            self.ylo.push(to_f64(b.ylo));
            self.yhi.push(to_f64(b.yhi));
        }
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "|coordinate| <= 2^40, exact in f64"
)]
fn to_f64(d: Dbu) -> f64 {
    d.raw() as f64
}

/// An axis-aligned segment is its own box, so two such segments are
/// `gx² + gy²` apart, with `g` the per-axis box gap (capped at `GAP_CAP`).
fn capped_gap2(a: Bbox, far: &EdgeBoxes, j: usize) -> f64 {
    let cap = to_f64(Dbu::new_unchecked(GAP_CAP));
    let gx = (to_f64(a.xlo).max(far.xlo[j]) - to_f64(a.xhi).min(far.xhi[j])).clamp(0.0, cap);
    let gy = (to_f64(a.ylo).max(far.ylo[j]) - to_f64(a.yhi).min(far.yhi[j])).clamp(0.0, cap);
    gx * gx + gy * gy
}

/// The scalar kernel: tail and oracle of [`capped_dist2_simd`].
fn capped_dist2_scalar(xs: &[Dbu], ys: &[Dbu], far: &EdgeBoxes, from: usize) -> f64 {
    let mut best = f64::INFINITY;
    for e in ring_segs(xs, ys) {
        let a = seg_bbox(e);
        for j in from..far.xlo.len() {
            best = best.min(capped_gap2(a, far, j));
        }
    }
    best
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::inline_always,
    reason = "an integer at most 2^53; a fearless_simd kernel inlines into its dispatch"
)]
#[inline(always)]
fn capped_dist2_simd<S: Simd>(s: S, xs: &[Dbu], ys: &[Dbu], far: &EdgeBoxes) -> i128 {
    let chunks = far.xlo.len() / 4 * 4;
    let (zero, cap) = (
        f64x4::splat(s, 0.0),
        f64x4::splat(s, to_f64(Dbu::new_unchecked(GAP_CAP))),
    );
    let mut best = f64x4::splat(s, f64::INFINITY);
    for e in ring_segs(xs, ys) {
        let a = seg_bbox(e);
        let (axlo, axhi) = (
            f64x4::splat(s, to_f64(a.xlo)),
            f64x4::splat(s, to_f64(a.xhi)),
        );
        let (aylo, ayhi) = (
            f64x4::splat(s, to_f64(a.ylo)),
            f64x4::splat(s, to_f64(a.yhi)),
        );
        for j in (0..chunks).step_by(4) {
            let load = |col: &[f64]| f64x4::from_slice(s, &col[j..j + 4]);
            let gx = (axlo.max(load(&far.xlo)) - axhi.min(load(&far.xhi)))
                .max(zero)
                .min(cap);
            let gy = (aylo.max(load(&far.ylo)) - ayhi.min(load(&far.yhi)))
                .max(zero)
                .min(cap);
            best = best.min(gx * gx + gy * gy);
        }
    }
    let best = best
        .reduce_min()
        .min(capped_dist2_scalar(xs, ys, far, chunks));
    i128::from(best as i64)
}

/// Label the rows `first_row ..` of one layer by the components of the pairs
/// whose distance `join` accepts. A label is its component's minimum row offset.
pub(crate) fn label_pairs_into(
    first_row: u32,
    node_count: u32,
    pairs: &[(PolyId, PolyId)],
    dists: &[DbuArea],
    join: impl Fn(DbuArea) -> bool,
    edges: &mut Vec<(u32, u32)>,
    labels: &mut Vec<ComponentLabel>,
) {
    edges.clear();
    edges.extend(
        pairs
            .iter()
            .zip(dists)
            .filter(|&(_, &d2)| join(d2))
            .map(|(&(a, b), _)| (a.0 - first_row, b.0 - first_row)),
    );
    components_into(node_count, edges, labels);
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpurify_geom::store::GeometryStoreBuilder;
    use gpurify_geom::{LayerId, MAX_ABS_DBU};

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: i64) -> i64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            i64::try_from(self.0 % n.unsigned_abs()).unwrap()
        }
        fn coord(&mut self, centre: i64, spread: i64) -> Dbu {
            let raw = centre + self.below(2 * spread + 1) - spread;
            Dbu::new_unchecked(raw.clamp(-MAX_ABS_DBU, MAX_ABS_DBU))
        }
    }

    /// A closed ring of `2k` vertices, every edge axis-aligned (may self-cross).
    fn staircase(r: &mut Rng, k: usize, c: (i64, i64), spread: i64) -> (Vec<Dbu>, Vec<Dbu>) {
        let px: Vec<Dbu> = (0..k).map(|_| r.coord(c.0, spread)).collect();
        let py: Vec<Dbu> = (0..k).map(|_| r.coord(c.1, spread)).collect();
        let (mut xs, mut ys) = (Vec::new(), Vec::new());
        for i in 0..k {
            xs.extend([px[i], px[(i + 1) % k]]);
            ys.extend([py[i], py[i]]);
        }
        (xs, ys)
    }

    fn free_ring(r: &mut Rng, n: usize, c: (i64, i64), spread: i64) -> (Vec<Dbu>, Vec<Dbu>) {
        (0..n)
            .map(|_| (r.coord(c.0, spread), r.coord(c.1, spread)))
            .unzip()
    }

    /// Differential: the capped path equals the exact i128 one below the cap,
    /// never reads under it above, and non-rectilinear pairs fall back.
    #[test]
    fn capped_distances_agree_with_poly_dist2() {
        let mut r = Rng(0x2545_f491_4f6c_dd1d);
        let cap2 = i128::from(GAP_CAP) * i128::from(GAP_CAP);
        for round in 0..400 {
            let spread = [10, 1_000, GAP_CAP, MAX_ABS_DBU][round % 4];
            let centre = if round % 7 == 0 { MAX_ABS_DBU - 5 } else { 0 };
            let mut b = GeometryStoreBuilder::default();
            for _ in 0..6 {
                let c = (r.coord(centre, spread).raw(), r.coord(0, spread).raw());
                let (xs, ys) = if r.below(3) == 0 {
                    let n = 3 + usize::try_from(r.below(5)).unwrap();
                    free_ring(&mut r, n, c, spread / 4 + 1)
                } else {
                    let k = 1 + usize::try_from(r.below(7)).unwrap();
                    staircase(&mut r, k, c, spread / 4 + 1)
                };
                b.push(LayerId(0), &xs, &ys);
            }
            let (store, _) = b.finish(1);
            let pairs: Vec<(PolyId, PolyId)> = (0..6)
                .flat_map(|a| (a + 1..6).map(move |b| (PolyId(a), PolyId(b))))
                .collect();
            let (mut exact, mut capped) = (Vec::new(), Vec::new());
            pair_distances_into(&store, &pairs, Dbu::new_unchecked(GAP_CAP), &mut exact);
            pair_distances_into(&store, &pairs, Dbu::new_unchecked(GAP_CAP - 1), &mut capped);
            for ((e, c), p) in exact.iter().zip(&capped).zip(&pairs) {
                if e.raw() < cap2 {
                    assert_eq!(e, c, "{p:?}");
                } else {
                    assert!(c.raw() >= cap2, "{p:?}: {c:?} under the cap for {e:?}");
                }
            }
        }
    }

    /// Differential: the SIMD kernel equals its scalar oracle for every edge
    /// count `0 ..= 3 * 4 + 1` on either side.
    #[test]
    fn capped_dist2_simd_matches_scalar() {
        let mut r = Rng(0x9e37_79b9_7f4a_7c15);
        let mut far = EdgeBoxes::default();
        for n in 0..=13 {
            for m in 0..=13 {
                for spread in [3, GAP_CAP, MAX_ABS_DBU] {
                    let (xs, ys) = free_ring(&mut r, n, (0, 0), spread);
                    let (bx, by) = free_ring(&mut r, m, (0, 0), spread);
                    far.fill(&bx, &by);
                    let simd = dispatch!(Level::new(), s => capped_dist2_simd(s, &xs, &ys, &far));
                    #[allow(clippy::cast_possible_truncation, reason = "at most 2^53, or inf")]
                    let scalar = i128::from(capped_dist2_scalar(&xs, &ys, &far, 0) as i64);
                    assert_eq!(simd, scalar, "n={n} m={m}");
                }
            }
        }
    }

    /// `cargo test --release -p gpurify-check -- --ignored --nocapture bench_pair`
    #[test]
    #[ignore = "timing"]
    fn bench_pair_distances() {
        use std::hint::black_box;
        use std::time::Instant;
        let mut r = Rng(7);
        let mut b = GeometryStoreBuilder::default();
        for k in [2usize, 2, 2, 2, 3, 6, 12] {
            for _ in 0..300 {
                let c = (r.below(20_000), r.below(20_000));
                let (xs, ys) = staircase(&mut r, k, c, 300);
                b.push(LayerId(0), &xs, &ys);
            }
        }
        let (store, _) = b.finish(1);
        // Real candidate pairs: boxes within the limit, as the spacing rules see them.
        let mut index = gpurify_geom::index::SpatialIndex::default();
        gpurify_geom::index::SpatialIndex::build_into(&store, LayerId(0), &mut index);
        let mut pairs = Vec::new();
        let limit = Dbu::new_unchecked(100);
        gpurify_geom::index::candidate_pairs_into(&store, &index, limit, &mut pairs);
        let (mut exact, mut capped) = (Vec::new(), Vec::new());
        let big = Dbu::new_unchecked(GAP_CAP);
        let t = Instant::now();
        pair_distances_into(&store, black_box(&pairs), big, &mut exact);
        let slow = t.elapsed();
        let t = Instant::now();
        pair_distances_into(
            &store,
            black_box(&pairs),
            Dbu::new_unchecked(100),
            &mut capped,
        );
        let fast = t.elapsed();
        assert_eq!(exact, capped);
        eprintln!(
            "{} pairs: exact i128 {slow:?}  capped simd {fast:?}",
            pairs.len()
        );
    }
}
