//! The booleans on operands with edges at any angle: snap rounding.
//!
//! Oracle, brute force: snap rounding moves every boundary point less than
//! half a unit along each axis (`boolean::union_into`), so at every point
//! farther than half a unit along some axis from every operand edge (outside
//! every edge's closed L∞ band of radius ½) the result holds exactly the
//! points the set operation of the operands' exact winding numbers holds. The
//! oracle reads both by even-odd ray casts at quarter-grid sample points,
//! exact in integers, never through the engine. Also: the eight symmetries
//! of the grid about the origin (rounding a half away from zero is
//! symmetric), shapes that do not cross merging to themselves, and
//! hand-derived crossings.

use gpurify_geom::boolean::{intersection_into, subtraction_into, union_into};
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_testgen::prop::{check, seeds};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::Rng;

/// Operands live in `[-SIDE, SIDE]²`.
const SIDE: i64 = 24;

type Ring = Vec<(i64, i64)>;
/// One drawn polygon: its layer and its counter-clockwise vertices.
type Shape = (u16, Ring);

/// A star-shaped polygon round a centre, its 3 to 7 vertices at distinct
/// angles: simple, at any angle, counter-clockwise.
pub(crate) fn random_star(rng: &mut Rng, side: i64) -> Ring {
    loop {
        let (cx, cy) = (
            rng.range(-side / 2, side / 2),
            rng.range(-side / 2, side / 2),
        );
        let n = rng.range(3, 8);
        let mut pts: Vec<(i64, i64)> = (0..n)
            .map(|_| (rng.range(-side, side + 1), rng.range(-side, side + 1)))
            .filter(|&p| p != (cx, cy))
            .collect();
        // By angle round the centre, exactly: half-plane, then cross product.
        let half = |(x, y): (i64, i64)| y < cy || (y == cy && x < cx);
        pts.sort_by(|&p, &q| {
            half(p).cmp(&half(q)).then_with(|| {
                let c = (p.0 - cx) * (q.1 - cy) - (p.1 - cy) * (q.0 - cx);
                0.cmp(&c)
            })
        });
        let distinct = pts.windows(2).all(|w| {
            let c = (w[0].0 - cx) * (w[1].1 - cy) - (w[0].1 - cy) * (w[1].0 - cx);
            !(c == 0 && half(w[0]) == half(w[1]))
        });
        // The centre strictly inside: every turn round it under 180 degrees.
        let k = pts.len();
        let inside = k >= 3
            && (0..k).all(|i| {
                let (p, q) = (pts[i], pts[(i + 1) % k]);
                (p.0 - cx) * (q.1 - cy) - (p.1 - cy) * (q.0 - cx) > 0
            });
        if distinct && inside {
            return pts;
        }
    }
}

fn generate(rng: &mut Rng) -> Vec<Shape> {
    let mut shapes = Vec::new();
    for layer in 0..2u16 {
        for _ in 0..rng.range(1, 4) {
            shapes.push((layer, random_star(rng, SIDE)));
        }
    }
    shapes
}

fn shrink(shapes: &[Shape]) -> Vec<Vec<Shape>> {
    (0..shapes.len())
        .map(|skip| {
            let mut fewer = shapes.to_vec();
            fewer.remove(skip);
            fewer
        })
        .collect()
}

fn store_of(shapes: &[Shape]) -> GeometryStore {
    let mut layout = LayoutBuilder::new(2);
    for (layer, points) in shapes {
        let (xs, ys): (Vec<i64>, Vec<i64>) = points.iter().copied().unzip();
        layout.push(LayerId(*layer), &xs, &ys);
    }
    layout.finish().0
}

fn validated(store: &GeometryStore, layer: u16) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_with(store, LayerId(layer), Angles::Any, &mut out)
        .expect("generated stars are valid rings");
    out
}

fn rings(layer: &ValidatedLayer) -> Vec<Ring> {
    let mut out = Vec::new();
    for idx in 0..u32::try_from(layer.len()).expect("small") {
        for ring in layer.poly_rings(idx) {
            let (xs, ys) = ring.coords();
            out.push(xs.iter().zip(ys).map(|(x, y)| (x.raw(), y.raw())).collect());
        }
    }
    out
}

/// Even-odd: is `(px, py) / 4` inside the ring (at unit scale)? The point
/// must lie on none of its edges.
fn inside4(ring: &Ring, px: i64, py: i64) -> bool {
    let mut odd = false;
    for i in 0..ring.len() {
        let ((ax, ay), (bx, by)) = (ring[i], ring[(i + 1) % ring.len()]);
        let (ax, ay, bx, by) = (4 * ax, 4 * ay, 4 * bx, 4 * by);
        if (ay > py) != (by > py) {
            let side = (bx - ax) * (py - ay) - (by - ay) * (px - ax);
            if (side > 0) == (by > ay) {
                odd = !odd;
            }
        }
    }
    odd
}

/// Whether the segment `a`-`b` meets the closed box `[x0, x1] x [y0, y1]`,
/// all at one scale: Liang-Barsky clipping with rational parameters.
fn meets_box(a: (i64, i64), b: (i64, i64), x0: i64, x1: i64, y0: i64, y1: i64) -> bool {
    // t in [lo_n/lo_d, hi_n/hi_d], denominators positive.
    let (mut lo, mut hi) = ((0i128, 1i128), (1i128, 1i128));
    for (from, to, min, max) in [(a.0, b.0, x0, x1), (a.1, b.1, y0, y1)] {
        let d = i128::from(to - from);
        let (s, min, max) = (i128::from(from), i128::from(min), i128::from(max));
        if d == 0 {
            if s < min || s > max {
                return false;
            }
            continue;
        }
        let (enter, leave) = if d > 0 {
            ((min - s, d), (max - s, d))
        } else {
            ((s - max, -d), (s - min, -d))
        };
        if enter.0 * lo.1 > lo.0 * enter.1 {
            lo = enter;
        }
        if leave.0 * hi.1 < hi.0 * leave.1 {
            hi = leave;
        }
    }
    lo.0 * hi.1 <= hi.0 * lo.1
}

/// The result agrees with the exact set operation at every quarter-grid point
/// farther than half a unit, along some axis, from every operand edge.
fn agrees(
    name: &str,
    got: &ValidatedLayer,
    a: &[Ring],
    b: &[Ring],
    op: fn(bool, bool) -> bool,
) -> Result<(), String> {
    let edges: Vec<((i64, i64), (i64, i64))> = a
        .iter()
        .chain(b)
        .flat_map(|r| (0..r.len()).map(move |i| (r[i], r[(i + 1) % r.len()])))
        .map(|((ax, ay), (bx, by))| ((4 * ax, 4 * ay), (4 * bx, 4 * by)))
        .collect();
    let result = rings(got);
    let mut checked = 0;
    for py in (-4 * SIDE - 4..=4 * SIDE + 4).step_by(3) {
        for px in (-4 * SIDE - 4..=4 * SIDE + 4).step_by(3) {
            if edges
                .iter()
                .any(|&(p, q)| meets_box(p, q, px - 2, px + 2, py - 2, py + 2))
            {
                continue;
            }
            checked += 1;
            let want = op(
                a.iter().any(|r| inside4(r, px, py)),
                b.iter().any(|r| inside4(r, px, py)),
            );
            let have = result.iter().filter(|r| inside4(r, px, py)).count() % 2 == 1;
            if want != have {
                return Err(format!(
                    "{name}: at ({px}, {py})/4 the result says {have}, the operands {want}"
                ));
            }
        }
    }
    if checked == 0 {
        return Err(format!("{name}: no sample point clear of the edges"));
    }
    Ok(())
}

fn run(kind: &str, a: &ValidatedLayer, b: &ValidatedLayer) -> Result<ValidatedLayer, String> {
    let mut out = ValidatedLayer::default();
    match kind {
        "or" => union_into(a, b, &mut out),
        "and" => intersection_into(a, b, &mut out),
        _ => subtraction_into(a, b, &mut out),
    }
    .map_err(|why| format!("{kind}: {why}"))?;
    Ok(out)
}

const OPS: [(&str, fn(bool, bool) -> bool); 3] = [
    ("or", |p, q| p | q),
    ("and", |p, q| p & q),
    ("not", |p, q| p & !q),
];

fn property(shapes: &[Shape]) -> Result<(), String> {
    let store = store_of(shapes);
    let (a, b) = (validated(&store, 0), validated(&store, 1));
    let of = |layer: u16| -> Vec<Ring> {
        shapes
            .iter()
            .filter(|(l, _)| *l == layer)
            .map(|(_, r)| r.clone())
            .collect()
    };
    let (ra, rb) = (of(0), of(1));
    for (kind, op) in OPS {
        let got = run(kind, &a, &b)?;
        agrees(kind, &got, &ra, &rb, op)?;
        let back = run(kind, &b, &a)?;
        agrees(&format!("{kind} swapped"), &back, &rb, &ra, op)?;
    }
    Ok(())
}

/// Oracle: the brute-force winding reference in the module doc, over 150
/// named seeds of one to three random any-angle stars per operand.
#[test]
fn any_angle_booleans_agree_with_the_exact_operation_away_from_the_rounding() {
    check(
        "any_angle_booleans_agree_with_the_exact_operation_away_from_the_rounding",
        seeds(
            "any_angle_booleans_agree_with_the_exact_operation_away_from_the_rounding",
            150,
        ),
        generate,
        |s| shrink(s),
        |s| property(s),
    );
}

/// The nightly twin, over 3000 seeds.
///
/// Oracle: the brute-force winding reference in the module doc.
#[test]
#[ignore = "nightly: 3000 seeds"]
fn any_angle_booleans_agree_with_the_exact_operation_nightly() {
    check(
        "any_angle_booleans_agree_with_the_exact_operation_away_from_the_rounding",
        seeds(
            "any_angle_booleans_agree_with_the_exact_operation_away_from_the_rounding",
            3000,
        ),
        generate,
        |s| shrink(s),
        |s| property(s),
    );
}

/// Every directed boundary edge of a layer, sorted: equal for equal regions,
/// whatever vertex each ring starts at.
fn edge_set(
    layer: &ValidatedLayer,
    map: impl Fn((i64, i64)) -> (i64, i64),
    mirror: bool,
) -> Vec<((i64, i64), (i64, i64))> {
    let mut out = Vec::new();
    for ring in rings(layer) {
        for i in 0..ring.len() {
            let (p, q) = (map(ring[i]), map(ring[(i + 1) % ring.len()]));
            out.push(if mirror { (q, p) } else { (p, q) });
        }
    }
    out.sort_unstable();
    out
}

/// The eight symmetries of the grid about the origin.
fn symmetry(t: usize) -> impl Fn((i64, i64)) -> (i64, i64) {
    move |(x, y)| {
        let (x, y) = if t & 4 == 0 { (x, y) } else { (y, x) };
        (
            if t & 1 == 0 { x } else { -x },
            if t & 2 == 0 { y } else { -y },
        )
    }
}

fn mirrors(t: usize) -> bool {
    (t & 1 != 0) ^ (t & 2 != 0) ^ (t & 4 != 0)
}

fn symmetric(shapes: &[Shape]) -> Result<(), String> {
    let store = store_of(shapes);
    let (a, b) = (validated(&store, 0), validated(&store, 1));
    for t in 1..8 {
        let image: Vec<Shape> = shapes
            .iter()
            .map(|(l, r)| {
                let mut r: Ring = r.iter().map(|&p| symmetry(t)(p)).collect();
                if mirrors(t) {
                    r.reverse();
                }
                (*l, r)
            })
            .collect();
        let image_store = store_of(&image);
        let (ta, tb) = (validated(&image_store, 0), validated(&image_store, 1));
        for (kind, _) in OPS {
            let here = edge_set(&run(kind, &a, &b)?, symmetry(t), mirrors(t));
            let there = edge_set(&run(kind, &ta, &tb)?, |p| p, false);
            if here != there {
                return Err(format!("{kind} under symmetry {t}: {here:?} vs {there:?}"));
            }
        }
    }
    Ok(())
}

/// Each operation commutes with every symmetry of the grid about the origin,
/// rounding included: a half rounds away from zero, so the pixels map onto
/// one another.
///
/// Oracle: metamorphic, the eight grid symmetries, over 100 named seeds.
#[test]
fn any_angle_booleans_commute_with_the_grid_symmetries() {
    check(
        "any_angle_booleans_commute_with_the_grid_symmetries",
        seeds("any_angle_booleans_commute_with_the_grid_symmetries", 100),
        generate,
        |s| shrink(s),
        |s| symmetric(s),
    );
}

fn layer_of(rings_in: &[Ring]) -> ValidatedLayer {
    let shapes: Vec<Shape> = rings_in.iter().map(|r| (0u16, r.clone())).collect();
    validated(&store_of(&shapes), 0)
}

fn twice_area(layer: &ValidatedLayer) -> i128 {
    (0..u32::try_from(layer.len()).expect("small"))
        .flat_map(|i| {
            layer
                .poly_rings(i)
                .map(|r| r.area2().raw())
                .collect::<Vec<_>>()
        })
        .sum()
}

/// Two triangles whose slanted sides cross at (5, 1.5), between grid points.
///
/// Oracle: hand-derived. `A` = (0,0),(10,0),(0,3) and `B` = (0,0),(10,0),
/// (10,3). The crossing rounds a half away from zero to (5, 2), and both
/// slanted sides pass its pixel `[4.5, 5.5) x [1.5, 2.5)` at x = 5, so both
/// bend through it: A and B is the triangle (0,0),(10,0),(5,2), area 10
/// (exactly 7.5 unrounded); A or B is 30 less the notch (0,3),(5,2),(10,3)
/// of area 5, so 25; A not B is (0,0),(5,2),(0,3), area 7.5.
#[test]
fn a_crossing_between_grid_points_rounds_to_the_nearest_one() {
    let a = layer_of(&[vec![(0, 0), (10, 0), (0, 3)]]);
    let b = layer_of(&[vec![(0, 0), (10, 0), (10, 3)]]);
    let and = run("and", &a, &b).expect("computes");
    assert_eq!(
        edge_set(&and, |p| p, false),
        edge_set(&layer_of(&[vec![(0, 0), (10, 0), (5, 2)]]), |p| p, false)
    );
    assert_eq!(twice_area(&and), 20);
    assert_eq!(twice_area(&run("or", &a, &b).expect("computes")), 50);
    assert_eq!(twice_area(&run("not", &a, &b).expect("computes")), 15);
}

/// Shapes at any angle that touch nothing merge to themselves: no crossing,
/// so nothing is rounded and no edge bends.
///
/// Oracle: construct-from-answer; the drawn rings are the answer.
#[test]
fn shapes_that_cross_nothing_merge_to_themselves() {
    let drawn = vec![
        vec![(0, 0), (7, 2), (3, 9)],
        vec![(20, 0), (31, 5), (26, 13), (19, 6)],
    ];
    let layer = layer_of(&drawn);
    let merged = run("or", &layer, &ValidatedLayer::default()).expect("computes");
    assert_eq!(
        edge_set(&merged, |p| p, false),
        edge_set(&layer, |p| p, false)
    );
}

/// A vertex inside a bent edge's pixel bends it again, so rounding never
/// carries an edge across a vertex.
///
/// Oracle: hand-derived. `A` = (0,0),(20,0),(20,1),(0,1) and the triangle
/// (2,-3),(3,-3),(10,4) of `B` cross between grid points, and the vertex
/// (9, 2) of `B`'s second triangle (9,2),(12,2),(9,5) lies within a unit of
/// the bent slanted side. The result must stay valid and agree with the
/// operation away from every edge (the module oracle), whatever bends.
#[test]
fn a_bent_edge_attracts_the_vertices_in_its_pixels() {
    let a = layer_of(&[vec![(0, 0), (20, 0), (20, 1), (0, 1)]]);
    let b = layer_of(&[
        vec![(2, -3), (3, -3), (10, 4)],
        vec![(9, 2), (12, 2), (9, 5)],
    ]);
    for (kind, op) in OPS {
        let got = run(kind, &a, &b).expect("computes");
        agrees(
            kind,
            &got,
            &[vec![(0, 0), (20, 0), (20, 1), (0, 1)]],
            &[
                vec![(2, -3), (3, -3), (10, 4)],
                vec![(9, 2), (12, 2), (9, 5)],
            ],
            op,
        )
        .expect("agrees");
    }
}
