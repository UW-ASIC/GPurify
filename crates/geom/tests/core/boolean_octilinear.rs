//! The booleans on octilinear operands: edges at 0, 45 and 90 degrees.
//!
//! The oracle is exact and independent of the sweep. On the integer grid every
//! line an octilinear edge can lie on is a side or a diagonal of a unit cell,
//! so each cell splits into four quarter triangles (bottom, right, top, left,
//! meeting at the cell's centre), and every operand and every result is
//! constant on each open quarter triangle. The oracle reads each operand at a
//! point inside each quarter triangle, applies the set operation triangle by
//! triangle, and then the snapping rule `boolean::union_into` states: the
//! cell's centre is the half-grid point where a rising and a falling diagonal
//! cross, its four triangles are the four sectors there, a lone triangle that
//! differs from the other three (a right-angled corner) takes their value, and
//! two opposite triangles of material with the other two empty (a pinch of the
//! connected model) fill the cell. The engine's result is read at the same
//! points and must agree on every triangle.
//!
//! Oracle: the quarter-triangle exact reference above, the snapping rule as
//! `boolean::union_into` documents it, the eight symmetries of the grid, the
//! 45-degree rotation law, and hand-derived configurations.

use gpurify_geom::boolean::{
    canonical_rings_into, intersection_into, subtraction_into, union_into,
};
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_testgen::prop::{check, regression_seeds, seeds};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::Rng;
use std::path::Path;

/// Operands live in `[0, SIDE]²`.
const SIDE: i64 = 16;

/// A set operation on "in a" and "in b".
type Op = fn(bool, bool) -> bool;

/// One drawn polygon: its layer and its counter-clockwise vertices.
type Shape = (u16, Vec<(i64, i64)>);

/// Consecutive repeats dropped, the closing vertex included.
fn dedup(mut points: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    points.dedup();
    while points.len() > 1 && points.first() == points.last() {
        points.pop();
    }
    points
}

/// A random octilinear shape inside `[0, SIDE]²`: a rectangle with chamfered
/// corners, a diamond, a right triangle, or a parallelogram.
pub(crate) fn random_shape(rng: &mut Rng) -> Vec<(i64, i64)> {
    match rng.range(0, 4) {
        0 => {
            let (x0, y0) = (rng.range(0, SIDE - 1), rng.range(0, SIDE - 1));
            let (x1, y1) = (rng.range(x0 + 1, SIDE + 1), rng.range(y0 + 1, SIDE + 1));
            let most = (x1 - x0).min(y1 - y0) / 2;
            let c: Vec<i64> = (0..4).map(|_| rng.range(0, most + 1)).collect();
            dedup(vec![
                (x0 + c[0], y0),
                (x1 - c[1], y0),
                (x1, y0 + c[1]),
                (x1, y1 - c[2]),
                (x1 - c[2], y1),
                (x0 + c[3], y1),
                (x0, y1 - c[3]),
                (x0, y0 + c[0]),
            ])
        }
        1 => {
            let r = rng.range(1, SIDE / 2 + 1);
            let (cx, cy) = (rng.range(r, SIDE - r + 1), rng.range(r, SIDE - r + 1));
            vec![(cx + r, cy), (cx, cy + r), (cx - r, cy), (cx, cy - r)]
        }
        2 => {
            let s = rng.range(1, SIDE + 1);
            let (x, y) = (rng.range(0, SIDE - s + 1), rng.range(0, SIDE - s + 1));
            match rng.range(0, 4) {
                0 => vec![(x, y), (x + s, y), (x, y + s)],
                1 => vec![(x, y), (x + s, y), (x + s, y + s)],
                2 => vec![(x + s, y), (x + s, y + s), (x, y + s)],
                _ => vec![(x, y), (x + s, y + s), (x, y + s)],
            }
        }
        _ => {
            let (w, h) = (rng.range(1, SIDE / 2 + 1), rng.range(1, SIDE / 2 + 1));
            let (x, y) = (rng.range(0, SIDE - w - h + 1), rng.range(0, SIDE - h + 1));
            if rng.range(0, 2) == 0 {
                vec![(x, y), (x + w, y), (x + w + h, y + h), (x + h, y + h)]
            } else {
                vec![(x + h, y), (x + h + w, y), (x + w, y + h), (x, y + h)]
            }
        }
    }
}

/// One to four shapes on each of three layers.
fn generate(rng: &mut Rng) -> Vec<Shape> {
    let mut shapes = Vec::new();
    for layer in 0..3u16 {
        for _ in 0..rng.range(1, 5) {
            shapes.push((layer, random_shape(rng)));
        }
    }
    shapes
}

/// Smaller inputs: each with one shape dropped.
fn shrink(shapes: &[Shape]) -> Vec<Vec<Shape>> {
    (0..shapes.len())
        .map(|skip| {
            let mut fewer = shapes.to_vec();
            fewer.remove(skip);
            fewer
        })
        .collect()
}

fn store_of(shapes: &[Shape], layers: usize) -> GeometryStore {
    let mut layout = LayoutBuilder::new(layers);
    for (layer, points) in shapes {
        let (xs, ys): (Vec<i64>, Vec<i64>) = points.iter().copied().unzip();
        layout.push(LayerId(*layer), &xs, &ys);
    }
    layout.finish().0
}

fn validated(store: &GeometryStore, layer: u16) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_with(store, LayerId(layer), Angles::Octilinear, &mut out)
        .expect("generated shapes are valid octilinear rings");
    out
}

/// Even-odd: does the point `(px, py)` lie inside the closed ring? The point
/// must lie on none of its edges. Every coordinate is at the same scale.
fn inside(ring: &[(i64, i64)], px: i64, py: i64) -> bool {
    let (xlo, xhi) = ring.iter().fold((i64::MAX, i64::MIN), |(lo, hi), p| {
        (lo.min(p.0), hi.max(p.0))
    });
    let (ylo, yhi) = ring.iter().fold((i64::MAX, i64::MIN), |(lo, hi), p| {
        (lo.min(p.1), hi.max(p.1))
    });
    if px < xlo || px > xhi || py < ylo || py > yhi {
        return false;
    }
    let mut odd = false;
    for i in 0..ring.len() {
        let ((ax, ay), (bx, by)) = (ring[i], ring[(i + 1) % ring.len()]);
        if (ay > py) != (by > py) {
            let side = (bx - ax) * (py - ay) - (by - ay) * (px - ax);
            if (side > 0) == (by > ay) {
                odd = !odd;
            }
        }
    }
    odd
}

/// The probe inside each quarter triangle of each cell, at four times scale,
/// in the order bottom, right, top, left; cell `(i, j)` at index `j·SIDE + i`.
fn probes(side: i64) -> Vec<[(i64, i64); 4]> {
    let mut out = Vec::new();
    for j in 0..side {
        for i in 0..side {
            let (x, y) = (4 * i, 4 * j);
            out.push([
                (x + 2, y + 1),
                (x + 3, y + 2),
                (x + 2, y + 3),
                (x + 1, y + 2),
            ]);
        }
    }
    out
}

/// A layer's rings, at four times scale.
fn rings4(layer: &ValidatedLayer) -> Vec<Vec<(i64, i64)>> {
    let mut out = Vec::new();
    for idx in 0..u32::try_from(layer.len()).expect("small") {
        for ring in layer.poly_rings(idx) {
            let (xs, ys) = ring.coords();
            out.push(
                xs.iter()
                    .zip(ys)
                    .map(|(x, y)| (4 * x.raw(), 4 * y.raw()))
                    .collect(),
            );
        }
    }
    out
}

/// Each quarter triangle of a validated layer: inside an odd number of its
/// rings (outer, hole and island alike), read at `map` of the probe.
fn sampled(layer: &ValidatedLayer, map: impl Fn((i64, i64)) -> (i64, i64)) -> Vec<[bool; 4]> {
    let rings = rings4(layer);
    probes(SIDE)
        .iter()
        .map(|cell| {
            cell.map(|probe| {
                let (px, py) = map(probe);
                rings.iter().filter(|r| inside(r, px, py)).count() % 2 == 1
            })
        })
        .collect()
}

/// Each quarter triangle of the drawn shapes on `layer`: inside any of them.
fn drawn(shapes: &[Shape], layer: u16) -> Vec<[bool; 4]> {
    let rings: Vec<Vec<(i64, i64)>> = shapes
        .iter()
        .filter(|(l, _)| *l == layer)
        .map(|(_, points)| points.iter().map(|&(x, y)| (4 * x, 4 * y)).collect())
        .collect();
    probes(SIDE)
        .iter()
        .map(|cell| cell.map(|(px, py)| rings.iter().any(|r| inside(r, px, py))))
        .collect()
}

/// The set operation triangle by triangle, exact (no snapping).
fn exact(a: &[[bool; 4]], b: &[[bool; 4]], op: Op) -> Vec<[bool; 4]> {
    a.iter()
        .zip(b)
        .map(|(p, q)| [0, 1, 2, 3].map(|k| op(p[k], q[k])))
        .collect()
}

/// The snapping rule of `boolean::union_into`, cell by cell.
fn snapped(cells: Vec<[bool; 4]>) -> Vec<[bool; 4]> {
    cells
        .into_iter()
        .map(|t| {
            let filled = t.iter().filter(|&&b| b).count();
            match filled {
                // A right-angled corner at the centre: the odd one takes the others' value.
                1 | 3 => [filled == 3; 4],
                // Opposite triangles alike, so material in two opposite sectors: a pinch.
                2 if t[0] == t[2] => [true; 4],
                _ => t,
            }
        })
        .collect()
}

/// The first quarter triangle where the engine and the oracle differ.
fn compare(name: &str, got: &[[bool; 4]], want: &[[bool; 4]]) -> Result<(), String> {
    for (index, (g, w)) in got.iter().zip(want).enumerate() {
        if g != w {
            let index = i64::try_from(index).expect("small");
            return Err(format!(
                "{name}: cell ({}, {}) has triangles (bottom, right, top, left) {g:?} in the \
                 result and {w:?} in the oracle",
                index % SIDE,
                index / SIDE
            ));
        }
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

fn or(p: bool, q: bool) -> bool {
    p | q
}

fn and(p: bool, q: bool) -> bool {
    p & q
}

fn not(p: bool, q: bool) -> bool {
    p & !q
}

/// Every operation, each way round, and composed forms, against the oracle.
fn property(shapes: &[Shape]) -> Result<(), String> {
    let store = store_of(shapes, 3);
    let (a, b, c) = (
        validated(&store, 0),
        validated(&store, 1),
        validated(&store, 2),
    );
    let (ra, rb, rc) = (drawn(shapes, 0), drawn(shapes, 1), drawn(shapes, 2));
    let id = |p: (i64, i64)| p;

    // Each operation, and whether its operands are taken the other way round.
    let cases: [(&str, bool, Op); 5] = [
        ("or", false, or),
        ("or", true, or),
        ("and", false, and),
        ("not", false, not),
        ("not", true, not),
    ];
    for (kind, swap, op) in cases {
        let ((x, rx), (y, ry)) = if swap {
            ((&b, &rb), (&a, &ra))
        } else {
            ((&a, &ra), (&b, &rb))
        };
        let got = run(kind, x, y)?;
        let name = format!("{kind}{}", if swap { " swapped" } else { "" });
        compare(&name, &sampled(&got, id), &snapped(exact(rx, ry, op)))?;
    }

    // Composed: each step snaps, in the oracle as in the engine.
    let b_or_c = run("or", &b, &c)?;
    let rbc = snapped(exact(&rb, &rc, or));
    compare("B or C", &sampled(&b_or_c, id), &rbc)?;
    let got = run("and", &a, &b_or_c)?;
    compare(
        "A and (B or C)",
        &sampled(&got, id),
        &snapped(exact(&ra, &rbc, and)),
    )?;
    let got = run("not", &a, &b_or_c)?;
    compare(
        "A not (B or C)",
        &sampled(&got, id),
        &snapped(exact(&ra, &rbc, not)),
    )?;
    // A merge snaps nothing a drawn layer holds: its vertices are on the grid
    // and only crossings can fall between grid points.
    let merged = run("or", &a, &ValidatedLayer::default())?;
    compare(
        "A merged",
        &sampled(&merged, id),
        &snapped(exact(&ra, &ra, or)),
    )?;
    Ok(())
}

/// The eight symmetries of `[0, SIDE]²` at scale `k`: the identity, the
/// mirrors and the quarter turns.
fn symmetry(t: usize, k: i64) -> impl Fn((i64, i64)) -> (i64, i64) {
    let side = k * SIDE;
    move |(x, y)| {
        let (x, y) = if t & 4 == 0 { (x, y) } else { (y, x) };
        let x = if t & 1 == 0 { x } else { side - x };
        let y = if t & 2 == 0 { y } else { side - y };
        (x, y)
    }
}

/// Whether a symmetry reverses orientation: one mirror, or a swap of axes.
fn mirrors(t: usize) -> bool {
    (t & 1 != 0) ^ (t & 2 != 0) ^ (t & 4 != 0)
}

/// The shapes moved by `map`, re-wound counter-clockwise when it mirrors.
fn moved(shapes: &[Shape], map: impl Fn((i64, i64)) -> (i64, i64), mirror: bool) -> Vec<Shape> {
    shapes
        .iter()
        .map(|(layer, points)| {
            let mut points: Vec<(i64, i64)> = points.iter().map(|&p| map(p)).collect();
            if mirror {
                points.reverse();
            }
            (*layer, points)
        })
        .collect()
}

/// Each operation commutes with every symmetry of the grid: the snapping rule
/// and the corner model treat every direction alike.
fn symmetric(shapes: &[Shape]) -> Result<(), String> {
    let store = store_of(shapes, 3);
    let (a, b) = (validated(&store, 0), validated(&store, 1));
    for t in 1..8 {
        let image = moved(shapes, symmetry(t, 1), mirrors(t));
        let image_store = store_of(&image, 3);
        let (ta, tb) = (validated(&image_store, 0), validated(&image_store, 1));
        for kind in ["or", "and", "not"] {
            let here = sampled(&run(kind, &a, &b)?, |p| p);
            let there = sampled(&run(kind, &ta, &tb)?, symmetry(t, 4));
            compare(&format!("{kind} under symmetry {t}"), &there, &here)?;
        }
    }
    Ok(())
}

/// The 45-degree rotation law. `(x, y) → (x − y, x + y)` turns every
/// octilinear direction into another and takes every half-grid point onto
/// the grid, so the rotated operation snaps nothing: read at the rotated
/// probes it is the exact operation, triangle by triangle.
fn rotated(shapes: &[Shape]) -> Result<(), String> {
    let turn = |(x, y): (i64, i64)| (x - y, x + y);
    let image = moved(shapes, turn, false);
    let store = store_of(&image, 3);
    let (a, b) = (validated(&store, 0), validated(&store, 1));
    let (ra, rb) = (drawn(shapes, 0), drawn(shapes, 1));
    for (kind, op) in [("or", or as Op), ("and", and), ("not", not)] {
        let got = sampled(&run(kind, &a, &b)?, turn);
        compare(
            &format!("{kind} turned 45 degrees"),
            &got,
            &exact(&ra, &rb, op),
        )?;
    }
    Ok(())
}

fn regressions() -> Vec<u64> {
    regression_seeds(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/regressions/boolean_octilinear.seeds"),
    )
}

/// Oracle: the quarter-triangle exact reference and the snapping rule in the
/// module doc, over 100 named seeds and the committed regressions.
#[test]
fn every_octilinear_boolean_is_its_quarter_triangle_reference() {
    check(
        "boolean_octilinear",
        seeds("boolean_octilinear", 100).chain(regressions()),
        generate,
        |shapes| shrink(shapes),
        |shapes| property(shapes),
    );
}

/// Oracle: the symmetry law in `symmetric`: the eight symmetries of the grid
/// commute with every operation, over 25 named seeds.
#[test]
fn octilinear_booleans_commute_with_the_symmetries_of_the_grid() {
    check(
        "boolean_octilinear_symmetry",
        seeds("boolean_octilinear_symmetry", 25),
        generate,
        |shapes| shrink(shapes),
        |shapes| symmetric(shapes),
    );
}

/// Oracle: the 45-degree rotation law in `rotated`, against the exact
/// quarter-triangle reference, over 50 named seeds.
#[test]
fn an_operation_turned_45_degrees_is_the_exact_operation() {
    check(
        "boolean_octilinear_turn",
        seeds("boolean_octilinear_turn", 50),
        generate,
        |shapes| shrink(shapes),
        |shapes| rotated(shapes),
    );
}

/// Oracle: as `every_octilinear_boolean_is_its_quarter_triangle_reference`,
/// over 10^5 seeds.
#[test]
#[ignore = "nightly: 10^5 random octilinear operand sets"]
fn every_octilinear_boolean_is_its_quarter_triangle_reference_at_nightly_depth() {
    check(
        "boolean_octilinear",
        seeds("boolean_octilinear", 100_000).chain(regressions()),
        generate,
        |shapes| shrink(shapes),
        |shapes| property(shapes),
    );
}

/// Oracle: as the merge-depth symmetry and rotation tests, over 10^4 seeds.
#[test]
#[ignore = "nightly: 10^4 random operand sets under every symmetry and the 45-degree turn"]
fn octilinear_symmetry_and_turn_laws_at_nightly_depth() {
    let all = seeds("boolean_octilinear_symmetry", 10_000);
    check(
        "boolean_octilinear_symmetry",
        all,
        generate,
        |s| shrink(s),
        |s| symmetric(s),
    );
    let all = seeds("boolean_octilinear_turn", 10_000);
    check(
        "boolean_octilinear_turn",
        all,
        generate,
        |s| shrink(s),
        |s| rotated(s),
    );
}

/// A layer of the given shapes, validated octilinear.
fn layer_of(shapes: &[Vec<(i64, i64)>]) -> ValidatedLayer {
    let tagged: Vec<Shape> = shapes.iter().map(|s| (0, s.clone())).collect();
    validated(&store_of(&tagged, 1), 0)
}

/// Each polygon's outer ring as a vertex list, and its area doubled.
fn figures(layer: &ValidatedLayer) -> Vec<(Vec<(i64, i64)>, i128)> {
    (0..u32::try_from(layer.len()).expect("small"))
        .map(|idx| {
            let polygon = layer.get(idx);
            let (xs, ys) = polygon.outer().coords();
            let ring = xs.iter().zip(ys).map(|(x, y)| (x.raw(), y.raw())).collect();
            // Holes wind clockwise, so their doubled areas are negative.
            let doubled = polygon
                .holes()
                .fold(polygon.outer().area2().raw(), |sum, hole| {
                    sum + hole.area2().raw()
                });
            (ring, doubled)
        })
        .collect()
}

/// The ring rotated to start at its least vertex, for a comparison that
/// does not depend on where the trace began.
fn from_least(mut ring: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    let least = (0..ring.len()).min_by_key(|&i| ring[i]).expect("a ring");
    ring.rotate_left(least);
    ring
}

/// Oracle: hand-derived. `x ≥ 0, y ≥ x, x + y ≤ 3` is the triangle (0, 0),
/// (1.5, 1.5), (0, 3) of area 2.25; its apex is a convex right angle at a
/// half-grid point, so the snap cuts the tip at (1, 1)-(1, 2): area 2.
#[test]
fn a_convex_corner_between_grid_points_is_cut_to_a_unit_edge() {
    let a = layer_of(&[vec![(0, 0), (3, 0), (0, 3)]]);
    let b = layer_of(&[vec![(0, 0), (3, 3), (0, 3)]]);
    let mut got = ValidatedLayer::default();
    intersection_into(&a, &b, &mut got).expect("octilinear operands");
    let figures = figures(&got);
    assert_eq!(figures.len(), 1);
    assert_eq!(
        from_least(figures[0].0.clone()),
        [(0, 0), (1, 1), (1, 2), (0, 3)]
    );
    assert_eq!(figures[0].1, 4, "2.25 less the quarter-unit tip, doubled");
    assert!(!got.is_rectilinear());
}

/// Oracle: hand-derived. The two triangles' union has a concave right angle
/// at (1.5, 1.5): exact area 4.5 + 4.5 - 2.25 = 6.75, and the snap fills the
/// tip of the empty sector at (2, 2)-(1, 2): area 7.
#[test]
fn a_concave_corner_between_grid_points_is_filled_to_a_unit_edge() {
    let a = layer_of(&[vec![(0, 0), (3, 0), (0, 3)]]);
    let b = layer_of(&[vec![(0, 0), (3, 0), (3, 3)]]);
    let mut got = ValidatedLayer::default();
    union_into(&a, &b, &mut got).expect("octilinear operands");
    let figures = figures(&got);
    assert_eq!(figures.len(), 1);
    assert_eq!(
        from_least(figures[0].0.clone()),
        [(0, 0), (3, 0), (3, 3), (2, 2), (1, 2), (0, 3)]
    );
    assert_eq!(figures[0].1, 14);
}

/// Oracle: hand-derived, and the connected corner model. Each operand is two
/// overlapping triangles that together miss one sector at (1.5, 1.5); their
/// intersection is the left and right sectors, meeting only at that point,
/// exact area 4.5. Connected, they are one figure, and the snap fills the
/// tips of both empty sectors: a neck one unit wide, area 5.
#[test]
fn a_pinch_between_grid_points_becomes_a_unit_neck() {
    let a = layer_of(&[vec![(0, 0), (3, 0), (3, 3)], vec![(0, 0), (3, 0), (0, 3)]]);
    let b = layer_of(&[vec![(0, 0), (3, 3), (0, 3)], vec![(3, 0), (3, 3), (0, 3)]]);
    let mut got = ValidatedLayer::default();
    intersection_into(&a, &b, &mut got).expect("octilinear operands");
    let figures = figures(&got);
    assert_eq!(
        figures.len(),
        1,
        "material meeting at a point is one figure"
    );
    assert_eq!(
        from_least(figures[0].0.clone()),
        [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 0),
            (3, 3),
            (2, 2),
            (1, 2),
            (0, 3)
        ]
    );
    assert_eq!(figures[0].1, 10);
}

/// Oracle: the connected corner model at 45 degrees, hand-derived: a diamond
/// whose bottom vertex touches the middle of a square's top edge is one
/// figure, its ring passing the touch point twice; area 100 + 50.
#[test]
fn a_diamond_touching_an_edge_at_its_vertex_joins_it() {
    let square = layer_of(&[vec![(0, 0), (10, 0), (10, 10), (0, 10)]]);
    let diamond = layer_of(&[vec![(5, 10), (10, 15), (5, 20), (0, 15)]]);
    let mut got = ValidatedLayer::default();
    union_into(&square, &diamond, &mut got).expect("octilinear operands");
    let figures = figures(&got);
    assert_eq!(figures.len(), 1, "the touch joins them");
    assert_eq!(figures[0].1, 2 * (100 + 50));
    let visits = figures[0].0.iter().filter(|&&p| p == (5, 10)).count();
    assert_eq!(visits, 2, "the ring passes the touch point twice");
}

/// Oracle: hand-derived. A diamond of radius 10 with a 4-square hole, written
/// as one keyhole ring through a vertical slit, is its outer diamond (200)
/// and its hole (16), wound opposite ways.
#[test]
fn an_octilinear_keyhole_decomposes_into_its_outer_and_its_hole() {
    // The outer from (0, -10), up the slit, the hole clockwise, back down.
    let xs = [0, 10, 0, -10, 0, 0, -2, -2, 2, 2, 0];
    let ys = [-10, 0, 10, 0, -10, -2, -2, 2, 2, -2, -2];
    let (mut rx, mut ry, mut start) = (Vec::new(), Vec::new(), Vec::new());
    canonical_rings_into(&xs, &ys, &mut rx, &mut ry, &mut start).expect("octilinear");
    let mut signed: Vec<i128> = start
        .windows(2)
        .map(|w| {
            let (lo, hi) = (w[0] as usize, w[1] as usize);
            let n = hi - lo;
            (0..n)
                .map(|i| {
                    let (p, q) = (lo + i, lo + (i + 1) % n);
                    i128::from(rx[p]) * i128::from(ry[q]) - i128::from(rx[q]) * i128::from(ry[p])
                })
                .sum::<i128>()
        })
        .collect();
    signed.sort_unstable();
    assert_eq!(signed, [-2 * 16, 2 * 200]);
}
