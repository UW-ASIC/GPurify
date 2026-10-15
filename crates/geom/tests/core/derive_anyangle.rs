//! The derived-layer operations on layers at any angle.
//!
//! Oracle: the Pythagorean rotation law. `(x, y) → (3x − 4y, 4x + 3y)` maps
//! the grid into itself and every length times 5, and every line through two
//! grid points of a rectilinear layout onto one whose lattice points are the
//! images of its own, so on the images of random rectangles (edges along
//! (3, 4) and (−4, 3)) every operation must return the image of what it
//! returns on the rectangles, exactly: edges, edge booleans, edge parts,
//! selections, holes and areas (times 25). Nothing rounds, so any difference
//! is a defect of the any-angle path.

use gpurify_geom::boolean::union_into;
use gpurify_geom::derive::{
    covering_into, edge_boolean_into, edge_interacting_into, edge_part_into, edges_into,
    holes_into, inside_into, interacting_into, overlapping_into, with_area_into, with_length_into,
    EdgeOp,
};
use gpurify_geom::ops::{Point, Seg};
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::{Dbu, LayerId};
use gpurify_testgen::prop::{check, seeds};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::Rng;

type Ring = Vec<(i64, i64)>;
type Pt = (i64, i64);

fn turn((x, y): Pt) -> Pt {
    (3 * x - 4 * y, 4 * x + 3 * y)
}

fn merged(rings: &[Ring]) -> ValidatedLayer {
    let mut layout = LayoutBuilder::new(1);
    for ring in rings {
        let (xs, ys): (Vec<i64>, Vec<i64>) = ring.iter().copied().unzip();
        layout.push(LayerId(0), &xs, &ys);
    }
    let (store, _) = layout.finish();
    let mut raw = ValidatedLayer::default();
    validate_layer_with(&store, LayerId(0), Angles::Any, &mut raw).expect("valid rings");
    let mut out = ValidatedLayer::default();
    union_into(&raw, &ValidatedLayer::default(), &mut out).expect("merges");
    out
}

fn rectangles(rng: &mut Rng) -> Vec<Ring> {
    (0..rng.range(1, 5))
        .map(|_| {
            let (x, y) = (rng.range(-12, 10), rng.range(-12, 10));
            let (w, h) = (rng.range(1, 13 - x), rng.range(1, 13 - y));
            vec![(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
        })
        .collect()
}

fn pt(p: Point) -> Pt {
    (p.x.raw(), p.y.raw())
}

fn segs(edges: &[Seg], map: impl Fn(Pt) -> Pt) -> Vec<(Pt, Pt)> {
    let mut out: Vec<(Pt, Pt)> = edges.iter().map(|s| (map(pt(s.a)), map(pt(s.b)))).collect();
    out.sort_unstable();
    out
}

fn rings(layer: &ValidatedLayer, map: impl Fn(Pt) -> Pt) -> Vec<(Pt, Pt)> {
    let mut out = Vec::new();
    for idx in 0..u32::try_from(layer.len()).expect("small") {
        for ring in layer.poly_rings(idx) {
            let (xs, ys) = ring.coords();
            let n = xs.len();
            for i in 0..n {
                let j = (i + 1) % n;
                out.push((
                    map((xs[i].raw(), ys[i].raw())),
                    map((xs[j].raw(), ys[j].raw())),
                ));
            }
        }
    }
    out.sort_unstable();
    out
}

fn same<T: PartialEq + std::fmt::Debug>(what: &str, want: T, got: T) -> Result<(), String> {
    if want == got {
        Ok(())
    } else {
        Err(format!("{what}: {want:?} turned, {got:?} computed"))
    }
}

fn commutes((ra, rb): &(Vec<Ring>, Vec<Ring>)) -> Result<(), String> {
    let image = |rs: &[Ring]| -> Vec<Ring> {
        rs.iter()
            .map(|r| r.iter().map(|&p| turn(p)).collect())
            .collect()
    };
    let (a, b) = (merged(ra), merged(rb));
    let (ta, tb) = (merged(&image(ra)), merged(&image(rb)));
    let id = |p: Pt| p;

    let (mut ea, mut eb, mut tea, mut teb) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    edges_into(&a, &mut ea);
    edges_into(&b, &mut eb);
    edges_into(&ta, &mut tea);
    edges_into(&tb, &mut teb);
    same("edges", segs(&ea, turn), segs(&tea, id))?;

    let (mut x, mut tx) = (Vec::new(), Vec::new());
    for op in [EdgeOp::And, EdgeOp::Not, EdgeOp::Or] {
        edge_boolean_into(&ea, &eb, op, &mut x);
        edge_boolean_into(&tea, &teb, op, &mut tx);
        same(&format!("edge {op:?}"), segs(&x, turn), segs(&tx, id))?;
    }
    for inside in [true, false] {
        edge_part_into(&ea, &b, inside, &mut x);
        edge_part_into(&tea, &tb, inside, &mut tx);
        same(
            &format!("part inside={inside}"),
            segs(&x, turn),
            segs(&tx, id),
        )?;
    }
    for keep in [true, false] {
        edge_interacting_into(&ea, &b, keep, &mut x);
        edge_interacting_into(&tea, &tb, keep, &mut tx);
        same(
            &format!("edge interacting {keep}"),
            segs(&x, turn),
            segs(&tx, id),
        )?;
    }
    // A side k units long turns into one 5k long.
    with_length_into(&ea, 3..=8, &mut x);
    with_length_into(&tea, 15..=40, &mut tx);
    same("with_length", segs(&x, turn), segs(&tx, id))?;

    let (mut s, mut ts) = (ValidatedLayer::default(), ValidatedLayer::default());
    for keep in [true, false] {
        interacting_into(&a, &b, keep, &mut s);
        interacting_into(&ta, &tb, keep, &mut ts);
        same(
            &format!("interacting {keep}"),
            rings(&s, turn),
            rings(&ts, id),
        )?;
        overlapping_into(&a, &b, keep, &mut s).map_err(|e| e.to_string())?;
        overlapping_into(&ta, &tb, keep, &mut ts).map_err(|e| e.to_string())?;
        same(
            &format!("overlapping {keep}"),
            rings(&s, turn),
            rings(&ts, id),
        )?;
        covering_into(&a, &b, keep, &mut s).map_err(|e| e.to_string())?;
        covering_into(&ta, &tb, keep, &mut ts).map_err(|e| e.to_string())?;
        same(&format!("covering {keep}"), rings(&s, turn), rings(&ts, id))?;
    }
    inside_into(&a, &b, &mut s).map_err(|e| e.to_string())?;
    inside_into(&ta, &tb, &mut ts).map_err(|e| e.to_string())?;
    same("inside", rings(&s, turn), rings(&ts, id))?;
    holes_into(&a, &mut s).map_err(|e| e.to_string())?;
    holes_into(&ta, &mut ts).map_err(|e| e.to_string())?;
    same("holes", rings(&s, turn), rings(&ts, id))?;
    with_area_into(&a, 20..=150, &mut s);
    with_area_into(&ta, 500..=3750, &mut ts);
    same("with_area", rings(&s, turn), rings(&ts, id))?;
    Ok(())
}

/// Oracle: the Pythagorean rotation law in the module doc, over 200 named
/// seeds of one to four rectangles on each of two layers.
#[test]
fn derived_layers_commute_with_a_pythagorean_turn() {
    check(
        "derive_anyangle_turn",
        seeds("derive_anyangle_turn", 200),
        |rng| (rectangles(rng), rectangles(rng)),
        |(a, b): &(Vec<Ring>, Vec<Ring>)| {
            let mut out = Vec::new();
            for skip in 0..a.len() {
                let mut fewer = a.clone();
                fewer.remove(skip);
                out.push((fewer, b.clone()));
            }
            for skip in 0..b.len() {
                let mut fewer = b.clone();
                fewer.remove(skip);
                out.push((a.clone(), fewer));
            }
            out
        },
        commutes,
    );
}

/// An edge cut where a slanted edge crosses it between the points of its
/// line's lattice ends at the last lattice point inside.
///
/// Oracle: hand-derived. The edge (0,0)→(9,3) runs on the lattice
/// (3k, k); the square (4,-5),(10,-5),(10,5),(4,5) crosses it at x = 4,
/// between the lattice points (3,1) and (6,2), so the part inside is
/// (6,2)→(9,3) and the part outside (0,0)→(3,1).
#[test]
fn a_part_of_a_slanted_edge_ends_on_its_lattice() {
    let d = Dbu::new_unchecked;
    let p = |x, y| Point { x: d(x), y: d(y) };
    let edge = [Seg {
        a: p(0, 0),
        b: p(9, 3),
    }];
    let square = merged(&[vec![(4, -5), (10, -5), (10, 5), (4, 5)]]);
    let mut out = Vec::new();
    edge_part_into(&edge, &square, true, &mut out);
    assert_eq!(segs(&out, |q| q), vec![((6, 2), (9, 3))]);
    edge_part_into(&edge, &square, false, &mut out);
    assert_eq!(segs(&out, |q| q), vec![((0, 0), (3, 1))]);
}
