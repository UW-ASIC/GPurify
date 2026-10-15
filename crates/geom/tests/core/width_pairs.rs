//! The width and notch of octilinear polygons (`width::narrowest_pair2`).
//!
//! Oracle: on rectilinear polygons, a differential against the rectilinear
//! measures (`narrowest_width2`, `narrowest_facing`), which the bitmap
//! reference and the `KLayout` mirror already hold; on 45-degree polygons,
//! hand-derived widths.

use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::Seg;
use gpurify_geom::relation::{pair_threshold2, projected_reach2, Metric, Relation, Zero};
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::width::{
    narrowest_facing, narrowest_pair2, narrowest_width2, poly_edges, FacingScratch,
};
use gpurify_geom::{Dbu, LayerId};
use gpurify_testgen::prop::{check, seeds};
use gpurify_testgen::shapes::{point, LayoutBuilder};
use gpurify_testgen::Rng;

/// A merged layer of the given rings, validated octilinear.
fn merged(rings: &[Vec<(i64, i64)>]) -> ValidatedLayer {
    let mut layout = LayoutBuilder::new(1);
    for ring in rings {
        let (xs, ys): (Vec<i64>, Vec<i64>) = ring.iter().copied().unzip();
        layout.push(LayerId(0), &xs, &ys);
    }
    let (store, _) = layout.finish();
    let mut raw = ValidatedLayer::default();
    validate_layer_with(&store, LayerId(0), Angles::Octilinear, &mut raw).expect("valid rings");
    let mut out = ValidatedLayer::default();
    union_into(&raw, &ValidatedLayer::default(), &mut out).expect("merges");
    out
}

/// Two to six random rectangles on a 40-unit grid, as rings.
fn rectangles(rng: &mut Rng) -> Vec<Vec<(i64, i64)>> {
    (0..rng.range(2, 7))
        .map(|_| {
            let (x, y) = (rng.range(0, 36), rng.range(0, 36));
            let (w, h) = (rng.range(1, 41 - x), rng.range(1, 41 - y));
            vec![(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
        })
        .collect()
}

const FAR: i64 = 1_000;

/// The general measure equals the rectilinear one on every figure: width
/// twice-squared, notch twice-squared, or both absent.
fn agrees(rings: &[Vec<(i64, i64)>]) -> Result<(), String> {
    let layer = merged(rings);
    let mut scratch = FacingScratch::default();
    for idx in 0..u32::try_from(layer.len()).expect("small") {
        let poly = layer.get(idx);
        let width = 2 * narrowest_width2(poly, &mut scratch).raw();
        let general = narrowest_pair2(poly, true, Dbu::new_unchecked(FAR)).map(|(d2, _)| d2);
        if general != Some(width) {
            return Err(format!(
                "figure {idx}: width {width} rectilinear, {general:?} general"
            ));
        }
        let notch =
            narrowest_facing(poly, false, &mut scratch).map(|(gap, _)| 2 * gap.mul_wide(gap).raw());
        let general = narrowest_pair2(poly, false, Dbu::new_unchecked(FAR)).map(|(d2, _)| d2);
        if general != notch {
            return Err(format!(
                "figure {idx}: notch {notch:?} rectilinear, {general:?} general"
            ));
        }
    }
    Ok(())
}

/// Oracle: differential against `narrowest_width2` and `narrowest_facing`
/// on random merged rectangles (overlaps, necks, notches, holes, corner
/// touches), over 300 named seeds.
#[test]
fn the_general_width_and_notch_are_the_rectilinear_ones_on_rectilinear_figures() {
    check(
        "width_pairs",
        seeds("width_pairs", 300),
        rectangles,
        |rings| {
            (0..rings.len())
                .map(|skip| {
                    let mut fewer = rings.clone();
                    fewer.remove(skip);
                    fewer
                })
                .collect()
        },
        |rings| agrees(rings),
    );
}

fn width2(rings: &[Vec<(i64, i64)>]) -> Option<i128> {
    let layer = merged(rings);
    assert_eq!(layer.len(), 1, "one figure");
    narrowest_pair2(layer.get(0), true, Dbu::new_unchecked(FAR)).map(|(d2, _)| d2)
}

/// Oracle: hand-derived Euclidean widths. A 45-degree bar with square ends
/// between `y = x` and `y = x + 10` is `10/√2` wide (twice squared, 100); a diamond
/// of radius 10 is `10·√2` across its parallel sides (400), its corners being
/// right angles; a right triangle's two 45-degree tips are acute, so 0 wide.
/// A 20-square with corners chamfered by 2 pairs each chamfer with the side
/// across, at 135 degrees, as `KLayout`'s Euclidean `width` does: from the
/// chamfer's end (18, 0) to the side's end (0, 2), `√328` (656), under 20.
#[test]
fn octilinear_widths_are_euclidean() {
    // gf180mcu `fd_pv` unit structures the foundry's deck flags (shifted to
    // the origin). NW.1a: a 2580 x 1720 box chamfered at one corner, its side
    // next to the chamfer 855 long; the chamfer's end is 855 from the bottom.
    let nw = vec![(0, 0), (2580, 0), (2580, 1720), (865, 1720), (0, 855)];
    assert_eq!(width2(&[nw]), Some(2 * 855 * 855));
    // DF.1a: an L of 221-wide arms whose outer corner is cut by a 158
    // chamfer; the inner corner (221, 221) is `284/√2` from the chamfer's
    // line `x + y = 158`, under the arms' 221.
    let l = vec![
        (158, 0),
        (884, 0),
        (884, 221),
        (221, 221),
        (221, 884),
        (0, 884),
        (0, 158),
    ];
    assert_eq!(width2(&[l]), Some(284 * 284));
    let bar = vec![(0, 0), (40, 40), (35, 45), (-5, 5)];
    assert_eq!(width2(&[bar]), Some(100));
    let diamond = vec![(10, 0), (0, 10), (-10, 0), (0, -10)];
    assert_eq!(width2(&[diamond]), Some(400));
    let chamfered = vec![
        (2, 0),
        (18, 0),
        (20, 2),
        (20, 18),
        (18, 20),
        (2, 20),
        (0, 18),
        (0, 2),
    ];
    assert_eq!(width2(&[chamfered]), Some(656));
    let triangle = vec![(0, 0), (10, 0), (0, 10)];
    assert_eq!(width2(&[triangle]), Some(0));
}

/// Oracle: the 45-degree law, construct-from-answer. A U with arms 10
/// wide, a base 5 tall and a slot 10 wide measures width 5 and notch 10
/// (twice squared, 50 and 200); turned by `(x, y) -> (x - y, x + y)`, which
/// turns every direction 45 degrees and stretches every length by `√2`, it
/// measures twice each square (100 and 400).
#[test]
fn a_u_turned_45_degrees_keeps_its_width_and_notch_times_root_two() {
    let u = vec![
        (0, 0),
        (30, 0),
        (30, 20),
        (20, 20),
        (20, 5),
        (10, 5),
        (10, 20),
        (0, 20),
    ];
    let turned: Vec<(i64, i64)> = u.iter().map(|&(x, y)| (x - y, x + y)).collect();
    for (ring, width, notch) in [(u, 50, 200), (turned, 100, 400)] {
        let layer = merged(&[ring]);
        let measure = |between| {
            narrowest_pair2(layer.get(0), between, Dbu::new_unchecked(FAR)).map(|(d2, _)| d2)
        };
        assert_eq!(measure(true), Some(width));
        assert_eq!(measure(false), Some(notch));
    }
}

/// `KLayout`'s width read edge pair by edge pair through
/// `gpurify_geom::relation` (every ordered pair of a figure's edges, its own
/// pair apart) equals [`narrowest_pair2`] on every figure, as twice squares,
/// or both find nothing.
fn pairs_agree(rings: &[Vec<(i64, i64)>]) -> Result<(), String> {
    let layer = merged(rings);
    for idx in 0..u32::try_from(layer.len()).expect("small") {
        let poly = layer.get(idx);
        let edges: Vec<Seg> = poly_edges(poly).map(|(a, b)| Seg { a: b, b: a }).collect();
        let by_pairs = edges
            .iter()
            .enumerate()
            .flat_map(|(i, &e)| {
                edges
                    .iter()
                    .enumerate()
                    .filter(move |&(j, _)| j != i)
                    .filter_map(move |(_, &f)| {
                        pair_threshold2(
                            Relation::Width,
                            Metric::Euclidean,
                            Zero::WhenTouching,
                            e,
                            f,
                        )
                    })
            })
            .min();
        let narrowest = narrowest_pair2(poly, true, Dbu::new_unchecked(FAR)).map(|(d2, _)| d2);
        if by_pairs != narrowest {
            return Err(format!(
                "figure {idx}: {by_pairs:?} by pairs, {narrowest:?} narrowest"
            ));
        }
    }
    Ok(())
}

/// Oracle: differential between two implementations of `KLayout`'s
/// unshielded Euclidean width, `narrowest_pair2` (held to `KLayout` itself by
/// the nightly mirror differential) and the edge-pair port in
/// `gpurify_geom::relation`, on random merged octilinear shapes (chamfered
/// rectangles, diamonds, right triangles, parallelograms) over 300 named
/// seeds. A port that misreads a cut, an angle, a zero-distance mode or a
/// near part disagrees on some figure.
#[test]
fn the_edge_pair_relation_reads_width_as_narrowest_pair2() {
    check(
        "relation_width",
        seeds("relation_width", 300),
        |rng| {
            (0..rng.range(1, 5))
                .map(|_| crate::boolean_octilinear::random_shape(rng))
                .collect::<Vec<_>>()
        },
        |rings: &Vec<Vec<(i64, i64)>>| {
            (0..rings.len())
                .map(|skip| {
                    let mut fewer = rings.clone();
                    fewer.remove(skip);
                    fewer
                })
                .filter(|fewer| !fewer.is_empty())
                .collect()
        },
        |rings| pairs_agree(rings),
    );
}

/// `a`-`b` as a segment.
fn segment(a: (i64, i64), b: (i64, i64)) -> Seg {
    Seg {
        a: point(a.0, a.1),
        b: point(b.0, b.1),
    }
}

/// Oracle: hand-derived. The 10 x 4 box at `(2, 6)` is narrowest across its
/// top and bottom edges, 4 apart: twice squared, 32. Its report point is the
/// midpoint of an end of one of those edges and that end's foot on the
/// other, so it lies on the box's middle line `y = 8`, at `x = 2` or `x = 12`.
#[test]
fn the_narrowest_pair_is_reported_midway_between_its_two_nearest_points() {
    let layer = merged(&[vec![(2, 6), (12, 6), (12, 10), (2, 10)]]);
    let (twice, at) =
        narrowest_pair2(layer.get(0), true, Dbu::new_unchecked(FAR)).expect("a box has a width");
    assert_eq!(twice, 32);
    assert_eq!(at.y.raw(), 8, "{at:?}");
    assert!([2, 12].contains(&at.x.raw()), "{at:?}");
}

/// Oracle: hand-derived. In `KLayout`'s orientation `a` is the top edge of a
/// shape below `y = 0`, and the slanted `b`, its shape up and to the right,
/// crosses `a` at `(8, 0)`: the two edges touch, so under the default zero
/// mode the pair is reported at distance 0 by projection. Only the part of
/// `b` above `a`'s line, `(2, 6)`-`(8, 0)`, faces `a`; read whole, `b`'s
/// lower end would put the nearest projected point at `(10, -2)`, 2 off.
#[test]
fn edges_that_cross_are_zero_apart_by_projection() {
    let a = segment((0, 0), (10, 0));
    let b = segment((14, -6), (2, 6));
    assert_eq!(
        pair_threshold2(
            Relation::Space,
            Metric::Projection,
            Zero::WhenTouching,
            a,
            b
        ),
        Some(0)
    );
}

/// Oracle: hand-derived. `a` is the top edge of a shape below `y = 0` and
/// `b` the bottom edge of one above `y = 4`, both in `KLayout`'s orientation:
/// the point `(5, 4)` of `b` stands square over `a` at 4, twice squared 32,
/// and `(15, 4)` is past `a`'s end, so no projection reaches it.
#[test]
fn a_projected_reach_is_the_square_distance_over_the_edge_and_none_past_it() {
    let a = segment((0, 0), (10, 0));
    let b = segment((20, 4), (0, 4));
    let reach =
        |x: i64, y: i64| projected_reach2(Relation::Space, Zero::WhenTouching, a, b, point(x, y));
    assert_eq!(reach(5, 4), Some(32));
    assert_eq!(reach(15, 4), None);
}
