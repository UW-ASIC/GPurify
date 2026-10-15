//! Widths, notches and the edge-pair relation at any angle
//! (`width::narrowest_pair_any`, `relation::pair_threshold_any`), and the
//! booleans under an exact rotation.
//!
//! Oracle: a differential against the octilinear measures on octilinear
//! figures (where both are exact integers); the Pythagorean rotation law, `(x,
//! y) → (3x − 4y, 4x + 3y)` mapping the grid into itself and every length
//! times 5, so a rectilinear figure's width and notch, twice squared, come
//! back times 25 on its image, whose edges are at any angle, and a boolean of
//! images is the image of the boolean (no crossing falls between grid
//! points); and a hand-derived width that is a fraction.

use gpurify_geom::boolean::{intersection_into, subtraction_into, union_into};
use gpurify_geom::derive::with_width_into;
use gpurify_geom::ops::Seg;
use gpurify_geom::relation::{pair_threshold2, pair_threshold_any, Metric, Relation, Zero};
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::width::{
    narrowest_facing, narrowest_pair2, narrowest_pair_any, narrowest_width2, poly_edges,
    FacingScratch,
};
use gpurify_geom::{Dbu, LayerId};
use gpurify_testgen::prop::{check, seeds};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::Rng;

type Ring = Vec<(i64, i64)>;

const FAR: i64 = 100_000;

fn layer(rings: &[Ring], merge: bool) -> ValidatedLayer {
    let mut layout = LayoutBuilder::new(1);
    for ring in rings {
        let (xs, ys): (Vec<i64>, Vec<i64>) = ring.iter().copied().unzip();
        layout.push(LayerId(0), &xs, &ys);
    }
    let (store, _) = layout.finish();
    let mut raw = ValidatedLayer::default();
    validate_layer_with(&store, LayerId(0), Angles::Any, &mut raw).expect("valid rings");
    if !merge {
        return raw;
    }
    let mut out = ValidatedLayer::default();
    union_into(&raw, &ValidatedLayer::default(), &mut out).expect("merges");
    out
}

fn shrink(rings: &Vec<Ring>) -> Vec<Vec<Ring>> {
    (0..rings.len())
        .map(|skip| {
            let mut fewer = rings.clone();
            fewer.remove(skip);
            fewer
        })
        .filter(|fewer| !fewer.is_empty())
        .collect()
}

/// On octilinear figures the any-angle measures are the octilinear ones,
/// exact: width and notch, and every relation in every zero mode.
fn octilinear_agree(rings: &[Ring]) -> Result<(), String> {
    let merged = layer(rings, true);
    let far = Dbu::new_unchecked(FAR);
    for idx in 0..u32::try_from(merged.len()).expect("small") {
        let poly = merged.get(idx);
        for between in [true, false] {
            let octo = narrowest_pair2(poly, between, far).map(|(d2, _)| (d2, false));
            let any = narrowest_pair_any(poly, between, far).map(|(d2, _)| d2);
            if octo != any {
                return Err(format!(
                    "figure {idx} between={between}: {octo:?} vs {any:?}"
                ));
            }
        }
        let edges: Vec<Seg> = poly_edges(poly).map(|(a, b)| Seg { a: b, b: a }).collect();
        for &e in &edges {
            for &f in &edges {
                for relation in [
                    Relation::Width,
                    Relation::Space,
                    Relation::Overlap,
                    Relation::Inside,
                ] {
                    for zero in [Zero::Never, Zero::WhenTouching, Zero::WhenOverlapping] {
                        let octo = pair_threshold2(relation, Metric::Euclidean, zero, e, f)
                            .map(|d2| (d2, false));
                        let any = pair_threshold_any(relation, zero, e, f);
                        if octo != any {
                            return Err(format!(
                                "{relation:?} {zero:?} {e:?} {f:?}: {octo:?} vs {any:?}"
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Oracle: differential against `narrowest_pair2` and `pair_threshold2` on
/// random merged octilinear shapes, over 200 named seeds.
#[test]
fn the_any_angle_measures_are_the_octilinear_ones_on_octilinear_figures() {
    check(
        "width_anyangle_octilinear",
        seeds("width_anyangle_octilinear", 200),
        |rng| {
            (0..rng.range(1, 5))
                .map(|_| crate::boolean_octilinear::random_shape(rng))
                .collect::<Vec<_>>()
        },
        shrink,
        |rings| octilinear_agree(rings),
    );
}

/// The Pythagorean rotation: the grid into itself, every length times 5.
fn turn((x, y): (i64, i64)) -> (i64, i64) {
    (3 * x - 4 * y, 4 * x + 3 * y)
}

fn rectangles(rng: &mut Rng) -> Vec<Ring> {
    (0..rng.range(1, 6))
        .map(|_| {
            let (x, y) = (rng.range(-20, 16), rng.range(-20, 16));
            let (w, h) = (rng.range(1, 21 - x), rng.range(1, 21 - y));
            vec![(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
        })
        .collect()
}

/// Every figure's width and notch, twice squared, sorted.
fn measures(merged: &ValidatedLayer, any: bool) -> Vec<((i128, bool), Option<(i128, bool)>)> {
    let mut scratch = FacingScratch::default();
    let far = Dbu::new_unchecked(FAR);
    let mut out: Vec<_> = (0..u32::try_from(merged.len()).expect("small"))
        .map(|idx| {
            let poly = merged.get(idx);
            if any {
                (
                    narrowest_pair_any(poly, true, far).expect("a width").0,
                    narrowest_pair_any(poly, false, far).map(|(d2, _)| d2),
                )
            } else {
                let w = 2 * narrowest_width2(poly, &mut scratch).raw();
                let notch = narrowest_facing(poly, false, &mut scratch)
                    .map(|(gap, _)| (25 * 2 * gap.mul_wide(gap).raw(), false));
                ((25 * w, false), notch)
            }
        })
        .collect();
    out.sort_unstable();
    out
}

fn edge_set(
    layer: &ValidatedLayer,
    map: impl Fn((i64, i64)) -> (i64, i64),
) -> Vec<((i64, i64), (i64, i64))> {
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

fn rotated(rings: &[Ring]) -> Result<(), String> {
    let image: Vec<Ring> = rings
        .iter()
        .map(|r| r.iter().map(|&p| turn(p)).collect())
        .collect();
    let (here, there) = (layer(rings, true), layer(&image, true));
    if measures(&here, false) != measures(&there, true) {
        return Err(format!(
            "widths: {:?} turned, {:?} measured",
            measures(&here, false),
            measures(&there, true)
        ));
    }
    // Booleans of images: the first rectangle against the rest.
    let split = |rs: &[Ring]| (layer(&rs[..1], false), layer(&rs[1..], false));
    let ((a, b), (ta, tb)) = (split(rings), split(&image));
    for kind in 0..3 {
        let (mut got, mut want) = (ValidatedLayer::default(), ValidatedLayer::default());
        let run = |x: &ValidatedLayer, y: &ValidatedLayer, out: &mut ValidatedLayer| match kind {
            0 => union_into(x, y, out),
            1 => intersection_into(x, y, out),
            _ => subtraction_into(x, y, out),
        };
        run(&a, &b, &mut want).map_err(|e| e.to_string())?;
        run(&ta, &tb, &mut got).map_err(|e| e.to_string())?;
        if edge_set(&want, turn) != edge_set(&got, |p| p) {
            return Err(format!("boolean {kind} does not commute with the turn"));
        }
    }
    Ok(())
}

/// Oracle: the Pythagorean rotation law in the module doc, on random
/// rectangles (overlaps, necks, notches, holes, corner touches), over 200
/// named seeds: widths and notches times 25, booleans commuting.
#[test]
fn a_pythagorean_turn_scales_widths_and_commutes_with_booleans() {
    check(
        "width_anyangle_turn",
        seeds("width_anyangle_turn", 200),
        rectangles,
        shrink,
        |rings| rotated(rings),
    );
}

/// Oracle: hand-derived. A rectangle turned to run along (5, 1), (0,0),
/// (25,5),(22,20),(-3,15), with a V notch cut from its top side down to
/// (10, 9) between (12, 18) and (7, 17): no corner is under 90 degrees, no
/// short edge joins two edges facing across it, and the narrowest width is
/// from the V's tip square to the bottom side: `cross((5,1), (10,9)) = 35`,
/// so twice the squared width is `2·35²/26 = 94.23…`, floored 94, a
/// fraction. Every other pair is wider (the V's sides against the left side,
/// `52/√26`; the top side against the bottom, `3·√26`). The bounds then read
/// the fraction exactly: `> √47` (`95..`) holds it, `>= √48` (`96..`) does
/// not, `<= √47` (`..=94`) does not, `< √48` (`..=95`) does.
#[test]
fn a_width_at_any_angle_is_a_fraction_compared_exactly() {
    let shape = vec![
        (0, 0),
        (25, 5),
        (22, 20),
        (12, 18),
        (10, 9),
        (7, 17),
        (-3, 15),
    ];
    let merged = layer(&[shape], true);
    let (width, _) =
        narrowest_pair_any(merged.get(0), true, Dbu::new_unchecked(FAR)).expect("a width");
    assert_eq!(width, (94, true));
    let kept = |range: std::ops::RangeInclusive<i128>| {
        let mut out = ValidatedLayer::default();
        with_width_into(&merged, range, &mut out);
        out.len()
    };
    assert_eq!(kept(95..=i128::MAX), 1, "> √47");
    assert_eq!(kept(96..=i128::MAX), 0, ">= √48");
    assert_eq!(kept(0..=94), 0, "<= √47");
    assert_eq!(kept(0..=95), 1, "< √48");
}
