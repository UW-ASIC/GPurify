//! The width and notch of octilinear polygons (`width::narrowest_pair2`).
//!
//! Oracle: on rectilinear polygons, a differential against the rectilinear
//! measures (`narrowest_width2`, `narrowest_facing`), which the bitmap
//! reference and the KLayout mirror already hold; on 45-degree polygons,
//! hand-derived widths.

use gpurify_geom::boolean::union_into;
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::width::{narrowest_facing, narrowest_pair2, narrowest_width2, FacingScratch};
use gpurify_geom::{Dbu, LayerId};
use gpurify_testgen::prop::{check, seeds};
use gpurify_testgen::shapes::LayoutBuilder;
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
/// right angles; a chamfered square keeps its side width 20 (800); a right
/// triangle's two 45-degree tips are acute, so 0 wide.
#[test]
fn octilinear_widths_are_euclidean() {
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
    assert_eq!(width2(&[chamfered]), Some(800));
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
