//! The exact booleans over random operands, against a bitmap.
//!
//! `boolean_laws.rs` pins named configurations; this checks the general case.
//! Each operand is a few random rectangles on a 32 × 32 integer grid, so every
//! vertex is an integer and every cell lies wholly inside or outside every
//! result. The oracle rasterises the rectangles and applies the set operation
//! cell by cell, without touching the code under test. The engine's result is
//! sampled at every cell centre and must be the oracle's bitmap exactly.
//! Exact equality of point sets implies every algebraic law (commutativity,
//! distributivity, de Morgan, inclusion-exclusion of areas), so the laws are
//! checked through it rather than one by one.
//!
//! Oracle: rasterisation, and the definition of union, intersection and
//! difference on sets of cells.

use gpurify_geom::boolean::{intersection_into, subtraction_into, union_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_testgen::prop::{check, regression_seeds, seeds, shrink_rects};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::Rng;
use std::path::Path;

/// The grid side, in database units: operands live in `[0, SIDE)²`.
const SIDE: i64 = 32;

type Rects = Vec<(u16, [i64; 4])>;

/// One to five rectangles on each of three layers, any size, overlapping,
/// abutting or apart as the seed falls.
fn generate(rng: &mut Rng) -> Rects {
    let mut rects = Vec::new();
    for layer in 0..3u16 {
        for _ in 0..rng.range(1, 6) {
            let (x, y) = (rng.range(0, SIDE - 1), rng.range(0, SIDE - 1));
            let (w, h) = (rng.range(1, SIDE - x + 1), rng.range(1, SIDE - y + 1));
            rects.push((layer, [x, y, x + w, y + h]));
        }
    }
    rects
}

/// The cells a layer's rectangles cover, as one bit per cell.
fn raster(rects: &Rects, layer: u16) -> Vec<bool> {
    let mut cells = vec![false; (SIDE * SIDE) as usize];
    for (_, [xlo, ylo, xhi, yhi]) in rects.iter().filter(|(l, _)| *l == layer) {
        for y in *ylo..*yhi {
            for x in *xlo..*xhi {
                cells[(y * SIDE + x) as usize] = true;
            }
        }
    }
    cells
}

/// Whether the point `(px, py)` lies inside the ring (even-odd ray cast to +x).
fn inside_ring(xs: &[i64], ys: &[i64], px: f64, py: f64) -> bool {
    let mut inside = false;
    for i in 0..xs.len() {
        let j = (i + 1) % xs.len();
        #[allow(clippy::cast_precision_loss, reason = "coordinates below 64")]
        let (x0, y0, x1, y1) = (xs[i] as f64, ys[i] as f64, xs[j] as f64, ys[j] as f64);
        if (y0 > py) != (y1 > py) && px < x0 + (py - y0) * (x1 - x0) / (y1 - y0) {
            inside = !inside;
        }
    }
    inside
}

/// The cells a validated layer covers, sampled at each cell's centre.
fn sampled(layer: &ValidatedLayer) -> Vec<bool> {
    let ring = |r: gpurify_geom::view::RingRef<'_>| {
        let (xs, ys) = r.coords();
        (
            xs.iter().map(|d| d.raw()).collect::<Vec<_>>(),
            ys.iter().map(|d| d.raw()).collect::<Vec<_>>(),
        )
    };
    let polygons: Vec<_> = (0..u32::try_from(layer.len()).expect("small"))
        .map(|index| {
            let polygon = layer.get(index);
            (
                ring(polygon.outer()),
                polygon.holes().map(ring).collect::<Vec<_>>(),
            )
        })
        .collect();
    let mut cells = vec![false; (SIDE * SIDE) as usize];
    for y in 0..SIDE {
        for x in 0..SIDE {
            #[allow(clippy::cast_precision_loss, reason = "coordinates below 64")]
            let (px, py) = (x as f64 + 0.5, y as f64 + 0.5);
            cells[(y * SIDE + x) as usize] = polygons.iter().any(|((xs, ys), holes)| {
                inside_ring(xs, ys, px, py)
                    && !holes.iter().any(|(hx, hy)| inside_ring(hx, hy, px, py))
            });
        }
    }
    cells
}

fn validated(store: &GeometryStore, layer: u16) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, LayerId(layer), &mut out).expect("rectangles are valid");
    out
}

/// The first cell where two bitmaps differ, for the failure message.
fn first_difference(got: &[bool], want: &[bool]) -> Option<(i64, i64, bool)> {
    let index = got.iter().zip(want).position(|(a, b)| a != b)?;
    let index = i64::try_from(index).expect("small");
    Some((index % SIDE, index / SIDE, got[index as usize]))
}

/// Every operation, and the expressions the laws combine them into, against the
/// bitmap.
fn property(rects: &Rects) -> Result<(), String> {
    let mut builder = LayoutBuilder::new(3);
    for (layer, [xlo, ylo, xhi, yhi]) in rects {
        builder.rect(LayerId(*layer), *xlo, *ylo, *xhi, *yhi);
    }
    let (store, _) = builder.finish();
    let (a, b, c) = (
        validated(&store, 0),
        validated(&store, 1),
        validated(&store, 2),
    );
    let (ra, rb, rc) = (raster(rects, 0), raster(rects, 1), raster(rects, 2));
    let cellwise = |x: &[bool], y: &[bool], op: fn(bool, bool) -> bool| -> Vec<bool> {
        x.iter().zip(y).map(|(p, q)| op(*p, *q)).collect()
    };
    let op =
        |kind: &str, x: &ValidatedLayer, y: &ValidatedLayer| -> Result<ValidatedLayer, String> {
            let mut out = ValidatedLayer::default();
            match kind {
                "or" => union_into(x, y, &mut out),
                "and" => intersection_into(x, y, &mut out),
                _ => subtraction_into(x, y, &mut out),
            }
            .map_err(|why| format!("{kind}: {why}"))?;
            Ok(out)
        };
    let expect = |name: &str, got: &ValidatedLayer, want: &[bool]| -> Result<(), String> {
        match first_difference(&sampled(got), want) {
            None => Ok(()),
            Some((x, y, got_cell)) => Err(format!(
                "{name}: cell ({x}, {y}) is {} in the result, {} in the bitmap",
                if got_cell { "in" } else { "out" },
                if got_cell { "out" } else { "in" }
            )),
        }
    };

    // The three operations, each way round.
    expect(
        "A or B",
        &op("or", &a, &b)?,
        &cellwise(&ra, &rb, |p, q| p | q),
    )?;
    expect(
        "B or A",
        &op("or", &b, &a)?,
        &cellwise(&ra, &rb, |p, q| p | q),
    )?;
    expect(
        "A and B",
        &op("and", &a, &b)?,
        &cellwise(&ra, &rb, |p, q| p & q),
    )?;
    expect(
        "A not B",
        &op("not", &a, &b)?,
        &cellwise(&ra, &rb, |p, q| p & !q),
    )?;
    expect(
        "B not A",
        &op("not", &b, &a)?,
        &cellwise(&rb, &ra, |p, q| p & !q),
    )?;
    // Composed: the distributive and de Morgan forms, and idempotence.
    let b_or_c = op("or", &b, &c)?;
    let rbc = cellwise(&rb, &rc, |p, q| p | q);
    expect(
        "A and (B or C)",
        &op("and", &a, &b_or_c)?,
        &cellwise(&ra, &rbc, |p, q| p & q),
    )?;
    expect(
        "A not (B or C)",
        &op("not", &a, &b_or_c)?,
        &cellwise(&ra, &rbc, |p, q| p & !q),
    )?;
    let a_not_b = op("not", &a, &b)?;
    expect(
        "(A not B) not C",
        &op("not", &a_not_b, &c)?,
        &cellwise(&cellwise(&ra, &rb, |p, q| p & !q), &rc, |p, q| p & !q),
    )?;
    expect("A or A", &op("or", &a, &a)?, &ra)?;
    expect("A and A", &op("and", &a, &a)?, &ra)?;
    Ok(())
}

fn regressions() -> Vec<u64> {
    regression_seeds(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/regressions/boolean_random.seeds"),
    )
}

/// Oracle: differential against the bitmap reference in the module doc: each
/// operand rasterised on the 32 x 32 grid and combined cell by cell, over
/// 300 named seeds and the committed regressions.
#[test]
fn every_boolean_is_its_bitmap_over_random_operands() {
    check(
        "boolean_random",
        seeds("boolean_random", 300).chain(regressions()),
        generate,
        |rects| shrink_rects(rects),
        property,
    );
}

/// Oracle: differential against the bitmap reference in the module doc, as
/// above, over 10^5 seeds.
#[test]
#[ignore = "nightly: 10^5 random operand sets"]
fn every_boolean_is_its_bitmap_over_random_operands_at_nightly_depth() {
    check(
        "boolean_random",
        seeds("boolean_random", 100_000).chain(regressions()),
        generate,
        |rects| shrink_rects(rects),
        property,
    );
}
