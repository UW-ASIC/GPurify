//! The corner model: material that meets only at a corner is joined there.
//!
//! `boolean::union_into` states it. Two cells touching at a corner are one
//! polygon, and the corner is a neck of width 0. Empty space does not pass a
//! corner where material meets, so a ring closed only at a corner encloses a
//! hole. A polygon is one 8-connected component of the cells, a hole one
//! 4-connected component of the space it encloses, however the cells were
//! drawn.
//!
//! Oracle: that definition, applied by hand to cells of side [`S`]. Pictures
//! are rows top to bottom, `#` a cell.

use gpurify_geom::boolean::union_into;
use gpurify_geom::view::{validate_layer_into, ValidatedLayer, ValidityError};
use gpurify_geom::width::{narrowest_facing, narrowest_width, FacingScratch};
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_testgen::shapes::{polygon_area, LayoutBuilder};

const S: i64 = 100;
const L: LayerId = LayerId(0);

/// The cells of a picture as `(column, row)`, row 0 at the bottom.
fn cells(picture: &str) -> Vec<(i64, i64)> {
    let rows: Vec<&str> = picture.split('|').collect();
    let top = i64::try_from(rows.len()).expect("small") - 1;
    (0..)
        .zip(&rows)
        .flat_map(|(r, row)| {
            (0..)
                .zip(row.bytes())
                .filter(|&(_, c)| c == b'#')
                .map(move |(x, _)| (x, top - r))
        })
        .collect()
}

/// One counter-clockwise ring per cell, each starting at corner `start` of
/// its four.
fn draw(cells: &[(i64, i64)], start: usize) -> GeometryStore {
    let mut layout = LayoutBuilder::new(1);
    for &(x, y) in cells {
        let (x0, y0) = (x * S, y * S);
        let mut xs = vec![x0, x0 + S, x0 + S, x0];
        let mut ys = vec![y0, y0, y0 + S, y0 + S];
        xs.rotate_left(start);
        ys.rotate_left(start);
        layout.push(L, &xs, &ys);
    }
    layout.finish().0
}

/// One ring of raw vertices on the layer.
fn ring(points: &[(i64, i64)]) -> GeometryStore {
    let mut layout = LayoutBuilder::new(1);
    let (xs, ys): (Vec<i64>, Vec<i64>) = points.iter().copied().unzip();
    layout.push(L, &xs, &ys);
    layout.finish().0
}

fn validated(store: &GeometryStore) -> Result<ValidatedLayer, ValidityError> {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, L, &mut out)?;
    Ok(out)
}

fn merged(store: &GeometryStore) -> ValidatedLayer {
    let drawn = validated(store).expect("the cells are valid");
    let mut out = ValidatedLayer::default();
    union_into(&drawn, &ValidatedLayer::default(), &mut out).expect("rectilinear");
    out
}

/// Each polygon's area and its holes' areas, ascending.
fn figures(layer: &ValidatedLayer) -> Vec<(i128, Vec<i128>)> {
    let mut out: Vec<(i128, Vec<i128>)> = (0..u32::try_from(layer.len()).expect("small"))
        .map(|i| {
            let poly = layer.get(i);
            let mut holes: Vec<i128> = poly.holes().map(|h| -h.area2().raw() / 2).collect();
            holes.sort_unstable();
            (polygon_area(poly).raw(), holes)
        })
        .collect();
    out.sort_unstable();
    out
}

/// The eight symmetries of the `n`-square, on cells.
fn symmetries(cells: &[(i64, i64)], n: i64) -> Vec<Vec<(i64, i64)>> {
    let maps: [fn(i64, i64, i64) -> (i64, i64); 8] = [
        |_, x, y| (x, y),
        |n, x, y| (n - 1 - y, x),
        |n, x, y| (n - 1 - x, n - 1 - y),
        |n, x, y| (y, n - 1 - x),
        |n, x, y| (n - 1 - x, y),
        |n, x, y| (x, n - 1 - y),
        |_, x, y| (y, x),
        |n, x, y| (n - 1 - y, n - 1 - x),
    ];
    maps.iter()
        .map(|map| cells.iter().map(|&(x, y)| map(n, x, y)).collect())
        .collect()
}

/// F38/F51's figure: `.#.|#.#`, three cells meeting at two corners, is one
/// polygon of three cells with no hole, and its outer ring passes each
/// corner twice. Before the corner model it was three polygons.
///
/// Oracle: the corner model `union_into` states (a polygon is one 8-connected
/// component of cells, a hole one 4-connected component of the space it
/// encloses), applied by hand: the three cells are one polygon of 30 000 with
/// no hole, and its ring passes each of the two touch points twice.
#[test]
fn cells_joined_only_at_corners_are_one_polygon() {
    let layer = merged(&draw(&cells(".#.|#.#"), 0));
    assert_eq!(figures(&layer), [(30_000, vec![])]);
    let (xs, ys) = layer.get(0).outer().coords();
    for corner in [(S, S), (2 * S, S)] {
        let visits = xs
            .iter()
            .zip(ys)
            .filter(|(x, y)| (x.raw(), y.raw()) == corner)
            .count();
        assert_eq!(visits, 2, "the outer ring passes {corner:?} once per cell");
    }
}

/// The touch point is a neck of width 0, and the 100-wide gap between the two
/// lower cells, across empty space inside the one figure, is a notch.
///
/// Oracle: the corner model `union_into` states (a polygon is one 8-connected
/// component of cells, a hole one 4-connected component of the space it
/// encloses), applied by hand: the touch point is a width of 0, and the gap
/// between the two lower cells, inside the one figure, faces itself at `S`.
#[test]
fn a_corner_is_a_neck_of_width_zero_and_the_gap_beside_it_a_notch() {
    let layer = merged(&draw(&cells(".#.|#.#"), 0));
    let poly = layer.get(0);
    let mut scratch = FacingScratch::default();
    assert_eq!(narrowest_width(poly, &mut scratch).raw(), 0);
    let (notch, _) = narrowest_facing(poly, false, &mut scratch).expect("the gap faces itself");
    assert_eq!(notch.raw(), S);
}

/// `###|#.#|.##` closes a ring of seven cells only at the centre cell's lower
/// left corner, and `##..|#.##|#..#|####` closes one round three empty cells
/// at a corner of the same orientation. Each is one polygon with one hole,
/// the empty cells inside, whatever the drawing: every symmetry of the
/// square, both drawing orders, each ring starting at each of its corners.
///
/// Oracle: the corner model `union_into` states (a polygon is one 8-connected
/// component of cells, a hole one 4-connected component of the space it
/// encloses), applied by hand, counted from the pictures (7 cells round
/// 1 empty, 11 round 3), and a metamorphic relation: every symmetry of the
/// square, drawing order and starting corner gives the same figure.
#[test]
fn a_ring_closed_only_at_a_corner_encloses_a_hole_however_it_is_drawn() {
    for (picture, n, cells_in, empty_in) in
        [("###|#.#|.##", 3, 7, 1), ("##..|#.##|#..#|####", 4, 11, 3)]
    {
        let want = vec![(
            i128::from(cells_in * S * S),
            vec![i128::from(empty_in * S * S)],
        )];
        for mut drawn in symmetries(&cells(picture), n) {
            for _ in 0..2 {
                for start in 0..4 {
                    let got = figures(&merged(&draw(&drawn, start)));
                    assert_eq!(
                        got, want,
                        "{picture} drawn as {drawn:?}, rings from corner {start}"
                    );
                }
                drawn.reverse();
            }
        }
    }
}

/// The same ring drawn as one polygon whose boundary runs round the outside,
/// through the corner into the centre and back out: validation takes it as one
/// figure of 70 000, and the merge gives the hole of 10 000 the cells give.
///
/// Oracle: the corner model `union_into` states (a polygon is one 8-connected
/// component of cells, a hole one 4-connected component of the space it
/// encloses), applied by hand: the boundary encloses seven cells, 70 000, and
/// the merge gives the one-cell hole of 10 000 the cell drawing gives.
#[test]
fn a_ring_closed_at_a_corner_drawn_as_one_boundary_merges_to_the_same_hole() {
    let store = ring(&[
        (100, 100),
        (100, 0),
        (300, 0),
        (300, 300),
        (0, 300),
        (0, 100),
        (100, 100),
        (100, 200),
        (200, 200),
        (200, 100),
    ]);
    let drawn = validated(&store).expect("a boundary touching itself at a corner is valid");
    assert_eq!(figures(&drawn), [(70_000, vec![])]);
    assert_eq!(figures(&merged(&store)), [(70_000, vec![10_000])]);
}

/// A hole that wraps an island joined to its frame at one corner is one hole
/// round it: in `#####|#...#|#.#.#|##..#|#####` the centre cell meets the
/// frame only at its lower left corner, so island and frame are one polygon of
/// 18 cells, and the seven empty cells one hole of 70 000. Under a corner model
/// that kept the island apart it was a second polygon inside a hole of eight
/// cells.
///
/// Oracle: the corner model `union_into` states (a polygon is one 8-connected
/// component of cells, a hole one 4-connected component of the space it
/// encloses), applied by hand: 18 cells joined into one polygon of
/// 180 000 round one hole of seven empty cells, 70 000.
#[test]
fn an_island_joined_to_its_frame_at_a_corner_is_part_of_the_frame() {
    let layer = merged(&draw(&cells("#####|#...#|#.#.#|##..#|#####"), 0));
    assert_eq!(figures(&layer), [(180_000, vec![70_000])]);
}

/// Two squares drawn as one boundary that passes their shared corner twice
/// are one valid figure of both their areas.
///
/// Oracle: the corner model `union_into` states (a polygon is one 8-connected
/// component of cells, a hole one 4-connected component of the space it
/// encloses), applied by hand: two 100 squares meeting at a corner are one
/// figure of 20 000.
#[test]
fn a_boundary_through_a_corner_twice_is_valid() {
    let store = ring(&[
        (0, 0),
        (100, 0),
        (100, 100),
        (200, 100),
        (200, 200),
        (100, 200),
        (100, 100),
        (0, 100),
    ]);
    let layer = validated(&store).expect("two squares meeting at a corner");
    assert_eq!(figures(&layer), [(20_000, vec![])]);
}

/// What the corner model does not admit: a boundary passing a vertex straight
/// twice crosses itself there, and a spike out of a vertex and back along the
/// same edge doubles back. Both stay refused.
///
/// Oracle: the corner model's limit, as `union_into` states it: only a corner
/// touch is admitted, so a boundary passing a vertex straight twice crosses
/// itself and a spike doubles back; both are `SelfIntersecting`.
#[test]
fn a_crossing_or_a_spike_at_a_twice_visited_vertex_is_refused() {
    let crossing = ring(&[
        (-200, 0),
        (0, 0),
        (200, 0),
        (200, 100),
        (0, 100),
        (0, 0),
        (0, -100),
        (-200, -100),
    ]);
    let spike = ring(&[
        (-100, 0),
        (0, 0),
        (0, 100),
        (0, 0),
        (100, 0),
        (100, -100),
        (-100, -100),
    ]);
    for (what, store) in [("crossing", crossing), ("spike", spike)] {
        assert_eq!(
            validated(&store).map(|_| ()),
            Err(ValidityError::SelfIntersecting(PolyId(0))),
            "{what}"
        );
    }
}
