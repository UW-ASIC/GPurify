//! Geometry builders: exact rectilinear shapes, and the store they go into.
//!
//! Coordinates are computed in plain `i64` and wrapped through [`dbu`] at the
//! last moment. Every outer boundary is counter-clockwise and every hole is
//! clockwise, the canonical winding [`gpurify_geom::view`] establishes. Each
//! shape function returns `(xs, ys)`, the vertex columns
//! [`LayoutBuilder::shape`] takes, and has a closed-form area beside it to
//! check a measurement against.

use gpurify_geom::ops::Point;
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_geom::{GeometryStore, GeometryStoreBuilder, LayerId, PolyId, PolygonRef};

/// Wraps an `i64` as a coordinate.
///
/// # Panics
///
/// Panics if `|value|` exceeds [`MAX_ABS_DBU`], the bound that keeps every
/// `i128` area product from overflowing.
#[must_use]
pub fn dbu(value: i64) -> Dbu {
    assert!(
        value.abs() <= MAX_ABS_DBU,
        "{value} is outside the legal coordinate domain of +/-{MAX_ABS_DBU}"
    );
    Dbu::new_unchecked(value)
}

/// Wraps a pair of `i64` as a report coordinate, such as a
/// violation's `at`.
///
/// # Panics
///
/// Panics as [`dbu`] does.
#[must_use]
pub fn point(x: i64, y: i64) -> Point {
    Point {
        x: dbu(x),
        y: dbu(y),
    }
}

/// Wraps an `i128` as a layout area, in database units squared.
#[must_use]
pub fn area(value: i128) -> DbuArea {
    DbuArea::new(value)
}

/// A rectangle, counter-clockwise from its lower-left corner.
///
/// # Panics
///
/// Panics unless `xlo < xhi` and `ylo < yhi`. Empty or inverted is legal as a
/// derived result but a bug in a generator, so it is refused.
#[must_use]
pub fn rect(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> (Vec<i64>, Vec<i64>) {
    assert!(
        xhi > xlo && yhi > ylo,
        "rect({xlo}, {ylo}, {xhi}, {yhi}) has no interior"
    );
    (vec![xlo, xhi, xhi, xlo], vec![ylo, ylo, yhi, yhi])
}

/// The same rectangle wound clockwise: a hole, pushed as its own polygon on
/// the layer of the shape it cuts.
///
/// # Panics
///
/// Panics as [`rect`] does.
#[must_use]
pub fn hole(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> (Vec<i64>, Vec<i64>) {
    let (xs, ys) = rect(xlo, ylo, xhi, yhi);
    (
        xs.into_iter().rev().collect(),
        ys.into_iter().rev().collect(),
    )
}

/// An L, with both arms of length `arm` and both of width `thickness`, its
/// outer corner at `(x, y)` and the arms running in +x and +y. Its area is
/// [`l_shape_area`].
///
/// # Panics
///
/// Panics unless `0 < thickness < arm`; outside that it would be a rectangle
/// or self-overlapping.
#[must_use]
pub fn l_shape(x: i64, y: i64, arm: i64, thickness: i64) -> (Vec<i64>, Vec<i64>) {
    assert!(
        thickness > 0 && thickness < arm,
        "an L needs 0 < thickness ({thickness}) < arm ({arm})"
    );
    (
        vec![x, x + arm, x + arm, x + thickness, x + thickness, x],
        vec![y, y, y + thickness, y + thickness, y + arm, y + arm],
    )
}

/// Closed-form area of [`l_shape`]: `thickness * (2 * arm - thickness)`,
/// strictly below the `arm * arm` of its bounding box.
#[must_use]
pub fn l_shape_area(arm: i64, thickness: i64) -> i128 {
    i128::from(thickness) * (2 * i128::from(arm) - i128::from(thickness))
}

/// A plus sign centred on `(cx, cy)`: two bars of width `thickness`, each
/// `2 * arm` long, crossing at the centre. Its area is [`plus_shape_area`].
///
/// # Panics
///
/// Panics unless `0 < thickness < 2 * arm` and `thickness` is even, so the
/// bars' edges are integer coordinates.
#[must_use]
pub fn plus_shape(cx: i64, cy: i64, arm: i64, thickness: i64) -> (Vec<i64>, Vec<i64>) {
    assert!(
        thickness > 0 && thickness < 2 * arm,
        "a plus needs 0 < thickness ({thickness}) < 2 * arm ({arm})"
    );
    assert!(thickness % 2 == 0, "thickness {thickness} must be even");
    let h = thickness / 2;
    (
        vec![
            cx - h,
            cx + h,
            cx + h,
            cx + arm,
            cx + arm,
            cx + h,
            cx + h,
            cx - h,
            cx - h,
            cx - arm,
            cx - arm,
            cx - h,
        ],
        vec![
            cy - arm,
            cy - arm,
            cy - h,
            cy - h,
            cy + h,
            cy + h,
            cy + arm,
            cy + arm,
            cy + h,
            cy + h,
            cy - h,
            cy - h,
        ],
    )
}

/// Closed-form area of [`plus_shape`]: the two bars less their double-counted
/// intersection.
#[must_use]
pub fn plus_shape_area(arm: i64, thickness: i64) -> i128 {
    4 * i128::from(arm) * i128::from(thickness) - i128::from(thickness) * i128::from(thickness)
}

/// A U opening upwards, lower-left corner at `(x, y)`, overall width
/// `2 * thickness + gap` and height `arm`. The notch is `gap` wide and runs
/// from `y + thickness` to `y + arm`. Its area is [`u_shape_area`].
///
/// # Panics
///
/// Panics unless `gap > 0` and `0 < thickness < arm`.
#[must_use]
pub fn u_shape(x: i64, y: i64, arm: i64, thickness: i64, gap: i64) -> (Vec<i64>, Vec<i64>) {
    assert!(gap > 0, "a U needs a positive gap, got {gap}");
    assert!(
        thickness > 0 && thickness < arm,
        "a U needs 0 < thickness ({thickness}) < arm ({arm})"
    );
    let width = 2 * thickness + gap;
    (
        vec![
            x,
            x + width,
            x + width,
            x + thickness + gap,
            x + thickness + gap,
            x + thickness,
            x + thickness,
            x,
        ],
        vec![
            y,
            y,
            y + arm,
            y + arm,
            y + thickness,
            y + thickness,
            y + arm,
            y + arm,
        ],
    )
}

/// Closed-form area of [`u_shape`]: `thickness * (2 * arm + gap)`.
#[must_use]
pub fn u_shape_area(arm: i64, thickness: i64, gap: i64) -> i128 {
    i128::from(thickness) * (2 * i128::from(arm) + i128::from(gap))
}

/// Accumulates shapes and hands back a store plus the identity of every shape.
///
/// The store sorts its polygons, so a shape's [`PolyId`] is not its push
/// order: every push returns a [`Handle`], and [`LayoutBuilder::finish`]
/// returns the [`Ids`] that resolve handles to ids.
#[derive(Debug)]
pub struct LayoutBuilder {
    builder: GeometryStoreBuilder,
    layer_count: usize,
    pushed: u32,
    /// Reused coordinate scratch.
    xs: Vec<Dbu>,
    ys: Vec<Dbu>,
}

/// A shape that has been pushed but not yet identified: a pre-sort row index,
/// opaque because it is meaningless to anything but [`Ids`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(u32);

/// Resolves [`LayoutBuilder`] handles to the ids the store gave them.
#[derive(Debug, Default)]
pub struct Ids {
    /// `id[handle] == PolyId`, the inverse of the builder's permutation.
    id: Vec<PolyId>,
}

impl Ids {
    /// The store row a handle became.
    ///
    /// # Panics
    ///
    /// Panics on a handle beyond this builder's pushes. A handle from another
    /// builder resolves silently to the wrong shape.
    #[must_use]
    pub fn of(&self, handle: Handle) -> PolyId {
        self.id[handle.0 as usize]
    }

    /// Resolve several handles, sorted ascending.
    #[must_use]
    pub fn sorted(&self, handles: &[Handle]) -> Vec<PolyId> {
        let mut ids: Vec<PolyId> = handles.iter().map(|&h| self.of(h)).collect();
        ids.sort_unstable();
        ids
    }
}

impl LayoutBuilder {
    /// Starts a layout over a layer table of `layer_count` layers; every
    /// pushed layer must be below it.
    #[must_use]
    pub fn new(layer_count: usize) -> Self {
        Self {
            builder: GeometryStoreBuilder::default(),
            layer_count,
            pushed: 0,
            xs: Vec::new(),
            ys: Vec::new(),
        }
    }

    /// Pushes a coordinate run as one polygon on `layer`, unclosed (the first
    /// vertex is not repeated).
    ///
    /// # Panics
    ///
    /// Panics if the columns differ in length, there are fewer than three
    /// vertices, or a coordinate is outside [`dbu`]'s domain.
    pub fn push(&mut self, layer: LayerId, xs: &[i64], ys: &[i64]) -> Handle {
        assert_eq!(xs.len(), ys.len(), "coordinate columns must be parallel");
        assert!(xs.len() >= 3, "a polygon needs at least three vertices");
        self.xs.clear();
        self.ys.clear();
        self.xs.extend(xs.iter().copied().map(dbu));
        self.ys.extend(ys.iter().copied().map(dbu));
        self.builder.push(layer, &self.xs, &self.ys);
        let handle = Handle(self.pushed);
        self.pushed += 1;
        handle
    }

    /// Pushes a shape from one of the free functions above. Panics as
    /// [`LayoutBuilder::push`] does.
    pub fn shape(&mut self, layer: LayerId, shape: &(Vec<i64>, Vec<i64>)) -> Handle {
        self.push(layer, &shape.0, &shape.1)
    }

    /// Pushes a rectangle. Panics as [`rect`] does.
    pub fn rect(&mut self, layer: LayerId, xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Handle {
        self.shape(layer, &rect(xlo, ylo, xhi, yhi))
    }

    /// How many shapes have been pushed.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.pushed
    }

    /// Whether nothing has been pushed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pushed == 0
    }

    /// Sorts the shapes into a store and inverts the store's permutation, so
    /// [`Ids`] can map each push's [`Handle`] to its [`PolyId`].
    #[must_use]
    pub fn finish(self) -> (GeometryStore, Ids) {
        let (store, permutation) = self.builder.finish(self.layer_count);
        assert_eq!(
            permutation.len(),
            self.pushed as usize,
            "the store returned a permutation of a different length than the pushes it received"
        );
        let mut id = vec![PolyId(0); permutation.len()];
        for (new_row, &old_row) in permutation.iter().enumerate() {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "new_row indexes a permutation whose length was pushed as a u32"
            )]
            let assigned = PolyId(new_row as u32);
            id[old_row as usize] = assigned;
        }
        (store, Ids { id })
    }
}

/// Two rectangles facing each other across an exact `gap` in x, centred on
/// `at`. Each is `size` wide and `2 * size` tall, spanning `at.1 - size` to
/// `at.1 + size`; the left one's right edge is at `at.0 - gap / 2`. Returns
/// (left, right).
///
/// # Panics
///
/// Panics unless `gap` is positive and even and `size` is positive.
pub fn spaced_pair(
    layout: &mut LayoutBuilder,
    layer: LayerId,
    at: (i64, i64),
    gap: i64,
    size: i64,
) -> (Handle, Handle) {
    assert!(
        gap > 0 && gap % 2 == 0,
        "gap {gap} must be positive and even"
    );
    assert!(size > 0, "size {size} must be positive");
    let (ax, ay) = at;
    let half = gap / 2;
    let a = layout.rect(layer, ax - half - size, ay - size, ax - half, ay + size);
    let b = layout.rect(layer, ax + half, ay - size, ax + half + size, ay + size);
    (a, b)
}

/// One layer of pseudo-random rectilinear geometry at an exactly known
/// coverage.
///
/// The region, `grid.cells` square cells of side `grid.cell` from `origin`,
/// gets at most one square per cell. `density` is split evenly between the
/// two random choices: a cell is filled with probability `sqrt(density)`, and
/// every square covers `sqrt(density)` of its cell, side
/// `floor(cell * density^(1/4))` (at least 1, at most `cell - 2`), jittered
/// inside its cell with at least one unit of clearance on each side. So no two
/// squares touch, the expected covered fraction is about `density`, and the
/// returned [`RandomLayer`] states the exact figure. At 1.0 every cell is
/// filled. The same `rng` state gives the same layer.
///
/// # Panics
///
/// Panics if `density` is outside `0.0..=1.0`, `cells` is zero, `cell` does
/// not fit a `u32`, or `cell` is under 3, too small for a square and its
/// clearance.
pub fn random_rectilinear_layer(
    layout: &mut LayoutBuilder,
    rng: &mut crate::Rng,
    layer: LayerId,
    origin: (i64, i64),
    grid: RandomLayerSpec,
) -> RandomLayer {
    assert!(
        (0.0..=1.0).contains(&grid.density),
        "density {} is outside 0.0..=1.0",
        grid.density
    );
    assert!(grid.cells > 0, "a layer needs at least one cell");
    assert!(
        grid.cell >= 3,
        "cell {} cannot hold a square with a unit of clearance on each side",
        grid.cell
    );
    #[allow(
        clippy::cast_precision_loss,
        reason = "cell is a layout dimension, far below 2^53"
    )]
    let ideal = f64::from(u32::try_from(grid.cell).expect("cell side must fit a u32"))
        * grid.density.sqrt().sqrt();
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "ideal is non-negative and at most cell, which fits a u32"
    )]
    // One unit of clearance on each side is enough: shapes in adjacent cells
    // then have a gap of at least two, so they neither touch nor overlap.
    let side = i64::from(ideal as u32).clamp(1, grid.cell - 2);
    let slack = grid.cell - side - 2;

    let mut shapes = 0u32;
    for row in 0..grid.cells {
        for col in 0..grid.cells {
            if rng.unit() >= grid.density.sqrt() {
                continue;
            }
            let jitter_x = if slack > 0 {
                rng.range(0, slack + 1)
            } else {
                0
            };
            let jitter_y = if slack > 0 {
                rng.range(0, slack + 1)
            } else {
                0
            };
            let x = origin.0 + i64::from(col) * grid.cell + 1 + jitter_x;
            let y = origin.1 + i64::from(row) * grid.cell + 1 + jitter_y;
            layout.rect(layer, x, y, x + side, y + side);
            shapes += 1;
        }
    }

    RandomLayer {
        shapes,
        side,
        covered: i128::from(shapes) * i128::from(side) * i128::from(side),
        extent: i64::from(grid.cells) * grid.cell,
    }
}

/// The shape of a [`random_rectilinear_layer`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RandomLayerSpec {
    /// Cells along each axis; the region is `cells * cell` square.
    pub cells: u32,
    /// Side of one cell, in database units.
    pub cell: i64,
    /// In `0.0..=1.0`: the expected covered fraction. Its square root is both
    /// the chance a cell is filled and the fraction of a filled cell its
    /// square covers. [`RandomLayer::covered`] is exact.
    pub density: f64,
}

/// What [`random_rectilinear_layer`] produced, with the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomLayer {
    /// Shapes emitted. Each stays one polygon: none of them touch.
    pub shapes: u32,
    /// Side of every shape.
    pub side: i64,
    /// Total covered area, exact: the shapes are disjoint.
    pub covered: i128,
    /// Side of the square region the shapes lie in.
    pub extent: i64,
}

/// Area of a validated polygon: the outer ring minus its holes. Positive for
/// the canonical winding, which validation establishes.
#[must_use]
pub fn polygon_area(poly: PolygonRef<'_>) -> DbuArea {
    // Holes wind CW, so their doubled areas are already negative.
    let doubled = poly
        .holes()
        .fold(poly.outer().area2(), |total, hole| total + hole.area2());
    DbuArea::new(doubled.raw() / 2)
}

#[cfg(test)]
mod tests {
    use super::{
        l_shape, l_shape_area, plus_shape, plus_shape_area, random_rectilinear_layer, u_shape,
        u_shape_area, LayoutBuilder, RandomLayerSpec,
    };
    use gpurify_geom::LayerId;

    /// F35: `density` is the expected coverage, applied once. At 1.0 every
    /// cell holds the largest square its clearance allows (98 of 100); at 0.25
    /// half the cells are filled with a 707-side square (√0.25 of a 1000 cell),
    /// 0.2499 expected, 0.0025 standard deviation over 10⁴ cells.
    ///
    /// Oracle: hand-derived, as above: at density 1.0 all 16 cells hold a
    /// 98 square; at 0.25 about half the cells hold a 707 square, 707^2 /
    /// 1000^2 = 0.4998 each, 0.2499 expected coverage.
    #[test]
    fn density_is_the_expected_coverage_and_one_fills_every_cell() {
        let layer = |density, cells, cell| {
            random_rectilinear_layer(
                &mut LayoutBuilder::new(1),
                &mut crate::Rng::new(5),
                LayerId(0),
                (0, 0),
                RandomLayerSpec {
                    cells,
                    cell,
                    density,
                },
            )
        };
        let full = layer(1.0, 4, 100);
        assert_eq!(
            (full.shapes, full.side, full.covered),
            (16, 98, 16 * 98 * 98)
        );

        let quarter = layer(0.25, 100, 1000);
        assert_eq!(quarter.side, 707);
        #[allow(clippy::cast_precision_loss, reason = "under 2^53")]
        let fraction = quarter.covered as f64 / 1e10;
        assert!(
            (fraction - 0.25).abs() < 0.01,
            "covered {fraction} of the region"
        );
    }

    /// Twice the signed area of a run; positive is counter-clockwise.
    fn shoelace(shape: &(Vec<i64>, Vec<i64>)) -> i128 {
        let (xs, ys) = shape;
        let n = xs.len();
        let mut twice = 0i128;
        for i in 0..n {
            let j = (i + 1) % n;
            twice += i128::from(xs[i]) * i128::from(ys[j]) - i128::from(xs[j]) * i128::from(ys[i]);
        }
        twice
    }

    /// Oracle: closed form, `thickness * (2 * arm - thickness)`, against the
    /// shoelace of the drawn vertices, whose positive sign is
    /// counter-clockwise.
    #[test]
    fn l_shape_area_matches_its_closed_form_and_winds_counter_clockwise() {
        for &(arm, thickness) in &[(100, 30), (7, 1), (1_000_000, 999_999)] {
            let twice = shoelace(&l_shape(-5, 11, arm, thickness));
            assert!(twice > 0, "an outer boundary must wind counter-clockwise");
            assert_eq!(twice, 2 * l_shape_area(arm, thickness));
        }
    }

    /// Oracle: closed form, `4 * arm * thickness - thickness^2` (two bars less
    /// their double-counted crossing), against the shoelace of the drawn
    /// vertices, whose positive sign is counter-clockwise.
    #[test]
    fn plus_shape_area_matches_its_closed_form_and_winds_counter_clockwise() {
        for &(arm, thickness) in &[(100, 30), (50, 2), (1_000, 998)] {
            let twice = shoelace(&plus_shape(3, -9, arm, thickness));
            assert!(twice > 0, "an outer boundary must wind counter-clockwise");
            assert_eq!(twice, 2 * plus_shape_area(arm, thickness));
        }
    }

    /// Oracle: closed form, `thickness * (2 * arm + gap)` (the bounding box
    /// less the notch), against the shoelace of the drawn vertices, whose
    /// positive sign is counter-clockwise.
    #[test]
    fn u_shape_area_matches_its_closed_form_and_winds_counter_clockwise() {
        for &(arm, thickness, gap) in &[(100, 20, 40), (9, 1, 3), (500, 499, 2)] {
            let twice = shoelace(&u_shape(0, 0, arm, thickness, gap));
            assert!(twice > 0, "an outer boundary must wind counter-clockwise");
            assert_eq!(twice, 2 * u_shape_area(arm, thickness, gap));
        }
    }

    /// A bounding box overstates every non-convex shape here.
    ///
    /// Oracle: hand-derived. The L is 30 * 170 = 5100 against 100^2, the plus 4
    /// * 100 * 30 - 900 = 11 100 against 200^2, the U 20 * 240 = 4800 against
    /// 80 * 100.
    #[test]
    fn non_convex_shapes_are_smaller_than_their_bounding_box() {
        assert!(l_shape_area(100, 30) < 100 * 100);
        assert!(plus_shape_area(100, 30) < 200 * 200);
        assert!(u_shape_area(100, 20, 40) < (2 * 20 + 40) * 100);
    }
}
