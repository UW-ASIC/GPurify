//! Geometry builders: exact rectilinear shapes, and the store they go into.
//!
//! Coordinates are computed in plain `i64` and wrapped through [`dbu`] at the
//! last moment. Every outer boundary is counter-clockwise and every hole is
//! clockwise, the canonical winding `core::view` establishes.

use gpurify_geom::ops::Point;
use gpurify_geom::{GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};

/// Wrap an `i64` as a coordinate. `MAX_ABS_DBU` is the bound that keeps every
/// `i128` area product from overflowing.
#[must_use]
pub fn dbu(value: i64) -> Dbu {
    assert!(
        value.abs() <= MAX_ABS_DBU,
        "{value} is outside the legal coordinate domain of +/-{MAX_ABS_DBU}"
    );
    Dbu::new_unchecked(value)
}

/// Wrap a pair of `i64` as a report coordinate.
#[must_use]
pub fn point(x: i64, y: i64) -> Point {
    Point {
        x: dbu(x),
        y: dbu(y),
    }
}

/// Wrap an `i128` as a layout area.
#[must_use]
pub fn area(value: i128) -> DbuArea {
    DbuArea::new(value)
}

/// A rectangle, counter-clockwise from its lower-left corner. Empty or inverted
/// is legal as a derived result but a bug in a generator, so it is refused.
#[must_use]
pub fn rect(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> (Vec<i64>, Vec<i64>) {
    assert!(
        xhi > xlo && yhi > ylo,
        "rect({xlo}, {ylo}, {xhi}, {yhi}) has no interior"
    );
    (vec![xlo, xhi, xhi, xlo], vec![ylo, ylo, yhi, yhi])
}

/// The same rectangle wound clockwise: a hole.
#[must_use]
pub fn hole(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> (Vec<i64>, Vec<i64>) {
    let (xs, ys) = rect(xlo, ylo, xhi, yhi);
    (
        xs.into_iter().rev().collect(),
        ys.into_iter().rev().collect(),
    )
}

/// An L, with both arms of length `arm` and both of width `thickness`, the
/// inner corner at `(x, y)`. Outside `0 < thickness < arm` it would be a
/// rectangle or self-overlapping.
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
/// `2 * arm` long, crossing at the centre.
///
/// An odd `thickness` has no integer centre line, which breaks the closed form,
/// so it is refused.
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
/// `2 * thickness + gap`.
///
/// The gap is a notch: an internal spacing within one polygon, a different
/// measurement from the spacing between two polygons.
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
/// [`GeometryStoreBuilder::finish`] sorts rows by layer, so a shape's [`PolyId`]
/// is not its push order; a push returns a [`Handle`] that [`Ids`] resolves.
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
    /// The store row a handle became. Panics on a handle from another builder.
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
    /// Start a layout over a layer table of `layer_count` layers.
    ///
    /// The count comes from the caller, not the geometry: a layer with no
    /// shapes still needs an empty range, or a rule naming it cannot find it.
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

    /// Push a coordinate run as one polygon on `layer`.
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

    /// Push a shape from one of the free functions above.
    pub fn shape(&mut self, layer: LayerId, shape: &(Vec<i64>, Vec<i64>)) -> Handle {
        self.push(layer, &shape.0, &shape.1)
    }

    /// Push a rectangle.
    pub fn rect(&mut self, layer: LayerId, xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Handle {
        self.shape(layer, &rect(xlo, ylo, xhi, yhi))
    }

    /// How many shapes have been pushed.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.pushed
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pushed == 0
    }

    /// Sort into a store and invert the permutation.
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

/// Two rectangles of side `size` facing each other across an exact gap.
///
/// Fixes the reported coordinate convention: `at` is the midpoint of the gap,
/// on the line joining the two facing edges, and a spacing rule must report it.
/// An odd gap has no integer midpoint, so it is refused rather than rounded.
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
/// A square of side `cell * sqrt(density)` is placed in each `cell`-sided cell
/// with probability `density`, jittered only within the margin that keeps it
/// clear of every neighbour — so the covered area is exactly `shapes * side^2`
/// and no two shapes merge.
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
    #[allow(
        clippy::cast_precision_loss,
        reason = "cell is a layout dimension, far below 2^53"
    )]
    let ideal = f64::from(u32::try_from(grid.cell).expect("cell side must fit a u32"))
        * grid.density.sqrt();
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "ideal is non-negative and below cell, which fits a u32"
    )]
    let side = i64::from(ideal as u32).max(1);
    // One unit of clearance on each side is enough: shapes in adjacent cells
    // then have a gap of at least two, so they neither touch nor overlap.
    let slack = grid.cell - side - 2;
    assert!(
        slack >= 0,
        "cell {} cannot hold a shape of side {side} with clearance",
        grid.cell
    );

    let mut shapes = 0u32;
    for row in 0..grid.cells {
        for col in 0..grid.cells {
            if rng.unit() >= grid.density {
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
    /// Fraction of the region to cover, in `0.0..=1.0`.
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

#[cfg(test)]
mod tests {
    use super::{l_shape, l_shape_area, plus_shape, plus_shape_area, u_shape, u_shape_area};

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

    #[test]
    fn l_shape_area_matches_its_closed_form_and_winds_counter_clockwise() {
        for &(arm, thickness) in &[(100, 30), (7, 1), (1_000_000, 999_999)] {
            let twice = shoelace(&l_shape(-5, 11, arm, thickness));
            assert!(twice > 0, "an outer boundary must wind counter-clockwise");
            assert_eq!(twice, 2 * l_shape_area(arm, thickness));
        }
    }

    #[test]
    fn plus_shape_area_matches_its_closed_form_and_winds_counter_clockwise() {
        for &(arm, thickness) in &[(100, 30), (50, 2), (1_000, 998)] {
            let twice = shoelace(&plus_shape(3, -9, arm, thickness));
            assert!(twice > 0, "an outer boundary must wind counter-clockwise");
            assert_eq!(twice, 2 * plus_shape_area(arm, thickness));
        }
    }

    #[test]
    fn u_shape_area_matches_its_closed_form_and_winds_counter_clockwise() {
        for &(arm, thickness, gap) in &[(100, 20, 40), (9, 1, 3), (500, 499, 2)] {
            let twice = shoelace(&u_shape(0, 0, arm, thickness, gap));
            assert!(twice > 0, "an outer boundary must wind counter-clockwise");
            assert_eq!(twice, 2 * u_shape_area(arm, thickness, gap));
        }
    }

    /// A bounding box overstates every non-convex shape here.
    #[test]
    fn non_convex_shapes_are_smaller_than_their_bounding_box() {
        assert!(l_shape_area(100, 30) < 100 * 100);
        assert!(plus_shape_area(100, 30) < 200 * 200);
        assert!(u_shape_area(100, 20, 40) < (2 * 20 + 40) * 100);
    }
}
