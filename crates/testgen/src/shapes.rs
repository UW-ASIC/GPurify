//! Geometry builders: exact rectilinear shapes, and the store they go into.
//!
//! # Why everything here speaks `i64`
//!
//! [`Dbu`] is a newtype whose accessor `raw` is a frozen signature with a
//! `todo!()` body until the Implementation-Phase, so this crate cannot read a
//! coordinate back out of one. It therefore computes in plain `i64`, where the
//! arithmetic is visible and checkable, and wraps at the last moment through
//! [`dbu`]. The range check `Dbu::new` performs is done by [`dbu`] instead, so
//! a builder that walks off the coordinate domain fails here rather than
//! producing geometry the tool would refuse.
//!
//! # Winding
//!
//! Every outer boundary produced here is counter-clockwise and every hole is
//! clockwise, which is the canonical winding `core::view` establishes. A
//! builder emitting the other direction would make a validation test pass for
//! the wrong reason.
//!
//! # The oracle these serve
//!
//! Closed form. The area of every shape below is written in its doc comment as
//! a formula in its parameters, computed by hand, and returned alongside the
//! geometry where a caller needs it. [`l_shape`] and [`plus_shape`] exist
//! specifically because their bounding box lies about them: an implementation
//! that measures the box instead of the polygon passes on rectangles and fails
//! on these.

use gpurify_core::ops::Point;
use gpurify_core::{GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
use gpurify_units::{Dbu, DbuArea, MAX_ABS_DBU};

/// Wrap an `i64` as a coordinate, checking the domain.
///
/// # Panics
///
/// When `value` is outside `±MAX_ABS_DBU`. That bound is what keeps every
/// `i128` area product from overflowing, so a generator that exceeds it is
/// building input the tool is entitled to reject — a bug in the test, not a
/// finding about the code.
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

/// A rectangle, counter-clockwise from its lower-left corner.
///
/// Area is `(xhi - xlo) * (yhi - ylo)`.
///
/// # Panics
///
/// When the rectangle is empty or inverted. A zero-width shape is legal as a
/// *derived* result but is not something a generator should be emitting, and
/// silently accepting one hides the builder bug that produced it.
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
/// inner corner at `(x, y)`.
///
/// **Area is `thickness * (2 * arm - thickness)`,** which is strictly less than
/// the `arm * arm` of its bounding box for every `thickness < arm`. That gap is
/// the point of this shape.
///
/// # Panics
///
/// When `thickness` is not strictly between zero and `arm` — outside that the
/// shape is a rectangle or is self-overlapping, and neither is an L.
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

/// Closed-form area of [`l_shape`].
#[must_use]
pub fn l_shape_area(arm: i64, thickness: i64) -> i128 {
    i128::from(thickness) * (2 * i128::from(arm) - i128::from(thickness))
}

/// A plus sign centred on `(cx, cy)`: two bars of width `thickness`, each
/// `2 * arm` long, crossing at the centre.
///
/// **Area is `4 * arm * thickness - thickness * thickness`** — the two bars
/// less their double-counted intersection. Twelve vertices, four reflex
/// corners, and a bounding box of `2 * arm` square that overstates it.
///
/// # Panics
///
/// When `thickness` is not strictly between zero and `2 * arm`, or when
/// `thickness` is odd — an odd bar cannot be centred on an integer coordinate
/// without one side being wider than the other, which would make the closed
/// form above wrong.
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

/// Closed-form area of [`plus_shape`].
#[must_use]
pub fn plus_shape_area(arm: i64, thickness: i64) -> i128 {
    4 * i128::from(arm) * i128::from(thickness) - i128::from(thickness) * i128::from(thickness)
}

/// A U, opening upwards: two uprights of width `thickness` and height `arm`,
/// joined by a base of height `thickness`, with a gap of exactly `gap` between
/// the uprights.
///
/// The gap is a *notch* — an internal spacing within one polygon, which is a
/// different measurement from the spacing between two polygons and is the
/// reason the two rules exist separately.
///
/// **Area is `thickness * (2 * arm + gap)`.** The base contributes
/// `(2 * thickness + gap) * thickness` and each upright another
/// `thickness * (arm - thickness)`, which is what those terms sum to. The
/// lower-left corner is at `(x, y)` and the overall width is
/// `2 * thickness + gap`.
///
/// # Panics
///
/// When `gap` or `thickness` is not positive, or `thickness` is not below
/// `arm`.
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

/// Closed-form area of [`u_shape`].
#[must_use]
pub fn u_shape_area(arm: i64, thickness: i64, gap: i64) -> i128 {
    i128::from(thickness) * (2 * i128::from(arm) + i128::from(gap))
}

/// Accumulates shapes and hands back a store plus the identity of every shape
/// in it.
///
/// # Why this type exists
///
/// [`GeometryStoreBuilder::finish`] sorts rows by layer and returns the
/// permutation, so the [`PolyId`] a shape ends up with is not the order it was
/// pushed in. Every construct-from-answer builder in this crate needs to name
/// the shape it deliberately made wrong, which means every one of them would
/// otherwise invert that permutation itself. Inverting it once, here, is the
/// difference between an oracle and eighteen chances to get an off-by-one into
/// the expected answer.
///
/// A push returns an opaque [`Handle`]; [`LayoutBuilder::finish`] returns the
/// store and a [`Ids`] that resolves handles to [`PolyId`].
#[derive(Debug)]
pub struct LayoutBuilder {
    builder: GeometryStoreBuilder,
    layer_count: usize,
    pushed: u32,
    /// Reused coordinate scratch, so a thousand-shape corpus allocates twice.
    xs: Vec<Dbu>,
    ys: Vec<Dbu>,
}

/// A shape that has been pushed but not yet identified.
///
/// Opaque on purpose: it is a pre-sort row index, which is meaningless to
/// anything but [`Ids`], and letting it be read as a number invites the exact
/// confusion this type prevents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(u32);

/// Resolves the handles a [`LayoutBuilder`] issued to the ids the store gave
/// them.
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
    /// When the handle came from a different builder.
    #[must_use]
    pub fn of(&self, handle: Handle) -> PolyId {
        self.id[handle.0 as usize]
    }

    /// Resolve several handles and sort the result ascending, which is the
    /// order every table in this workspace states its polygon lists in.
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
    /// The count comes from the caller rather than from the geometry because
    /// that is what `GeometryStoreBuilder::finish` requires: a layer with no
    /// shapes still needs an empty range, so a rule naming it reports "no
    /// violations" rather than failing to find the layer.
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
    ///
    /// # Panics
    ///
    /// When the two runs differ in length, or the run has fewer than three
    /// vertices.
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

    /// Push a shape produced by one of the free functions above.
    pub fn shape(&mut self, layer: LayerId, shape: &(Vec<i64>, Vec<i64>)) -> Handle {
        self.push(layer, &shape.0, &shape.1)
    }

    /// Push a rectangle. The overwhelmingly common case, so it is one call.
    pub fn rect(&mut self, layer: LayerId, xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Handle {
        self.shape(layer, &rect(xlo, ylo, xhi, yhi))
    }

    /// How many shapes have been pushed. The floor a `RuleRun::examined`
    /// assertion is written against.
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
/// **The oracle is construct-from-answer, and this is also where the reported
/// coordinate convention is fixed:** `at` is the midpoint of the gap, on the
/// line joining the two facing edges. A spacing rule must report that point.
/// The Implementation-Phase satisfies this test; it does not get to choose a
/// different point and call the test wrong.
///
/// # Panics
///
/// When `gap` is not positive and even. An odd gap has no integer midpoint, so
/// the expected coordinate would be a rounding and the test would be asserting
/// on a choice rather than on a fact.
pub fn spaced_pair(
    layout: &mut LayoutBuilder,
    layer: LayerId,
    at: (i64, i64),
    gap: i64,
    size: i64,
) -> (Handle, Handle) {
    assert!(gap > 0 && gap % 2 == 0, "gap {gap} must be positive and even");
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
/// # What makes the answer known
///
/// The region is tiled into `cell`-sided cells and a shape is placed in a cell
/// with probability `density`. Every shape is a square of the same side, and
/// the side is chosen so `side^2 / cell^2` is `density` as closely as an
/// integer allows — so the covered area is `shapes * side^2` **exactly**, with
/// no overlap correction, because a shape is jittered only within the margin
/// that keeps it clear of every neighbouring cell.
///
/// That clearance is not decoration. Shapes that touched would merge under net
/// extraction and the polygon count would stop being the shape count, which is
/// the number half the assertions in the suite are written against.
///
/// # Panics
///
/// When `density` is outside `0.0..=1.0`, or `cells` is zero, or `cell` is too
/// small to hold a shape and its clearance.
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
            let jitter_x = if slack > 0 { rng.range(0, slack + 1) } else { 0 };
            let jitter_y = if slack > 0 { rng.range(0, slack + 1) } else { 0 };
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
    /// Cells along each axis. The region is `cells * cell` square.
    pub cells: u32,
    /// Side of one cell, in database units.
    pub cell: i64,
    /// Fraction of the region to cover, in `0.0..=1.0`.
    pub density: f64,
}

/// What [`random_rectilinear_layer`] produced, with the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomLayer {
    /// Shapes emitted. Each is one polygon and stays one polygon: none of them
    /// touch.
    pub shapes: u32,
    /// Side of every shape.
    pub side: i64,
    /// Total covered area, exact — the shapes are disjoint, so it is a sum.
    pub covered: i128,
    /// Side of the square region the shapes lie in.
    pub extent: i64,
}

#[cfg(test)]
mod tests {
    use super::{l_shape, l_shape_area, plus_shape, plus_shape_area, u_shape, u_shape_area};

    /// Oracle: closed form. Shoelace over the emitted run must agree with the
    /// formula in the doc comment. This tests the *generator*, which is the
    /// only thing in this workspace that has to be right before the
    /// Implementation-Phase — an L whose area formula is wrong would make a
    /// correct `min_area` implementation look broken.
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

    /// Oracle: law. A bounding box overstates every non-convex shape here, and
    /// that gap is the reason these shapes exist. A generator whose L happened
    /// to be a rectangle would silently weaken every rule that uses it.
    #[test]
    fn non_convex_shapes_are_smaller_than_their_bounding_box() {
        assert!(l_shape_area(100, 30) < 100 * 100);
        assert!(plus_shape_area(100, 30) < 200 * 200);
        assert!(u_shape_area(100, 20, 40) < (2 * 20 + 40) * 100);
    }
}
