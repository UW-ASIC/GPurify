//! Deterministic collection of polygon components.

use super::error::ExactGeometryError;
use super::point::Point;
use super::polygon::Polygon;
use super::predicates::PointClassification;
use super::ring::Ring;

/// A deterministic collection of polygon components. Components are sorted by
/// canonical outer/hole vertex order. Set membership is their union.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolygonSet {
    pub(super) polygons: Vec<Polygon>,
}

impl PolygonSet {
    pub fn new(mut polygons: Vec<Polygon>) -> Result<Self, ExactGeometryError> {
        polygons.sort_by(|a, b| {
            a.outer
                .vertices()
                .cmp(b.outer.vertices())
                .then_with(|| compare_holes(&a.holes, &b.holes))
        });
        Ok(Self { polygons })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_polygon(polygon: Polygon) -> Self {
        Self {
            polygons: vec![polygon],
        }
    }

    #[must_use]
    pub fn polygons(&self) -> &[Polygon] {
        &self.polygons
    }

    #[must_use]
    pub fn into_polygons(self) -> Vec<Polygon> {
        self.polygons
    }

    #[must_use]
    pub fn component_count(&self) -> usize {
        self.polygons.len()
    }

    /// Sum of component signed twice-areas. Components supplied to [`Self::new`]
    /// may overlap; use a union boolean first when a union-area measurement is
    /// required. Boolean results are non-overlapping, so this is their set area.
    #[must_use]
    pub fn area2(&self) -> i128 {
        self.polygons.iter().map(Polygon::area2).sum()
    }

    #[must_use]
    pub fn is_rectilinear(&self) -> bool {
        self.polygons.iter().all(Polygon::is_rectilinear)
    }

    #[must_use]
    pub fn classify_point(&self, p: Point) -> PointClassification {
        self.classify_scaled2(p.x as i128 * 2, p.y as i128 * 2)
    }

    pub(super) fn classify_scaled2(&self, px2: i128, py2: i128) -> PointClassification {
        let mut boundary = false;
        for polygon in &self.polygons {
            match polygon.classify_scaled2(px2, py2) {
                PointClassification::Inside => return PointClassification::Inside,
                PointClassification::Boundary => boundary = true,
                PointClassification::Outside => {}
            }
        }
        if boundary {
            PointClassification::Boundary
        } else {
            PointClassification::Outside
        }
    }
}

impl PolygonSet {
    pub fn union(&self, other: &Self) -> Result<Self, ExactGeometryError> {
        use super::boolean::{general_boolean, rectilinear_boolean, BooleanOp};
        if self.is_rectilinear() && other.is_rectilinear() {
            rectilinear_boolean(self, other, BooleanOp::Union)
        } else {
            general_boolean(self, other, BooleanOp::Union)
        }
    }

    pub fn intersection(&self, other: &Self) -> Result<Self, ExactGeometryError> {
        use super::boolean::{general_boolean, rectilinear_boolean, BooleanOp};
        if self.is_rectilinear() && other.is_rectilinear() {
            rectilinear_boolean(self, other, BooleanOp::Intersection)
        } else {
            general_boolean(self, other, BooleanOp::Intersection)
        }
    }

    pub fn subtraction(&self, other: &Self) -> Result<Self, ExactGeometryError> {
        use super::boolean::{general_boolean, rectilinear_boolean, BooleanOp};
        if self.is_rectilinear() && other.is_rectilinear() {
            rectilinear_boolean(self, other, BooleanOp::Subtraction)
        } else {
            general_boolean(self, other, BooleanOp::Subtraction)
        }
    }
}

fn compare_holes(a: &[Ring], b: &[Ring]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| {
        a.iter()
            .map(|r| r.vertices())
            .cmp(b.iter().map(|r| r.vertices()))
    })
}
