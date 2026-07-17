//! Typed derived-layer expressions evaluated by the shared exact geometry kernel.
//!
//! Area expressions always return canonical [`PolygonSet`] values. Edge expressions
//! are deliberately a different value type so a deck cannot accidentally feed an edge
//! selection into an area rule. Rectilinear booleans and square-kernel offsets are exact;
//! arbitrary-angle inputs fail with [`DerivedError::Geometry`] rather than falling back
//! to bounding boxes.

use crate::geometry::exact::{
    rectilinear_intersection, rectilinear_subtraction, rectilinear_union, ExactGeometryError,
    Point, Polygon, PolygonSet,
};
use crate::geometry::{GeometryStore, LayerId, PolyId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A base or named-derived layer reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum LayerExprRef {
    Base { layer: LayerId },
    Derived { name: String },
}

/// Edge orientation selector. `Any` accepts horizontal and vertical edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeOrientation {
    Any,
    Horizontal,
    Vertical,
}

/// Strict derived-layer AST. `NotWithin` requires an explicit finite universe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum DerivedExpr {
    Layer {
        layer: LayerExprRef,
    },
    Union {
        operands: Vec<DerivedExpr>,
    },
    Intersection {
        lhs: Box<DerivedExpr>,
        rhs: Box<DerivedExpr>,
    },
    Subtraction {
        lhs: Box<DerivedExpr>,
        rhs: Box<DerivedExpr>,
    },
    Xor {
        lhs: Box<DerivedExpr>,
        rhs: Box<DerivedExpr>,
    },
    NotWithin {
        region: Box<DerivedExpr>,
        operand: Box<DerivedExpr>,
    },
    Grow {
        operand: Box<DerivedExpr>,
        distance: i32,
    },
    Shrink {
        operand: Box<DerivedExpr>,
        distance: i32,
    },
    Inside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
    },
    Outside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
    },
    /// Keep complete source components with a positive-area interaction.
    Interacting {
        operand: Box<DerivedExpr>,
        other: Box<DerivedExpr>,
    },
    Edges {
        operand: Box<DerivedExpr>,
        orientation: EdgeOrientation,
        min_length: Option<i32>,
        max_length: Option<i32>,
    },
    /// Sizing with expression-based distance (from deck variable/table).
    SizeByExpr {
        operand: Box<DerivedExpr>,
        distance_expr: Box<super::production::ScalarExpr>,
    },
}

/// Exact edge selected from a canonical area boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivedEdge {
    pub start: Point,
    pub end: Point,
    pub is_hole: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedValue {
    Area(PolygonSet),
    Edges(Vec<DerivedEdge>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedError {
    UnknownLayer(LayerId),
    UnknownDerivedLayer(String),
    Cycle(Vec<String>),
    EmptyOperands(&'static str),
    InvalidDistance(i32),
    InvalidEdgeRange,
    TypeMismatch {
        operation: &'static str,
        expected: &'static str,
    },
    CapacityExceeded {
        cells: usize,
        limit: usize,
    },
    Geometry(ExactGeometryError),
}

impl fmt::Display for DerivedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLayer(layer) => write!(f, "unknown base layer {layer}"),
            Self::UnknownDerivedLayer(name) => write!(f, "unknown derived layer `{name}`"),
            Self::Cycle(path) => write!(f, "derived-layer cycle: {}", path.join(" -> ")),
            Self::EmptyOperands(op) => write!(f, "{op} requires at least one operand"),
            Self::InvalidDistance(distance) => {
                write!(f, "offset distance must be non-negative, got {distance}")
            }
            Self::InvalidEdgeRange => write!(f, "edge length limits are invalid"),
            Self::TypeMismatch {
                operation,
                expected,
            } => {
                write!(f, "{operation} requires a {expected} operand")
            }
            Self::CapacityExceeded { cells, limit } => {
                write!(
                    f,
                    "offset decomposition requires {cells} cells (limit {limit})"
                )
            }
            Self::Geometry(error) => write!(f, "exact geometry error: {error}"),
        }
    }
}

impl std::error::Error for DerivedError {}

impl From<ExactGeometryError> for DerivedError {
    fn from(value: ExactGeometryError) -> Self {
        Self::Geometry(value)
    }
}

/// Maximum occupied decomposition cells materialized by an offset.
pub const MAX_OFFSET_CELLS: usize = 2_000_000;

/// Evaluates named expressions once and detects recursive definitions.
pub struct DerivedEvaluator<'a> {
    store: &'a GeometryStore,
    definitions: &'a BTreeMap<String, DerivedExpr>,
    known_layer_count: Option<usize>,
    cache: BTreeMap<String, DerivedValue>,
    stack: Vec<String>,
}

impl<'a> DerivedEvaluator<'a> {
    pub fn new(store: &'a GeometryStore, definitions: &'a BTreeMap<String, DerivedExpr>) -> Self {
        Self {
            store,
            definitions,
            known_layer_count: None,
            cache: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    /// Construct an evaluator that can distinguish a valid empty layer from an
    /// out-of-schema numeric layer ID.
    pub fn new_checked(
        store: &'a GeometryStore,
        definitions: &'a BTreeMap<String, DerivedExpr>,
        known_layer_count: usize,
    ) -> Self {
        Self {
            store,
            definitions,
            known_layer_count: Some(known_layer_count),
            cache: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    pub fn evaluate_named(&mut self, name: &str) -> Result<DerivedValue, DerivedError> {
        if let Some(value) = self.cache.get(name) {
            return Ok(value.clone());
        }
        if let Some(index) = self.stack.iter().position(|entry| entry == name) {
            let mut path = self.stack[index..].to_vec();
            path.push(name.to_owned());
            return Err(DerivedError::Cycle(path));
        }
        let expression = self
            .definitions
            .get(name)
            .ok_or_else(|| DerivedError::UnknownDerivedLayer(name.to_owned()))?
            .clone();
        self.stack.push(name.to_owned());
        let value = self.evaluate(&expression);
        self.stack.pop();
        let value = value?;
        self.cache.insert(name.to_owned(), value.clone());
        Ok(value)
    }

    pub fn evaluate(&mut self, expression: &DerivedExpr) -> Result<DerivedValue, DerivedError> {
        use DerivedExpr::*;
        match expression {
            Layer {
                layer: LayerExprRef::Base { layer },
            } => Ok(DerivedValue::Area(layer_polygon_set(
                self.store,
                *layer,
                self.known_layer_count,
            )?)),
            Layer {
                layer: LayerExprRef::Derived { name },
            } => self.evaluate_named(name),
            Union { operands } => {
                if operands.is_empty() {
                    return Err(DerivedError::EmptyOperands("union"));
                }
                let mut result = PolygonSet::empty();
                for operand in operands {
                    result = rectilinear_union(&result, &self.area(operand, "union")?)?;
                }
                Ok(DerivedValue::Area(result))
            }
            Intersection { lhs, rhs }
            | Inside {
                operand: lhs,
                region: rhs,
            } => Ok(DerivedValue::Area(rectilinear_intersection(
                &self.area(lhs, "intersection")?,
                &self.area(rhs, "intersection")?,
            )?)),
            Subtraction { lhs, rhs }
            | Outside {
                operand: lhs,
                region: rhs,
            } => Ok(DerivedValue::Area(rectilinear_subtraction(
                &self.area(lhs, "subtraction")?,
                &self.area(rhs, "subtraction")?,
            )?)),
            Xor { lhs, rhs } => {
                let lhs = self.area(lhs, "xor")?;
                let rhs = self.area(rhs, "xor")?;
                let only_lhs = rectilinear_subtraction(&lhs, &rhs)?;
                let only_rhs = rectilinear_subtraction(&rhs, &lhs)?;
                Ok(DerivedValue::Area(rectilinear_union(&only_lhs, &only_rhs)?))
            }
            NotWithin { region, operand } => Ok(DerivedValue::Area(rectilinear_subtraction(
                &self.area(region, "not_within")?,
                &self.area(operand, "not_within")?,
            )?)),
            Grow { operand, distance } => {
                let source = self.area(operand, "grow")?;
                Ok(DerivedValue::Area(offset_square(&source, *distance, true)?))
            }
            Shrink { operand, distance } => {
                let source = self.area(operand, "shrink")?;
                Ok(DerivedValue::Area(offset_square(
                    &source, *distance, false,
                )?))
            }
            Interacting { operand, other } => {
                let source = self.area(operand, "interacting")?;
                let other = self.area(other, "interacting")?;
                let mut selected = PolygonSet::empty();
                for polygon in source.polygons() {
                    let component = PolygonSet::from_polygon(polygon.clone());
                    if !rectilinear_intersection(&component, &other)?
                        .polygons()
                        .is_empty()
                    {
                        selected = rectilinear_union(&selected, &component)?;
                    }
                }
                Ok(DerivedValue::Area(selected))
            }
            // ponytail: SizeByExpr needs the production deck to resolve the expression;
            // the evaluator doesn't carry one. Callers pre-resolve to Grow/Shrink.
            SizeByExpr { .. } => {
                return Err(DerivedError::TypeMismatch {
                    operation: "size_by_expr",
                    expected:
                        "pre-resolved Grow/Shrink (expression requires production deck context)",
                });
            }
            Edges {
                operand,
                orientation,
                min_length,
                max_length,
            } => {
                if min_length.is_some_and(|v| v < 0)
                    || max_length.is_some_and(|v| v < 0)
                    || min_length.zip(*max_length).is_some_and(|(a, b)| a > b)
                {
                    return Err(DerivedError::InvalidEdgeRange);
                }
                let area = self.area(operand, "edges")?;
                let mut edges = Vec::new();
                for polygon in area.polygons() {
                    collect_edges(
                        polygon.outer().vertices(),
                        false,
                        *orientation,
                        *min_length,
                        *max_length,
                        &mut edges,
                    )?;
                    for hole in polygon.holes() {
                        collect_edges(
                            hole.vertices(),
                            true,
                            *orientation,
                            *min_length,
                            *max_length,
                            &mut edges,
                        )?;
                    }
                }
                edges.sort();
                Ok(DerivedValue::Edges(edges))
            }
        }
    }

    fn area(
        &mut self,
        expression: &DerivedExpr,
        operation: &'static str,
    ) -> Result<PolygonSet, DerivedError> {
        match self.evaluate(expression)? {
            DerivedValue::Area(area) => Ok(area),
            DerivedValue::Edges(_) => Err(DerivedError::TypeMismatch {
                operation,
                expected: "polygon-area",
            }),
        }
    }
}

/// Convert all polygons on a base layer and exact-union overlapping fragments.
pub fn layer_polygon_set(
    store: &GeometryStore,
    layer: LayerId,
    known_layer_count: Option<usize>,
) -> Result<PolygonSet, DerivedError> {
    if known_layer_count.is_some_and(|count| usize::from(layer) >= count) {
        return Err(DerivedError::UnknownLayer(layer));
    }
    let mut result = PolygonSet::empty();
    for poly in store.polys_on_layer(layer) {
        let component = polygon_from_store(store, poly)?;
        result = rectilinear_union(&result, &PolygonSet::from_polygon(component))?;
    }
    Ok(result)
}

fn polygon_from_store(store: &GeometryStore, poly: PolyId) -> Result<Polygon, DerivedError> {
    Ok(store.poly_as_exact(poly)?)
}

fn collect_edges(
    vertices: &[Point],
    is_hole: bool,
    orientation: EdgeOrientation,
    min_length: Option<i32>,
    max_length: Option<i32>,
    out: &mut Vec<DerivedEdge>,
) -> Result<(), DerivedError> {
    for index in 0..vertices.len() {
        let start = vertices[index];
        let end = vertices[(index + 1) % vertices.len()];
        let horizontal = start.y == end.y;
        let vertical = start.x == end.x;
        let accepted = match orientation {
            EdgeOrientation::Any => horizontal || vertical,
            EdgeOrientation::Horizontal => horizontal,
            EdgeOrientation::Vertical => vertical,
        };
        let dx = i64::from(end.x) - i64::from(start.x);
        let dy = i64::from(end.y) - i64::from(start.y);
        let length = dx
            .checked_abs()
            .and_then(|dx| dy.checked_abs().and_then(|dy| dx.checked_add(dy)))
            .ok_or(DerivedError::Geometry(
                ExactGeometryError::ArithmeticOverflow,
            ))?;
        if accepted
            && min_length.is_none_or(|min| length >= i64::from(min))
            && max_length.is_none_or(|max| length <= i64::from(max))
        {
            out.push(DerivedEdge {
                start,
                end,
                is_hole,
            });
        }
    }
    Ok(())
}

/// Exact L-infinity (square-kernel) grow/shrink for canonical rectilinear sets.
fn offset_square(
    source: &PolygonSet,
    distance: i32,
    grow: bool,
) -> Result<PolygonSet, DerivedError> {
    if distance < 0 {
        return Err(DerivedError::InvalidDistance(distance));
    }
    if distance == 0 || source.polygons().is_empty() {
        return Ok(source.clone());
    }
    if !source.is_rectilinear() {
        return Err(DerivedError::Geometry(ExactGeometryError::Unsupported {
            operation: if grow {
                crate::geometry::exact::BooleanOp::Union
            } else {
                crate::geometry::exact::BooleanOp::Subtraction
            },
            reason: "arbitrary-angle offsets are not implemented",
        }));
    }

    let rectangles = occupied_rectangles(source)?;
    if grow {
        let mut result = PolygonSet::empty();
        for (x0, y0, x1, y1) in rectangles {
            let x0 = x0
                .checked_sub(distance)
                .ok_or(ExactGeometryError::ArithmeticOverflow)?;
            let y0 = y0
                .checked_sub(distance)
                .ok_or(ExactGeometryError::ArithmeticOverflow)?;
            let x1 = x1
                .checked_add(distance)
                .ok_or(ExactGeometryError::ArithmeticOverflow)?;
            let y1 = y1
                .checked_add(distance)
                .ok_or(ExactGeometryError::ArithmeticOverflow)?;
            result = rectilinear_union(&result, &rectangle_set(x0, y0, x1, y1)?)?;
        }
        return Ok(result);
    }

    // Erode A by d using A \ grow(complement(A), d) inside a padded finite universe.
    let (xmin, ymin, xmax, ymax) = set_bbox(source).ok_or(DerivedError::EmptyOperands("shrink"))?;
    let pad = distance
        .checked_add(1)
        .ok_or(ExactGeometryError::ArithmeticOverflow)?;
    let universe = rectangle_set(
        xmin.checked_sub(pad)
            .ok_or(ExactGeometryError::ArithmeticOverflow)?,
        ymin.checked_sub(pad)
            .ok_or(ExactGeometryError::ArithmeticOverflow)?,
        xmax.checked_add(pad)
            .ok_or(ExactGeometryError::ArithmeticOverflow)?,
        ymax.checked_add(pad)
            .ok_or(ExactGeometryError::ArithmeticOverflow)?,
    )?;
    let complement = rectilinear_subtraction(&universe, source)?;
    let grown_complement = offset_square(&complement, distance, true)?;
    Ok(rectilinear_subtraction(source, &grown_complement)?)
}

fn occupied_rectangles(source: &PolygonSet) -> Result<Vec<(i32, i32, i32, i32)>, DerivedError> {
    let mut xs = BTreeSet::new();
    let mut ys = BTreeSet::new();
    for polygon in source.polygons() {
        for ring in std::iter::once(polygon.outer()).chain(polygon.holes().iter()) {
            for point in ring.vertices() {
                xs.insert(point.x);
                ys.insert(point.y);
            }
        }
    }
    let xs: Vec<_> = xs.into_iter().collect();
    let ys: Vec<_> = ys.into_iter().collect();
    let cells = xs
        .len()
        .saturating_sub(1)
        .saturating_mul(ys.len().saturating_sub(1));
    if cells > MAX_OFFSET_CELLS {
        return Err(DerivedError::CapacityExceeded {
            cells,
            limit: MAX_OFFSET_CELLS,
        });
    }
    let mut rectangles = Vec::new();
    for y in ys.windows(2) {
        for x in xs.windows(2) {
            // Integer midpoint truncation drops 1-DBU cells by sampling their
            // boundary. Exact cell intersection is equivalent to a rational
            // doubled-coordinate midpoint classification without a private kernel.
            let cell = rectangle_set(x[0], y[0], x[1], y[1])?;
            if rectilinear_intersection(source, &cell)?.area2() > 0 {
                rectangles.push((x[0], y[0], x[1], y[1]));
            }
        }
    }
    Ok(rectangles)
}

fn rectangle_set(x0: i32, y0: i32, x1: i32, y1: i32) -> Result<PolygonSet, DerivedError> {
    Ok(PolygonSet::from_polygon(Polygon::from_outer(vec![
        Point::new(x0, y0),
        Point::new(x1, y0),
        Point::new(x1, y1),
        Point::new(x0, y1),
    ])?))
}

fn set_bbox(set: &PolygonSet) -> Option<(i32, i32, i32, i32)> {
    let mut bbox = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
    let mut any = false;
    for polygon in set.polygons() {
        for point in polygon.outer().vertices() {
            any = true;
            bbox.0 = bbox.0.min(point.x);
            bbox.1 = bbox.1.min(point.y);
            bbox.2 = bbox.2.max(point.x);
            bbox.3 = bbox.3.max(point.y);
        }
    }
    any.then_some(bbox)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(layer: LayerId) -> DerivedExpr {
        DerivedExpr::Layer {
            layer: LayerExprRef::Base { layer },
        }
    }

    #[test]
    fn named_boolean_is_consumable_and_detects_cycles() {
        let mut store = GeometryStore::new();
        store.add_rect(0, 0, 0, 10, 10);
        store.add_rect(1, 5, 0, 10, 10);
        let mut definitions = BTreeMap::new();
        definitions.insert(
            "cut".into(),
            DerivedExpr::Intersection {
                lhs: Box::new(base(0)),
                rhs: Box::new(base(1)),
            },
        );
        let mut evaluator = DerivedEvaluator::new(&store, &definitions);
        let DerivedValue::Area(cut) = evaluator.evaluate_named("cut").unwrap() else {
            panic!("area expected")
        };
        assert_eq!(cut.area2(), 100);

        definitions.insert(
            "a".into(),
            DerivedExpr::Layer {
                layer: LayerExprRef::Derived { name: "b".into() },
            },
        );
        definitions.insert(
            "b".into(),
            DerivedExpr::Layer {
                layer: LayerExprRef::Derived { name: "a".into() },
            },
        );
        let mut evaluator = DerivedEvaluator::new(&store, &definitions);
        assert!(matches!(
            evaluator.evaluate_named("a"),
            Err(DerivedError::Cycle(_))
        ));
    }

    #[test]
    fn rectilinear_offsets_and_edge_filter_are_exact() {
        let mut store = GeometryStore::new();
        store.add_rect(0, 0, 0, 10, 10);
        let definitions = BTreeMap::new();
        let mut evaluator = DerivedEvaluator::new(&store, &definitions);
        let DerivedValue::Area(grown) = evaluator
            .evaluate(&DerivedExpr::Grow {
                operand: Box::new(base(0)),
                distance: 2,
            })
            .unwrap()
        else {
            panic!("area expected")
        };
        assert_eq!(grown.area2(), 392); // 14 * 14 * 2
        let DerivedValue::Area(shrunk) = evaluator
            .evaluate(&DerivedExpr::Shrink {
                operand: Box::new(base(0)),
                distance: 2,
            })
            .unwrap()
        else {
            panic!("area expected")
        };
        assert_eq!(shrunk.area2(), 72); // 6 * 6 * 2

        let DerivedValue::Edges(edges) = evaluator
            .evaluate(&DerivedExpr::Edges {
                operand: Box::new(base(0)),
                orientation: EdgeOrientation::Horizontal,
                min_length: Some(10),
                max_length: Some(10),
            })
            .unwrap()
        else {
            panic!("edges expected")
        };
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn arbitrary_angle_boolean_fails_closed() {
        let mut store = GeometryStore::new();
        store.add_polygon(0, &[(0, 0), (10, 0), (5, 10)]);
        let definitions = BTreeMap::new();
        let mut evaluator = DerivedEvaluator::new(&store, &definitions);
        assert!(matches!(
            evaluator.evaluate(&DerivedExpr::Grow {
                operand: Box::new(base(0)),
                distance: 1
            }),
            Err(DerivedError::Geometry(
                ExactGeometryError::Unsupported { .. }
            ))
        ));
    }

    #[test]
    fn base_layer_preserves_multiple_keyhole_holes() {
        let mut store = GeometryStore::new();
        store.add_polygon(
            0,
            &[
                (0, 0),
                (100, 0),
                (100, 100),
                (70, 100),
                (70, 80),
                (90, 80),
                (90, 60),
                (60, 60),
                (60, 80),
                (70, 80),
                (70, 100),
                (40, 100),
                (40, 80),
                (50, 80),
                (50, 60),
                (20, 60),
                (20, 80),
                (40, 80),
                (40, 100),
                (0, 100),
            ],
        );
        let set = layer_polygon_set(&store, 0, Some(1)).unwrap();
        assert_eq!(set.component_count(), 1);
        assert_eq!(set.polygons()[0].holes().len(), 2);
        assert_eq!(set.area2(), 17_600);
    }

    #[test]
    fn edge_selection_handles_full_i32_deltas_without_wrapping() {
        let mut store = GeometryStore::new();
        store.add_polygon(
            0,
            &[(i32::MIN, 0), (i32::MAX, 0), (i32::MAX, 1), (i32::MIN, 1)],
        );
        let definitions = BTreeMap::new();
        let mut evaluator = DerivedEvaluator::new(&store, &definitions);
        let DerivedValue::Edges(edges) = evaluator
            .evaluate(&DerivedExpr::Edges {
                operand: Box::new(base(0)),
                orientation: EdgeOrientation::Horizontal,
                min_length: None,
                max_length: None,
            })
            .unwrap()
        else {
            panic!("edges expected")
        };
        assert_eq!(edges.len(), 2);

        let DerivedValue::Edges(filtered) = evaluator
            .evaluate(&DerivedExpr::Edges {
                operand: Box::new(base(0)),
                orientation: EdgeOrientation::Horizontal,
                min_length: None,
                max_length: Some(i32::MAX),
            })
            .unwrap()
        else {
            panic!("edges expected")
        };
        assert!(filtered.is_empty());
    }

    #[test]
    fn unit_width_cells_survive_offsets_on_both_sides_of_zero() {
        for x in [3, -4] {
            let mut store = GeometryStore::new();
            store.add_rect(0, x, -2, 1, 5);
            let definitions = BTreeMap::new();
            let mut evaluator = DerivedEvaluator::new(&store, &definitions);
            let DerivedValue::Area(grown) = evaluator
                .evaluate(&DerivedExpr::Grow {
                    operand: Box::new(base(0)),
                    distance: 1,
                })
                .unwrap()
            else {
                panic!("area expected")
            };
            assert_eq!(grown.area2(), 42, "unit-width cell at x={x} was dropped");
            let DerivedValue::Area(shrunk) = evaluator
                .evaluate(&DerivedExpr::Shrink {
                    operand: Box::new(base(0)),
                    distance: 1,
                })
                .unwrap()
            else {
                panic!("area expected")
            };
            assert!(shrunk.polygons().is_empty());
        }
    }
}
