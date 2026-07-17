//! Validated simple ring: the atom every polygon is built from.

use super::error::ExactGeometryError;
use super::point::{cross, on_segment, Point};
use super::predicates::{
    classify_point_in_ring, classify_point_scaled2, classify_segment_intersection,
    PointClassification, SegmentIntersection,
};

/// Winding required by the canonical polygon-set representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Winding {
    Clockwise,
    CounterClockwise,
}

/// Exact signed twice-area. Positive is counter-clockwise.
pub fn ring_signed_area2(points: &[Point]) -> Result<i128, ExactGeometryError> {
    if points.len() < 3 {
        return Err(ExactGeometryError::TooFewVertices {
            count: points.len(),
        });
    }
    let mut area = 0_i128;
    for i in 0..points.len() {
        let a = points[i];
        let b = points[(i + 1) % points.len()];
        let term = (a.x as i128)
            .checked_mul(b.y as i128)
            .and_then(|v| v.checked_sub((b.x as i128) * (a.y as i128)))
            .ok_or(ExactGeometryError::ArithmeticOverflow)?;
        area = area
            .checked_add(term)
            .ok_or(ExactGeometryError::ArithmeticOverflow)?;
    }
    Ok(area)
}

/// A validated simple ring, canonicalized to start at its lexicographically
/// smallest vertex. Its winding is retained until it is placed in a `Polygon`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ring {
    pub(super) vertices: Vec<Point>,
    pub(super) area2: i128,
}

impl Ring {
    pub fn new(mut vertices: Vec<Point>) -> Result<Self, ExactGeometryError> {
        while vertices.len() > 1 && vertices.first() == vertices.last() {
            vertices.pop();
        }
        if vertices.len() < 3 {
            return Err(ExactGeometryError::TooFewVertices {
                count: vertices.len(),
            });
        }
        for i in 0..vertices.len() {
            if vertices[i] == vertices[(i + 1) % vertices.len()] {
                return Err(ExactGeometryError::DuplicateConsecutiveVertex { index: i });
            }
        }

        remove_redundant_collinear_vertices(&mut vertices);
        if vertices.len() < 3 {
            return Err(ExactGeometryError::TooFewVertices {
                count: vertices.len(),
            });
        }
        validate_simple(&vertices)?;
        let area2 = ring_signed_area2(&vertices)?;
        if area2 == 0 {
            return Err(ExactGeometryError::DegenerateRing);
        }
        rotate_to_minimum(&mut vertices);
        Ok(Self { vertices, area2 })
    }

    pub fn vertices(&self) -> &[Point] {
        &self.vertices
    }

    pub fn signed_area2(&self) -> i128 {
        self.area2
    }

    pub fn winding(&self) -> Winding {
        if self.area2 > 0 {
            Winding::CounterClockwise
        } else {
            Winding::Clockwise
        }
    }

    pub fn is_rectilinear(&self) -> bool {
        self.vertices.iter().enumerate().all(|(i, &a)| {
            let b = self.vertices[(i + 1) % self.vertices.len()];
            a.x == b.x || a.y == b.y
        })
    }

    pub fn classify_point(&self, p: Point) -> PointClassification {
        classify_point_in_ring(&self.vertices, p)
    }

    pub(super) fn classify_scaled2(&self, px2: i128, py2: i128) -> PointClassification {
        classify_point_scaled2(&self.vertices, px2, py2)
    }

    pub(super) fn orient_as(mut self, winding: Winding) -> Self {
        if self.winding() != winding {
            self.vertices.reverse();
            self.area2 = -self.area2;
            rotate_to_minimum(&mut self.vertices);
        }
        self
    }
}

fn validate_simple(vertices: &[Point]) -> Result<(), ExactGeometryError> {
    let n = vertices.len();
    for i in 0..n {
        let a0 = vertices[i];
        let a1 = vertices[(i + 1) % n];
        for j in i + 1..n {
            let adjacent = j == i + 1 || (i == 0 && j == n - 1);
            let b0 = vertices[j];
            let b1 = vertices[(j + 1) % n];
            let kind = classify_segment_intersection(a0, a1, b0, b1);
            if adjacent {
                if kind != SegmentIntersection::Touch {
                    return Err(ExactGeometryError::SelfIntersection {
                        edge_a: i,
                        edge_b: j,
                        kind,
                    });
                }
            } else if kind != SegmentIntersection::None {
                return Err(ExactGeometryError::SelfIntersection {
                    edge_a: i,
                    edge_b: j,
                    kind,
                });
            }
        }
    }
    Ok(())
}

fn remove_redundant_collinear_vertices(vertices: &mut Vec<Point>) {
    loop {
        if vertices.len() <= 3 {
            return;
        }
        let n = vertices.len();
        let remove = (0..n).find(|&i| {
            let a = vertices[(i + n - 1) % n];
            let b = vertices[i];
            let c = vertices[(i + 1) % n];
            cross(a, b, c) == 0 && on_segment(a, c, b)
        });
        if let Some(i) = remove {
            vertices.remove(i);
        } else {
            return;
        }
    }
}

pub(super) fn rotate_to_minimum(vertices: &mut Vec<Point>) {
    if let Some((index, _)) = vertices.iter().enumerate().min_by_key(|(_, p)| **p) {
        vertices.rotate_left(index);
    }
}

/// Classification of a polygon edge by its slope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    Horizontal,
    Vertical,
    Diagonal45,
    Arbitrary,
}

/// Classify the edge from `a` to `b`.
pub fn classify_edge(a: Point, b: Point) -> EdgeKind {
    let dx = (b.x as i64 - a.x as i64).abs();
    let dy = (b.y as i64 - a.y as i64).abs();
    if dy == 0 {
        EdgeKind::Horizontal
    } else if dx == 0 {
        EdgeKind::Vertical
    } else if dx == dy {
        EdgeKind::Diagonal45
    } else {
        EdgeKind::Arbitrary
    }
}

/// O(n log n) sweep-line simplicity check. For rings with many edges this is
/// faster than the O(n²) `validate_simple`.
///
/// ponytail: uses a Vec sorted on each insertion instead of a real balanced tree;
/// still O(n log n) on average for non-pathological input, upgrade to BTreeSet
/// with custom Ord wrapper if the linear scan in the sorted vec becomes a bottleneck.
pub fn validate_simple_sweep(vertices: &[Point]) -> Result<(), ExactGeometryError> {
    let n = vertices.len();
    if n < 3 {
        return Err(ExactGeometryError::TooFewVertices { count: n });
    }

    // Build edges and events.
    #[derive(Clone, Copy)]
    struct Edge {
        left: Point,
        right: Point,
        index: usize,
    }

    let mut edges = Vec::with_capacity(n);
    for i in 0..n {
        let a = vertices[i];
        let b = vertices[(i + 1) % n];
        let (left, right) = if (a.x, a.y) <= (b.x, b.y) {
            (a, b)
        } else {
            (b, a)
        };
        edges.push(Edge {
            left,
            right,
            index: i,
        });
    }

    // Events: (x, y, is_right_endpoint, edge_index)
    // Left endpoints first (is_right=false < is_right=true).
    let mut events: Vec<(i32, i32, bool, usize)> = Vec::with_capacity(2 * n);
    for (ei, e) in edges.iter().enumerate() {
        events.push((e.left.x, e.left.y, false, ei));
        events.push((e.right.x, e.right.y, true, ei));
    }
    events.sort_unstable();

    // Active edge set, keyed by a proxy y-value for ordering.
    // ponytail: simple vec-based active set; O(n) insert/remove but constant
    // factors beat BTree for typical layout rings (< 10k edges). Upgrade if profiled.
    let mut active: Vec<usize> = Vec::new();

    // Helper: evaluate y at a given x for an edge (rational, but we only need ordering).
    // Returns (numerator, denominator) with denominator > 0.
    let y_at_x = |ei: usize, x: i32| -> (i128, i128) {
        let e = &edges[ei];
        if e.left.x == e.right.x {
            // Vertical edge: use midpoint y as proxy.
            ((e.left.y as i128 + e.right.y as i128), 2)
        } else {
            let dx = e.right.x as i128 - e.left.x as i128;
            let dy = e.right.y as i128 - e.left.y as i128;
            let t_x = x as i128 - e.left.x as i128;
            // y = e.left.y + dy * t_x / dx => num = e.left.y * dx + dy * t_x, den = dx
            let num = (e.left.y as i128) * dx + dy * t_x;
            if dx > 0 {
                (num, dx)
            } else {
                (-num, -dx)
            }
        }
    };

    // Check new edge against its neighbors in the active set.
    let check_pair = |ei_a: usize, ei_b: usize| -> Result<(), ExactGeometryError> {
        let a_idx = edges[ei_a].index;
        let b_idx = edges[ei_b].index;
        let adjacent = {
            let diff = if a_idx > b_idx {
                a_idx - b_idx
            } else {
                b_idx - a_idx
            };
            diff == 1 || diff == n - 1
        };
        let kind = classify_segment_intersection(
            edges[ei_a].left,
            edges[ei_a].right,
            edges[ei_b].left,
            edges[ei_b].right,
        );
        if adjacent {
            if kind != SegmentIntersection::Touch {
                return Err(ExactGeometryError::SelfIntersection {
                    edge_a: a_idx.min(b_idx),
                    edge_b: a_idx.max(b_idx),
                    kind,
                });
            }
        } else if kind != SegmentIntersection::None {
            return Err(ExactGeometryError::SelfIntersection {
                edge_a: a_idx.min(b_idx),
                edge_b: a_idx.max(b_idx),
                kind,
            });
        }
        Ok(())
    };

    for &(x, _y, is_right, ei) in &events {
        if is_right {
            // Remove from active set.
            if let Some(pos) = active.iter().position(|&a| a == ei) {
                active.remove(pos);
                // Check new neighbors.
                if pos > 0 && pos < active.len() {
                    check_pair(active[pos - 1], active[pos])?;
                }
            }
        } else {
            // Insert into active set, sorted by y_at_x.
            let key = y_at_x(ei, x);
            let pos = active
                .iter()
                .position(|&a| {
                    let ak = y_at_x(a, x);
                    // Compare ak > key as fractions: ak.0/ak.1 > key.0/key.1
                    ak.0 * key.1 > key.0 * ak.1
                })
                .unwrap_or(active.len());
            active.insert(pos, ei);
            // Check against neighbors.
            if pos > 0 {
                check_pair(active[pos - 1], ei)?;
            }
            if pos + 1 < active.len() {
                check_pair(ei, active[pos + 1])?;
            }
        }
    }

    Ok(())
}
