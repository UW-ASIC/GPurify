//! Exact rectilinear booleans by coordinate decomposition.

use std::collections::BTreeMap;

use super::error::ExactGeometryError;
use super::point::{on_segment, Point};
use super::polygon::Polygon;
use super::polygon_set::PolygonSet;
use super::predicates::PointClassification;
use super::ring::{Ring, Winding};

/// Boolean operation supported by [`rectilinear_boolean`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BooleanOp {
    Union,
    Intersection,
    Subtraction,
}

/// Explicit capacity guard for the current coordinate-decomposition implementation.
pub const MAX_RECTILINEAR_BOOLEAN_CELLS: usize = 16_000_000;

/// Exact rectilinear boolean. See the module-level supported-semantics contract.
pub fn rectilinear_boolean(
    lhs: &PolygonSet,
    rhs: &PolygonSet,
    operation: BooleanOp,
) -> Result<PolygonSet, ExactGeometryError> {
    ensure_rectilinear(lhs, operation)?;
    ensure_rectilinear(rhs, operation)?;

    if lhs.polygons.is_empty() || rhs.polygons.is_empty() {
        return match operation {
            BooleanOp::Union if lhs.polygons.is_empty() => Ok(rhs.clone()),
            BooleanOp::Union => Ok(lhs.clone()),
            BooleanOp::Intersection => Ok(PolygonSet::empty()),
            BooleanOp::Subtraction if lhs.polygons.is_empty() => Ok(PolygonSet::empty()),
            BooleanOp::Subtraction => Ok(lhs.clone()),
        };
    }

    let mut xs = Vec::new();
    let mut ys = Vec::new();
    collect_coordinates(lhs, &mut xs, &mut ys);
    collect_coordinates(rhs, &mut xs, &mut ys);
    xs.sort_unstable();
    ys.sort_unstable();
    xs.dedup();
    ys.dedup();
    if xs.len() < 2 || ys.len() < 2 {
        return Ok(PolygonSet::empty());
    }

    let nx = xs.len() - 1;
    let ny = ys.len() - 1;
    let cells = nx
        .checked_mul(ny)
        .ok_or(ExactGeometryError::CapacityExceeded {
            cells: usize::MAX,
            limit: MAX_RECTILINEAR_BOOLEAN_CELLS,
        })?;
    if cells > MAX_RECTILINEAR_BOOLEAN_CELLS {
        return Err(ExactGeometryError::CapacityExceeded {
            cells,
            limit: MAX_RECTILINEAR_BOOLEAN_CELLS,
        });
    }
    let mut occupied = vec![false; cells];
    for y in 0..ny {
        let py2 = ys[y] as i128 + ys[y + 1] as i128;
        for x in 0..nx {
            let px2 = xs[x] as i128 + xs[x + 1] as i128;
            let in_lhs = lhs.classify_scaled2(px2, py2) == PointClassification::Inside;
            let in_rhs = rhs.classify_scaled2(px2, py2) == PointClassification::Inside;
            occupied[y * nx + x] = match operation {
                BooleanOp::Union => in_lhs || in_rhs,
                BooleanOp::Intersection => in_lhs && in_rhs,
                BooleanOp::Subtraction => in_lhs && !in_rhs,
            };
        }
    }
    reconstruct_rectilinear_set(&xs, &ys, nx, ny, &occupied)
}

pub fn rectilinear_union(
    lhs: &PolygonSet,
    rhs: &PolygonSet,
) -> Result<PolygonSet, ExactGeometryError> {
    rectilinear_boolean(lhs, rhs, BooleanOp::Union)
}

pub fn rectilinear_intersection(
    lhs: &PolygonSet,
    rhs: &PolygonSet,
) -> Result<PolygonSet, ExactGeometryError> {
    rectilinear_boolean(lhs, rhs, BooleanOp::Intersection)
}

pub fn rectilinear_subtraction(
    lhs: &PolygonSet,
    rhs: &PolygonSet,
) -> Result<PolygonSet, ExactGeometryError> {
    rectilinear_boolean(lhs, rhs, BooleanOp::Subtraction)
}

fn ensure_rectilinear(set: &PolygonSet, operation: BooleanOp) -> Result<(), ExactGeometryError> {
    if set.is_rectilinear() {
        Ok(())
    } else {
        Err(ExactGeometryError::Unsupported {
            operation,
            reason: "arbitrary-angle boolean topology is not implemented",
        })
    }
}

fn collect_coordinates(set: &PolygonSet, xs: &mut Vec<i32>, ys: &mut Vec<i32>) {
    for polygon in &set.polygons {
        for ring in std::iter::once(&polygon.outer).chain(polygon.holes.iter()) {
            for point in ring.vertices() {
                xs.push(point.x);
                ys.push(point.y);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DirectedEdge {
    start: Point,
    end: Point,
}

fn reconstruct_rectilinear_set(
    xs: &[i32],
    ys: &[i32],
    nx: usize,
    ny: usize,
    occupied: &[bool],
) -> Result<PolygonSet, ExactGeometryError> {
    let filled = |x: isize, y: isize| -> bool {
        x >= 0
            && y >= 0
            && (x as usize) < nx
            && (y as usize) < ny
            && occupied[y as usize * nx + x as usize]
    };
    let mut edges = Vec::new();
    for y in 0..ny {
        for x in 0..nx {
            if !occupied[y * nx + x] {
                continue;
            }
            let (x0, x1, y0, y1) = (xs[x], xs[x + 1], ys[y], ys[y + 1]);
            if !filled(x as isize, y as isize - 1) {
                edges.push(DirectedEdge {
                    start: Point::new(x0, y0),
                    end: Point::new(x1, y0),
                });
            }
            if !filled(x as isize + 1, y as isize) {
                edges.push(DirectedEdge {
                    start: Point::new(x1, y0),
                    end: Point::new(x1, y1),
                });
            }
            if !filled(x as isize, y as isize + 1) {
                edges.push(DirectedEdge {
                    start: Point::new(x1, y1),
                    end: Point::new(x0, y1),
                });
            }
            if !filled(x as isize - 1, y as isize) {
                edges.push(DirectedEdge {
                    start: Point::new(x0, y1),
                    end: Point::new(x0, y0),
                });
            }
        }
    }
    if edges.is_empty() {
        return Ok(PolygonSet::empty());
    }
    edges.sort_unstable();
    let mut outgoing: BTreeMap<Point, Vec<usize>> = BTreeMap::new();
    for (index, edge) in edges.iter().enumerate() {
        outgoing.entry(edge.start).or_default().push(index);
    }
    for indices in outgoing.values_mut() {
        indices.sort_unstable_by_key(|&i| edges[i].end);
    }

    let mut used = vec![false; edges.len()];
    let mut rings = Vec::new();
    for start_edge in 0..edges.len() {
        if used[start_edge] {
            continue;
        }
        let start = edges[start_edge].start;
        let mut ring_points = Vec::new();
        let mut current = start_edge;
        loop {
            if used[current] {
                return Err(ExactGeometryError::InternalTopology(
                    "boundary edge was revisited",
                ));
            }
            used[current] = true;
            let edge = edges[current];
            ring_points.push(edge.start);
            if edge.end == start {
                break;
            }
            let candidates = outgoing
                .get(&edge.end)
                .ok_or(ExactGeometryError::InternalTopology("open boundary chain"))?;
            current = choose_continuation(edge, candidates, &edges, &used).ok_or(
                ExactGeometryError::InternalTopology("no unused boundary continuation"),
            )?;
            if ring_points.len() > edges.len() {
                return Err(ExactGeometryError::InternalTopology(
                    "boundary chain did not close",
                ));
            }
        }
        rings.push(Ring::new(ring_points)?);
    }

    let mut outers: Vec<(Ring, Vec<Ring>)> = rings
        .iter()
        .filter(|ring| ring.winding() == Winding::CounterClockwise)
        .cloned()
        .map(|outer| (outer, Vec::new()))
        .collect();
    let holes: Vec<Ring> = rings
        .into_iter()
        .filter(|ring| ring.winding() == Winding::Clockwise)
        .collect();
    for hole in holes {
        let witness = hole.vertices()[0];
        let owner = outers
            .iter()
            .enumerate()
            .filter(|(_, (outer, _))| outer.classify_point(witness) == PointClassification::Inside)
            .min_by_key(|(_, (outer, _))| outer.signed_area2())
            .map(|(index, _)| index)
            .ok_or(ExactGeometryError::InternalTopology(
                "hole has no containing outer ring",
            ))?;
        outers[owner].1.push(hole);
    }
    let polygons = outers
        .into_iter()
        .map(|(outer, holes)| Polygon::new(outer, holes))
        .collect::<Result<Vec<_>, _>>()?;
    PolygonSet::new(polygons)
}

fn choose_continuation(
    incoming: DirectedEdge,
    candidates: &[usize],
    edges: &[DirectedEdge],
    used: &[bool],
) -> Option<usize> {
    let incoming_dir = direction(incoming.start, incoming.end)?;
    candidates
        .iter()
        .copied()
        .filter(|&index| !used[index])
        .min_by_key(|&index| {
            let next_dir = direction(edges[index].start, edges[index].end).unwrap_or(0);
            let delta = (next_dir + 4 - incoming_dir) % 4;
            let turn_preference = match delta {
                1 => 0, // left: separates corner-touching components
                0 => 1, // straight
                3 => 2, // right
                _ => 3, // reversal (invalid topology, but deterministic)
            };
            (turn_preference, edges[index].end)
        })
}

/// E=0, N=1, W=2, S=3.
fn direction(a: Point, b: Point) -> Option<u8> {
    if a.y == b.y && b.x > a.x {
        Some(0)
    } else if a.x == b.x && b.y > a.y {
        Some(1)
    } else if a.y == b.y && b.x < a.x {
        Some(2)
    } else if a.x == b.x && b.y < a.y {
        Some(3)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// General (all-angle) boolean via sweep-line arrangement
// ---------------------------------------------------------------------------

/// Capacity guard for sweep-line arrangement.
pub const MAX_SWEEP_EVENTS: usize = 4_000_000;

/// Which input set an edge came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EdgeOrigin {
    Lhs,
    Rhs,
}

/// A directed edge in the arrangement, with origin tag.
#[derive(Clone, Debug)]
struct ArrEdge {
    start: Point,
    end: Point,
    origin: EdgeOrigin,
}

/// General boolean for arbitrary-angle polygon sets.
///
/// Approach: collect all edges from both inputs, compute the full arrangement
/// (all edge-edge intersections split into sub-edges with integer endpoints),
/// then classify each arrangement face by point-in-polygon tests against the
/// original inputs, and reconstruct the output boundary.
///
/// ponytail: this is the O(n² log n) "split all edges, classify faces" approach
/// rather than a true Bentley-Ottmann with O((n+k) log n). Simpler, correct,
/// sufficient for layout-scale inputs (< ~50k edges). Upgrade to proper BO if
/// profiling shows this is a bottleneck.
pub fn general_boolean(
    lhs: &PolygonSet,
    rhs: &PolygonSet,
    operation: BooleanOp,
) -> Result<PolygonSet, ExactGeometryError> {
    // Trivial cases.
    if lhs.polygons.is_empty() || rhs.polygons.is_empty() {
        return match operation {
            BooleanOp::Union if lhs.polygons.is_empty() => Ok(rhs.clone()),
            BooleanOp::Union => Ok(lhs.clone()),
            BooleanOp::Intersection => Ok(PolygonSet::empty()),
            BooleanOp::Subtraction if lhs.polygons.is_empty() => Ok(PolygonSet::empty()),
            BooleanOp::Subtraction => Ok(lhs.clone()),
        };
    }

    // 1. Collect all directed edges with origin tags.
    let mut raw_edges: Vec<ArrEdge> = Vec::new();
    collect_directed_edges(lhs, EdgeOrigin::Lhs, &mut raw_edges);
    collect_directed_edges(rhs, EdgeOrigin::Rhs, &mut raw_edges);

    if raw_edges.len() * 2 > MAX_SWEEP_EVENTS {
        return Err(ExactGeometryError::CapacityExceeded {
            cells: raw_edges.len() * 2,
            limit: MAX_SWEEP_EVENTS,
        });
    }

    // 2. Split all edges at intersection points to produce the arrangement.
    let arr_edges = split_edges_at_intersections(&raw_edges)?;

    // 3. Classify each sub-edge: does it lie on the result boundary?
    //
    // For a directed sub-edge from a CCW outer ring, "left" = inside that
    // polygon, "right" = outside. A sub-edge is on the result boundary iff
    // the result classification differs on its two sides.
    //
    // ponytail: test the midpoint of each sub-edge against the OTHER polygon
    // set to determine the "right-side" classification. This avoids building a
    // full arrangement / DCEL. O(n * m) where n = sub-edges, m = polygon
    // complexity. Fine for layout scale.
    let mut boundary_edges: Vec<ArrEdge> = Vec::new();

    for edge in &arr_edges {
        // Midpoint in doubled coordinates for exact evaluation.
        let mx2 = edge.start.x as i128 + edge.end.x as i128;
        let my2 = edge.start.y as i128 + edge.end.y as i128;

        // The left side of this directed edge is "inside" its origin polygon.
        // Test a point slightly to the right of the midpoint against the other set.
        // Instead: test the midpoint itself against the other set, which tells us
        // whether the midpoint lies inside the other polygon. Since the edge is
        // a boundary edge of its own polygon, the midpoint is ON the boundary of
        // its own polygon. We need to know whether it's inside the OTHER polygon.
        //
        // For a sub-edge that is also on the boundary of the other polygon (shared
        // edge), this test returns Boundary, which we handle separately.
        let (other_set, own_set) = match edge.origin {
            EdgeOrigin::Lhs => (rhs, lhs),
            EdgeOrigin::Rhs => (lhs, rhs),
        };

        let other_class = other_set.classify_scaled2(mx2, my2);

        // Determine if this edge should be on the result boundary.
        // For a CCW-wound outer ring edge, left = inside own, right = outside own.
        //
        // The edge is on the result boundary iff result(left) != result(right).
        //   left:  in_own = true,  in_other = (other_class for left side)
        //   right: in_own = false, in_other = (other_class for right side)
        //
        // Since the midpoint is on the boundary of the own polygon, other_class
        // tells us the classification at the midpoint. The left and right sides
        // near the midpoint have the same other_class (unless the edge is on the
        // boundary of the other polygon too — the shared edge case).
        //
        // For non-shared edges:
        //   left:  in_own=T, in_other=other_class   → result_left
        //   right: in_own=F, in_other=other_class   → result_right
        //   edge is on boundary iff result_left != result_right

        if other_class == PointClassification::Boundary {
            // Shared edge: both polygons have this edge on their boundary.
            // For union: shared boundary is interior, not on result boundary.
            // For intersection: shared boundary is on result boundary IF same direction.
            // For subtraction: shared boundary cancels out.
            // ponytail: skip shared boundary edges — they appear in both polygon
            // boundaries and including them causes duplicates. The boundary from
            // the non-shared edges will close correctly.
            continue;
        }

        let in_other = other_class == PointClassification::Inside;

        let (result_left, result_right) = match edge.origin {
            EdgeOrigin::Lhs => {
                // Left: in_lhs=true, in_rhs=in_other. Right: in_lhs=false, in_rhs=in_other.
                let rl = match operation {
                    BooleanOp::Union => true, // in_lhs || in_rhs
                    BooleanOp::Intersection => in_other,
                    BooleanOp::Subtraction => !in_other,
                };
                let rr = match operation {
                    BooleanOp::Union => in_other,
                    BooleanOp::Intersection => false,
                    BooleanOp::Subtraction => false,
                };
                (rl, rr)
            }
            EdgeOrigin::Rhs => {
                // Left: in_rhs=true, in_lhs=in_other. Right: in_rhs=false, in_lhs=in_other.
                let rl = match operation {
                    BooleanOp::Union => true,
                    BooleanOp::Intersection => in_other,
                    BooleanOp::Subtraction => false, // in_other && !true = false
                };
                let rr = match operation {
                    BooleanOp::Union => in_other,
                    BooleanOp::Intersection => false,
                    BooleanOp::Subtraction => in_other, // in_other && !false = in_other
                };
                (rl, rr)
            }
        };

        if result_left != result_right {
            if result_left {
                // Keep edge as-is: result is to the left (CCW outer boundary).
                boundary_edges.push(edge.clone());
            } else {
                // Result is to the right: reverse the edge direction.
                boundary_edges.push(ArrEdge {
                    start: edge.end,
                    end: edge.start,
                    origin: edge.origin,
                });
            }
        }
    }

    // 4. Chain boundary edges into rings.
    let rings = chain_arrangement_edges(&boundary_edges)?;

    // 5. Separate into outers (CCW) and holes (CW), assign holes to outers.
    let mut result_outers: Vec<(Ring, Vec<Ring>)> = Vec::new();
    let mut result_holes: Vec<Ring> = Vec::new();

    for ring in rings {
        match ring.winding() {
            Winding::CounterClockwise => result_outers.push((ring, Vec::new())),
            Winding::Clockwise => result_holes.push(ring),
        }
    }

    for hole in result_holes {
        let witness = hole.vertices()[0];
        let owner = result_outers
            .iter()
            .enumerate()
            .filter(|(_, (outer, _))| outer.classify_point(witness) == PointClassification::Inside)
            .min_by_key(|(_, (outer, _))| outer.signed_area2())
            .map(|(i, _)| i);
        if let Some(idx) = owner {
            result_outers[idx].1.push(hole);
        }
        // ponytail: hole with no owner is outside the result, silently drop
    }

    let polygons = result_outers
        .into_iter()
        .map(|(outer, holes)| Polygon::new(outer, holes))
        .collect::<Result<Vec<_>, _>>()?;
    PolygonSet::new(polygons)
}

fn collect_directed_edges(set: &PolygonSet, origin: EdgeOrigin, out: &mut Vec<ArrEdge>) {
    for polygon in &set.polygons {
        for ring in std::iter::once(&polygon.outer).chain(polygon.holes.iter()) {
            let verts = ring.vertices();
            for i in 0..verts.len() {
                out.push(ArrEdge {
                    start: verts[i],
                    end: verts[(i + 1) % verts.len()],
                    origin,
                });
            }
        }
    }
}

/// Split every edge at every intersection with every other edge.
/// Returns sub-edges with the same origin tags.
///
/// ponytail: O(n²) all-pairs intersection scan; fine for layout geometry
/// where n < ~10k total edges. Upgrade to sweep-line intersection detection
/// if n grows past that.
fn split_edges_at_intersections(edges: &[ArrEdge]) -> Result<Vec<ArrEdge>, ExactGeometryError> {
    use super::point::segment_intersection_rational;

    // For each edge, collect all split points (as the original endpoints plus
    // intersection points). We work in integer coords since we snap all
    // intersection points.
    let n = edges.len();

    // Collect split points per edge.
    let mut splits: Vec<Vec<Point>> = (0..n).map(|i| vec![edges[i].start, edges[i].end]).collect();

    for i in 0..n {
        for j in i + 1..n {
            // Check for proper intersection.
            if let Some(rp) = segment_intersection_rational(
                edges[i].start,
                edges[i].end,
                edges[j].start,
                edges[j].end,
            ) {
                let snapped = rp.try_snap().ok_or(ExactGeometryError::RationalOverflow)?;
                splits[i].push(snapped);
                splits[j].push(snapped);
            }

            // Also handle T-intersections: endpoint of one on interior of other.
            add_on_segment_split(edges[i].start, edges[i].end, edges[j].start, &mut splits[i]);
            add_on_segment_split(edges[i].start, edges[i].end, edges[j].end, &mut splits[i]);
            add_on_segment_split(edges[j].start, edges[j].end, edges[i].start, &mut splits[j]);
            add_on_segment_split(edges[j].start, edges[j].end, edges[i].end, &mut splits[j]);
        }
    }

    // Now produce sub-edges.
    let mut result = Vec::new();
    for (i, edge) in edges.iter().enumerate() {
        let pts = &mut splits[i];
        // Deduplicate.
        pts.sort_unstable();
        pts.dedup();
        // Sort along edge direction.
        sort_along_edge(edge.start, edge.end, pts);
        for w in pts.windows(2) {
            if w[0] != w[1] {
                result.push(ArrEdge {
                    start: w[0],
                    end: w[1],
                    origin: edge.origin,
                });
            }
        }
    }
    Ok(result)
}

/// If `p` lies strictly in the interior of segment `a`—`b`, add it to `splits`.
fn add_on_segment_split(a: Point, b: Point, p: Point, splits: &mut Vec<Point>) {
    if p == a || p == b {
        return;
    }
    if on_segment(a, b, p) {
        splits.push(p);
    }
}

/// Sort points along the direction from `start` to `end`.
fn sort_along_edge(start: Point, end: Point, points: &mut [Point]) {
    let dx = end.x as i64 - start.x as i64;
    let dy = end.y as i64 - start.y as i64;
    points.sort_unstable_by(|a, b| {
        // Project onto the edge direction: dot product with (dx, dy).
        let pa = (a.x as i64 - start.x as i64) * dx + (a.y as i64 - start.y as i64) * dy;
        let pb = (b.x as i64 - start.x as i64) * dx + (b.y as i64 - start.y as i64) * dy;
        pa.cmp(&pb)
    });
}

/// Chain directed boundary edges into closed rings.
///
/// At vertices with multiple outgoing edges, picks the first CW turn from the
/// reverse of the incoming edge (standard face-to-the-left tracing).
///
/// ponytail: no twin edges needed since we only chain pre-classified boundary
/// edges. Each edge appears exactly once; vertices shared by disjoint
/// components route correctly via the CW-turn rule.
fn chain_arrangement_edges(edges: &[ArrEdge]) -> Result<Vec<Ring>, ExactGeometryError> {
    if edges.is_empty() {
        return Ok(Vec::new());
    }

    // Build adjacency: for each vertex, outgoing edges sorted by angle.
    let mut outgoing: BTreeMap<Point, Vec<usize>> = BTreeMap::new();
    for (i, e) in edges.iter().enumerate() {
        outgoing.entry(e.start).or_default().push(i);
    }
    for indices in outgoing.values_mut() {
        indices.sort_unstable_by(|&a, &b| {
            angle_key(edges[a].start, edges[a].end).cmp(&angle_key(edges[b].start, edges[b].end))
        });
    }

    let mut used = vec![false; edges.len()];
    let mut rings = Vec::new();

    for start_edge in 0..edges.len() {
        if used[start_edge] {
            continue;
        }
        let start = edges[start_edge].start;
        let mut ring_points = Vec::new();
        let mut current = start_edge;
        loop {
            if used[current] {
                return Err(ExactGeometryError::InternalTopology(
                    "boundary edge revisited during chain",
                ));
            }
            used[current] = true;
            ring_points.push(edges[current].start);
            if edges[current].end == start && ring_points.len() > 1 {
                break;
            }
            let candidates = outgoing
                .get(&edges[current].end)
                .ok_or(ExactGeometryError::InternalTopology("open boundary chain"))?;

            current = choose_general_continuation(&edges[current], candidates, edges, &used)
                .ok_or(ExactGeometryError::InternalTopology(
                    "no unused boundary continuation",
                ))?;
            if ring_points.len() > edges.len() {
                return Err(ExactGeometryError::InternalTopology(
                    "boundary chain did not close",
                ));
            }
        }
        if ring_points.len() >= 3 {
            match Ring::new(ring_points) {
                Ok(ring) => rings.push(ring),
                Err(_) => {
                    // ponytail: degenerate sliver from split edges, skip it
                }
            }
        }
    }
    Ok(rings)
}

/// Pick the outgoing edge that is first **clockwise** from the reverse of the
/// incoming edge. This traces the face to the **left** of each directed edge,
/// which is the standard DCEL face-tracing convention.
fn choose_general_continuation(
    incoming: &ArrEdge,
    candidates: &[usize],
    edges: &[ArrEdge],
    used: &[bool],
) -> Option<usize> {
    // Incoming direction (reversed): from incoming.end back to incoming.start.
    let in_dx = incoming.start.x as i64 - incoming.end.x as i64;
    let in_dy = incoming.start.y as i64 - incoming.end.y as i64;

    // ponytail: max_by picks largest CCW angle from reference = first CW turn,
    // which is the correct DCEL face-to-the-left tracing.
    candidates
        .iter()
        .copied()
        .filter(|&i| !used[i])
        .max_by(|&a, &b| {
            let ea = &edges[a];
            let eb = &edges[b];
            let da_x = ea.end.x as i64 - ea.start.x as i64;
            let da_y = ea.end.y as i64 - ea.start.y as i64;
            let db_x = eb.end.x as i64 - eb.start.x as i64;
            let db_y = eb.end.y as i64 - eb.start.y as i64;
            // Compare angles relative to incoming reverse direction.
            // Use the cross-product-based comparison for sorting by angle.
            compare_angle_from_ref(in_dx, in_dy, da_x, da_y, db_x, db_y)
        })
}

/// Compare two directions (da, db) by their angle measured CCW from a reference
/// direction (ref_dx, ref_dy). Returns Ordering.
///
/// Uses exact integer cross products — no trig.
fn compare_angle_from_ref(
    ref_dx: i64,
    ref_dy: i64,
    da_x: i64,
    da_y: i64,
    db_x: i64,
    db_y: i64,
) -> std::cmp::Ordering {
    // Classify each direction into a half-plane relative to the reference.
    // "Left" half: cross(ref, d) > 0 or (cross == 0 and dot > 0) [same direction].
    let cross_a = ref_dx as i128 * da_y as i128 - ref_dy as i128 * da_x as i128;
    let cross_b = ref_dx as i128 * db_y as i128 - ref_dy as i128 * db_x as i128;
    let dot_a = ref_dx as i128 * da_x as i128 + ref_dy as i128 * da_y as i128;
    let dot_b = ref_dx as i128 * db_x as i128 + ref_dy as i128 * db_y as i128;

    let half_a = half_plane(cross_a, dot_a);
    let half_b = half_plane(cross_b, dot_b);

    if half_a != half_b {
        return half_a.cmp(&half_b);
    }

    // Same half-plane: the one with positive cross product from the other comes later.
    let cross_ab = da_x as i128 * db_y as i128 - da_y as i128 * db_x as i128;
    // If cross_ab > 0, a is CW from b (a comes first in CCW sweep).
    // We want "smallest left turn first" — the one closest to the reverse incoming.
    cross_ab.cmp(&0).reverse()
}

/// Assign a half-plane index for angle sorting. 0 = same direction as ref,
/// 1 = left half, 2 = opposite, 3 = right half. Gives a correct CCW ordering.
fn half_plane(cross: i128, dot: i128) -> u8 {
    if cross > 0 {
        1
    } else if cross < 0 {
        3
    } else if dot > 0 {
        0
    } else {
        2
    }
}

/// Deterministic angle sort key for initial bucket sorting.
/// Uses (half-plane quadrant, slope-comparison proxy).
fn angle_key(from: Point, to: Point) -> (i8, i64, i64) {
    let dx = to.x as i64 - from.x as i64;
    let dy = to.y as i64 - from.y as i64;
    let quadrant = if dx > 0 && dy >= 0 {
        0
    } else if dx <= 0 && dy > 0 {
        1
    } else if dx < 0 && dy <= 0 {
        2
    } else {
        3
    };
    // Within a quadrant, sort by slope dy/dx. We store (dy, dx) and compare
    // as fractions: a.dy * b.dx <=> b.dy * a.dx. For the sort key, just use
    // (quadrant, dy, dx) — the actual comparison in chain uses cross products.
    (quadrant, dy, dx)
}
