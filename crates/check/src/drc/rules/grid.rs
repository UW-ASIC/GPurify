//! Grid family: off-grid vertices and disallowed edge angles, over every
//! polygon in the store, reported at the vertex.
//!
//! Data in: the store's coordinate columns. Data out: one violation per
//! offending vertex (off-grid) or edge (angle, at the vertex it leaves).

use super::{ring_segs, Verdict};
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::ops::Point;
use gpurify_geom::{Dbu, GeometryStore, PolyId};
use gpurify_ingest::StrId;

/// Chebyshev distance from `(x, y)` to the nearest `pitch` lattice point; zero
/// exactly on the lattice.
fn lattice_offset(x: Dbu, y: Dbu, pitch: i64) -> i64 {
    let rx = x.raw().rem_euclid(pitch);
    let ry = y.raw().rem_euclid(pitch);
    rx.min(pitch - rx).max(ry.min(pitch - ry))
}

fn store_polys(store: &GeometryStore) -> impl Iterator<Item = PolyId> {
    (0..u32::try_from(store.poly_count()).expect("a store indexes polygons with a u32")).map(PolyId)
}

/// Every vertex must sit on the `pitch` lattice. `examined` counts vertices.
pub(crate) fn off_grid(
    store: &GeometryStore,
    rule: StrId,
    pitch: Dbu,
    out: &mut Violations,
) -> Verdict {
    let pitch = pitch.raw();
    let mut examined = 0u64;
    for poly in store_polys(store) {
        let (xs, ys) = store.poly_verts(poly);
        examined += xs.len() as u64;
        for (&x, &y) in xs.iter().zip(ys) {
            let offset = lattice_offset(x, y, pitch);
            if offset != 0 {
                out.push(Violation {
                    rule,
                    layer: store.poly_layer(poly),
                    severity: Severity::Error,
                    at: Point { x, y },
                    measured: Measurement::Length(Dbu::new_unchecked(offset)),
                    limit: Measurement::Length(Dbu::new_unchecked(0)),
                    shapes: (poly, None),
                });
            }
        }
    }
    (Outcome::Ran, examined)
}

/// Bit of the line (0, 45, 90, 135 degrees) edge `(dx, dy)` lies along, or 0.
fn line_bit(dx: i64, dy: i64) -> u8 {
    u8::from(dy == 0) | u8::from(dx == dy) << 1 | u8::from(dx == 0) << 2 | u8::from(dx == -dy) << 3
}

/// Every non-zero edge must lie along an `allowed` line. Measured as the count
/// of allowed lines matched (zero) against a limit of one. `examined` counts
/// non-zero edges.
pub(crate) fn angle(
    store: &GeometryStore,
    rule: StrId,
    allowed: u8,
    out: &mut Violations,
) -> Verdict {
    let mut examined = 0u64;
    for poly in store_polys(store) {
        let (xs, ys) = store.poly_verts(poly);
        for seg in ring_segs(xs, ys) {
            let (dx, dy) = (seg.b.x.raw() - seg.a.x.raw(), seg.b.y.raw() - seg.a.y.raw());
            if dx == 0 && dy == 0 {
                continue;
            }
            examined += 1;
            if line_bit(dx, dy) & allowed == 0 {
                out.push(Violation {
                    rule,
                    layer: store.poly_layer(poly),
                    severity: Severity::Error,
                    at: seg.a,
                    measured: Measurement::Count(0),
                    limit: Measurement::Count(1),
                    shapes: (poly, None),
                });
            }
        }
    }
    (Outcome::Ran, examined)
}
