//! Grid family: off-grid vertices, over every drawn polygon, and disallowed
//! edge angles, over every drawn polygon (or one layer's), reported at the
//! vertex.
//!
//! Data in: the store's coordinate columns. Data out: one violation per
//! offending vertex (off-grid) or edge (angle, at the vertex it leaves).

use super::{ring_segs, Verdict};
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::ops::Point;
use gpurify_geom::view::ring_defect;
use gpurify_geom::{Dbu, GeometryStore, LayerId, PolyId};
use gpurify_ingest::StrId;

/// Chebyshev distance from `(x, y)` to the nearest `pitch` lattice point; zero
/// exactly on the lattice.
fn lattice_offset(x: Dbu, y: Dbu, pitch: i64) -> i64 {
    // A power-of-two pitch is a mask (two's complement makes it exact for
    // negatives too), which skips two integer divisions per vertex.
    let rem = |v: i64| {
        if pitch & (pitch - 1) == 0 {
            v & (pitch - 1)
        } else {
            v.rem_euclid(pitch)
        }
    };
    let (rx, ry) = (rem(x.raw()), rem(y.raw()));
    rx.min(pitch - rx).max(ry.min(pitch - ry))
}

/// Every row on the drawn layers `0..drawn`.
fn drawn_rows(store: &GeometryStore, drawn: usize) -> impl Iterator<Item = PolyId> + '_ {
    (0..drawn)
        .flat_map(|layer| {
            store.polys_on_layer(LayerId(u16::try_from(layer).expect("a LayerId is a u16")))
        })
        .map(PolyId)
}

/// Every vertex on the drawn layers `0..drawn` must sit on the `pitch`
/// lattice; a derived layer is computed, not drawn, and repeats its operands'
/// vertices. `examined` counts vertices.
pub(crate) fn off_grid(
    store: &GeometryStore,
    rule: StrId,
    pitch: Dbu,
    drawn: usize,
    out: &mut Violations,
) -> Verdict {
    let pitch = pitch.raw();
    let mut examined = 0u64;
    for poly in drawn_rows(store, drawn) {
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

/// Every non-zero edge on `layer`, or on every drawn layer `0..drawn` when
/// `None` (a derived layer repeats its operands' edges), must lie along an
/// `allowed` line. Measured as the count of allowed lines matched (zero)
/// against a limit of one. `examined` counts non-zero edges.
pub(crate) fn angle(
    store: &GeometryStore,
    rule: StrId,
    (layer, drawn): (Option<LayerId>, usize),
    allowed: u8,
    out: &mut Violations,
) -> Verdict {
    let mut examined = 0u64;
    let polys: Box<dyn Iterator<Item = PolyId>> = match layer {
        Some(layer) => Box::new(store.polys_on_layer(layer).map(PolyId)),
        None => Box::new(drawn_rows(store, drawn)),
    };
    for poly in polys {
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

/// The rows a rule reads: `layer`'s, or every drawn layer's (`0..drawn`) when
/// `None`.
fn rows_of(
    store: &GeometryStore,
    (layer, drawn): (Option<LayerId>, usize),
) -> Box<dyn Iterator<Item = PolyId> + '_> {
    match layer {
        Some(layer) => Box::new(store.polys_on_layer(layer).map(PolyId)),
        None => Box::new(drawn_rows(store, drawn)),
    }
}

/// The angle at a corner on its shape's side, in degrees from 0 to 360, from
/// the edge arriving at it, `(ax, ay)`, and the edge leaving it, `(bx, by)`.
/// A row's shape lies left of travel (outer rings counter-clockwise, holes
/// clockwise), so the angle is 180 less the signed turn. Rounded to 1e-9
/// degree, so a right angle reads exactly 90.
#[allow(
    clippy::cast_precision_loss,
    reason = "the products are exact in i128; their ratio is all the angle needs"
)]
fn interior_degrees((ax, ay): (i64, i64), (bx, by): (i64, i64)) -> f64 {
    let (ax, ay, bx, by) = (
        i128::from(ax),
        i128::from(ay),
        i128::from(bx),
        i128::from(by),
    );
    let (cross, dot) = (ax * by - ay * bx, ax * bx + ay * by);
    let turn = (cross as f64).atan2(dot as f64).to_degrees();
    ((180.0 - turn) * 1e9).round() / 1e9
}

/// Every corner of the rows read (one layer's, or every drawn layer's) whose
/// angle inside its shape is below `limit` degrees (IHP 3.1 "acute angles
/// <87 degree"), at the vertex, measuring the angle. A zero-length edge is
/// skipped. `examined` counts the corners measured.
pub(crate) fn min_interior_angle(
    store: &GeometryStore,
    rule: StrId,
    read: (Option<LayerId>, usize),
    limit: f64,
    out: &mut Violations,
) -> Verdict {
    let mut examined = 0u64;
    for poly in rows_of(store, read) {
        let (xs, ys) = store.poly_verts(poly);
        let n = xs.len();
        for at in 0..n {
            let (before, after) = ((at + n - 1) % n, (at + 1) % n);
            let arriving = (
                xs[at].raw() - xs[before].raw(),
                ys[at].raw() - ys[before].raw(),
            );
            let leaving = (
                xs[after].raw() - xs[at].raw(),
                ys[after].raw() - ys[at].raw(),
            );
            if arriving == (0, 0) || leaving == (0, 0) {
                continue;
            }
            examined += 1;
            let angle = interior_degrees(arriving, leaving);
            if angle < limit {
                out.push(Violation {
                    rule,
                    layer: store.poly_layer(poly),
                    severity: Severity::Error,
                    at: Point {
                        x: xs[at],
                        y: ys[at],
                    },
                    measured: Measurement::Ratio(angle),
                    limit: Measurement::Ratio(limit),
                    shapes: (poly, None),
                });
            }
        }
    }
    (Outcome::Ran, examined)
}

/// Every row read (one layer's, or every drawn layer's) that is no valid
/// polygon whatever its angles (IHP 3.1 "self-intersecting polygons must be
/// avoided"): degenerate or self-intersecting, as layer validation decides
/// ([`ring_defect`]). One violation per row at its first vertex. `examined`
/// counts rows.
pub(crate) fn polygon_validity(
    store: &GeometryStore,
    rule: StrId,
    read: (Option<LayerId>, usize),
    out: &mut Violations,
) -> Verdict {
    let mut examined = 0u64;
    for poly in rows_of(store, read) {
        examined += 1;
        let (xs, ys) = store.poly_verts(poly);
        if ring_defect(xs, ys, poly).is_none() {
            continue;
        }
        out.push(Violation {
            rule,
            layer: store.poly_layer(poly),
            severity: Severity::Error,
            // A row with no vertex at all is reported at the origin.
            at: xs.first().zip(ys.first()).map_or(
                Point {
                    x: Dbu::new_unchecked(0),
                    y: Dbu::new_unchecked(0),
                },
                |(&x, &y)| Point { x, y },
            ),
            measured: Measurement::Count(0),
            limit: Measurement::Count(1),
            shapes: (poly, None),
        });
    }
    (Outcome::Ran, examined)
}

#[cfg(test)]
mod tests {
    use super::lattice_offset;
    use gpurify_geom::{Dbu, MAX_ABS_DBU};

    fn reference(x: i64, y: i64, pitch: i64) -> i64 {
        let (rx, ry) = (x.rem_euclid(pitch), y.rem_euclid(pitch));
        rx.min(pitch - rx).max(ry.min(pitch - ry))
    }

    /// Oracle: differential against `reference`, the offset written with
    /// `rem_euclid`, at every listed pitch (powers of two and not) and
    /// coordinate, signs and domain edges included.
    #[test]
    fn the_power_of_two_mask_is_rem_euclid() {
        let d = Dbu::new_unchecked;
        let values = [
            -MAX_ABS_DBU,
            -1025,
            -1024,
            -7,
            -1,
            0,
            1,
            3,
            1023,
            MAX_ABS_DBU,
        ];
        for pitch in [1, 2, 3, 5, 8, 1024, 1 << 30, MAX_ABS_DBU] {
            for &x in &values {
                for &y in &values {
                    assert_eq!(lattice_offset(d(x), d(y), pitch), reference(x, y, pitch));
                }
            }
        }
    }
}
