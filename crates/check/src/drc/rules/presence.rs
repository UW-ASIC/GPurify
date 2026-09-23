//! Presence family: what must not exist, and what must hold or lie inside what.
//!
//! Data in: one or two validated layers, merged (touching shapes are one).
//! Data out: one violation per offending shape, or per edge of an edge layer.

use super::{centre, mid, owners_of, seg_bbox, SortedRects, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::Point;
use gpurify_geom::rects::{covered_area, decompose_into};
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

/// Every shape on the layer, as drawn, and every edge of an edge layer.
/// A shape reports its area, an edge its length. `examined` counts both.
pub(crate) fn forbidden(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    let polys = u32::try_from(drawn.len()).expect("a layer indexes polygons with a u32");
    for idx in 0..polys {
        let poly = drawn.get(idx);
        let area2 = std::iter::once(poly.outer())
            .chain(poly.holes())
            .fold(0i128, |sum, ring| sum + ring.area2().raw());
        let (xs, ys) = poly.outer().coords();
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: Point { x: xs[0], y: ys[0] },
            measured: Measurement::Area(DbuArea::new(area2 / 2)),
            limit: Measurement::Area(DbuArea::new(0)),
            shapes: (poly.provenance(), None),
        });
    }
    let edges = store.edges_on_layer(layer);
    for &edge in edges {
        let b = seg_bbox(edge);
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(b),
            measured: Measurement::Length((b.xhi - b.xlo) + (b.yhi - b.ylo)),
            limit: Measurement::Length(Dbu::new_unchecked(0)),
            shapes: (PolyId(u32::MAX), None),
        });
    }
    (Outcome::Ran, u64::from(polys) + edges.len() as u64)
}

/// A layer validated and merged; `None` when it does not validate.
fn merged(store: &GeometryStore, layer: LayerId, s: &mut Scratch) -> Option<ValidatedLayer> {
    let drawn = s.validated.get(store, layer)?;
    let mut figures = ValidatedLayer::default();
    union_into(drawn, &ValidatedLayer::default(), &mut figures).ok()?;
    Some(figures)
}

/// Rectangles of `figures`, CSR by figure.
fn rects_of(figures: &ValidatedLayer) -> (Vec<Bbox>, Vec<u32>) {
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(figures, &mut rects, &mut start);
    (rects, start)
}

/// Per inner figure, the outer figure covering all of it, if one does. Outer
/// figures share no area, so an inner figure fully covered lies in exactly one.
fn hosts(inner: &(Vec<Bbox>, Vec<u32>), outer: &(Vec<Bbox>, Vec<u32>)) -> Vec<Option<u32>> {
    let labelled = outer
        .1
        .windows(2)
        .zip(0u32..)
        .flat_map(|(span, figure)| {
            outer.0[span[0] as usize..span[1] as usize]
                .iter()
                .map(move |&r| (r, figure))
        })
        .collect();
    let outer = SortedRects::new(labelled);
    inner
        .1
        .windows(2)
        .map(|span| {
            let mine = &inner.0[span[0] as usize..span[1] as usize];
            let (mut covered, mut host) = (DbuArea::new(0), None);
            for &r in mine {
                for (clip, figure) in outer.overlapping(r) {
                    covered = covered + clip.area();
                    host = Some(figure);
                }
            }
            (covered == covered_area(mine)).then_some(host).flatten()
        })
        .collect()
}

/// A point on figure `figure`'s material: the centre of its first rectangle.
fn inside_point(rects: &(Vec<Bbox>, Vec<u32>), figure: usize) -> Point {
    let r = rects.0[rects.1[figure] as usize];
    Point {
        x: mid(r.xlo, r.xhi),
        y: mid(r.ylo, r.yhi),
    }
}

/// Each merged `outer` figure must hold at least `min_count` merged `inner`
/// figures entirely (licon.16 "every tap must enclose at least one licon").
/// One that straddles the outer's edge is not held. `examined` counts outer
/// figures.
pub(crate) fn must_contain(
    store: &GeometryStore,
    rule: StrId,
    outer: LayerId,
    inner: LayerId,
    min_count: u32,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let (Some(inner_figures), Some(outer_figures)) =
        (merged(store, inner, s), merged(store, outer, s))
    else {
        return REFUSED;
    };
    let (inner_rects, outer_rects) = (rects_of(&inner_figures), rects_of(&outer_figures));
    let mut held = vec![0u32; outer_figures.len()];
    for host in hosts(&inner_rects, &outer_rects).into_iter().flatten() {
        held[host as usize] += 1;
    }
    let drawn = s.validated.get(store, outer).expect("merged above");
    s.rects_a.build(store, outer, drawn);
    let owners = owners_of(&outer_figures, &s.rects_a);
    for (figure, &count) in held.iter().enumerate() {
        if count < min_count {
            out.push(Violation {
                rule,
                layer: outer,
                severity: Severity::Error,
                at: inside_point(&outer_rects, figure),
                measured: Measurement::Count(count),
                limit: Measurement::Count(min_count),
                shapes: (owners[figure], None),
            });
        }
    }
    (Outcome::Ran, held.len() as u64)
}

/// Each merged `inner` figure must lie entirely inside `outer`, touching its
/// edge from inside allowed (licon.18 "npc must enclose `poly_licon`"). Reports
/// the area left outside. `examined` counts inner figures.
pub(crate) fn must_be_inside(
    store: &GeometryStore,
    rule: StrId,
    inner: LayerId,
    outer: LayerId,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let (Some(inner_figures), Some(outer_figures)) =
        (merged(store, inner, s), merged(store, outer, s))
    else {
        return REFUSED;
    };
    let (inner_rects, outer_rects) = (rects_of(&inner_figures), rects_of(&outer_figures));
    let outer_all = SortedRects::new(outer_rects.0.iter().map(|&r| (r, ())).collect());
    let drawn = s.validated.get(store, inner).expect("merged above");
    s.rects_a.build(store, inner, drawn);
    let owners = owners_of(&inner_figures, &s.rects_a);
    for (figure, host) in hosts(&inner_rects, &outer_rects).into_iter().enumerate() {
        if host.is_some() {
            continue;
        }
        let span = &inner_rects.1[figure..figure + 2];
        let mine = &inner_rects.0[span[0] as usize..span[1] as usize];
        let covered = mine
            .iter()
            .flat_map(|&r| outer_all.overlapping(r))
            .fold(DbuArea::new(0), |sum, (clip, ())| sum + clip.area());
        out.push(Violation {
            rule,
            layer: inner,
            severity: Severity::Error,
            at: inside_point(&inner_rects, figure),
            measured: Measurement::Area(covered_area(mine) - covered),
            limit: Measurement::Area(DbuArea::new(0)),
            shapes: (owners[figure], None),
        });
    }
    (Outcome::Ran, inner_figures.len() as u64)
}
