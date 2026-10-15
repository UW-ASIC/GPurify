//! Presence family: what must not exist, and what must hold or lie inside what.
//!
//! Data in: one or two validated layers, merged (touching shapes are one),
//! except that `forbidden` reports shapes as drawn.
//! Data out: one violation per offending shape, or per edge of an edge layer.

use super::{
    centre, figure_point, figures_holding, merged, owners_by_point, owners_of, seg_bbox,
    SortedRects, Verdict, REFUSED,
};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::{subtraction_into, union_into};
use gpurify_geom::derive::inside_flags;
use gpurify_geom::ops::{isqrt, Point};
use gpurify_geom::rects::{covered_area, decompose_into};
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

/// Every shape on the layer, as drawn, and every edge of an edge layer.
/// A shape reports its area, an edge its length. `examined` counts both.
/// Shapes and edges at any angle included: a half-unit area and a slanted
/// edge's length are reported floored.
pub(crate) fn forbidden(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get_any(store, layer) else {
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
            measured: Measurement::Length(isqrt(
                (b.xhi - b.xlo).mul_wide(b.xhi - b.xlo) + (b.yhi - b.ylo).mul_wide(b.yhi - b.ylo),
            )),
            limit: Measurement::Length(Dbu::new_unchecked(0)),
            shapes: (PolyId(u32::MAX), None),
        });
    }
    (Outcome::Ran, u64::from(polys) + edges.len() as u64)
}

/// Rectangles of `figures`, CSR by figure.
pub(super) fn rects_of(figures: &ValidatedLayer) -> (Vec<Bbox>, Vec<u32>) {
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(figures, &mut rects, &mut start);
    (rects, start)
}

/// Per inner figure, the outer figure covering all of it, if one does. Outer
/// figures share no area, so an inner figure fully covered lies in exactly one.
pub(super) fn hosts(
    inner: &(Vec<Bbox>, Vec<u32>),
    outer: &(Vec<Bbox>, Vec<u32>),
) -> Vec<Option<u32>> {
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
pub(super) fn inside_point(rects: &(Vec<Bbox>, Vec<u32>), figure: usize) -> Point {
    let r = rects.0[rects.1[figure] as usize];
    centre(r)
}

/// Each merged `outer` figure must hold at least `min_count` and at most
/// `max_count` merged `inner` figures entirely (licon.16 "every tap must
/// enclose at least one licon"; rpm.1g "only 1 licon is allowed"). One that
/// straddles the outer's edge is not held. `examined` counts outer figures.
pub(crate) fn must_contain(
    store: &GeometryStore,
    rule: StrId,
    (outer, inner): (LayerId, LayerId),
    (min_count, max_count): (u32, u32),
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if let Some(octilinear) = octilinear_pair(store, (outer, inner), s) {
        let Some((outer_figures, inner_figures, owners)) = octilinear else {
            return REFUSED;
        };
        // Held: an inner figure the outer covers, in the figure holding it.
        let Ok(covered) = inside_flags(&inner_figures, &outer_figures) else {
            return REFUSED;
        };
        let mut held = vec![0u32; outer_figures.len()];
        for (inner, home) in figures_holding(&outer_figures, &inner_figures)
            .into_iter()
            .enumerate()
        {
            if let Some(host) = home.filter(|_| covered[inner]) {
                held[host as usize] += 1;
            }
        }
        for (figure, &count) in held.iter().enumerate() {
            let Some(broken) = count_broken(count, (min_count, max_count)) else {
                continue;
            };
            out.push(Violation {
                rule,
                layer: outer,
                severity: Severity::Error,
                at: point_in(&outer_figures, figure),
                measured: Measurement::Count(count),
                limit: Measurement::Count(broken),
                shapes: (owners[figure], None),
            });
        }
        return (Outcome::Ran, held.len() as u64);
    }
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
        let Some(broken) = count_broken(count, (min_count, max_count)) else {
            continue;
        };
        out.push(Violation {
            rule,
            layer: outer,
            severity: Severity::Error,
            at: inside_point(&outer_rects, figure),
            measured: Measurement::Count(count),
            limit: Measurement::Count(broken),
            shapes: (owners[figure], None),
        });
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
    inside_where(store, rule, (inner, outer), s, out, |_| true)
}

/// Each merged figure of `layer`, by its lowest-numbered drawn polygon, and
/// whether it shares area with `tag` (an edge or a corner is no share).
/// `None` when either layer will not validate or merge.
pub(crate) fn tagged_figures(
    store: &GeometryStore,
    layer: LayerId,
    tag: LayerId,
    s: &mut Scratch,
) -> Option<Vec<(PolyId, bool)>> {
    let (figures, tags) = (merged(store, layer, s)?, merged(store, tag, s)?);
    let (rects, tag_rects) = (rects_of(&figures), rects_of(&tags));
    let tagged = SortedRects::new(tag_rects.0.iter().map(|&r| (r, ())).collect());
    let drawn = s.validated.get(store, layer).expect("merged above");
    s.rects_a.build(store, layer, drawn);
    let owners = owners_of(&figures, &s.rects_a);
    Some(
        rects
            .1
            .windows(2)
            .zip(owners)
            .map(|(span, owner)| {
                let mine = &rects.0[span[0] as usize..span[1] as usize];
                let shares = mine.iter().any(|&r| tagged.overlapping(r).next().is_some());
                (owner, shares)
            })
            .collect(),
    )
}

/// The bound a count of held figures breaks, `None` when within both.
fn count_broken(count: u32, (min_count, max_count): (u32, u32)) -> Option<u32> {
    if count < min_count {
        Some(min_count)
    } else if count > max_count {
        Some(max_count)
    } else {
        None
    }
}

/// A point of figure `figure` of `figures` ([`figure_point`]).
fn point_in(figures: &ValidatedLayer, figure: usize) -> Point {
    figure_point(figures.get(u32::try_from(figure).expect("a u32 index")))
}

/// Where either of two layers has a slanted edge (`Some`): both merged,
/// with the lowest drawn row under each figure of the first, or `None`
/// inside when either will not validate or merge (the rule is `Refused`).
/// `None` when both are rectilinear, for the rectangle path.
#[allow(clippy::type_complexity, reason = "two merged layers and owners, once")]
fn octilinear_pair(
    store: &GeometryStore,
    (first, second): (LayerId, LayerId),
    s: &mut Scratch,
) -> Option<Option<(ValidatedLayer, ValidatedLayer, Vec<PolyId>)>> {
    let Some((a, b)) = s.validated.pair_any(store, first, second) else {
        return Some(None);
    };
    if a.is_rectilinear() && b.is_rectilinear() {
        return None;
    }
    let (mut fa, mut fb) = (ValidatedLayer::default(), ValidatedLayer::default());
    let empty = ValidatedLayer::default();
    if union_into(a, &empty, &mut fa).is_err() || union_into(b, &empty, &mut fb).is_err() {
        return Some(None);
    }
    let owners = owners_by_point(&fa, a);
    Some(Some((fa, fb, owners)))
}

/// Twice the area of a polygon, holes subtracted: whole on the octilinear grid.
fn area2(poly: gpurify_geom::PolygonRef<'_>) -> i128 {
    std::iter::once(poly.outer())
        .chain(poly.holes())
        .map(|ring| ring.area2().raw())
        .sum()
}

/// [`must_be_inside`] for the merged `inner` figures `judge` takes, each by
/// its lowest-numbered drawn polygon; `examined` counts those. Where either
/// layer has a 45-degree edge, the area left outside is exact and reported
/// rounded up, so a half unit outside reads 1.
pub(crate) fn inside_where(
    store: &GeometryStore,
    rule: StrId,
    (inner, outer): (LayerId, LayerId),
    s: &mut Scratch,
    out: &mut Violations,
    judge: impl Fn(PolyId) -> bool,
) -> Verdict {
    if let Some(octilinear) = octilinear_pair(store, (inner, outer), s) {
        let Some((inner_figures, outer_figures, owners)) = octilinear else {
            return REFUSED;
        };
        // The parts outside, each inside exactly one inner figure.
        let mut rest = ValidatedLayer::default();
        if subtraction_into(&inner_figures, &outer_figures, &mut rest).is_err() {
            return REFUSED;
        }
        let mut outside2 = vec![0i128; inner_figures.len()];
        for (part, home) in figures_holding(&inner_figures, &rest)
            .into_iter()
            .enumerate()
        {
            // At any angle a sliver the rounding left outside every inner
            // figure holds no area of one.
            let Some(home) = home else {
                continue;
            };
            outside2[home as usize] += area2(rest.get(u32::try_from(part).expect("a u32 index")));
        }
        let mut examined = 0u64;
        for (figure, &twice) in outside2.iter().enumerate() {
            if !judge(owners[figure]) {
                continue;
            }
            examined += 1;
            if twice == 0 {
                continue;
            }
            out.push(Violation {
                rule,
                layer: inner,
                severity: Severity::Error,
                at: point_in(&inner_figures, figure),
                measured: Measurement::Area(DbuArea::new((twice + 1) / 2)),
                limit: Measurement::Area(DbuArea::new(0)),
                shapes: (owners[figure], None),
            });
        }
        return (Outcome::Ran, examined);
    }
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
    let mut examined = 0u64;
    for (figure, host) in hosts(&inner_rects, &outer_rects).into_iter().enumerate() {
        if !judge(owners[figure]) {
            continue;
        }
        examined += 1;
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
    (Outcome::Ran, examined)
}
