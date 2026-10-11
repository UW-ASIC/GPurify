//! Spacing read off the edges of the merged layer: facing edges classed by
//! their lengths, and gaps in a forbidden range.
//!
//! Data in: one layer, validated and merged into `s.layer_out`; every rule
//! here reads whole edges of the merged figures, so a side drawn as several
//! strips is one edge. Data out: one violation per pair of merged figures,
//! named by the lowest drawn row under each, at the middle of the stretch the
//! two nearest offending edges face each other over.

use super::spacing::{line_of, nearest, on_line, spacing_violation};
use super::{owners_of, ring_segs, Verdict, REFUSED};
use crate::drc::ruleset::ClassTable;
use crate::drc::Scratch;
use crate::report::{Outcome, Violations};
use gpurify_geom::derive::merge_into;
use gpurify_geom::ops::Seg;
use gpurify_geom::{Dbu, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

/// One edge of a merged figure. Field order is the sort order the facing scan
/// relies on: by line orientation, then the way the edge faces, then its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Edge {
    /// Whether the edge runs along y (its line is `x = pos`).
    pub(super) vertical: bool,
    /// Whether the edge faces toward higher coordinates: its material lies
    /// below its line (left of it, for a vertical edge).
    pub(super) faces_up: bool,
    /// The fixed coordinate of the edge's line.
    pub(super) pos: i64,
    /// The low end of the edge's span along its line.
    pub(super) lo: i64,
    /// The high end of the edge's span, above `lo`.
    pub(super) hi: i64,
    /// The merged figure the edge bounds.
    pub(super) figure: u32,
    /// Whether both of its corners are convex (the material turns away from
    /// the space in front of the edge at each end): a line end's corners.
    pub(super) convex: bool,
}

impl Edge {
    pub(super) const fn length(&self) -> i64 {
        self.hi - self.lo
    }
}

/// The layer validated and merged into `s.layer_out`, and the lowest drawn
/// row under each merged figure; `None` (the rule is `Refused`) when the
/// layer does not validate or the merge fails.
pub(super) fn merged_owners(
    store: &GeometryStore,
    layer: LayerId,
    s: &mut Scratch,
) -> Option<Vec<PolyId>> {
    let drawn = s.validated.get(store, layer)?;
    merge_into(drawn, &mut s.layer_out).ok()?;
    s.rects_a.build(store, layer, drawn);
    Some(owners_of(&s.layer_out, &s.rects_a))
}

/// Every edge of every figure of `figures` (a merged layer, so each edge is
/// a maximal run with its material on its left), sorted.
pub(super) fn figure_edges(figures: &ValidatedLayer) -> Vec<Edge> {
    let mut edges = Vec::new();
    for figure in 0..u32::try_from(figures.len()).expect("a layer indexes polygons with a u32") {
        for ring in figures.poly_rings(figure) {
            let (xs, ys) = ring.coords();
            let n = xs.len();
            // A left turn at a vertex is a convex corner: the material is on
            // the left of travel, outer rings and holes alike.
            let convex = |i: usize| {
                let (back, next) = ((i + n - 1) % n, (i + 1) % n);
                let (inx, iny) = (xs[i].raw() - xs[back].raw(), ys[i].raw() - ys[back].raw());
                let (outx, outy) = (xs[next].raw() - xs[i].raw(), ys[next].raw() - ys[i].raw());
                i128::from(inx) * i128::from(outy) > i128::from(iny) * i128::from(outx)
            };
            for (i, seg) in ring_segs(xs, ys).enumerate() {
                let (vertical, pos, forward, lo, hi) = line_of(seg);
                if hi > lo {
                    edges.push(Edge {
                        vertical,
                        // Material on the left: an up-travelling vertical edge
                        // faces +x, a left-travelling horizontal one +y.
                        faces_up: forward == vertical,
                        pos,
                        lo,
                        hi,
                        figure,
                        convex: convex(i) && convex((i + 1) % n),
                    });
                }
            }
        }
    }
    edges.sort_unstable();
    edges
}

/// Calls `visit` for every two edges of `edges` (sorted) that face each
/// other across empty space at most `reach` apart over a positive run: the
/// edge facing up first, then the one facing down from above it, their gap,
/// and the span they face each other over. Two edges whose spans only meet at
/// a point do not face.
pub(super) fn each_facing(
    edges: &[Edge],
    reach: i64,
    mut visit: impl FnMut(&Edge, &Edge, i64, (i64, i64)),
) {
    for e in edges.iter().filter(|e| e.faces_up) {
        // ponytail: every down edge within `reach` above each up edge;
        // quadratic only where many edges share one `reach`-wide band.
        let from = edges
            .partition_point(|f| (f.vertical, f.faces_up, f.pos) <= (e.vertical, false, e.pos));
        let above = edges[from..]
            .iter()
            .take_while(|f| f.vertical == e.vertical && !f.faces_up && f.pos - e.pos <= reach);
        for f in above {
            let (lo, hi) = (e.lo.max(f.lo), e.hi.min(f.hi));
            if hi > lo {
                visit(e, f, f.pos - e.pos, (lo, hi));
            }
        }
    }
}

/// One offending approach between two figures: the figures (lower first),
/// the gap judged, the space it needed, and the stretch of each side it was
/// measured over.
pub(super) type Hit = (u32, u32, i64, i64, Seg, Seg);

/// One violation per pair of figures among `hits`: its smallest gap, held to
/// the largest need among the hits at that gap, at the middle of their
/// nearest stretches ([`nearest`]); `shapes` are the figures' `owners`.
pub(super) fn report_pairs(
    rule: StrId,
    layer: LayerId,
    owners: &[PolyId],
    hits: &mut [Hit],
    out: &mut Violations,
) {
    hits.sort_unstable_by_key(|&(a, b, gap, ..)| (a, b, gap));
    for pair in hits.chunk_by(|p, q| (p.0, p.1) == (q.0, q.1)) {
        let gap = pair[0].2;
        let nearest_hits = pair.iter().take_while(|hit| hit.2 == gap);
        let need = nearest_hits
            .clone()
            .map(|hit| hit.3)
            .max()
            .expect("a pair has a hit");
        let found = nearest(nearest_hits.map(|hit| (hit.4, hit.5))).expect("a pair has a hit");
        let shapes = (owners[pair[0].0 as usize], owners[pair[0].1 as usize]);
        out.push(spacing_violation(
            rule,
            layer,
            shapes,
            found,
            Dbu::new_unchecked(need),
        ));
    }
}

/// The hit for two facing edges `e` and `f` of different figures, `gap`
/// apart over `span`, that needed `need`.
fn hit(e: &Edge, f: &Edge, gap: i64, (lo, hi): (i64, i64), need: i64) -> Hit {
    (
        e.figure.min(f.figure),
        e.figure.max(f.figure),
        gap,
        need,
        on_line(e.vertical, e.pos, lo, hi),
        on_line(f.vertical, f.pos, lo, hi),
    )
}

/// Spacing between facing edges of different figures by the classes of
/// both edges' lengths (ASAP7 M1.S.1 to M1.S.5). `examined` counts the facing
/// pairs of edges in different figures closer than the table's largest cell.
pub(crate) fn tip_spacing_table(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    table: &ClassTable,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    let edges = figure_edges(&s.layer_out);
    let widest = table.space.iter().map(|cell| cell.raw()).max().unwrap_or(0);
    // The last class whose threshold the length reaches; the first is 0.
    let class = |len: i64| table.class.partition_point(|t| t.raw() <= len) - 1;
    let (mut hits, mut examined) = (Vec::new(), 0u64);
    each_facing(&edges, widest - 1, |e, f, gap, span| {
        if e.figure == f.figure {
            return;
        }
        examined += 1;
        let need = table.at(class(e.length()), class(f.length())).raw();
        if gap < need {
            hits.push(hit(e, f, gap, span, need));
        }
    });
    report_pairs(rule, layer, &owners, &mut hits, out);
    (Outcome::Ran, examined)
}

/// A gap from `min` to `max`, both included, between facing edges of
/// different figures that run alongside each other for more than `prl`
/// (`LEF58_TWOWIRESFORBIDDENSPACING`). `examined` counts the facing pairs of
/// edges in different figures at most `max` apart running more than `prl`.
pub(crate) fn forbidden_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    (min, max, prl): (Dbu, Dbu, Dbu),
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    let edges = figure_edges(&s.layer_out);
    let (mut hits, mut examined) = (Vec::new(), 0u64);
    each_facing(&edges, max.raw(), |e, f, gap, (lo, hi)| {
        if e.figure == f.figure || hi - lo <= prl.raw() {
            return;
        }
        examined += 1;
        if gap >= min.raw() {
            hits.push(hit(e, f, gap, (lo, hi), max.raw() + 1));
        }
    });
    report_pairs(rule, layer, &owners, &mut hits, out);
    (Outcome::Ran, examined)
}
