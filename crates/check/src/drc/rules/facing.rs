//! Rules read off the edges and corners of the merged layer: facing edges
//! classed by their lengths, gaps in a forbidden range, the space in front of
//! an end of line as LEF defines it and its keep-out box, convex corners as
//! LEF58 spaces them, the spans (chords) of a figure, and the pitch of
//! neighbouring rectangles.
//!
//! Data in: one layer, validated and merged into `s.layer_out`; every rule
//! here reads whole edges of the merged figures, so a side drawn as several
//! strips is one edge. Data out: the violations each kind's
//! [`Rule`](crate::drc::Rule) variant states, named by the lowest drawn row
//! under each figure; a pair of figures reports once, at the middle of the
//! stretch its two nearest offending edges face each other over.

use super::spacing::{line_of, nearest, on_line, spacing_violation};
use super::{centre, clamped, figure_rects, merged, mid, owners_of, ring_segs, Verdict, REFUSED};
use crate::drc::ruleset::{ClassTable, EncloseCut, Eol58, EolParallel, SpanTable};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::derive::merge_into;
use gpurify_geom::ops::{isqrt, Point, Seg};
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};
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
    /// The lengths of the edges meeting it at its low and its high end.
    pub(super) sides: (i64, i64),
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
            // The length of the edge from vertex `i` to the next.
            let len = |i: usize| {
                let j = (i + 1) % n;
                (xs[j].raw() - xs[i].raw()).abs() + (ys[j].raw() - ys[i].raw()).abs()
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
                        // The edge before meets this one at its start, the
                        // low end when it travels up.
                        sides: if forward {
                            (len((i + n - 1) % n), len((i + 1) % n))
                        } else {
                            (len((i + 1) % n), len((i + n - 1) % n))
                        },
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

/// LEF end-of-line spacing (`SPACING ENDOFLINE ... WITHIN`, with
/// `PARALLELEDGE`, `TWOEDGES` and the `LEF58` `ENDTOEND`): each end of line
/// the rule applies to holds the facing edges of other figures in its
/// widened keep-out to `limit`, or to `end_to_end` when the facing edge is an
/// end of line too, with the `LEF58_SPACING ENDOFLINE` qualifiers of
/// `lef58` ([`Eol58`]). `examined` counts the ends of line the rule applies
/// to.
pub(crate) fn eol_within_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    (eol_width, within, limit): (Dbu, Dbu, Dbu),
    (parallel, end_to_end, lef58): (Option<EolParallel>, Option<Dbu>, Eol58),
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let cut_edges = match lef58.enclose_cut {
        None => Vec::new(),
        Some(cut) => match merged(store, cut.cut, s) {
            Some(cuts) => figure_edges(&cuts),
            None => return REFUSED,
        },
    };
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    let edges = figure_edges(&s.layer_out);
    let is_end = |e: &Edge| e.convex && e.length() < eol_width.raw();
    // MINLENGTH / MAXLENGTH: the edges beside the end.
    let sides_hold = |e: &Edge| {
        lef58.side_length.is_none_or(|side| {
            let holds = |l: i64| {
                if side.maximum {
                    l <= side.length.raw()
                } else {
                    l >= side.length.raw()
                }
            };
            let (a, b) = (holds(e.sides.0), holds(e.sides.1));
            if side.two_sides {
                a && b
            } else {
                a || b
            }
        })
    };
    // WRONGDIRSPACING: an end lying along the preferred direction.
    let base = |end: &Edge| match lef58.wrong_dir {
        Some((space, horizontal)) if end.vertical != horizontal => space.raw(),
        _ => limit.raw(),
    };
    let w = within.raw();
    let reach = [
        Some(limit),
        end_to_end,
        lef58.wrong_dir.map(|(space, _)| space),
        lef58.end_prl.map(|(space, _)| space),
    ]
    .into_iter()
    .flatten()
    .map(Dbu::raw)
    .max()
    .unwrap_or(0);
    let (mut hits, mut examined) = (Vec::new(), 0u64);
    for end in edges.iter().filter(|&e| is_end(e)) {
        if !parallel.is_none_or(|p| beside(&edges, end, p, w, lef58)) || !sides_hold(end) {
            continue;
        }
        examined += 1;
        // The facing edges out in front: on the end's orientation, facing
        // back at it, from depth 0 to just under `reach`.
        let (first, last) = if end.faces_up {
            (end.pos, end.pos + reach - 1)
        } else {
            (end.pos - reach + 1, end.pos)
        };
        let from = edges.partition_point(|f| {
            (f.vertical, f.faces_up, f.pos) < (end.vertical, !end.faces_up, first)
        });
        let facing = edges[from..].iter().take_while(|f| {
            f.vertical == end.vertical && f.faces_up != end.faces_up && f.pos <= last
        });
        let own = base(end);
        for f in facing {
            if f.figure == end.figure {
                continue;
            }
            let depth = (f.pos - end.pos).abs();
            let (lo, hi, need) = match lef58.end_prl {
                // ENDPRLSPACING: past the end's own space, a run along the
                // end itself, positive and at most `run`.
                Some((space, run)) if depth >= own => {
                    let (lo, hi) = (f.lo.max(end.lo), f.hi.min(end.hi));
                    if hi <= lo || hi - lo > run.raw() {
                        continue;
                    }
                    (lo, hi, space.raw())
                }
                _ => {
                    let ends = end_to_end.filter(|_| is_end(f));
                    // ENDTOEND EXTENSION: both spans widened by it.
                    let widen = match (ends, lef58.extension) {
                        (Some(_), Some(extension)) => 2 * extension.raw(),
                        _ => w,
                    };
                    let (lo, hi) = (f.lo.max(end.lo - widen), f.hi.min(end.hi + widen));
                    if hi <= lo {
                        continue;
                    }
                    (lo, hi, ends.map_or(own, Dbu::raw))
                }
            };
            if depth < need
                && lef58
                    .opposite_width
                    .is_none_or(|width| narrow_beyond(&edges, end, f, (lo, hi), width.raw()))
                && encloses_cut(&cut_edges, end, f, lef58.enclose_cut)
            {
                hits.push(hit(end, f, depth, (lo, hi), need));
            }
        }
    }
    report_pairs(rule, layer, &owners, &mut hits, out);
    (Outcome::Ran, examined)
}

/// `OPPOSITEWIDTH` ([`Eol58::opposite_width`]): whether the wire beyond the
/// end, whose facing edge is `f`, is narrower than `width` over part of the
/// stretch `lo..hi` it faces the end over: an edge facing back the way `end`
/// faces, less than `width` past `f` into its material, overlapping the
/// stretch by a positive length. The first such edge past `f` bounds `f`'s
/// material, so any one within `width` does.
fn narrow_beyond(edges: &[Edge], end: &Edge, f: &Edge, (lo, hi): (i64, i64), width: i64) -> bool {
    // `f` faces back at the end, so its material lies further out.
    let (from, to) = if end.faces_up {
        (f.pos + 1, f.pos + width - 1)
    } else {
        (f.pos - width + 1, f.pos - 1)
    };
    let first = edges
        .partition_point(|g| (g.vertical, g.faces_up, g.pos) < (end.vertical, end.faces_up, from));
    edges[first..]
        .iter()
        .take_while(|g| g.vertical == end.vertical && g.faces_up == end.faces_up && g.pos <= to)
        .any(|g| g.lo.max(lo) < g.hi.min(hi))
}

/// `ENCLOSECUT` ([`EncloseCut`]): whether a cut edge of `cuts` (the cut
/// layer's merged figure edges, sorted) facing the same way as `end`, its
/// line on `end`'s or behind it into the material by less than `within`, and
/// its span touching
/// `end`'s, lies less than `space` from the facing edge `f`, segment to
/// segment; with `all`, every such cut edge, and at least one. `true` when
/// the rule has no `ENCLOSECUT`.
fn encloses_cut(cuts: &[Edge], end: &Edge, f: &Edge, enclose: Option<EncloseCut>) -> bool {
    let Some(enclose) = enclose else {
        return true;
    };
    let d = enclose.within.raw();
    // Behind the end is where its material lies: below a line facing up.
    let (from, to) = if end.faces_up {
        (end.pos - d + 1, end.pos)
    } else {
        (end.pos, end.pos + d - 1)
    };
    let first = cuts
        .partition_point(|c| (c.vertical, c.faces_up, c.pos) < (end.vertical, end.faces_up, from));
    let space2 = i128::from(enclose.space.raw()).pow(2);
    let mut close = cuts[first..]
        .iter()
        .take_while(|c| c.vertical == end.vertical && c.faces_up == end.faces_up && c.pos <= to)
        .filter(|c| c.lo <= end.hi && end.lo <= c.hi)
        .map(|c| {
            let across = i128::from(c.pos - f.pos);
            let along = i128::from((c.lo.max(f.lo) - c.hi.min(f.hi)).max(0));
            across * across + along * along < space2
        });
    if enclose.all {
        let mut any = false;
        close.all(|near| {
            any = true;
            near
        }) && any
    } else {
        close.any(|near| near)
    }
}

/// Whether a parallel edge runs beside the line that ends at `end` (LEF
/// `PARALLELEDGE`): at its low corner an edge facing up toward the line's
/// side, at its high corner one facing down, its line less than
/// `parallel.space` out from the side's, its span overlapping the stretch
/// from `parallel.within` behind the end's line to `within` past it. Both
/// corners with `two_edges`, either without. With `lef58`'s
/// `subtract_eol_width` the space shrinks by the end's length, and with its
/// `parallel_min_length` a corner whose side is shorter has no parallel edge.
fn beside(edges: &[Edge], end: &Edge, parallel: EolParallel, within: i64, lef58: Eol58) -> bool {
    let space = parallel.space.raw()
        - if lef58.subtract_eol_width {
            end.length()
        } else {
            0
        };
    let back = parallel.within.raw();
    let counts = |side: i64| {
        lef58
            .parallel_min_length
            .is_none_or(|min| side >= min.raw())
    };
    // The stretch along the line's sides, across the end's line.
    let (wlo, whi) = if end.faces_up {
        (end.pos - back, end.pos + within)
    } else {
        (end.pos - within, end.pos + back)
    };
    // An edge across the end, facing `faces_up`, its line from `from` to `to`.
    let side = |faces_up: bool, from: i64, to: i64| {
        let first = edges
            .partition_point(|f| (f.vertical, f.faces_up, f.pos) < (!end.vertical, faces_up, from));
        edges[first..]
            .iter()
            .take_while(|f| f.vertical != end.vertical && f.faces_up == faces_up && f.pos <= to)
            .any(|f| f.lo.max(wlo) < f.hi.min(whi))
    };
    let low = counts(end.sides.0) && side(true, end.lo - space + 1, end.lo);
    let high = counts(end.sides.1) && side(false, end.hi, end.hi + space - 1);
    if parallel.two_edges {
        low && high
    } else {
        low || high
    }
}

/// LEF58 end-of-line keep-out (`LEF58_EOLKEEPOUT`): every other figure whose
/// material overlaps an end of line's box with a positive area, one finding
/// per end and figure, measuring that area. `examined` counts ends of line.
pub(crate) fn eol_keep_out(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    eol_width: Dbu,
    (backward, side, forward): (Dbu, Dbu, Dbu),
    (except_within, corner_only): (Option<(Dbu, Dbu)>, bool),
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    let edges = figure_edges(&s.layer_out);
    // CORNERONLY reads the figures' vertices, by x.
    let mut vertices: Vec<(i64, i64, u32)> = Vec::new();
    if corner_only {
        for figure in
            0..u32::try_from(s.layer_out.len()).expect("a layer indexes polygons with a u32")
        {
            for ring in s.layer_out.poly_rings(figure) {
                let (xs, ys) = ring.coords();
                vertices.extend(xs.iter().zip(ys).map(|(x, y)| (x.raw(), y.raw(), figure)));
            }
        }
        vertices.sort_unstable();
    }
    let material = figure_rects(&s.layer_out);
    let mut examined = 0u64;
    for end in edges
        .iter()
        .filter(|e| e.convex && e.length() < eol_width.raw())
    {
        examined += 1;
        let zone = keep_out_box(end, (backward.raw(), side.raw(), forward.raw()));
        // EXCEPTWITHIN: a figure reaching into a side zone is exempt.
        let exempt = |figure: u32| {
            except_within.is_some_and(|(low, high)| {
                side_zones(
                    end,
                    (backward.raw(), forward.raw()),
                    (low.raw(), high.raw()),
                )
                .into_iter()
                .any(|z| material.overlapping(z).any(|(_, f)| f == figure))
            })
        };
        // Per intruding figure: what it measures and the box of it inside.
        let mut found: Vec<(u32, Measurement, Bbox)> = Vec::new();
        if corner_only {
            let first = vertices.partition_point(|v| v.0 <= zone.xlo.raw());
            let mut inside: Vec<(u32, i64, i64)> = vertices[first..]
                .iter()
                .take_while(|v| v.0 < zone.xhi.raw())
                .filter(|v| zone.ylo.raw() < v.1 && v.1 < zone.yhi.raw() && v.2 != end.figure)
                .map(|&(x, y, figure)| (figure, x, y))
                .collect();
            inside.sort_unstable();
            for corners in inside.chunk_by(|a, b| a.0 == b.0) {
                let bounds = corners.iter().fold(Bbox::EMPTY, |sum, &(_, x, y)| {
                    sum.union(Bbox::point(Dbu::new_unchecked(x), Dbu::new_unchecked(y)))
                });
                let n = u32::try_from(corners.len()).unwrap_or(u32::MAX);
                found.push((corners[0].0, Measurement::Count(n), bounds));
            }
        } else {
            let mut inside: Vec<(u32, Bbox)> = material
                .overlapping(zone)
                .filter(|&(_, figure)| figure != end.figure)
                .map(|(part, figure)| (figure, part))
                .collect();
            inside.sort_unstable_by_key(|&(figure, _)| figure);
            for intruder in inside.chunk_by(|a, b| a.0 == b.0) {
                let area = intruder
                    .iter()
                    .fold(DbuArea::new(0), |sum, &(_, part)| sum + part.area());
                let bounds = intruder
                    .iter()
                    .fold(Bbox::EMPTY, |sum, &(_, part)| sum.union(part));
                found.push((intruder[0].0, Measurement::Area(area), bounds));
            }
        }
        for (figure, measured, bounds) in found {
            if exempt(figure) {
                continue;
            }
            let limit = match measured {
                Measurement::Count(_) => Measurement::Count(0),
                _ => Measurement::Area(DbuArea::new(0)),
            };
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(bounds),
                measured,
                limit,
                shapes: (owners[end.figure as usize], Some(owners[figure as usize])),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// `EXCEPTWITHIN low high`'s side zones of the end `end`: beside each of
/// its corners, from `low` to `high` past it along its line, and across from
/// `backward` behind its line to `forward` past it
/// (`getEolKeepOutExceptWithinRects`).
fn side_zones(end: &Edge, (backward, forward): (i64, i64), (low, high): (i64, i64)) -> [Bbox; 2] {
    let depth = keep_out_box(end, (backward, 0, forward));
    let along = |lo: i64, hi: i64| {
        if end.vertical {
            Bbox {
                ylo: clamped(lo),
                yhi: clamped(hi),
                ..depth
            }
        } else {
            Bbox {
                xlo: clamped(lo),
                xhi: clamped(hi),
                ..depth
            }
        }
    };
    [
        along(end.lo - high, end.lo - low),
        along(end.hi + low, end.hi + high),
    ]
}

/// The keep-out box of the end of line `end`: its span widened by `side` on
/// each side, from `backward` behind its line to `forward` past it, clamped
/// to the coordinate domain.
fn keep_out_box(end: &Edge, (backward, side, forward): (i64, i64, i64)) -> Bbox {
    let (along_lo, along_hi) = (end.lo - side, end.hi + side);
    let (across_lo, across_hi) = if end.faces_up {
        (end.pos - backward, end.pos + forward)
    } else {
        (end.pos - forward, end.pos + backward)
    };
    if end.vertical {
        Bbox {
            xlo: clamped(across_lo),
            ylo: clamped(along_lo),
            xhi: clamped(across_hi),
            yhi: clamped(along_hi),
        }
    } else {
        Bbox {
            xlo: clamped(along_lo),
            ylo: clamped(across_lo),
            xhi: clamped(along_hi),
            yhi: clamped(across_hi),
        }
    }
}

/// Spans (`LEF58_SPANLENGTHTABLE`): every chord a horizontal or vertical line
/// cuts from a merged figure must be a legal length on its axis's list. One
/// finding per maximal region of an unchanged illegal chord. `examined`
/// counts the regions of unchanged chord, both axes.
pub(crate) fn span_length(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    spans: &SpanTable,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    let mut edges = figure_edges(&s.layer_out);
    edges.sort_unstable_by_key(|e| (e.figure, e.vertical));
    let mut examined = 0u64;
    // A figure's vertical edges bound its horizontal chords, measured on the
    // `x` list; its horizontal edges its vertical chords, on `y`.
    for group in edges.chunk_by(|e, f| (e.figure, e.vertical) == (f.figure, f.vertical)) {
        let (figure, across_x) = (group[0].figure, group[0].vertical);
        let legal = if across_x { &spans.x } else { &spans.y };
        // EXCEPTOTHERSPAN: a rectangle's span is held only when its span the
        // other way exceeds the list's exception.
        let poly = s.layer_out.get(figure);
        let rectangle = poly.outer().coords().0.len() == 4 && poly.holes().next().is_none();
        let (box_, except) = (
            poly.bbox(),
            if across_x {
                spans.x_except
            } else {
                spans.y_except
            },
        );
        let other = if across_x {
            box_.height()
        } else {
            box_.width()
        };
        if rectangle && except.is_some_and(|except| other <= except) {
            continue;
        }
        for (lo, hi, from, to) in chords(group) {
            examined += 1;
            let Some(next) = SpanTable::next_legal(legal, hi - lo) else {
                continue;
            };
            let at = |v: i64| Dbu::new_unchecked(v);
            let region = if across_x {
                Bbox {
                    xlo: at(lo),
                    ylo: at(from),
                    xhi: at(hi),
                    yhi: at(to),
                }
            } else {
                Bbox {
                    xlo: at(from),
                    ylo: at(lo),
                    xhi: at(to),
                    yhi: at(hi),
                }
            };
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(region),
                measured: Measurement::Length(at(hi - lo)),
                limit: Measurement::Length(at(next)),
                shapes: (owners[figure as usize], None),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// The chords lines across one figure cut, from its edges of one orientation
/// (`edges`, each with its line `pos` across the chords and its span along
/// them): `(chord lo, chord hi, from, to)`, one per maximal stretch `from..to`
/// of lines over which the chord `lo..hi` stays the same. The lines are read
/// between consecutive ends of the edges, where no vertex lies, and the
/// figure's material between two edges a line crosses alternates (its rings
/// are simple but at pinches, which only meet at such ends).
fn chords(edges: &[Edge]) -> Vec<(i64, i64, i64, i64)> {
    let mut cuts: Vec<i64> = edges.iter().flat_map(|e| [e.lo, e.hi]).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let (mut regions, mut open) = (Vec::new(), Vec::<(i64, i64, i64)>::new());
    let mut crossing = Vec::new();
    for slab in cuts.windows(2) {
        let (from, to) = (slab[0], slab[1]);
        crossing.clear();
        crossing.extend(
            edges
                .iter()
                .filter(|e| e.lo <= from && e.hi >= to)
                .map(|e| e.pos),
        );
        crossing.sort_unstable();
        let (pairs, _) = crossing.as_chunks::<2>();
        // A chord that stops here closes its region; a new one opens one.
        open.retain(|&(lo, hi, start)| {
            let goes_on = pairs.contains(&[lo, hi]);
            if !goes_on {
                regions.push((lo, hi, start, from));
            }
            goes_on
        });
        for &[lo, hi] in pairs {
            if !open.iter().any(|&(l, h, _)| (l, h) == (lo, hi)) {
                open.push((lo, hi, from));
            }
        }
    }
    let end = cuts.last().copied().unwrap_or_default();
    regions.extend(open.into_iter().map(|(lo, hi, start)| (lo, hi, start, end)));
    regions
}

/// A convex corner of a merged figure: its vertex, the diagonal it faces out
/// along (each component ±1), its figure, and whether it is a corner of an
/// end of line.
type Corner = (i64, i64, i64, i64, u32, bool);

/// Every convex corner of `figures` (a merged layer), sorted; with `eol`, a
/// corner on an edge strictly shorter than `eol` whose two corners are
/// convex is marked as an end of line's.
fn figure_corners(figures: &ValidatedLayer, eol: Option<i64>) -> Vec<Corner> {
    let mut corners = Vec::new();
    for figure in 0..u32::try_from(figures.len()).expect("a layer indexes polygons with a u32") {
        for ring in figures.poly_rings(figure) {
            let (xs, ys) = ring.coords();
            let n = xs.len();
            let step = |i: usize| {
                let next = (i + 1) % n;
                (xs[next].raw() - xs[i].raw(), ys[next].raw() - ys[i].raw())
            };
            // Vertex `i` turns from edge `i - 1` into edge `i`; a left turn is
            // convex, and its outward diagonal is along the edge coming in,
            // against the one leaving.
            let turn = |i: usize| {
                let ((inx, iny), (outx, outy)) = (step((i + n - 1) % n), step(i));
                let convex =
                    i128::from(inx) * i128::from(outy) > i128::from(iny) * i128::from(outx);
                (convex, (inx - outx).signum(), (iny - outy).signum())
            };
            // Edge `i` runs from vertex `i` to `i + 1`.
            let end = |i: usize| {
                let (dx, dy) = step(i);
                eol.is_some_and(|w| dx.abs() + dy.abs() < w && turn(i).0 && turn((i + 1) % n).0)
            };
            for i in 0..n {
                let (convex, sx, sy) = turn(i);
                if convex {
                    let on_end = end((i + n - 1) % n) || end(i);
                    corners.push((xs[i].raw(), ys[i].raw(), sx, sy, figure, on_end));
                }
            }
        }
    }
    corners.sort_unstable();
    corners
}

/// `LEF58_CORNERSPACING CONVEXCORNER`: facing convex corners of different
/// figures closer than `limit` by the larger axis gap, or Euclidean with
/// `corner_to_corner`; with `except_eol`, an end of line's corners on either
/// figure are exempt. `examined` counts the facing pairs of corners judged.
pub(crate) fn convex_corner_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    (corner_to_corner, except_eol): (bool, Option<Dbu>),
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    let corners = figure_corners(&s.layer_out, except_eol.map(Dbu::raw));
    let reach = limit.raw();
    let need = if corner_to_corner {
        i128::from(reach) * i128::from(reach)
    } else {
        i128::from(reach)
    };
    let point = |x: i64, y: i64| {
        let p = Point {
            x: Dbu::new_unchecked(x),
            y: Dbu::new_unchecked(y),
        };
        Seg { a: p, b: p }
    };
    let (mut hits, mut examined) = (Vec::new(), 0u64);
    // Each corner facing +x against the corners right of it, facing back.
    for &(x, y, _, sy, figure, on_end) in corners.iter().filter(|c| c.2 > 0) {
        let from = corners.partition_point(|c| c.0 <= x);
        let near = corners[from..].iter().take_while(|c| c.0 - x < reach);
        for &(cx, cy, csx, csy, other, other_on_end) in near {
            let facing = csx < 0 && csy == -sy && (cy - y).signum() == sy;
            if !facing || other == figure || on_end || other_on_end {
                continue;
            }
            examined += 1;
            let (dx, dy) = (i128::from(cx - x), i128::from((cy - y).abs()));
            let gap = if corner_to_corner {
                dx * dx + dy * dy
            } else {
                dx.max(dy)
            };
            if gap < need {
                hits.push((
                    figure.min(other),
                    figure.max(other),
                    gap,
                    point(x, y),
                    point(cx, cy),
                ));
            }
        }
    }
    hits.sort_unstable_by_key(|&(a, b, gap, ..)| (a, b, gap));
    for pair in hits.chunk_by(|p, q| (p.0, p.1) == (q.0, q.1)) {
        let gap = pair[0].2;
        let (_, at) = nearest(
            pair.iter()
                .take_while(|hit| hit.2 == gap)
                .map(|hit| (hit.3, hit.4)),
        )
        .expect("a pair has a hit");
        let measured = if corner_to_corner {
            isqrt(DbuArea::new(gap))
        } else {
            Dbu::new_unchecked(i64::try_from(gap).expect("an axis gap under the limit"))
        };
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at,
            measured: Measurement::Length(measured),
            limit: Measurement::Length(limit),
            shapes: (owners[pair[0].0 as usize], Some(owners[pair[0].1 as usize])),
        });
    }
    (Outcome::Ran, examined)
}

/// Exact pitch between neighbouring rectangles along one axis (ASAP7
/// FIN.S.1, GATE.S.1): each rectangle's neighbours past it on the axis, the
/// nearest that overlap it across, must have their centre lines exactly
/// `pitch` apart. A layer with a figure that is not a rectangle is refused.
/// `examined` counts the neighbouring pairs.
pub(crate) fn exact_pitch(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    vertical: bool,
    pitch: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(owners) = merged_owners(store, layer, s) else {
        return REFUSED;
    };
    // Each rectangle as (lo, hi) along the pitch's axis, then (lo, hi)
    // across it, and its figure.
    let mut rects = Vec::with_capacity(s.layer_out.len());
    for figure in 0..u32::try_from(s.layer_out.len()).expect("a layer indexes polygons with a u32")
    {
        let polygon = s.layer_out.get(figure);
        if polygon.outer().coords().0.len() != 4 || polygon.holes().next().is_some() {
            return REFUSED;
        }
        let b = polygon.bbox();
        rects.push(if vertical {
            (b.ylo, b.yhi, b.xlo, b.xhi, figure)
        } else {
            (b.xlo, b.xhi, b.ylo, b.yhi, figure)
        });
    }
    rects.sort_unstable();
    let mut examined = 0u64;
    for &(lo, hi, across_lo, across_hi, figure) in &rects {
        // ponytail: scans past every rectangle that starts beyond this one
        // until the nearest overlapping row; quadratic for columns that never
        // overlap across.
        let first = rects.partition_point(|r| r.0 < hi);
        let mut row = None;
        for &(next_lo, next_hi, next_across_lo, next_across_hi, other) in &rects[first..] {
            if row.is_some_and(|nearest| next_lo > nearest) {
                break;
            }
            let (from, to) = (across_lo.max(next_across_lo), across_hi.min(next_across_hi));
            if to <= from {
                continue;
            }
            row = Some(next_lo);
            examined += 1;
            // Twice the distance between the centre lines, exact.
            let twice = (next_lo.raw() + next_hi.raw()) - (lo.raw() + hi.raw());
            if twice == 2 * pitch.raw() {
                continue;
            }
            let (along, across) = (mid(hi, next_lo), mid(from, to));
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: if vertical {
                    Point {
                        x: across,
                        y: along,
                    }
                } else {
                    Point {
                        x: along,
                        y: across,
                    }
                },
                measured: Measurement::Length(Dbu::new_unchecked(twice.div_euclid(2))),
                limit: Measurement::Length(pitch),
                shapes: (owners[figure as usize], Some(owners[other as usize])),
            });
        }
    }
    (Outcome::Ran, examined)
}
