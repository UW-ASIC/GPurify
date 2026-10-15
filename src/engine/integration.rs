//! System-on-chip integration checks on a DEF design (catalog FLOW-003): what a
//! placed-and-routed block must satisfy beyond its shapes' design rules.
//! They run with DRC when the layout is a DEF.
//!
//! Data in: the design as read ([`Design`]: the DEF and its LEF library).
//! Data out: violations and one [`RuleRun`] per check, under these ids:
//!
//! | Id | Flags | Defined by |
//! |---|---|---|
//! | `def.fill_outside_die` | a `FILLS` shape not wholly inside the `DIEAREA` | IC Validator's "fill outside boundary"; DEF `DIEAREA` (LEF/DEF 5.8 p. 245) |
//! | `def.component_outside_die` | a placed component whose `SIZE` box is not wholly inside the `DIEAREA` | IC Validator's block/pad-ring checks; DEF `COMPONENTS` placement (p. 244) |
//! | `def.component_overlap` | two placed components whose boxes overlap in area, `COVER` macros (bumps over the core) aside | IC Validator's "block/pad-ring overlap"; LEF `CLASS COVER`: "the MACRO SIZE statement does not affect the placers" (p. 114) |
//! | `def.off_site` | a placed `CORE` component whose placement point is no site of any `ROW` | DEF `ROW … DO … STEP` (p. 299): a row's sites are `origin + k·step`; LEF `CLASS CORE` cells are placed in rows |
//! | `def.pin_off_track` | a placed DEF pin whose shape's centre is on no routing track of its layer | IC Validator's "ports off grid"; DEF `TRACKS` (p. 336) |
//! | `def.off_manufacturing_grid` | a shape vertex that is not a multiple of the LEF `MANUFACTURINGGRID` | LEF `MANUFACTURINGGRID`: "shapes and cells are placed in locations that snap to the manufacturing grid" (p. 148) |
//! | `def.cell_edge_spacing` | two placed cells' typed edges closer than the library's `LEF58_CELLEDGESPACINGTABLE` allows for their two types | the ISPD 2014 placement contest's Benchmark Suite A (slide 16: "Each vertical edge of a cell may have specified minimum spacings from any other vertical cell edge that can be placed right or left of it"; slide 27: the `LEF58_CELLEDGESPACINGTABLE` and `LEF58_EDGETYPE` properties); the ICCAD 2017 Problem C FAQ ("for a pair of edge types, the edge spacing rules are symmetric") |
//!
//! Cell edge spacing (catalog DRC-127). A macro's `LEF58_EDGETYPE` types
//! a side of its `SIZE` box, or a stretch of it (`CELLROW n` the `n`-th row
//! the cell spans, of the height of the first DEF row's site; `HALFROW n` a
//! half row; `RANGE b e` along a top or bottom side); each typed edge is
//! placed with its component, so a mirrored cell's `LEFT` edge lies on its
//! right. Two parallel typed edges of different components, sharing a
//! stretch of positive length, are held to the table's spacing for their
//! types, the last entry naming the pair; the gap is the distance between
//! their lines, and any two parallel edges count, a left against a left as
//! the contest's slide states ("the left edge of every ao22s01 cell must be
//! placed at least 0.400um away from the left edge of every other"), not
//! only edges facing each other. `EXCEPTABUTTED` exempts two edges with no
//! gap, which only its name defines. A filler (`CLASS CORE SPACER`) has no
//! edges. Not checked, as no public text defines them: an entry carrying
//! `EXCEPTNONFILLERINBETWEEN`, `OPTIONAL`, `SOFT` or `EXACT`; a `DEFAULT`
//! type for a side no statement types. A `RANGE` on a vertical side or a
//! `CELLROW` or `HALFROW` on a horizontal one types the whole side. Each
//! finding sits at the middle of the shared stretch, between the two lines,
//! measuring the gap against the spacing.
//!
//! A check with nothing to examine (no rows, no tracks for a pin's layer,
//! no manufacturing grid) runs and examines nothing; one whose input is
//! absent is not refused, since a DEF need not state it. The violation sits
//! at the offending shape's or component's lower-left corner, on no layer.
//!
//! IC Validator's "macro synchronization" (a macro's layout against its
//! abstract) is not checked here: it needs the macro's own GDS.

use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::{ops::Point, Dbu, DbuArea, LayerId, PolyId, StrTable};
use gpurify_ingest::lefdef::{flatten, Design, EdgeSide, EdgeSpan, Origin, Pt};

/// The checks' ids, in report order.
pub const RULE_IDS: [&str; 7] = [
    "def.fill_outside_die",
    "def.component_outside_die",
    "def.component_overlap",
    "def.off_site",
    "def.pin_off_track",
    "def.off_manufacturing_grid",
    "def.cell_edge_spacing",
];

/// Interns [`RULE_IDS`], so [`check`] can run on a shared string table.
pub fn intern_rule_ids(strings: &mut StrTable) {
    for id in RULE_IDS {
        strings.intern(id);
    }
}

/// Whether `p` is inside the rectilinear ring or on its boundary.
fn inside(ring: &[Pt], (x, y): Pt) -> bool {
    let n = ring.len();
    let mut crossings = false;
    for k in 0..n {
        let (a, b) = (ring[k], ring[(k + 1) % n]);
        // On the edge.
        let (xlo, xhi, ylo, yhi) = (a.0.min(b.0), a.0.max(b.0), a.1.min(b.1), a.1.max(b.1));
        if (a.0 == b.0 && x == a.0 && (ylo..=yhi).contains(&y))
            || (a.1 == b.1 && y == a.1 && (xlo..=xhi).contains(&x))
        {
            return true;
        }
        // A vertical edge to the right of p crossing its row (half-open in y).
        if a.0 == b.0 && a.0 > x && ylo <= y && y < yhi {
            crossings = !crossings;
        }
    }
    crossings
}

/// Whether simple rectilinear `ring` lies wholly inside simple rectilinear
/// `die`: every vertex of `ring` in `die` (boundary included), no vertex of
/// `die` strictly inside `ring`, and no edge of `die` crossing an edge of
/// `ring` at a point inside both. If `ring` left `die`, the die's boundary
/// would enter `ring`'s interior, through a vertex or a crossing.
fn contained(ring: &[Pt], die: &[Pt]) -> bool {
    if !ring.iter().all(|&p| inside(die, p)) {
        return false;
    }
    if die
        .iter()
        .any(|&p| inside(ring, p) && !on_boundary(ring, p))
    {
        return false;
    }
    let edges = |r: &[Pt]| -> Vec<(Pt, Pt)> {
        (0..r.len()).map(|k| (r[k], r[(k + 1) % r.len()])).collect()
    };
    let (ring_edges, die_edges) = (edges(ring), edges(die));
    // A vertical edge `v` and a horizontal edge `h` crossing inside both.
    let cross = |v: (Pt, Pt), h: (Pt, Pt)| {
        let (x, (ya, yb)) = (v.0 .0, (v.0 .1.min(v.1 .1), v.0 .1.max(v.1 .1)));
        let (y, (xa, xb)) = (h.0 .1, (h.0 .0.min(h.1 .0), h.0 .0.max(h.1 .0)));
        v.0 .0 == v.1 .0 && h.0 .1 == h.1 .1 && xa < x && x < xb && ya < y && y < yb
    };
    !ring_edges
        .iter()
        .any(|&a| die_edges.iter().any(|&b| cross(a, b) || cross(b, a)))
}

fn on_boundary(ring: &[Pt], (x, y): Pt) -> bool {
    let n = ring.len();
    (0..n).any(|k| {
        let (a, b) = (ring[k], ring[(k + 1) % n]);
        (a.0 == b.0 && x == a.0 && (a.1.min(b.1)..=a.1.max(b.1)).contains(&y))
            || (a.1 == b.1 && y == a.1 && (a.0.min(b.0)..=a.0.max(b.0)).contains(&x))
    })
}

/// A box `(xlo, ylo, xhi, yhi)`.
type Box4 = (i64, i64, i64, i64);

/// Every placed component's box `(xlo, ylo, xhi, yhi)` and its macro's
/// class, by component index; `None` for an unplaced one or an unknown
/// macro.
fn component_boxes(design: &Design) -> Vec<Option<(Box4, &str)>> {
    design
        .def
        .components
        .iter()
        .map(|comp| {
            let (at, orient) = comp.placement?;
            let model = design.lef.macros.iter().find(|m| m.name == comp.model)?;
            let (a, b) = (orient.apply((0, 0)), orient.apply(model.size));
            let (w, h) = ((a.0 - b.0).abs(), (a.1 - b.1).abs());
            Some(((at.0, at.1, at.0 + w, at.1 + h), model.class.as_str()))
        })
        .collect()
}

/// Runs every check of the module docs on `design`, appending violations
/// and one run per check. Ids must be interned ([`intern_rule_ids`]).
///
/// # Panics
///
/// If an id was not interned.
pub fn check(design: &Design, strings: &StrTable, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let id = |name: &str| strings.get(name).expect("integration ids are interned");
    let mut row = |rule: &str, examined: u64, found: Vec<(Pt, Measurement, Measurement)>| {
        let rule = id(rule);
        for (at, measured, limit) in &found {
            out.push(Violation {
                rule,
                layer: LayerId(u16::MAX),
                severity: Severity::Error,
                at: Point {
                    x: Dbu::new_unchecked(at.0),
                    y: Dbu::new_unchecked(at.1),
                },
                measured: *measured,
                limit: *limit,
                shapes: (PolyId(u32::MAX), None),
            });
        }
        runs.push(RuleRun {
            rule,
            outcome: Outcome::Ran,
            examined,
            violations: u32::try_from(found.len()).unwrap_or(u32::MAX),
        });
    };
    let count = |n: usize| u64::try_from(n).expect("a count");
    let zero = Measurement::Area(DbuArea::new(0));
    let die = &design.def.die_area;

    // Fill outside the die: the area of the shape's box, against none.
    let mut found = Vec::new();
    let mut examined = 0;
    let fills = flatten(&design.def, &design.lef).unwrap_or_default();
    for shape in fills.iter().filter(|s| s.origin == Origin::Fill) {
        examined += 1;
        if !die.is_empty() && !contained(&shape.shape.ring, die) {
            let (x0, y0, x1, y1) = shape.shape.bbox();
            let area = DbuArea::new(i128::from(x1 - x0) * i128::from(y1 - y0));
            found.push(((x0, y0), Measurement::Area(area), zero));
        }
    }
    row("def.fill_outside_die", examined, found);

    let boxes = component_boxes(design);
    let mut found = Vec::new();
    for &((x0, y0, x1, y1), _) in boxes.iter().flatten() {
        let ring = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)];
        if !die.is_empty() && !contained(&ring, die) {
            let area = DbuArea::new(i128::from(x1 - x0) * i128::from(y1 - y0));
            found.push(((x0, y0), Measurement::Area(area), zero));
        }
    }
    row(
        "def.component_outside_die",
        count(boxes.iter().flatten().count()),
        found,
    );

    // Overlaps: a sweep in x over the boxes, COVER macros aside.
    let mut solid: Vec<(i64, i64, i64, i64)> = boxes
        .iter()
        .flatten()
        .filter(|(_, class)| *class != "COVER")
        .map(|&(b, _)| b)
        .collect();
    solid.sort_unstable();
    let mut found = Vec::new();
    for (k, a) in solid.iter().enumerate() {
        for b in solid[k + 1..].iter().take_while(|b| b.0 < a.2) {
            let (w, h) = (a.2.min(b.2) - b.0, a.3.min(b.3) - a.1.max(b.1));
            if w > 0 && h > 0 {
                let area = DbuArea::new(i128::from(w) * i128::from(h));
                found.push(((b.0, a.1.max(b.1)), Measurement::Area(area), zero));
            }
        }
    }
    row("def.component_overlap", count(solid.len()), found);

    // Off site: a CORE component's placement point on no row's site.
    let rows = &design.def.rows;
    let on_site = |(x, y): Pt| {
        rows.iter().any(|r| {
            let on = |v: i64, origin: i64, step: i64, num: i64| {
                let d = v - origin;
                if step == 0 {
                    d == 0
                } else {
                    d % step == 0 && (0..num).contains(&(d / step))
                }
            };
            on(x, r.origin.0, r.step.0, r.num.0) && on(y, r.origin.1, r.step.1, r.num.1)
        })
    };
    let mut found = Vec::new();
    let mut examined = 0;
    if !rows.is_empty() {
        for (comp, placed) in design.def.components.iter().zip(&boxes) {
            let (Some((at, _)), Some((_, "CORE"))) = (comp.placement, placed) else {
                continue;
            };
            examined += 1;
            if !on_site(at) {
                found.push((at, Measurement::Count(0), Measurement::Count(1)));
            }
        }
    }
    row("def.off_site", examined, found);

    // Pins off track: the shape's centre on a track of its layer.
    let on_track = |layer: &str, (x, y): Pt| -> Option<bool> {
        let tracks: Vec<_> = design
            .def
            .tracks
            .iter()
            .filter(|t| t.layers.iter().any(|l| l == layer))
            .collect();
        if tracks.is_empty() {
            return None;
        }
        Some(tracks.iter().any(|t| {
            let v = if t.x { x } else { y };
            let d = v - t.start;
            t.step > 0 && d % t.step == 0 && (0..t.count).contains(&(d / t.step))
        }))
    };
    let mut found = Vec::new();
    let mut examined = 0;
    for pin in &design.def.pins {
        for shape in &pin.shapes {
            let (x0, y0, x1, y1) = shape.bbox();
            // A centre between two grid points is on no track.
            if (x0 + x1) % 2 != 0 || (y0 + y1) % 2 != 0 {
                examined += 1;
                found.push(((x0, y0), Measurement::Count(0), Measurement::Count(1)));
                continue;
            }
            match on_track(&shape.layer, (x0.midpoint(x1), y0.midpoint(y1))) {
                None => {}
                Some(on) => {
                    examined += 1;
                    if !on {
                        found.push(((x0, y0), Measurement::Count(0), Measurement::Count(1)));
                    }
                }
            }
        }
    }
    row("def.pin_off_track", examined, found);

    // Manufacturing grid: every vertex of every shape drawn.
    let mut found = Vec::new();
    let mut examined = 0;
    if let Some(grid) = design.lef.manufacturing_grid.filter(|&g| g > 0) {
        for shape in &fills {
            examined += 1;
            if let Some(&(x, y)) = shape
                .shape
                .ring
                .iter()
                .find(|&&(x, y)| x % grid != 0 || y % grid != 0)
            {
                found.push((
                    (x, y),
                    Measurement::Length(Dbu::new_unchecked(
                        x.rem_euclid(grid).max(y.rem_euclid(grid)),
                    )),
                    Measurement::Length(Dbu::new_unchecked(0)),
                ));
            }
        }
    }
    row("def.off_manufacturing_grid", examined, found);

    let (examined, found) = cell_edge_spacing(design);
    row("def.cell_edge_spacing", examined, found);
}

/// One typed cell edge as placed: on the line `x = at` (vertical) or `y =
/// at`, from `lo` to `hi` along it, of type `kind` (an index into the
/// table's names), on component `comp`.
#[derive(Debug, Clone, Copy)]
struct PlacedEdge {
    vertical: bool,
    at: i64,
    lo: i64,
    hi: i64,
    kind: usize,
    comp: usize,
}

/// Every typed edge of every placed, non-filler component whose type the
/// library's `LEF58_CELLEDGESPACINGTABLE` names, and the names.
fn placed_edges(design: &Design) -> (Vec<PlacedEdge>, Vec<&str>) {
    let lef = &design.lef;
    let mut names: Vec<&str> = Vec::new();
    for entry in &lef.cell_edge_spacing {
        for name in [entry.first.as_str(), entry.second.as_str()] {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    // A cell spans whole rows of the first row's site.
    let row_height = design
        .def
        .rows
        .first()
        .and_then(|row| lef.sites.iter().find(|(name, _)| *name == row.site))
        .map_or(0, |(_, size)| size.1);
    let mut edges = Vec::new();
    for (comp, component) in design.def.components.iter().enumerate() {
        let Some((at, orient)) = component.placement else {
            continue;
        };
        let Some(cell) = lef.macros.iter().find(|m| m.name == component.model) else {
            continue;
        };
        if cell.spacer {
            continue;
        }
        let (w, h) = cell.size;
        let rows = if row_height > 0 {
            (h / row_height).max(1)
        } else {
            1
        };
        let per_row = h / rows;
        let (a, b) = (orient.apply((0, 0)), orient.apply((w, h)));
        let corner = (a.0.min(b.0), a.1.min(b.1));
        let place = |p: Pt| {
            let q = orient.apply(p);
            (at.0 + q.0 - corner.0, at.1 + q.1 - corner.1)
        };
        for edge in &cell.edge_types {
            let Some(kind) = names.iter().position(|&n| n == edge.name) else {
                continue;
            };
            let vertical = matches!(edge.side, EdgeSide::Left | EdgeSide::Right);
            let (lo, hi) = match (edge.span, vertical) {
                (EdgeSpan::CellRow(k), true) => {
                    let k = i64::from(k);
                    ((k - 1) * per_row, (k * per_row).min(h))
                }
                (EdgeSpan::HalfRow(k), true) => {
                    let k = i64::from(k);
                    ((k - 1) * per_row / 2, (k * per_row / 2).min(h))
                }
                (EdgeSpan::Range(lo, hi), false) => (lo, hi),
                _ if vertical => (0, h),
                _ => (0, w),
            };
            let (p, q) = match edge.side {
                EdgeSide::Left => ((0, lo), (0, hi)),
                EdgeSide::Right => ((w, lo), (w, hi)),
                EdgeSide::Bottom => ((lo, 0), (hi, 0)),
                EdgeSide::Top => ((lo, h), (hi, h)),
            };
            let (p, q) = (place(p), place(q));
            let vertical = p.0 == q.0;
            let (at, lo, hi) = if vertical {
                (p.0, p.1.min(q.1), p.1.max(q.1))
            } else {
                (p.1, p.0.min(q.0), p.0.max(q.0))
            };
            edges.push(PlacedEdge {
                vertical,
                at,
                lo,
                hi,
                kind,
                comp,
            });
        }
    }
    (edges, names)
}

/// The cell edge spacing check (`def.cell_edge_spacing`): `examined` typed
/// edges, and per pair too close `(at, measured, limit)`.
fn cell_edge_spacing(design: &Design) -> (u64, Vec<(Pt, Measurement, Measurement)>) {
    let (mut edges, names) = placed_edges(design);
    // The spacing between two types, either way round: the last entry that
    // names the pair, unless it carries an undefined option.
    let spacing = |a: usize, b: usize| {
        design
            .lef
            .cell_edge_spacing
            .iter()
            .rev()
            .find(|e| {
                let (x, y) = (e.first.as_str(), e.second.as_str());
                (x, y) == (names[a], names[b]) || (y, x) == (names[a], names[b])
            })
            .filter(|e| e.undefined.is_empty())
    };
    let reach = design
        .lef
        .cell_edge_spacing
        .iter()
        .map(|e| e.spacing)
        .max()
        .unwrap_or(0);
    edges.sort_unstable_by_key(|e| (e.vertical, e.at, e.lo, e.hi, e.comp, e.kind));
    let mut found = Vec::new();
    for (i, a) in edges.iter().enumerate() {
        for b in edges[i + 1..]
            .iter()
            .take_while(|b| b.vertical == a.vertical && b.at - a.at < reach)
        {
            let run = (a.lo.max(b.lo), a.hi.min(b.hi));
            if a.comp == b.comp || run.0 >= run.1 {
                continue;
            }
            let Some(entry) = spacing(a.kind, b.kind) else {
                continue;
            };
            let gap = b.at - a.at;
            if gap >= entry.spacing || (gap == 0 && entry.except_abutted) {
                continue;
            }
            let along = run.0.midpoint(run.1);
            let at = if a.vertical {
                (a.at.midpoint(b.at), along)
            } else {
                (along, a.at.midpoint(b.at))
            };
            found.push((
                at,
                Measurement::Length(Dbu::new_unchecked(gap)),
                Measurement::Length(Dbu::new_unchecked(entry.spacing)),
            ));
        }
    }
    (u64::try_from(edges.len()).expect("a count"), found)
}

#[cfg(test)]
mod tests {
    use super::{cell_edge_spacing, contained, inside};
    use gpurify_check::report::Measurement;
    use gpurify_ingest::lefdef::{read_def, read_lef_into, Design, Lef};

    /// A library at 2000 database units per micrometre with a 0.19 x 1.4 um
    /// site, the edge-spacing `table`, and two cells: `ONE`, 0.76 um wide and
    /// one row tall, typed `one`; `TWO`, as wide and two rows tall, typed
    /// `two`; each `LEF58_EDGETYPE` statement as given.
    fn library(table: &str, one: &str, two: &str) -> Lef {
        let text = format!(
            "VERSION 5.8 ;
PROPERTYDEFINITIONS
  LIBRARY LEF58_CELLEDGESPACINGTABLE STRING \"CELLEDGESPACINGTABLE {table} ;\" ;
  MACRO LEF58_EDGETYPE STRING ;
END PROPERTYDEFINITIONS
SITE core
  SIZE 0.19 BY 1.4 ;
END core
MACRO ONE
  CLASS CORE ;
  SIZE 0.76 BY 1.4 ;
  PROPERTY LEF58_EDGETYPE \"{one}\" ;
END ONE
MACRO TWO
  CLASS CORE ;
  SIZE 0.76 BY 2.8 ;
  PROPERTY LEF58_EDGETYPE \"{two}\" ;
END TWO
MACRO FILL
  CLASS CORE SPACER ;
  SIZE 0.38 BY 1.4 ;
  PROPERTY LEF58_EDGETYPE \"EDGETYPE LEFT E2 ; EDGETYPE RIGHT E2 ;\" ;
END FILL
END LIBRARY
"
        );
        let mut lef = Lef::default();
        read_lef_into(&text, 2000, &mut lef).expect("the library reads");
        lef
    }

    /// The `(gap, spacing)` of each finding on `components` (`name model x y
    /// orient` lines) over `lef`, with rows of `core` sites from y = 0.
    fn gaps(lef: Lef, components: &[&str]) -> Vec<(i64, i64)> {
        let def = format!(
            "VERSION 5.8 ;
DESIGN top ;
UNITS DISTANCE MICRONS 2000 ;
DIEAREA ( 0 0 ) ( 40000 28000 ) ;
ROW r0 core 0 0 N DO 100 BY 1 STEP 380 0 ;
COMPONENTS {} ;
{}
END COMPONENTS
END DESIGN
",
            components.len(),
            components
                .iter()
                .map(|line| {
                    let f: Vec<&str> = line.split_whitespace().collect();
                    format!(
                        "- {} {} + PLACED ( {} {} ) {} ;",
                        f[0], f[1], f[2], f[3], f[4]
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        );
        let def = read_def(&def, &lef).expect("the design reads");
        let (_, found) = cell_edge_spacing(&Design { def, lef });
        found
            .into_iter()
            .map(|(_, gap, spacing)| match (gap, spacing) {
                (Measurement::Length(g), Measurement::Length(s)) => (g.raw(), s.raw()),
                other => panic!("a gap is a length, not {other:?}"),
            })
            .collect()
    }

    /// Catalog DRC-127.
    ///
    /// Oracle: hand-derived from OpenROAD's dpl test
    /// `mirror_edge_spacing`
    /// (its LEF and DEF, R4's reading): `E2 E2 0.5` (1000 units); `ONE` has
    /// an untyped-in-the-table `E1` left and an `E2` right. At x 3800 and
    /// 5320, both N, the `E2` edges are 1520 apart: clean. Mirrored (FN), the
    /// second's `E2` lies on its left, at 5320, on the first's: one finding,
    /// 0 against 1000; `EXCEPTABUTTED` exempts it; `SOFT` leaves the entry
    /// unchecked. A filler between them is no cell. Breaks if mirroring does
    /// not move the edge, a type absent from the table is held, or an
    /// undefined option is read as a rule.
    #[test]
    fn a_mirrored_cell_brings_its_typed_edge_onto_its_neighbours() {
        let one = "EDGETYPE LEFT E1 ; EDGETYPE RIGHT E2 ;";
        let two = "EDGETYPE LEFT E2 ;";
        let pair = |table: &str, orient: &str| {
            gaps(
                library(table, one, two),
                &["u1 ONE 3800 0 N", &format!("u2 ONE 5320 0 {orient}")],
            )
        };
        assert_eq!(pair("EDGETYPE E2 E2 0.5", "N"), []);
        assert_eq!(pair("EDGETYPE E2 E2 0.5", "FN"), [(0, 1000)]);
        assert_eq!(pair("EDGETYPE E2 E2 EXCEPTABUTTED 0.5", "FN"), []);
        assert_eq!(pair("EDGETYPE E2 E2 SOFT 0.5", "FN"), []);
        let filler = gaps(
            library("EDGETYPE E2 E2 0.5", one, two),
            &["u1 ONE 3800 0 N", "f FILL 5320 0 N"],
        );
        assert_eq!(filler, []);
    }

    /// Catalog DRC-127.
    ///
    /// Oracle: hand-derived from OpenROAD's dpl test
    /// `edge_spacing`: a
    /// two-row cell typed `E1` on its first row and `E2` on its second, both
    /// sides, under `E1 E1 0.1 E2 E2 0.5` (200 and 1000 units). Two such
    /// cells 1140 apart: clean (E1/E1 needs 200, E2/E2 1000). 760 apart: the
    /// second rows' E2 edges, one finding 760 against 1000. A one-row `E1`
    /// cell abutting the first on its second row meets an `E2` edge, a pair
    /// the table does not name, and touches its first row's `E1` edge only
    /// at a point: nothing. Breaks if `CELLROW` is not the row's stretch or
    /// a point contact counts as a run.
    #[test]
    fn cellrow_types_one_row_of_a_tall_cells_side() {
        let two = "EDGETYPE LEFT E1 CELLROW 1 ; EDGETYPE LEFT E2 CELLROW 2 ; \
                   EDGETYPE RIGHT E1 CELLROW 1 ; EDGETYPE RIGHT E2 CELLROW 2 ;";
        let one = "EDGETYPE LEFT E1 ; EDGETYPE RIGHT E1 ;";
        let table = "EDGETYPE E1 E1 0.1 EDGETYPE E2 E2 0.5";
        let run = |second: i64| {
            gaps(
                library(table, one, two),
                &[
                    "u2 TWO 7220 0 N",
                    &format!("r3 TWO {second} 0 N"),
                    "r2 ONE 5700 2800 N",
                ],
            )
        };
        assert_eq!(run(9880), []);
        assert_eq!(run(9500), [(760, 1000)]);
    }

    /// Oracle: hand-derived on an L-shaped die `(0,0)-(100,0)-(100,50)-
    /// (50,50)-(50,100)-(0,100)` and a U-shaped one with a notch from x =
    /// 30 to 70 down to y = 40: a box in the L's foot is inside, the
    /// boundary counts as inside (DEF lets a shape touch the die edge), and
    /// a box bridging the U's notch is outside although all four of its
    /// corners are inside and no die vertex is in it.
    #[test]
    fn containment_in_an_l_and_a_u_shaped_die() {
        let die = [(0, 0), (100, 0), (100, 50), (50, 50), (50, 100), (0, 100)];
        let rect = |x0, y0, x1, y1| [(x0, y0), (x1, y0), (x1, y1), (x0, y1)];
        assert!(inside(&die, (100, 50)) && inside(&die, (10, 10)));
        assert!(!inside(&die, (75, 75)));
        assert!(contained(&rect(0, 0, 100, 50), &die));
        assert!(contained(&rect(10, 10, 40, 90), &die));
        assert!(!contained(&rect(40, 40, 60, 60), &die));
        assert!(!contained(&rect(90, 40, 110, 45), &die));
        let u = [
            (0, 0),
            (100, 0),
            (100, 100),
            (70, 100),
            (70, 40),
            (30, 40),
            (30, 100),
            (0, 100),
        ];
        assert!(!contained(&rect(10, 50, 90, 60), &u));
        assert!(contained(&rect(10, 10, 90, 40), &u));
        assert!(contained(&rect(70, 50, 100, 60), &u));
    }
}
