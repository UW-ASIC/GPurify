//! SoC integration checks on a DEF design (catalog FLOW-003): what a
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
use gpurify_ingest::lefdef::{flatten, Design, Origin, Pt};

/// The checks' ids, in report order.
pub const RULE_IDS: [&str; 6] = [
    "def.fill_outside_die",
    "def.component_outside_die",
    "def.component_overlap",
    "def.off_site",
    "def.pin_off_track",
    "def.off_manufacturing_grid",
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

/// Every placed component's box `(xlo, ylo, xhi, yhi)` and its macro's
/// class, by component index; `None` for an unplaced one or an unknown
/// macro.
fn component_boxes(design: &Design) -> Vec<Option<((i64, i64, i64, i64), &str)>> {
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
            match on_track(&shape.layer, ((x0 + x1) / 2, (y0 + y1) / 2)) {
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
}

#[cfg(test)]
mod tests {
    use super::{contained, inside};

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
