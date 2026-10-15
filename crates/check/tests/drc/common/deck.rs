//! Deck-text fixtures run inside the crate: the root `tests/exhaustive`
//! harness's shape (a deck, a layout in nanometres, the findings each rule
//! must report) without its GDS round trip or engine, so this crate's own
//! tests reach the rule kinds the deck language selects. The deck is parsed,
//! its derived layers computed (`gpurify_ingest::layout::derive_layers`), its
//! nets extracted from its `connect` statements, its rules typed
//! (`CompiledDeck::from_deck`) and its DRC rules run over those nets.
//!
//! An expectation is derived from the rule's definition, never from a run;
//! each test states its oracle. A case is checked under the eight symmetries
//! of the square at two translations ([`check_everywhere`]) when its rule is
//! symmetric: every length, area and count is invariant, and every pinned
//! marker moves with the layout.

use gpurify_check::deck::CompiledDeck;
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_check::topology::net::{extract_nets_into, NetTable};
use gpurify_geom::{Dbu, DbuArea, Grid};
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::layout::derive_layers;
use gpurify_ingest::{Provenance, StrTable};
use gpurify_testgen::shapes::LayoutBuilder;

/// The translations a case is repeated at: the origin, and far off it in the
/// negative quadrant, so nothing depends on small or positive coordinates.
pub const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// A layout: polygons on deck layer names, counter-clockwise, in nanometres.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub shapes: Vec<(String, Vec<(i64, i64)>)>,
}

impl Layout {
    /// Adds an axis-aligned rectangle.
    pub fn rect(mut self, layer: &str, xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Self {
        assert!(xlo < xhi && ylo < yhi, "{layer}: an empty rectangle");
        self.shapes.push((
            layer.to_owned(),
            vec![(xlo, ylo), (xhi, ylo), (xhi, yhi), (xlo, yhi)],
        ));
        self
    }

    /// Adds rectangles `(xlo, ylo, xhi, yhi)`.
    pub fn rects(self, layer: &str, rects: &[(i64, i64, i64, i64)]) -> Self {
        rects.iter().fold(self, |layout, &(xlo, ylo, xhi, yhi)| {
            layout.rect(layer, xlo, ylo, xhi, yhi)
        })
    }

    /// Adds a polygon, counter-clockwise.
    pub fn polygon(mut self, layer: &str, points: &[(i64, i64)]) -> Self {
        self.shapes.push((layer.to_owned(), points.to_vec()));
        self
    }

    /// The layout under symmetry `s` ([`apply`]), then moved by `(dx, dy)`;
    /// outlines stay counter-clockwise.
    pub fn transformed(&self, s: Symmetry, dx: i64, dy: i64) -> Self {
        Layout {
            shapes: self
                .shapes
                .iter()
                .map(|(layer, points)| {
                    let mut out: Vec<_> = points
                        .iter()
                        .map(|&p| {
                            let (x, y) = apply(s, p);
                            (x + dx, y + dy)
                        })
                        .collect();
                    if s.1 {
                        out.reverse();
                    }
                    (layer.clone(), out)
                })
                .collect(),
        }
    }
}

/// One of the eight symmetries of the square: counter-clockwise quarter
/// turns, then a mirror of x.
pub type Symmetry = (u8, bool);

/// All eight, identity first.
pub const SYMMETRIES: [Symmetry; 8] = [
    (0, false),
    (1, false),
    (2, false),
    (3, false),
    (0, true),
    (1, true),
    (2, true),
    (3, true),
];

/// Maps a point under a symmetry.
pub fn apply((turns, mirror): Symmetry, (mut x, mut y): (i64, i64)) -> (i64, i64) {
    for _ in 0..turns {
        (x, y) = (-y, x);
    }
    if mirror {
        x = -x;
    }
    (x, y)
}

/// One finding a rule must report: its measurement, the limit it was held
/// to, and its marker, each claimed only when set.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Finding {
    pub measured: Option<Measurement>,
    pub limit: Option<Measurement>,
    pub at: Option<(i64, i64)>,
}

impl Finding {
    /// A finding measuring a length.
    pub fn length(nm: i64) -> Self {
        Self::of(Measurement::Length(Dbu::new_unchecked(nm)))
    }
    /// A finding measuring an area in nm².
    pub fn area(nm2: i128) -> Self {
        Self::of(Measurement::Area(DbuArea::new(nm2)))
    }
    /// A finding measuring a count.
    pub fn count(n: u32) -> Self {
        Self::of(Measurement::Count(n))
    }
    /// A finding measuring a ratio.
    pub fn ratio(r: f64) -> Self {
        Self::of(Measurement::Ratio(r))
    }
    /// A finding claiming only that it exists.
    pub fn any() -> Self {
        Finding {
            measured: None,
            limit: None,
            at: None,
        }
    }
    fn of(m: Measurement) -> Self {
        Finding {
            measured: Some(m),
            limit: None,
            at: None,
        }
    }
    /// Pins the marker.
    pub fn at(mut self, x: i64, y: i64) -> Self {
        self.at = Some((x, y));
        self
    }
    /// Pins the marker at `(x2 / 2, y2 / 2)`, the doubled coordinates of a
    /// midpoint, when both halves are whole. A midpoint off the lattice is
    /// floored, and a floor does not commute with a mirror, so it stays
    /// unpinned.
    pub fn at_half(self, x2: i64, y2: i64) -> Self {
        if x2 % 2 == 0 && y2 % 2 == 0 {
            self.at(x2 / 2, y2 / 2)
        } else {
            self
        }
    }
    /// Claims the limit it was held to.
    pub fn limit(mut self, limit: Measurement) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// One rule's row of a run, with its findings.
#[derive(Debug)]
pub struct Row {
    pub id: String,
    pub outcome: Outcome,
    pub examined: u64,
    /// Each finding: what it measured, what it was held to, where.
    pub findings: Vec<(Measurement, Measurement, (i64, i64))>,
}

/// Parses `deck` on a 1 nm grid, draws `layout`, computes the derived
/// layers and runs every DRC rule: one row per rule, in deck order.
///
/// # Panics
///
/// When the deck does not parse or type, or names a layer it lacks.
pub fn run(deck: &str, layout: &Layout) -> Vec<Row> {
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let mut strings = StrTable::default();
    let parsed = parse_deck(deck, grid, &mut strings).expect("the fixture deck parses");
    let mut builder = LayoutBuilder::new(parsed.layers.len());
    for (layer, points) in &layout.shapes {
        let id = parsed
            .layers
            .id(&strings, layer)
            .unwrap_or_else(|| panic!("the deck has no layer {layer}"));
        let xs: Vec<i64> = points.iter().map(|p| p.0).collect();
        let ys: Vec<i64> = points.iter().map(|p| p.1).collect();
        builder.push(id, &xs, &ys);
    }
    let (mut store, _) = builder.finish();
    derive_layers(&mut store, &parsed, &Provenance::default(), &strings)
        .expect("derived layers compute");
    let mut nets = NetTable::default();
    extract_nets_into(&store, &parsed.connectivity, &mut nets);
    let compiled = CompiledDeck::from_deck(parsed, grid, &strings).expect("the fixture deck types");
    let (mut out, mut runs): (Violations, Vec<RuleRun>) = (Violations::default(), Vec::new());
    compiled
        .drc
        .run_with_nets(&store, Some(&nets), &mut out, &mut runs);
    runs.iter()
        .map(|run| Row {
            id: strings.resolve(run.rule).to_owned(),
            outcome: run.outcome,
            examined: run.examined,
            findings: (0..out.len())
                .map(|k| out.get(k))
                .filter(|v| v.rule == run.rule)
                .map(|v| (v.measured, v.limit, (v.at.x.raw(), v.at.y.raw())))
                .collect(),
        })
        .collect()
}

/// Whether two measurements agree: exactly, or to 1e-9 relative for a ratio.
fn same(a: Measurement, b: Measurement) -> bool {
    match (a, b) {
        (Measurement::Ratio(x), Measurement::Ratio(y)) => {
            (x - y).abs() <= 1e-9 * x.abs().max(y.abs()).max(1e-30)
        }
        _ => a == b,
    }
}

/// Asserts each `(rule, findings)` row ran and found exactly those findings,
/// in any order; `name` labels a failure.
///
/// # Panics
///
/// On the first rule whose row breaks its claim.
pub fn check(name: &str, deck: &str, layout: &Layout, expect: &[(&str, Vec<Finding>)]) {
    let rows = run(deck, layout);
    for (id, want) in expect {
        let row = rows
            .iter()
            .find(|row| row.id == *id)
            .unwrap_or_else(|| panic!("{name}: no row for rule {id}"));
        assert_eq!(row.outcome, Outcome::Ran, "{name}: {id} did not run");
        // Pinned claims first, so an unpinned one cannot take a pinned one's match.
        let mut want = want.clone();
        want.sort_by_key(|f| (f.at.is_none(), f.measured.is_none()));
        let mut free: Vec<_> = row.findings.iter().collect();
        for w in &want {
            let hit = free.iter().position(|&&(m, l, at)| {
                w.measured.is_none_or(|wm| same(wm, m))
                    && w.limit.is_none_or(|wl| same(wl, l))
                    && w.at.is_none_or(|wa| wa == at)
            });
            match hit {
                Some(k) => {
                    free.swap_remove(k);
                }
                None => panic!("{name}: {id} lacks {w:?}; it found {:?}", row.findings),
            }
        }
        assert!(
            free.is_empty(),
            "{name}: {id} found more than claimed: {free:?}"
        );
    }
}

/// Groups `(rule, finding)` claims into [`check`]'s rows, one per id in
/// `ids` in that order: an id with no claim must run and find nothing.
pub fn by_rule<'a>(ids: &[&'a str], claims: &[(&str, Finding)]) -> Vec<(&'a str, Vec<Finding>)> {
    ids.iter()
        .map(|&id| {
            let findings = claims.iter().filter(|c| c.0 == id).map(|c| c.1).collect();
            (id, findings)
        })
        .collect()
}

/// [`check`] under every symmetry at every offset, each pinned marker
/// mapped with the layout.
pub fn check_everywhere(name: &str, deck: &str, layout: &Layout, expect: &[(&str, Vec<Finding>)]) {
    check_under(name, deck, layout, expect, |_| true);
}

/// [`check`] under the symmetries `keep` accepts, at every offset.
pub fn check_under(
    name: &str,
    deck: &str,
    layout: &Layout,
    expect: &[(&str, Vec<Finding>)],
    keep: fn(Symmetry) -> bool,
) {
    for &(dx, dy) in &OFFSETS {
        for s in SYMMETRIES.into_iter().filter(|&s| keep(s)) {
            let moved: Vec<(&str, Vec<Finding>)> = expect
                .iter()
                .map(|(id, findings)| {
                    let findings = findings
                        .iter()
                        .map(|f| Finding {
                            at: f.at.map(|p| {
                                let (x, y) = apply(s, p);
                                (x + dx, y + dy)
                            }),
                            ..*f
                        })
                        .collect();
                    (*id, findings)
                })
                .collect();
            check(
                &format!("{name}/{s:?}+({dx},{dy})"),
                deck,
                &layout.transformed(s, dx, dy),
                &moved,
            );
        }
    }
}

/// [`check`] under the four symmetries without a quarter turn, at every
/// offset: for a rule tied to an axis, which a quarter turn swaps.
pub fn check_axes(name: &str, deck: &str, layout: &Layout, expect: &[(&str, Vec<Finding>)]) {
    check_under(name, deck, layout, expect, |s| s.0 % 2 == 0);
}

/// The largest `r` with `r * r <= n`: a Euclidean gap as the report floors it.
pub fn floor_sqrt(n: i64) -> i64 {
    (0..=n).take_while(|r| r * r <= n).last().unwrap_or(0)
}

/// `outer` with `hole` cut out, as four abutting bands on `layer` that
/// merge into one figure with a hole: what one drawn outline cannot be,
/// since a ring through itself does not validate.
pub fn ring(layout: Layout, layer: &str, outer: [i64; 4], hole: [i64; 4]) -> Layout {
    let [xlo, ylo, xhi, yhi] = outer;
    let [hxlo, hylo, hxhi, hyhi] = hole;
    layout
        .rect(layer, xlo, ylo, xhi, hylo)
        .rect(layer, xlo, hyhi, xhi, yhi)
        .rect(layer, xlo, hylo, hxlo, hyhi)
        .rect(layer, hxhi, hylo, xhi, hyhi)
}

/// `met1` rectangles `[xlo, ylo, xhi, yhi]`.
pub fn met1(boxes: &[[i64; 4]]) -> Layout {
    boxes.iter().fold(Layout::default(), |l, &[a, b, c, d]| {
        l.rect("met1", a, b, c, d)
    })
}

/// A deck of `met1`, `met2` and `region`, then `rules`.
pub fn deck(rules: &str) -> String {
    format!(
        "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
         layer region = gds(81, 1)\n{rules}\n"
    )
}

/// A deck of one layer, `met1`, then `rules`.
pub fn one_layer_deck(rules: &str) -> String {
    format!("grid 1nm\nlayer met1 = gds(68, 20)\n{rules}\n")
}

/// A deck on a 1 nm grid with each of `layers` drawn on its own GDS layer,
/// then `body`.
pub fn new_deck(layers: &[&str], body: &str) -> String {
    let mut out = String::from("grid 1nm\n");
    for (gds, name) in (1..).zip(layers) {
        out.push_str(&format!("layer {name} = gds({gds}, 0)\n"));
    }
    out + body
}

/// The limit swept one grid step either side, each value with its side's name.
pub fn sweep(limit: i64) -> [(i64, &'static str); 3] {
    [(limit - 1, "below"), (limit, "at"), (limit + 1, "above")]
}

/// A `>=` rule's verdict on one measurement: a finding measuring it when it
/// is below `limit`, nothing at or above.
pub fn below(measured: i64, limit: i64) -> Vec<Finding> {
    if measured < limit {
        vec![Finding::length(measured)]
    } else {
        Vec::new()
    }
}

/// One finding per length.
pub fn lengths(values: &[i64]) -> Vec<Finding> {
    values.iter().map(|&v| Finding::length(v)).collect()
}

/// One finding per area, in nm².
pub fn areas(values: &[i128]) -> Vec<Finding> {
    values.iter().map(|&v| Finding::area(v)).collect()
}

/// The row of rule `id` in a run.
///
/// # Panics
///
/// When the run has no such row.
pub fn row<'a>(rows: &'a [Row], id: &str) -> &'a Row {
    rows.iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("no row for rule {id}"))
}
