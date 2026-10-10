//! The bitmap reference DRC (X3): every small pattern, run through `GPurify` and
//! through an oracle written from each `drc::Rule` variant's rustdoc alone.
//!
//! A pattern is an n×n grid of cells of side [`S`], each filled or empty, and
//! each filled cell is drawn as its own rectangle, so abutting cells merge only
//! if the tool merges them. The oracle works on the cells and is meant to be
//! read, not to be fast. Its semantics, as the rustdoc states them:
//!
//! - **Figures.** Shapes that touch or overlap are one figure, and "touch" is
//!   sharing an edge: the merge, `geom::boolean::union_into`, keeps two cells
//!   meeting only at a corner as two polygons. So figures are the 4-connected
//!   components of the filled cells, and empty space is 8-connected (a corner
//!   contact is not a wall).
//! - **`min_width`** (DRC-010): per figure, the narrowest of (a) the gap
//!   between parallel edges facing across material with overlapping
//!   projections, on cells the shortest run of a row or column, and (b) the
//!   Euclidean gap between two concave corners facing across material: voids
//!   pointing away from each other, each corner on the other's material side.
//!   One finding per figure under the limit.
//! - **`min_spacing`** (DRC-023): every pair of drawn rows (cells) in different
//!   figures, Euclidean, boundary to boundary. Cells of two figures meeting at
//!   a corner measure 0.
//! - **`notch`** (DRC-024): per figure, the narrowest gap between two of its
//!   cells in one row or column with none of its cells between: parallel edges
//!   facing across empty space with overlapping projections, holes included,
//!   corner-to-corner gaps not measured.
//! - **`min_area`** (DRC-017): per figure, its cell count times `S²`.
//! - **`min_enclosed_area`** (DRC-019): per figure, each bounded 8-connected
//!   component of the cells not in it, times `S²`.
//! - **`min_enclosure`** (DRC-040): each inner cell, drawn inset by [`INSET`],
//!   is its own polygon; its host is the outer figure under it, and its
//!   enclosure the Euclidean distance to the nearest point outside the host;
//!   unhosted measures 0.
//! - **`min_extension`** (DRC-045) and **`overlap`** (DRC-046), on every pair
//!   of one rectangle per layer: see [`extension`] and [`overlap`]. Their
//!   rustdoc measures bounding boxes and says where that departs from the rule
//!   (F19); a pair where the box measure and the rule differ is marked
//!   `known("F19")`.
//!
//! Lengths are compared exactly (squared, in nm²), and `measured` is the
//! distance floored to a whole nm, as the `Rule` rustdoc states.
//!
//! The nightly depth enumerates every 4×4 single-layer pattern (65 536, which
//! hold every 3×3 pattern at the origin), every 3×3 two-layer enclosure
//! pattern (2^18), and every pair of rectangles on a 5×5 lattice. The merge
//! depth runs a fixed-seed sample of [`SAMPLE`] of each.
//!
//! Two disagreements are new findings, each marked on the patterns that show
//! it (pictures are rows top to bottom):
//! - F51: `min_spacing` treats two figures meeting at a corner as one,
//!   while `notch`, `min_width` and `min_area` treat them as two, so the
//!   corner and every gap between them go unreported. `.#.|#.#`, three cells,
//!   has a 100 nm gap that neither `space >= 120nm` nor `notch >= 150nm` sees,
//!   whichever reading of a corner contact one takes.
//! - F53: a figure that meets itself at a corner (`###|#.#|.##`) closes a
//!   ring there in the engine, which then reports the cell inside as a hole
//!   and a width of 0 at the corner; this oracle, like `KLayout`'s default
//!   merge, lets empty space pass through the corner, so there is no hole and
//!   the width is the narrowest run. Until F52 was fixed (by C3), every rule
//!   that merges the layer refused such a figure.

use crate::drc_dimension::DRC;
use crate::harness::{Depth, Expect, Finding, Fixture, Layout};
use gpurify_testgen::Rng;
use std::fmt::Write as _;

/// The side of a cell, in nm.
const S: i64 = 100;
/// How far an enclosed cell is drawn inside its cell on every side, in nm.
const INSET: i64 = 30;
/// Patterns per kind at the merge depth.
const SAMPLE: usize = 300;
/// The merge sample's seed.
const SEED: u64 = 0x0b17_3a9e;

/// Every fixture this module generates at `depth`.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    // One thread per kind: the nightly enumeration is about 600 000 fixtures.
    std::thread::scope(|scope| {
        let mut jobs: Vec<_> = KINDS
            .iter()
            .map(|kind| scope.spawn(move || single_layer(kind, depth)))
            .collect();
        jobs.push(scope.spawn(move || enclosures(depth)));
        jobs.extend(
            PAIRS
                .iter()
                .map(|kind| scope.spawn(move || rect_pairs(kind, depth))),
        );
        jobs.into_iter()
            .flat_map(|job| job.join().expect("generating fixtures does not panic"))
            .collect()
    })
}

/// Every index below `domain` at nightly; a fixed-seed sample of [`SAMPLE`] at
/// merge, drawn per kind so the kinds see different patterns.
fn sample(depth: Depth, domain: u32, kind: &str) -> Vec<u32> {
    let mut all: Vec<u32> = (0..domain).collect();
    if depth == Depth::Merge {
        let salt = kind
            .bytes()
            .fold(SEED, |h, b| h.rotate_left(5) ^ u64::from(b));
        Rng::new(salt).shuffle(&mut all);
        all.truncate(SAMPLE);
    }
    all
}

// ---------------------------------------------------------------- patterns ---

/// A cell `(x, y)`: the square `[x S, (x+1) S] × [y S, (y+1) S]`.
type Cell = (i64, i64);

/// A set of cells with `-1 <= x, y <= 6`, cell `(x, y)` as bit
/// `8 (y + 1) + x + 1`. Patterns are at most 4×4, so the set holds the grid,
/// the ring of cells around it that stands for everything outside, and two
/// empty columns that keep a shift by one bit from wrapping onto real cells.
type Set = u64;

fn bit((x, y): Cell) -> Set {
    1 << (8 * (y + 1) + x + 1)
}

fn has(set: Set, (x, y): Cell) -> bool {
    (-1..=6).contains(&x) && (-1..=6).contains(&y) && set & bit((x, y)) != 0
}

fn cells(mut set: Set) -> impl Iterator<Item = Cell> {
    std::iter::from_fn(move || {
        let i = i64::from(set.trailing_zeros());
        set &= set.wrapping_sub(1);
        (i < 64).then_some((i % 8 - 1, i / 8 - 1))
    })
}

/// The n×n grid and its ring.
fn padded(n: i64) -> Set {
    (-1..=n)
        .flat_map(|x| (-1..=n).map(move |y| bit((x, y))))
        .sum()
}

/// The components of `set`, 4-connected or 8-connected.
fn components(mut left: Set, eight: bool) -> Vec<Set> {
    let mut out = Vec::new();
    while left != 0 {
        let mut part = left & left.wrapping_neg();
        loop {
            let mut grown = part | part << 1 | part >> 1 | part << 8 | part >> 8;
            if eight {
                grown |= part << 7 | part >> 7 | part << 9 | part >> 9;
            }
            grown &= left;
            if grown == part {
                break;
            }
            part = grown;
        }
        left &= !part;
        out.push(part);
    }
    out
}

/// An n×n pattern: bit `y n + x` fills cell `(x, y)`.
#[derive(Debug, Clone, Copy)]
struct Pattern {
    n: i64,
    bits: u32,
}

impl Pattern {
    fn set(self) -> Set {
        (0..self.n * self.n)
            .filter(|i| self.bits >> i & 1 == 1)
            .map(|i| bit((i % self.n, i / self.n)))
            .sum()
    }

    /// The merged figures.
    fn figures(self) -> Vec<Set> {
        components(self.set(), false)
    }

    /// The cells as rectangles on `layer`, each inset by `inset`.
    fn draw(self, mut layout: Layout, layer: &str, inset: i64) -> Layout {
        for (x, y) in cells(self.set()) {
            let (x0, y0) = (x * S, y * S);
            layout = layout.rect(
                layer,
                x0 + inset,
                y0 + inset,
                x0 + S - inset,
                y0 + S - inset,
            );
        }
        layout
    }
}

/// The gap along one axis between two cells `d` apart, the first drawn
/// `inset` inside its cell: 0 where they share the axis' span.
fn gap(d: i64, inset: i64) -> i64 {
    if d == 0 {
        0
    } else {
        inset + (d.abs() - 1) * S
    }
}

/// Squared Euclidean distance between cell `a` (inset by `inset`) and cell `b`.
fn dist2(a: Cell, b: Cell, inset: i64) -> i64 {
    gap(a.0 - b.0, inset).pow(2) + gap(a.1 - b.1, inset).pow(2)
}

/// A finding for a squared length under `limit`, measured floored to a nm.
fn short(d2: i64, limit: i64) -> Option<Finding> {
    (d2 < limit * limit).then(|| Finding::length(d2.isqrt()))
}

/// A finding for an area under `limit`.
fn small(area: i64, limit: i64) -> Option<Finding> {
    (area < limit).then(|| Finding::area(i128::from(area)))
}

fn area(set: Set) -> i64 {
    i64::from(set.count_ones()) * S * S
}

// ------------------------------------------------------------------ oracles ---

/// Squared narrowest width of a figure, in nm².
fn width2(fig: Set) -> i64 {
    let mut best = i64::MAX;
    // Parallel edges across material: every maximal run of a row or column.
    for (x, y) in cells(fig) {
        if !has(fig, (x - 1, y)) {
            let run = (1..8).find(|k| !has(fig, (x + k, y))).expect("finite");
            best = best.min((run * S).pow(2));
        }
        if !has(fig, (x, y - 1)) {
            let run = (1..8).find(|k| !has(fig, (x, y + k))).expect("finite");
            best = best.min((run * S).pow(2));
        }
    }
    // Concave corners: lattice points with exactly three of the four cells
    // around them in the figure; the void points at the fourth. Lattice point
    // `(x, y)` is the bottom-left corner of cell `(x, y)` and takes its bit, so
    // shifting the figure by 1, 8 or 9 bits lines up the cell to its west,
    // south or south-west with it.
    let (ne, nw, se, sw) = (fig, fig << 1, fig << 8, fig << 9);
    let corners = [
        ((1, 1), !ne & nw & se & sw),
        ((-1, 1), ne & !nw & se & sw),
        ((1, -1), ne & nw & !se & sw),
        ((-1, -1), ne & nw & se & !sw),
    ];
    for (v, ps) in corners {
        for (w, qs) in corners {
            if w != (-v.0, -v.1) {
                continue;
            }
            for p in cells(ps) {
                for q in cells(qs) {
                    if (q.0 - p.0) * v.0 <= 0 && (q.1 - p.1) * v.1 <= 0 {
                        best = best.min(((q.0 - p.0) * S).pow(2) + ((q.1 - p.1) * S).pow(2));
                    }
                }
            }
        }
    }
    best
}

fn min_width(figs: &[Set], _n: i64) -> Vec<i64> {
    figs.iter().map(|&f| width2(f)).collect()
}

fn min_spacing(figs: &[Set], _n: i64) -> Vec<i64> {
    let mut out = Vec::new();
    for (i, &a) in figs.iter().enumerate() {
        for &b in &figs[i + 1..] {
            for c in cells(a) {
                out.extend(cells(b).map(|d| dist2(c, d, 0)));
            }
        }
    }
    out
}

/// Squared narrowest gap between two cells of `fig` in one row or column with
/// none of its cells between.
fn notch2(fig: Set) -> Option<i64> {
    let mut gaps = Vec::new();
    for (x, y) in cells(fig) {
        for (dx, dy) in [(1, 0), (0, 1)] {
            let next = (1..6).find(|&k| has(fig, (x + k * dx, y + k * dy)));
            gaps.extend(next.filter(|&k| k > 1).map(|k| ((k - 1) * S).pow(2)));
        }
    }
    gaps.into_iter().min()
}

fn notch(figs: &[Set], _n: i64) -> Vec<i64> {
    figs.iter().filter_map(|&f| notch2(f)).collect()
}

fn min_area(figs: &[Set], _n: i64) -> Vec<i64> {
    figs.iter().map(|&f| area(f)).collect()
}

fn min_enclosed_area(figs: &[Set], n: i64) -> Vec<i64> {
    let ring = padded(n) & !(padded(n - 2) << 9);
    figs.iter()
        .flat_map(|&f| components(padded(n) & !f, true))
        .filter(|&hole| hole & ring == 0)
        .map(area)
        .collect()
}

// -------------------------------------------------------- single-layer kinds ---

/// One single-layer kind: its deck check, catalog row, limits and oracle.
struct Kind {
    name: &'static str,
    catalog: &'static str,
    /// The deck check, before `>= <limit><unit>`.
    check: &'static str,
    /// `nm` for a length, `nm2` for an area.
    unit: &'static str,
    /// Chosen between and on the values a 4×4 pattern can measure.
    limits: &'static [i64],
    /// What each finding-to-be measures before the limit, from the figures of
    /// an n×n pattern: a squared length or an area, both in nm².
    measure: fn(&[Set], i64) -> Vec<i64>,
    /// The finding that makes a pattern with these figures fail today.
    known: fn(&[Set]) -> Option<&'static str>,
}

/// Widths on cells: 100, 141 (√2·S), 200, 223 (√5·S), 282, 300, 400. Spacing
/// adds 0 for a corner contact. Notches are 100 or 200. Areas and holes are
/// multiples of 10 000 nm².
const KINDS: &[Kind] = &[
    Kind {
        name: "min_width",
        catalog: "DRC-010",
        check: "width(met1)",
        unit: "nm",
        limits: &[120, 150, 200, 250],
        measure: min_width,
        known: pinched,
    },
    Kind {
        name: "min_spacing",
        catalog: "DRC-023",
        check: "space(met1)",
        unit: "nm",
        limits: &[50, 120, 150, 200, 250],
        measure: min_spacing,
        known: corner_contact,
    },
    Kind {
        name: "notch",
        catalog: "DRC-024",
        check: "notch(met1)",
        unit: "nm",
        limits: &[150, 200, 250],
        measure: notch,
        known: never,
    },
    Kind {
        name: "min_area",
        catalog: "DRC-017",
        check: "area(met1)",
        unit: "nm2",
        limits: &[15_000, 20_000, 35_000, 50_000],
        measure: min_area,
        known: never,
    },
    Kind {
        name: "min_enclosed_area",
        catalog: "DRC-019",
        check: "hole_area(met1)",
        unit: "nm2",
        limits: &[15_000, 20_000, 25_000],
        measure: min_enclosed_area,
        known: never,
    },
];

/// F53 where it changes the holes: empty space that may not pass through a
/// corner leaves a different set of holes in a 4×4 pattern than empty space
/// that may.
fn closes_at_a_corner(figs: &[Set]) -> Option<&'static str> {
    let ring = padded(4) & !(padded(2) << 9);
    let holes = |eight| {
        let mut holes: Vec<Set> = figs
            .iter()
            .flat_map(|&f| components(padded(4) & !f, eight))
            .filter(|&hole| hole & ring == 0)
            .collect();
        holes.sort_unstable();
        holes
    };
    (holes(true) != holes(false)).then_some("F53")
}

/// No pattern of this kind is known to fail.
fn never(_: &[Set]) -> Option<&'static str> {
    None
}

/// F53: a figure with two diagonal cells sharing no neighbour in it meets
/// itself at a corner, where the engine closes a ring the oracle leaves open.
fn pinched(figs: &[Set]) -> Option<&'static str> {
    let pinch = figs.iter().any(|&f| {
        cells(f).any(|(x, y)| {
            [(1, 1), (1, -1)].iter().any(|&(dx, dy)| {
                has(f, (x + dx, y + dy)) && !has(f, (x + dx, y)) && !has(f, (x, y + dy))
            })
        })
    });
    pinch.then_some("F53")
}

/// F51: `min_spacing` takes two figures meeting at a corner as one, so
/// neither the corner nor any gap between them is reported.
fn corner_contact(figs: &[Set]) -> Option<&'static str> {
    let diagonal = |s: Set| s << 7 | s >> 7 | s << 9 | s >> 9;
    let contact = figs
        .iter()
        .enumerate()
        .any(|(i, &a)| figs[i + 1..].iter().any(|&b| diagonal(a) & b != 0));
    contact.then_some("F51")
}

/// The rule id for one limit of a kind.
fn rule_id(kind: &str, limit: i64) -> String {
    format!("{kind}.{limit}")
}

/// A deck on a 1 nm grid declaring `layers`, with `check >= <limit><unit>`
/// once per limit.
fn deck(layers: &[&str], kind: &str, check: &str, unit: &str, limits: &[i64]) -> String {
    let mut deck = String::from("grid 1nm\n");
    for (gds, layer) in (68..).zip(layers) {
        writeln!(deck, "layer {layer} = gds({gds}, 0)").expect("a String takes any text");
    }
    for &limit in limits {
        let id = rule_id(kind, limit);
        writeln!(deck, "rule {id} {check} >= {limit}{unit}").expect("a String takes any text");
    }
    deck
}

fn single_layer(kind: &Kind, depth: Depth) -> Vec<Fixture> {
    let deck = deck(&["met1"], kind.name, kind.check, kind.unit, kind.limits);
    sample(depth, 1 << 16, kind.name)
        .into_iter()
        .map(|bits| Pattern { n: 4, bits })
        // A hole closed only at a corner is a hole or not by the corner model
        // F53 has to choose, and the engine answers both ways today, so its
        // patterns wait for that choice rather than presume one.
        .filter(|p| kind.name != "min_enclosed_area" || closes_at_a_corner(&p.figures()).is_none())
        .map(|p| single(kind, &deck, p))
        .collect()
}

fn single(kind: &Kind, deck: &str, p: Pattern) -> Fixture {
    let name = format!("bitmap/{}/4x4/{:04x}", kind.name, p.bits);
    let mut fixture = Fixture::new(&name, &[kind.catalog], deck, DRC).layout(p.draw(
        Layout::default(),
        "met1",
        0,
    ));
    let figs = p.figures();
    let values = (kind.measure)(&figs, p.n);
    for &limit in kind.limits {
        let findings = values.iter().filter_map(|&v| {
            if kind.unit == "nm" {
                short(v, limit)
            } else {
                small(v, limit)
            }
        });
        let id = rule_id(kind.name, limit);
        fixture = fixture.expect(Expect::rule(&id, findings.collect()));
    }
    match (kind.known)(&figs) {
        Some(finding) => fixture.known(finding),
        None => fixture,
    }
}

// ------------------------------------------------------------ min_enclosure ---

/// Enclosure on inset cells: 0 unhosted, 30 beside the host's edge, 42 (√2·30)
/// off its corner, 130 one cell in, 133 beside that.
const ENCLOSURE_LIMITS: &[i64] = &[30, 40, 50, 131];

/// What one outer 3×3 pattern does to an inner cell at each of the nine
/// places: its squared enclosure, then the finding that fails it today. Inner
/// cells never touch, so each is measured alone and this is all there is.
type Hosting = ([i64; 9], Option<&'static str>);

fn hosting(outer: Pattern) -> Hosting {
    let figs = outer.figures();
    let mut e2 = [0; 9];
    for (i, e2) in (0..).zip(&mut e2) {
        let c = (i % 3, i / 3);
        if let Some(&host) = figs.iter().find(|&&f| has(f, c)) {
            *e2 = cells(padded(3) & !host)
                .map(|q| dist2(c, q, INSET))
                .min()
                .expect("the ring is outside every host");
        }
    }
    (e2, None)
}

fn enclosures(depth: Depth) -> Vec<Fixture> {
    let check = "enclosure(via1, met1)";
    let deck = deck(
        &["met1", "via1"],
        "min_enclosure",
        check,
        "nm",
        ENCLOSURE_LIMITS,
    );
    let hostings: Vec<Hosting> = (0..1 << 9)
        .map(|bits| hosting(Pattern { n: 3, bits }))
        .collect();
    sample(depth, 1 << 18, "min_enclosure")
        .into_iter()
        .map(|bits| enclosure(&deck, bits, hostings[bits as usize & 0x1ff]))
        .collect()
}

/// The outer pattern is the low nine bits, the inner the high nine.
fn enclosure(deck: &str, bits: u32, (e2, known): Hosting) -> Fixture {
    let outer = Pattern {
        n: 3,
        bits: bits & 0x1ff,
    };
    let inner = Pattern {
        n: 3,
        bits: bits >> 9,
    };
    let name = format!(
        "bitmap/min_enclosure/3x3/{:03x}_in_{:03x}",
        inner.bits, outer.bits
    );
    let layout = inner.draw(outer.draw(Layout::default(), "met1", 0), "via1", INSET);
    let mut fixture = Fixture::new(&name, &["DRC-040"], deck, DRC).layout(layout);
    let values: Vec<i64> = (0..9)
        .filter(|i| inner.bits >> i & 1 == 1)
        .map(|i| e2[i])
        .collect();
    for &limit in ENCLOSURE_LIMITS {
        let findings = values.iter().filter_map(|&v| short(v, limit)).collect();
        fixture = fixture.expect(Expect::rule(&rule_id("min_enclosure", limit), findings));
    }
    match known {
        Some(finding) => fixture.known(finding),
        None => fixture,
    }
}

// ------------------------------------------------ min_extension and overlap ---

/// A rectangle `[x0, x1] × [y0, y1]` in units of [`S`].
type Rect = (i64, i64, i64, i64);

/// Every rectangle with corners on the lattice `0..=4`: 100.
fn rects() -> Vec<Rect> {
    let spans: Vec<(i64, i64)> = (0..=4)
        .flat_map(|lo| (lo + 1..=4).map(move |hi| (lo, hi)))
        .collect();
    spans
        .iter()
        .flat_map(|&(x0, x1)| spans.iter().map(move |&(y0, y1)| (x0, y0, x1, y1)))
        .collect()
}

/// Both limits of the pair kinds; measurements are multiples of [`S`].
const PAIR_LIMITS: &[i64] = &[150, 200];

/// How A's span relates to B's along one axis.
enum Rel {
    /// Inside it, ends flush included.
    Within,
    /// Past it at both ends or past one and flush at the other.
    Spans,
    /// Past one end and short of the other.
    Partial,
}

/// What a pair measures, by the rule and by the rustdoc's bounding boxes;
/// `None` is no finding at any limit.
struct Measures {
    rule: Option<i64>,
    boxes: Option<i64>,
}

/// One kind measured on pairs of rectangles.
struct PairKind {
    name: &'static str,
    catalog: &'static str,
    check: &'static str,
    /// `None` for a pair the rule's words do not decide: it gets no fixture.
    measure: fn(Rect, Rect) -> Option<Measures>,
}

const PAIRS: &[PairKind] = &[
    PairKind {
        name: "min_extension",
        catalog: "DRC-045",
        check: "extension(poly, diff)",
        measure: extension,
    },
    PairKind {
        name: "overlap",
        catalog: "DRC-046",
        check: "overlap(poly, diff)",
        measure: |a, b| Some(overlap(a, b)),
    },
];

/// `extension(A, B)`: "A not extending past B by the limit, as poly past
/// diffusion", on one rectangle each. Along each axis A's span is within B's
/// (equal included), strictly spans it, or is partly past one end.
/// - Apart (no shared point): nothing. Touching only: undecided.
/// - A within B on both axes: 0, it extends past nothing.
/// - A spans one axis and lies within the other, not equal to it (a gate): the
///   smaller protrusion along the spanned axis, a flush end measuring 0. With
///   the other axis equal it is undecided which way A runs.
/// - A partly past B on one axis and within it on the other: 0, A ends inside B.
/// - A spans both, protruding on all four sides: the smallest protrusion.
/// - Everything else (a corner overlap, partly past one axis and spanning the
///   other, spanning both with a flush side): undecided.
///
/// The boxes: every pair whose boxes touch or overlap, the smallest amount A
/// reaches past B on any side where it reaches past, or 0 where on none.
fn extension(a: Rect, b: Rect) -> Option<Measures> {
    let protrusions = [b.0 - a.0, b.1 - a.1, a.2 - b.2, a.3 - b.3];
    let touch = a.0 <= b.2 && b.0 <= a.2 && a.1 <= b.3 && b.1 <= a.3;
    let boxes = touch.then(|| {
        protrusions
            .iter()
            .copied()
            .filter(|&p| p > 0)
            .min()
            .unwrap_or(0)
            * S
    });
    let overlaps = a.0 < b.2 && b.0 < a.2 && a.1 < b.3 && b.1 < a.3;
    let rel = |a0, a1, b0, b1| {
        if a0 >= b0 && a1 <= b1 {
            Rel::Within
        } else if a0 <= b0 && a1 >= b1 {
            Rel::Spans
        } else {
            Rel::Partial
        }
    };
    let (rx, ry) = (rel(a.0, a.2, b.0, b.2), rel(a.1, a.3, b.1, b.3));
    let (equal_x, equal_y) = ((a.0, a.2) == (b.0, b.2), (a.1, a.3) == (b.1, b.3));
    if !touch {
        return Some(Measures { rule: None, boxes });
    }
    if !overlaps {
        return None;
    }
    let units = match (rx, ry) {
        (Rel::Within | Rel::Partial, Rel::Within) | (Rel::Within, Rel::Partial) => 0,
        (Rel::Spans, Rel::Within) if !equal_y => protrusions[0].min(protrusions[2]),
        (Rel::Within, Rel::Spans) if !equal_x => protrusions[1].min(protrusions[3]),
        (Rel::Spans, Rel::Spans) if protrusions.iter().all(|&p| p > 0) => {
            protrusions.into_iter().min().expect("four sides")
        }
        _ => return None,
    };
    Some(Measures {
        rule: Some(units * S),
        boxes,
    })
}

/// `overlap(A, B)`: "A and B overlapping by less than the limit", on one
/// rectangle each: the shorter side of their shared area; shapes sharing no
/// area do not overlap and are not measured. The boxes also measure a pair
/// that only touches, as 0 (F19).
fn overlap(a: Rect, b: Rect) -> Measures {
    let (ix, iy) = (a.2.min(b.2) - a.0.max(b.0), a.3.min(b.3) - a.1.max(b.1));
    let boxes = (ix >= 0 && iy >= 0).then(|| ix.min(iy) * S);
    let rule = (ix > 0 && iy > 0).then(|| ix.min(iy) * S);
    Measures { rule, boxes }
}

/// Every pair of rectangles the rule decides, or a sample of them.
fn rect_pairs(kind: &PairKind, depth: Depth) -> Vec<Fixture> {
    let deck = deck(&["poly", "diff"], kind.name, kind.check, "nm", PAIR_LIMITS);
    let rects = rects();
    let pairs = u32::try_from(rects.len().pow(2)).expect("few rectangles");
    sample(depth, pairs, kind.name)
        .into_iter()
        .filter_map(|i| {
            let i = i as usize;
            rect_pair(&deck, kind, rects[i / rects.len()], rects[i % rects.len()])
        })
        .collect()
}

/// The fixture for one pair, if the rule decides it.
fn rect_pair(deck: &str, kind: &PairKind, a: Rect, b: Rect) -> Option<Fixture> {
    let Measures { rule, boxes } = (kind.measure)(a, b)?;
    let name = format!(
        "bitmap/{}/a{}{}{}{}_b{}{}{}{}",
        kind.name, a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3
    );
    let layout = Layout::default()
        .rect("poly", a.0 * S, a.1 * S, a.2 * S, a.3 * S)
        .rect("diff", b.0 * S, b.1 * S, b.2 * S, b.3 * S);
    let mut fixture = Fixture::new(&name, &[kind.catalog], deck, DRC).layout(layout);
    let mut differs = false;
    for &limit in PAIR_LIMITS {
        let found = |m: Option<i64>| m.and_then(|m| short(m * m, limit));
        differs |= found(rule) != found(boxes);
        let findings = found(rule).into_iter().collect();
        fixture = fixture.expect(Expect::rule(&rule_id(kind.name, limit), findings));
    }
    Some(if differs {
        fixture.known("F19")
    } else {
        fixture
    })
}
