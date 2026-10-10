//! Parasitic extraction against closed forms and the laws a capacitance matrix
//! obeys (PEX-001 to PEX-005, PEX-010).
//!
//! Two stacks, each written into its deck from the [`Stack`] constants below,
//! so the deck text and every expectation read the same numbers:
//!
//! - [`PARAMS`]: the `met1`, `via1` and `met2` rows of
//!   `tests/fixtures/params.deck`, for the closed forms of the crate docs
//!   (`gpurify_extract`, "The closed forms"): `R = Rs·L/W` per polygon, as the
//!   rectangle with the polygon's area and perimeter; `R = Rcut/n` per via
//!   array; `C = Ca·A + Cf·P` per polygon; lateral `ε₀εr·t·L/S`; interlayer
//!   `ε₀εr·A/d`.
//! - [`COARSE`]: thick layers 500 nm apart, for the field solves. The panel
//!   edge is the stack's finest stated length, so this keeps every solve to a
//!   few hundred panels and the module inside its merge budget.
//!
//! Tolerances, each stated where it is used:
//!
//! - [`EXACT`], `1e-9` relative: a closed form evaluated in `f64` on both
//!   sides differs only by round-off, six orders below this; a missed square
//!   or a perimeter counted twice is at least `1e-3`.
//! - [`PORT`], `1e-6` relative: a field-solved inductance is `Im(Z)/ω` of a
//!   port impedance whose real part is 10⁴ to 10⁵ times larger at 1 MHz, so
//!   it carries the resistance's round-off amplified by that ratio.
//! - [`GROVER`], `1e-2` relative: Grover's bar formula against the same bar
//!   cut in two, which is as close as the formula itself is to the exact
//!   partial inductance at these aspect ratios ("a fraction of a percent").
//! - [`MODEL`], `5e-2` relative: the physically right answer for a bent or
//!   via-joined net, where the corner's square or the via's landing
//!   point is counted is a modelling choice worth at most 2% at these lengths.
//! - [`SAME_FIELD`], `1e-8` relative: one field solved twice, moved by a
//!   symmetry or scaled; two orders above the solve's own `1e-10` residual.
//! - The field-solve bounds (Thomson's principle: a flux tube's capacitance
//!   is a lower bound) and monotone laws are inequalities, held exactly.
//!
//! What a fixture cannot state (coupling, the Maxwell matrix, SPEF) is a
//! `#[test]` at the end of the file, against the same closed forms.
//!
//! Known gaps get fixtures that state the correct physics and carry the
//! finding that breaks them: F23, F24, F30, F31, and the new findings
//! `N-x6-1` (closed forms read each drawn polygon, not the conductor),
//! `N-x6-2` (a field-solved polygon is one filament along its bounding box),
//! `N-x6-3` (the field-solve mesh depends on absolute position) and `N-x6-4`
//! (the reciprocity gate refuses ordinary layouts).

#![allow(
    clippy::cast_precision_loss,
    reason = "test geometry is below 2^40 nm, exact in an f64"
)]

use crate::harness::{self, Depth, Expect, Fixture, Layout, Quantity, Ran, Symmetry, NONE};
use gpurify::check::topology::NetId;
use gpurify::engine::run::Checks;
use gpurify::extract::field::CapMatrix;
use gpurify::extract::network::NodeId;
use gpurify::extract::{Parasitic, ParasiticNetwork};

/// PEX alone.
const PEX: Checks = Checks { pex: true, ..NONE };

/// Closed form against closed form: round-off only.
const EXACT: f64 = 1e-9;
/// A field-solved inductance, read off a resistance-dominated impedance.
const PORT: f64 = 1e-6;
/// Grover's bar formula against itself cut in two.
const GROVER: f64 = 1e-2;
/// The physically right number, up to where a corner or a via is counted.
const MODEL: f64 = 5e-2;
/// The same field, solved again after a symmetry or a scale.
const SAME_FIELD: f64 = 1e-8;

/// ε₀ in aF/µm (CODATA 2018), the unit of the deck's capacitance coefficients.
const EPSILON0_AF_PER_UM: f64 = 8.854_187_812_8;

/// The translations a placement-invariant fixture is repeated at: the origin,
/// and far off it in the negative quadrant.
const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// One `pex` row: lengths in nm, sheet in Ω/□ (Ω per cut on a via layer),
/// area capacitance in aF/µm², fringe in aF/µm.
#[derive(Debug, Clone, Copy)]
struct Row {
    thickness: f64,
    height: f64,
    sheet: f64,
    k: f64,
    area: f64,
    fringe: f64,
}

impl Row {
    /// The deck line for `layer`.
    fn line(self, layer: &str) -> String {
        format!(
            "pex {layer} thickness {}nm height {}nm sheet {}ohm dielectric {} area_cap {}aF/um2 \
             fringe_cap {}aF/um\n",
            self.thickness, self.height, self.sheet, self.k, self.area, self.fringe
        )
    }

    /// Every length times `k`; the coefficients per area and per length stay.
    fn scaled(self, k: f64) -> Self {
        Row {
            thickness: self.thickness * k,
            height: self.height * k,
            ..self
        }
    }
}

/// The three rows a deck here describes.
#[derive(Debug, Clone, Copy)]
struct Stack {
    m1: Row,
    v1: Row,
    m2: Row,
}

/// `met1`, `via1` and `met2` of `tests/fixtures/params.deck`.
const PARAMS: Stack = Stack {
    m1: Row {
        thickness: 400.0,
        height: 1300.0,
        sheet: 0.1,
        k: 3.9,
        area: 25.0,
        fringe: 40.0,
    },
    v1: Row {
        thickness: 300.0,
        height: 1700.0,
        sheet: 5.0,
        k: 3.9,
        area: 0.0,
        fringe: 0.0,
    },
    m2: Row {
        thickness: 400.0,
        height: 2000.0,
        sheet: 0.08,
        k: 3.9,
        area: 15.0,
        fringe: 30.0,
    },
};

/// Thick layers 500 nm apart, `m1` 250 nm over the substrate: the finest
/// stated length is 500 nm, which is the field solve's panel edge.
const COARSE: Stack = Stack {
    m1: Row {
        thickness: 500.0,
        height: 250.0,
        sheet: 0.1,
        k: 3.9,
        area: 25.0,
        fringe: 40.0,
    },
    v1: Row {
        thickness: 500.0,
        height: 750.0,
        sheet: 5.0,
        k: 3.9,
        area: 0.0,
        fringe: 0.0,
    },
    m2: Row {
        thickness: 500.0,
        height: 1250.0,
        sheet: 0.08,
        k: 3.9,
        area: 15.0,
        fringe: 30.0,
    },
};

impl Stack {
    fn scaled(self, k: f64) -> Self {
        Stack {
            m1: self.m1.scaled(k),
            v1: self.v1.scaled(k),
            m2: self.m2.scaled(k),
        }
    }
}

/// Two metals joined by `v1` cuts, a label layer each, and the stack's rows
/// except those named in `omit`; `rules` is appended.
fn deck(stack: Stack, omit: &[&str], rules: &str) -> String {
    let mut deck = String::from(
        "grid 1nm\n\
         layer m1 = gds(7, 0)\n\
         layer v1 = gds(8, 0)\n\
         layer m2 = gds(9, 0)\n\
         layer m1_label = gds(7, 5)\n\
         layer m2_label = gds(9, 5)\n\
         connect conductors [m1, m2]\n\
         connect touch_within_layer\n\
         connect via v1 [m1, m2]\n\
         connect label m1_label names m1\n\
         connect label m2_label names m2\n",
    );
    for (layer, row) in [("m1", stack.m1), ("v1", stack.v1), ("m2", stack.m2)] {
        if !omit.contains(&layer) {
            deck.push_str(&row.line(layer));
        }
    }
    deck.push_str(rules);
    deck
}

/// A conductor layer of the decks here.
#[derive(Debug, Clone, Copy)]
enum Metal {
    M1,
    M2,
}

impl Metal {
    fn name(self) -> &'static str {
        match self {
            Metal::M1 => "m1",
            Metal::M2 => "m2",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Metal::M1 => "m1_label",
            Metal::M2 => "m2_label",
        }
    }

    fn row(self, stack: Stack) -> Row {
        match self {
            Metal::M1 => stack.m1,
            Metal::M2 => stack.m2,
        }
    }
}

// The closed forms, in the deck's units: nm in, Ω, fF and pH out.

/// `Rs · L / W`.
fn wire_ohm(row: Row, length: i64, width: i64) -> f64 {
    row.sheet * length as f64 / width as f64
}

/// `Ca · A + Cf · P`, with `A` in nm² and `P` in nm.
fn ground_ff(row: Row, area: f64, perimeter: f64) -> f64 {
    (row.area * area / 1e6 + row.fringe * perimeter / 1e3) / 1e3
}

/// `ε₀ εr t · L / S` for two facing sidewalls on one layer.
fn lateral_ff(row: Row, run: i64, gap: i64) -> f64 {
    EPSILON0_AF_PER_UM * row.k * row.thickness / 1e3 * run as f64 / gap as f64 / 1e3
}

/// `ε₀ εr · A / d` for overlapping plates, `d` from the top of `lower` to the
/// bottom of `upper`. Both decks give every layer the same `εr`.
fn interlayer_ff(lower: Row, upper: Row, area: f64) -> f64 {
    let gap_um = (upper.height - lower.height - lower.thickness) / 1e3;
    EPSILON0_AF_PER_UM * lower.k * area / 1e6 / gap_um / 1e3
}

/// Grover's self inductance of a straight rectangular bar (Grover,
/// *Inductance Calculations*, 1946; Rosa 1908), in pH:
/// `(µ₀/2π) l [ln(2l/(w+t)) + 1/2 + 0.2235 (w+t)/l]`, `µ₀/2π = 2e-7 H/m`.
fn grover_ph(length: f64, width: f64, thickness: f64) -> f64 {
    let (l, wt) = (length * 1e-9, (width + thickness) * 1e-9);
    2e-7 * l * ((2.0 * l / wt).ln() + 0.5 + 0.2235 * wt / l) * 1e12
}

/// A polygon's area (nm²) and perimeter (nm), by the shoelace formula.
fn outline(points: &[(i64, i64)]) -> (f64, f64) {
    let mut twice_area = 0_i128;
    let mut perimeter = 0.0;
    for (i, &(x0, y0)) in points.iter().enumerate() {
        let (x1, y1) = points[(i + 1) % points.len()];
        twice_area += i128::from(x0) * i128::from(y1) - i128::from(x1) * i128::from(y0);
        perimeter += ((x1 - x0) as f64).hypot((y1 - y0) as f64);
    }
    (twice_area.abs() as f64 / 2.0, perimeter)
}

/// The capacitance to the substrate of one polygon.
fn polygon_ff(row: Row, points: &[(i64, i64)]) -> f64 {
    let (area, perimeter) = outline(points);
    ground_ff(row, area, perimeter)
}

/// A claim on net `net`.
fn claim(net: &str, quantity: Quantity, value: f64, rel: f64) -> Expect {
    Expect::Parasitic {
        net: net.to_owned(),
        quantity,
        value,
        rel,
    }
}

/// Each fixture under every symmetry of the square at every offset.
fn every_placement(fixtures: &[Fixture]) -> Vec<Fixture> {
    fixtures
        .iter()
        .flat_map(|f| {
            OFFSETS
                .iter()
                .flat_map(|&(dx, dy)| f.every_symmetry(dx, dy))
        })
        .collect()
}

/// Every fixture this module generates at `depth`.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    [
        bars(depth),
        bends(depth),
        pieces(),
        vias(depth),
        stack_gaps(),
        field(depth),
    ]
    .concat()
}

/// PEX-001, PEX-002: a straight bar is `L/W` squares and `Ca·LW + Cf·2(L+W)`,
/// swept over width (100 nm is `params.deck`'s `met1.min_width`) and length
/// (one square, ten, a thousand), on both metals so a row mix-up shows.
fn bars(depth: Depth) -> Vec<Fixture> {
    let (widths, squares): (&[i64], &[i64]) = match depth {
        Depth::Merge => (&[100, 1000], &[1, 10, 1000]),
        Depth::Nightly => (&[100, 101, 140, 1000, 4999], &[1, 2, 3, 10, 57, 1000]),
    };
    let deck = deck(PARAMS, &[], "");
    let mut out = Vec::new();
    for metal in [Metal::M1, Metal::M2] {
        let row = metal.row(PARAMS);
        for &w in widths {
            for &n in squares {
                let l = w * n;
                out.push(
                    Fixture::new(
                        &format!("pex/bar/{}/w{w}/l{l}", metal.name()),
                        &["PEX-001", "PEX-002"],
                        &deck,
                        PEX,
                    )
                    .layout(Layout::default().rect(metal.name(), 0, 0, l, w).label(
                        metal.label(),
                        l / 2,
                        w / 2,
                        "A",
                    ))
                    .expect(claim("A", Quantity::Resistance, wire_ohm(row, l, w), EXACT))
                    .expect(claim(
                        "A",
                        Quantity::GroundCap,
                        ground_ff(row, (l * w) as f64, (2 * (l + w)) as f64),
                        EXACT,
                    )),
                );
            }
        }
    }
    every_placement(&out)
}

/// A constant-width path of width `w` as one polygon, counter-clockwise from
/// the origin, with the length of its centre line.
///
/// For such a path the rectangle with the same area (`w·Lc`) and perimeter
/// (`2Lc + 2w`) is exactly `Lc × w`, so the documented square count is
/// `Lc / w`: every corner counts as one square.
fn bend(shape: &str, a: i64, b: i64, w: i64) -> (Vec<(i64, i64)>, i64) {
    match shape {
        // Legs `a` along x and `b` up the right end.
        "l" => (
            vec![(0, 0), (a, 0), (a, b), (a - w, b), (a - w, w), (0, w)],
            a + b - w,
        ),
        // `a` across the bottom, `b` up both ends.
        "u" => (
            vec![
                (0, 0),
                (a, 0),
                (a, b),
                (a - w, b),
                (a - w, w),
                (w, w),
                (w, b),
                (0, b),
            ],
            a + 2 * b - 2 * w,
        ),
        // `a` along x, `b` up, `a` along x again: two bends.
        "s" => (
            vec![
                (0, 0),
                (a, 0),
                (a, b - w),
                (2 * a - w, b - w),
                (2 * a - w, b),
                (a - w, b),
                (a - w, w),
                (0, w),
            ],
            2 * a + b - 2 * w,
        ),
        _ => unreachable!("no bend {shape}"),
    }
}

/// PEX-001, PEX-002: bent wires drawn as one polygon. R is `Rs·Lc/w` (the
/// documented rectangle of equal area and perimeter), C is `Ca·A + Cf·P` of
/// the outline.
fn bends(depth: Depth) -> Vec<Fixture> {
    let mut legs = vec![("l", 20, 12), ("u", 10, 15), ("s", 9, 14)];
    if depth == Depth::Nightly {
        legs.extend([("l", 2, 2), ("u", 3, 2), ("s", 2, 3), ("l", 300, 7)]);
    }
    let deck = deck(PARAMS, &[], "");
    let mut out = Vec::new();
    for metal in [Metal::M1, Metal::M2] {
        let row = metal.row(PARAMS);
        for w in [100, 1000] {
            for &(shape, a, b) in &legs {
                let (points, centre) = bend(shape, a * w, b * w, w);
                out.push(
                    Fixture::new(
                        &format!("pex/bend/{shape}/{}/w{w}/{a}x{b}", metal.name()),
                        &["PEX-001", "PEX-002"],
                        &deck,
                        PEX,
                    )
                    .layout(Layout::default().polygon(metal.name(), &points).label(
                        metal.label(),
                        w / 2,
                        w / 2,
                        "A",
                    ))
                    .expect(claim(
                        "A",
                        Quantity::Resistance,
                        wire_ohm(row, centre, w),
                        EXACT,
                    ))
                    .expect(claim(
                        "A",
                        Quantity::GroundCap,
                        polygon_ff(row, &points),
                        EXACT,
                    )),
                );
            }
        }
    }
    every_placement(&out)
}

/// PEX-001, PEX-002: one conductor drawn as several polygons. Its R and C are
/// those of the conductor, however it is cut up.
///
/// R holds where the documentation promises it (a net's total is the sum of
/// its polygons, each at least a square). C does not: each polygon's fringe
/// counts the edge it shares with its neighbour, and overlapping polygons
/// count their overlap twice (`N-x6-1`). A piece shorter than it is wide
/// counts as `long/short ≥ 1` squares, so a bar cut across into short pieces
/// reads too many squares (`N-x6-1`).
fn pieces() -> Vec<Fixture> {
    let row = PARAMS.m1;
    let deck = deck(PARAMS, &[], "");
    let case = |name: &str, layout: Layout| {
        Fixture::new(
            &format!("pex/pieces/{name}"),
            &["PEX-001", "PEX-002"],
            &deck,
            PEX,
        )
        .layout(layout.label("m1_label", 500, 500, "A"))
    };
    let mut holds = Vec::new();
    let mut known = Vec::new();

    // A 12 x 1 um bar in k abutting pieces, each three or more squares long.
    for k in [2_i64, 3, 4] {
        let mut layout = Layout::default();
        for i in 0..k {
            layout = layout.rect("m1", i * 12_000 / k, 0, (i + 1) * 12_000 / k, 1_000);
        }
        holds.push(case(&format!("bar_in_{k}/r"), layout.clone()).expect(claim(
            "A",
            Quantity::Resistance,
            wire_ohm(row, 12_000, 1_000),
            EXACT,
        )));
        known.push(
            case(&format!("bar_in_{k}/c"), layout)
                .expect(claim(
                    "A",
                    Quantity::GroundCap,
                    ground_ff(row, 12e6, 26_000.0),
                    EXACT,
                ))
                .known("N-x6-1"),
        );
    }

    // An L of legs 20 and 12 um, 1 um wide, as two abutting rectangles: the
    // second leg's rectangle starts where the first ends.
    let (a, b, w) = (20_000, 12_000, 1_000);
    let (points, centre) = bend("l", a, b, w);
    let abutting = Layout::default()
        .rect("m1", 0, 0, a, w)
        .rect("m1", a - w, w, a, b);
    holds.push(case("l_abutting/r", abutting.clone()).expect(claim(
        "A",
        Quantity::Resistance,
        wire_ohm(row, centre, w),
        EXACT,
    )));
    known.push(
        case("l_abutting/c", abutting)
            .expect(claim(
                "A",
                Quantity::GroundCap,
                polygon_ff(row, &points),
                EXACT,
            ))
            .known("N-x6-1"),
    );
    // The same L as two full-length bars overlapping at the corner square.
    known.push(
        case(
            "l_overlapping",
            Layout::default()
                .rect("m1", 0, 0, a, w)
                .rect("m1", a - w, 0, a, b),
        )
        .expect(claim(
            "A",
            Quantity::Resistance,
            wire_ohm(row, centre, w),
            EXACT,
        ))
        .expect(claim(
            "A",
            Quantity::GroundCap,
            polygon_ff(row, &points),
            EXACT,
        ))
        .known("N-x6-1"),
    );
    // A 3 x 1 um bar (three squares) cut across into four 750 nm pieces.
    let mut short = Layout::default();
    for i in 0..4 {
        short = short.rect("m1", i * 750, 0, (i + 1) * 750, 1_000);
    }
    known.push(
        case("bar_in_short_pieces/r", short)
            .expect(claim(
                "A",
                Quantity::Resistance,
                wire_ohm(row, 3_000, 1_000),
                EXACT,
            ))
            .known("N-x6-1"),
    );

    let mut out = every_placement(&holds);
    out.extend(known);
    out
}

/// `n` 200 nm cuts in the 1 x 1 um square where an `m1` bar at `[x, x+5um]`
/// meets an `m2` bar at `[x+4um, x+9um]`, on a 300 nm pitch.
fn joint(mut layout: Layout, x: i64, n: i64) -> Layout {
    for i in 0..n {
        let (cx, cy) = (x + 4_100 + 300 * (i % 3), 100 + 300 * (i / 3));
        layout = layout.rect("v1", cx, cy, cx + 200, cy + 200);
    }
    layout
}

/// PEX-001: `n` cuts joining one pair of plates are `Rcut / n`, in series with
/// both plates; cuts carry no capacitance. A cut that misses a plate is left
/// out (documented). A chain of joints is their series sum.
fn vias(depth: Depth) -> Vec<Fixture> {
    let cuts: Vec<i64> = match depth {
        Depth::Merge => vec![1, 2, 4, 9],
        Depth::Nightly => (1..=9).collect(),
    };
    let deck = deck(PARAMS, &[], "");
    let bar = |metal: Metal| {
        (
            wire_ohm(metal.row(PARAMS), 5_000, 1_000),
            ground_ff(metal.row(PARAMS), 5e6, 12_000.0),
        )
    };
    let ((r1, c1), (r2, c2)) = (bar(Metal::M1), bar(Metal::M2));
    let per_cut = PARAMS.v1.sheet;
    let pair = || {
        Layout::default()
            .rect("m1", 0, 0, 5_000, 1_000)
            .rect("m2", 4_000, 0, 9_000, 1_000)
            .label("m1_label", 500, 500, "A")
    };
    let case = |name: String, layout: Layout, ohm: f64, ff: f64| {
        Fixture::new(&name, &["PEX-001", "PEX-002"], &deck, PEX)
            .layout(layout)
            .expect(claim("A", Quantity::Resistance, ohm, EXACT))
            .expect(claim("A", Quantity::GroundCap, ff, EXACT))
    };
    let mut out = Vec::new();
    for &n in &cuts {
        out.push(case(
            format!("pex/via/cuts_{n}"),
            joint(pair(), 0, n),
            r1 + r2 + per_cut / n as f64,
            c1 + c2,
        ));
    }
    out.push(case(
        "pex/via/cuts_2_and_a_stray".into(),
        joint(pair(), 0, 2).rect("v1", 1_000, 400, 1_200, 600),
        r1 + r2 + per_cut / 2.0,
        c1 + c2,
    ));
    // m1, m2, m1, m2 end to end, joined by one, two and three cuts.
    let mut chain = Layout::default().label("m1_label", 500, 500, "A");
    for (x, n) in [(0, 1), (4_000, 2), (8_000, 3)] {
        chain = joint(chain, x, n);
    }
    for i in 0..4 {
        let metal = if i % 2 == 0 { "m1" } else { "m2" };
        chain = chain.rect(metal, 4_000 * i, 0, 4_000 * i + 5_000, 1_000);
    }
    out.push(case(
        "pex/via/chain_1_2_3".into(),
        chain,
        2.0 * (r1 + r2) + per_cut * (1.0 + 1.0 / 2.0 + 1.0 / 3.0),
        2.0 * (c1 + c2),
    ));
    every_placement(&out)
}

/// F30: a layer the stack does not describe is refused, never read as a
/// perfect wire. The closed forms give it zero today; the field solve refuses.
fn stack_gaps() -> Vec<Fixture> {
    let bar = Layout::default()
        .rect("m1", 0, 0, 10_000, 1_000)
        .label("m1_label", 500, 500, "A");
    let mut field_solved = Fixture::new(
        "pex/stack_gap/field_solve_refuses_m1",
        &["PEX-005"],
        &deck(COARSE, &["m1"], ""),
        PEX,
    )
    .layout(bar.clone())
    .expect(Expect::Passes(false));
    field_solved.quasistatic = vec!["A".into()];
    vec![
        Fixture::new(
            "pex/stack_gap/no_m1_row",
            &["PEX-001", "PEX-002"],
            &deck(PARAMS, &["m1"], ""),
            PEX,
        )
        .layout(bar)
        .expect(Expect::Passes(false))
        .known("F30"),
        Fixture::new(
            "pex/stack_gap/no_v1_row",
            &["PEX-001"],
            &deck(PARAMS, &["v1"], ""),
            PEX,
        )
        .layout(joint(
            Layout::default()
                .rect("m1", 0, 0, 5_000, 1_000)
                .rect("m2", 4_000, 0, 9_000, 1_000)
                .label("m1_label", 500, 500, "A"),
            0,
            2,
        ))
        .expect(Expect::Passes(false))
        .known("F30"),
        field_solved,
    ]
}

/// A fixture on [`COARSE`] that field-solves `nets`.
fn solved(name: &str, catalog: &[&'static str], layout: Layout, nets: &[&str]) -> Fixture {
    let mut fixture = Fixture::new(name, catalog, &deck(COARSE, &[], ""), PEX).layout(layout);
    fixture.quasistatic = nets.iter().map(|&n| n.to_owned()).collect();
    fixture
}

/// PEX-004, PEX-005: the field-solved path.
///
/// - A straight bar's series L is Grover's closed form and its R is
///   `Rs·L/W` (one filament carries the bar's DC resistance).
/// - The same bar drawn as two collinear halves is the same conductor.
/// - A net that does not exist is refused.
/// - F23: an L drawn as two touching rectangles, and a bar pair joined by a
///   via, have the R and L of the conductor they draw, not zero.
/// - `N-x6-2`: an L drawn as one polygon likewise, not a filament along its
///   bounding box.
/// - F24: a plate's ground capacitance is at least the parallel-plate
///   `ε₀εr·A/h` to the substrate.
/// - F31: naming a net twice is refused or deduplicated; the run completes.
/// - `N-x6-4`: four ordinary conductors solved together are not refused.
fn field(depth: Depth) -> Vec<Fixture> {
    let sizes: &[(i64, i64)] = match depth {
        Depth::Merge => &[(20_000, 1_000)],
        Depth::Nightly => &[
            (10_000, 500),
            (20_000, 1_000),
            (40_000, 2_000),
            (40_000, 500),
        ],
    };
    let mut bars = Vec::new();
    for metal in [Metal::M1, Metal::M2] {
        let row = metal.row(COARSE);
        for &(l, w) in sizes {
            bars.push(
                solved(
                    &format!("pex/field/bar/{}/{l}x{w}", metal.name()),
                    &["PEX-004", "PEX-005"],
                    Layout::default().rect(metal.name(), 0, 0, l, w).label(
                        metal.label(),
                        w / 2,
                        w / 2,
                        "A",
                    ),
                    &["A"],
                )
                .expect(claim("A", Quantity::Resistance, wire_ohm(row, l, w), EXACT))
                .expect(claim(
                    "A",
                    Quantity::Inductance,
                    grover_ph(l as f64, w as f64, row.thickness),
                    PORT,
                )),
            );
        }
    }
    let mut out = every_placement(&bars);

    let row = COARSE.m1;
    let t = row.thickness;
    out.push(
        solved(
            "pex/field/bar_in_halves",
            &["PEX-004", "PEX-005"],
            Layout::default()
                .rect("m1", 0, 0, 20_000, 1_000)
                .rect("m1", 20_000, 0, 40_000, 1_000)
                .label("m1_label", 500, 500, "A"),
            &["A"],
        )
        .expect(claim(
            "A",
            Quantity::Resistance,
            wire_ohm(row, 40_000, 1_000),
            EXACT,
        ))
        .expect(claim(
            "A",
            Quantity::Inductance,
            grover_ph(40_000.0, 1_000.0, t),
            GROVER,
        )),
    );
    out.push(
        solved(
            "pex/field/unknown_net_is_refused",
            &["PEX-005"],
            Layout::default()
                .rect("m1", 0, 0, 4_000, 1_000)
                .label("m1_label", 500, 500, "A"),
            &["B"],
        )
        .expect(Expect::Passes(false)),
    );

    // An L with legs of 20 and 16 um, 1 um wide. Its legs are perpendicular, so
    // they have no mutual partial inductance: L is the sum of the legs'
    // self-inductances along the centre line, and R is Lc/w squares.
    let (a, b, w) = (20_000, 16_000, 1_000);
    let (points, centre) = bend("l", a, b, w);
    let (wf, af, bf) = (w as f64, a as f64, b as f64);
    let l_shape = grover_ph(af - wf / 2.0, wf, t) + grover_ph(bf - wf / 2.0, wf, t);
    let bent = |name: &str, layout: Layout, finding: &'static str| {
        solved(
            name,
            &["PEX-004", "PEX-005"],
            layout.label("m1_label", 500, 500, "A"),
            &["A"],
        )
        .expect(claim(
            "A",
            Quantity::Resistance,
            wire_ohm(row, centre, w),
            MODEL,
        ))
        .expect(claim("A", Quantity::Inductance, l_shape, MODEL))
        .known(finding)
    };
    out.push(bent(
        "pex/field/l_two_rectangles",
        Layout::default()
            .rect("m1", 0, 0, a, w)
            .rect("m1", a - w, w, a, b),
        "F23",
    ));
    out.push(bent(
        "pex/field/l_one_polygon",
        Layout::default().polygon("m1", &points),
        "N-x6-2",
    ));
    // m1 and m2 bars joined by one cut: the bars and the cut in series.
    out.push(
        solved(
            "pex/field/via_joined",
            &["PEX-004", "PEX-005"],
            joint(
                Layout::default()
                    .rect("m1", 0, 0, 5_000, 1_000)
                    .rect("m2", 4_000, 0, 9_000, 1_000)
                    .label("m1_label", 500, 500, "A"),
                0,
                1,
            ),
            &["A"],
        )
        .expect(claim(
            "A",
            Quantity::Resistance,
            wire_ohm(COARSE.m1, 5_000, 1_000) + wire_ohm(COARSE.m2, 5_000, 1_000) + COARSE.v1.sheet,
            MODEL,
        ))
        .known("F23"),
    );

    // An 8 um plate 250 nm over the substrate (W/h = 32). The column under it
    // alone is ε₀εr·A/h (Thomson's principle makes that a lower bound), and
    // fringing adds at most 4·c·h/W of it, under 40% for any edge factor
    // c < 3; so the ground C is within [1, 2] times the column.
    let column = EPSILON0_AF_PER_UM * row.k * 64.0 / (row.height / 1e3) / 1e3;
    out.push(
        solved(
            "pex/field/plate_over_substrate",
            &["PEX-003", "PEX-005"],
            Layout::default()
                .rect("m1", 0, 0, 8_000, 8_000)
                .label("m1_label", 500, 500, "A"),
            &["A"],
        )
        .expect(claim("A", Quantity::GroundCap, 1.5 * column, 1.0 / 3.0))
        .known("F24"),
    );

    // The DRC row stands for "the run completed": an abort loses it, and both
    // a refusal and a deduplicated solve report it.
    let mut twice = Fixture::new(
        "pex/field/net_named_twice",
        &["PEX-005"],
        &deck(COARSE, &[], "rule w width(m1) >= 10nm\n"),
        Checks {
            drc: true,
            pex: true,
            ..NONE
        },
    )
    .layout(
        Layout::default()
            .rect("m1", 0, 0, 4_000, 1_000)
            .label("m1_label", 500, 500, "A"),
    )
    .expect(Expect::clean("w"))
    .known("F31");
    twice.quasistatic = vec!["A".into(), "A".into()];
    out.push(twice);

    // Four ordinary conductors solved together. The matrix is reciprocal to
    // about 1e-11 of its diagonal, but the engine holds each off-diagonal's
    // asymmetry, relative to that entry alone, to the 1e-10 residual, so the
    // most weakly coupled pair refuses the run (`N-x6-4`).
    out.push(
        solved(
            "pex/field/four_conductors",
            &["PEX-003", "PEX-005"],
            four_conductors(),
            &["A", "B", "C", "D"],
        )
        .expect(Expect::Passes(true))
        .known("N-x6-4"),
    );
    out
}

// Laws a fixture cannot state: coupling, the Maxwell matrix, SPEF.

/// Runs `layout` on `deck` with `checks` and the field solve of `nets`.
fn run(deck: &str, layout: Layout, checks: Checks, nets: &[&str]) -> Ran {
    let mut fixture = Fixture::new("pex/law", &["PEX-003"], deck, checks).layout(layout);
    fixture.quasistatic = nets.iter().map(|&n| n.to_owned()).collect();
    harness::run(&fixture).unwrap_or_else(|why| panic!("the run did not complete: {why}"))
}

/// The net a label names.
fn net(ran: &Ran, label: &str) -> NetId {
    ran.loaded
        .strings
        .get(label)
        .and_then(|id| ran.extracted.ports.net_of(id))
        .unwrap_or_else(|| panic!("no net is labelled {label}"))
}

/// Every coupling element of a run's network, summed, in fF.
fn coupling_ff(ran: &Ran) -> f64 {
    let network = ran.outputs.parasitics.as_ref().expect("PEX ran");
    network
        .value
        .iter()
        .map(|value| match value {
            Parasitic::CouplingCap(c) => c.raw(),
            _ => 0.0,
        })
        .sum()
}

/// The field-solved Maxwell matrix of the labelled nets on [`COARSE`]
/// (scaled by `scale`), in fF, rows and columns in `labels` order; and the
/// network `quasistatic::extract_into` writes from it, read back as a matrix
/// (`−C_ij` off the diagonal, ground plus every coupling on it).
fn maxwell(layout: Layout, labels: &[&str], scale: f64) -> (Vec<Vec<f64>>, Vec<Vec<f64>>) {
    let ran = run(&deck(COARSE.scaled(scale), &[], ""), layout, NONE, &[]);
    let nets: Vec<NetId> = labels.iter().map(|label| net(&ran, label)).collect();
    let (mut matrix, mut network) = (CapMatrix::default(), ParasiticNetwork::default());
    gpurify::extract::quasistatic::extract_into(
        &ran.loaded.store,
        &ran.extracted.nets,
        &nets,
        &ran.loaded.deck.stack,
        ran.loaded.grid,
        &mut matrix,
        &mut network,
    )
    .expect("the field solve converges");
    let n = nets.len();
    let row_of = |net: NetId| {
        matrix
            .net
            .iter()
            .position(|&m| m == net)
            .expect("every selected net has a row")
    };
    let solved = nets
        .iter()
        .map(|&i| {
            nets.iter()
                .map(|&j| matrix.value[row_of(i) * n + row_of(j)] * 1e15)
                .collect()
        })
        .collect();
    let index = |node: NodeId| {
        let of = network.node_net[node.0 as usize];
        nets.iter()
            .position(|&net| net == of)
            .expect("a solved net")
    };
    let mut read = vec![vec![0.0; n]; n];
    for (k, value) in network.value.iter().enumerate() {
        let i = index(network.from[k]);
        match (value, network.to[k]) {
            (Parasitic::GroundCap(q), None) => read[i][i] += q.raw(),
            (Parasitic::CouplingCap(q), Some(far)) => {
                let j = index(far);
                read[i][j] -= q.raw();
                read[j][i] -= q.raw();
                read[i][i] += q.raw();
                read[j][j] += q.raw();
            }
            _ => {}
        }
    }
    (solved, read)
}

/// Two conductors' capacitance to each other alone, charged `±Q`, from their
/// 2 × 2 Maxwell block: `(C11 C22 − C12²) / (C11 + C22 + 2 C12)`. This is what
/// Thomson's principle bounds from below by any flux tube between them.
fn pair_ff(c: &[Vec<f64>]) -> f64 {
    (c[0][0] * c[1][1] - c[0][1] * c[1][0]) / (c[0][0] + c[1][1] + c[0][1] + c[1][0])
}

fn relative(a: f64, b: f64) -> f64 {
    (a - b).abs() / a.abs().max(b.abs()).max(1e-300)
}

/// Two parallel bars on `metal`, `A` below and `B` above, each `length` by
/// `width`, a `gap` apart, `B` slid along x by `shift`.
fn parallel(metal: Metal, length: i64, width: i64, gap: i64, shift: i64) -> Layout {
    let (m, half) = (metal.name(), width / 2);
    Layout::default()
        .rect(m, 0, 0, length, width)
        .rect(m, shift, width + gap, shift + length, 2 * width + gap)
        .label(metal.label(), half, half, "A")
        .label(metal.label(), shift + half, width + gap + half, "B")
}

/// The four conductors of the matrix laws: two parallel `m1` bars, an `m2`
/// bar crossing both, and an `m1` plate off to one side. Small, because each
/// solve is dense in its panels.
fn four_conductors() -> Layout {
    parallel(Metal::M1, 3_000, 500, 500, 0)
        .rect("m2", 1_250, -500, 1_750, 2_000)
        .label("m2_label", 1_500, -250, "C")
        .rect("m1", 4_500, 0, 5_500, 1_000)
        .label("m1_label", 5_000, 500, "D")
}

/// PEX-003: the analytical lateral coupling of two facing bars is
/// `ε₀εr·t·L/S` over their facing run, within ten thicknesses (4 um on
/// `params.deck`'s met1) and nothing beyond; invariant under every symmetry
/// and translation.
#[test]
fn analytical_lateral_coupling_is_the_facing_sidewall_closed_form() {
    let deck = deck(PARAMS, &[], "");
    let mut broken = Vec::new();
    for metal in [Metal::M1, Metal::M2] {
        for gap in [100, 250, 1_000, 3_900, 4_100] {
            for shift in [0_i64, 1_500, -2_000, 6_500] {
                let run_len = (6_000 - shift.abs()).max(0);
                let want = if (gap as f64) < 10.0 * metal.row(PARAMS).thickness && run_len > 0 {
                    lateral_ff(metal.row(PARAMS), run_len, gap)
                } else {
                    0.0
                };
                let layout = parallel(metal, 6_000, 1_000, gap, shift);
                for symmetry in Symmetry::ALL {
                    for (dx, dy) in OFFSETS {
                        let placed = layout.transformed(symmetry, dx, dy);
                        let got = coupling_ff(&run(&deck, placed, PEX, &[]));
                        if relative(got, want) > EXACT && (got - want).abs() > 1e-15 {
                            broken.push(format!(
                                "{} gap {gap} shift {shift} {}: {got} fF, want {want}",
                                metal.name(),
                                symmetry.name()
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// PEX-003: the analytical coupling of overlapping plates on `m1` and `m2` is
/// `ε₀εr·A/d` over the overlap, `d` the dielectric between them.
#[test]
fn analytical_interlayer_coupling_is_the_parallel_plate_closed_form() {
    let deck = deck(PARAMS, &[], "");
    let mut broken = Vec::new();
    for (x, y) in [(1_000, 500), (0, 0), (-500, 1_500), (3_000, 2_000)] {
        let wide = (3_000_i64.min(x + 4_000) - x.max(0)).max(0);
        let tall = (2_000_i64.min(y + 3_000) - y.max(0)).max(0);
        let want = interlayer_ff(PARAMS.m1, PARAMS.m2, (wide * tall) as f64);
        let layout = Layout::default()
            .rect("m1", 0, 0, 3_000, 2_000)
            .rect("m2", x, y, x + 4_000, y + 3_000)
            .label("m1_label", 100, 100, "A")
            .label("m2_label", x + 3_900, y + 2_900, "B");
        for symmetry in Symmetry::ALL {
            let got = coupling_ff(&run(&deck, layout.transformed(symmetry, 0, 0), PEX, &[]));
            if relative(got, want) > EXACT && (got - want).abs() > 1e-15 {
                broken.push(format!(
                    "m2 at ({x}, {y}) {}: {got} fF, want {want}",
                    symmetry.name()
                ));
            }
        }
    }
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// PEX-003, PEX-005: a field-solved capacitance matrix is a Maxwell matrix:
/// symmetric (reciprocity), a positive diagonal, negative off-diagonals
/// (every pair sees each other in free space), and strictly diagonally
/// dominant (each row sums to the capacitance to infinity, which is
/// positive). The network carries it as documented: each row sum as the
/// net's ground C, `−C_ij` as the coupling of each pair.
#[test]
fn a_field_solved_capacitance_matrix_is_a_maxwell_matrix() {
    let (c, network) = maxwell(four_conductors(), &["A", "B", "C", "D"], 1.0);
    for (i, row) in c.iter().enumerate() {
        assert!(row[i] > 0.0, "C[{i}][{i}] = {}", row[i]);
        for (j, &entry) in row.iter().enumerate().filter(|&(j, _)| j != i) {
            assert!(entry < 0.0, "C[{i}][{j}] = {entry}");
            assert!(
                relative(entry, c[j][i]) <= SAME_FIELD,
                "C[{i}][{j}] = {entry} against C[{j}][{i}] = {}",
                c[j][i]
            );
        }
        let sum: f64 = row.iter().sum();
        assert!(sum > 0.0, "row {i} sums to {sum}: not diagonally dominant");
    }
    let broken = differences("the network", &network, &c, 1.0);
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// PEX-003: field-solved coupling between two parallel bars falls strictly
/// as their gap grows, and their pair capacitance never drops below the flux
/// tube between the facing sidewalls, `ε₀εr·t·L/S`.
#[test]
fn field_solved_coupling_falls_as_the_gap_grows() {
    let row = COARSE.m1;
    let mut previous = f64::INFINITY;
    for gap in [250, 500, 1_000, 2_000, 4_000] {
        let (c, _) = maxwell(parallel(Metal::M1, 6_000, 1_000, gap, 0), &["A", "B"], 1.0);
        let coupling = -c[0][1];
        assert!(
            coupling < previous,
            "coupling {coupling} fF at gap {gap} is not below {previous} at the gap before"
        );
        let tube = lateral_ff(row, 6_000, gap);
        assert!(
            pair_ff(&c) >= tube,
            "gap {gap}: pair capacitance {} fF below the sidewall tube {tube}",
            pair_ff(&c)
        );
        previous = coupling;
    }
}

/// PEX-003: field-solved coupling between an `m1` bar and an `m2` bar over it
/// grows strictly with their overlap, and their pair capacitance never drops
/// below the parallel plate over the overlap, `ε₀εr·A/d`.
#[test]
fn field_solved_coupling_grows_with_the_overlap() {
    let mut previous = 0.0;
    for overlap in [1_000, 2_000, 4_000, 8_000] {
        let layout = Layout::default()
            .rect("m1", 0, 0, 8_000, 1_000)
            .rect("m2", 8_000 - overlap, 0, 16_000 - overlap, 1_000)
            .label("m1_label", 100, 500, "A")
            .label("m2_label", 15_900 - overlap, 500, "B");
        let (c, _) = maxwell(layout, &["A", "B"], 1.0);
        let coupling = -c[0][1];
        assert!(
            coupling > previous,
            "coupling {coupling} fF at overlap {overlap} is not above {previous} at the one before"
        );
        let plate = interlayer_ff(COARSE.m1, COARSE.m2, (overlap * 1_000) as f64);
        assert!(
            pair_ff(&c) >= plate,
            "overlap {overlap}: pair capacitance {} fF below the parallel plate {plate}",
            pair_ff(&c)
        );
        previous = coupling;
    }
}

/// The three conductors the invariance laws solve: two parallel `m1` bars,
/// one slid along the other, and an `m2` bar crossing both.
fn three_conductors() -> Layout {
    parallel(Metal::M1, 3_000, 500, 500, 500)
        .rect("m2", 1_000, -500, 1_500, 2_000)
        .label("m2_label", 1_250, -250, "C")
}

/// Every entry of `c` that is not `factor` times `reference`.
fn differences(what: &str, c: &[Vec<f64>], reference: &[Vec<f64>], factor: f64) -> Vec<String> {
    let mut out = Vec::new();
    for (i, (row, want)) in c.iter().zip(reference).enumerate() {
        for (j, (&got, &want)) in row.iter().zip(want).enumerate() {
            if relative(got, factor * want) > SAME_FIELD {
                out.push(format!(
                    "{what}: C[{i}][{j}] = {got} fF, want {factor} x {want}"
                ));
            }
        }
    }
    out
}

/// A law that fails today because of `finding`, as [`Fixture::known`]: it
/// must keep failing, and one that holds is reported so the fix is recorded.
fn known(finding: &str, broken: &[String]) {
    assert!(
        !broken.is_empty(),
        "expected to fail until {finding} is fixed, and it now holds; drop the \
         `known` call and record {finding} as fixed"
    );
}

/// PEX-005: a field solve is a function of the geometry, not of how it is
/// drawn: every symmetry of the square gives the same matrix, and doubling
/// every length (layout and stack) doubles every capacitance, as it must in a
/// homogeneous dielectric.
#[test]
fn a_field_solve_is_invariant_under_symmetry_and_covariant_under_scale() {
    let labels = ["A", "B", "C"];
    let layout = three_conductors();
    let (reference, _) = maxwell(layout.clone(), &labels, 1.0);
    let mut broken = Vec::new();
    for symmetry in Symmetry::ALL {
        let (c, _) = maxwell(layout.transformed(symmetry, 0, 0), &labels, 1.0);
        broken.extend(differences(&symmetry.name(), &c, &reference, 1.0));
    }
    let doubled = Layout {
        shapes: layout
            .shapes
            .iter()
            .map(|(layer, points)| {
                (
                    layer.clone(),
                    points.iter().map(|&(x, y)| (2 * x, 2 * y)).collect(),
                )
            })
            .collect(),
        labels: layout
            .labels
            .iter()
            .map(|(layer, x, y, text)| (layer.clone(), 2 * x, 2 * y, text.clone()))
            .collect(),
    };
    let (c, _) = maxwell(doubled, &labels, 2.0);
    broken.extend(differences("doubled", &c, &reference, 2.0));
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// PEX-005: moving a layout moves its field and changes nothing else. Today
/// a face is cut into `ceil(width / edge)` panels with the width taken from
/// absolute coordinates in metres, so where the width is an exact multiple of
/// the edge, round-off at some positions adds a panel: the same three
/// conductors 1 mm to the right read capacitances 1e-4 apart (`N-x6-3`).
#[test]
fn a_field_solve_is_invariant_under_translation() {
    let labels = ["A", "B", "C"];
    let layout = three_conductors();
    let (reference, _) = maxwell(layout.clone(), &labels, 1.0);
    let mut broken = Vec::new();
    for (dx, dy) in [(1_000_000, 0), OFFSETS[1]] {
        let (c, _) = maxwell(layout.transformed(Symmetry::IDENTITY, dx, dy), &labels, 1.0);
        broken.extend(differences(&format!("+({dx},{dy})"), &c, &reference, 1.0));
    }
    known("N-x6-3", &broken);
}

/// PEX-010: SPEF carries the network: a net's `*D_NET` total is its
/// closed-form capacitance and its `*RES` rows its closed-form resistances,
/// to the six decimals of fF and Ω the writer prints.
#[test]
fn spef_carries_the_closed_form_totals() {
    let layout = joint(
        Layout::default()
            .rect("m1", 0, 0, 5_000, 1_000)
            .rect("m2", 4_000, 0, 9_000, 1_000)
            .label("m1_label", 500, 500, "A"),
        0,
        2,
    );
    let ran = run(&deck(PARAMS, &[], ""), layout, PEX, &[]);
    let header = gpurify::export::Header {
        tool_version: "test",
        deck_path: "pex.deck".into(),
        layout_path: "pex.gds".into(),
        timestamp: None,
    };
    let mut spef = String::new();
    gpurify::export::parasitic::write_spef(
        ran.outputs.parasitics.as_ref().expect("PEX ran"),
        &ran.extracted.ports,
        &ran.loaded.strings,
        &header,
        &mut spef,
    )
    .expect("SPEF writes");

    let want_c = ground_ff(PARAMS.m1, 5e6, 12_000.0) + ground_ff(PARAMS.m2, 5e6, 12_000.0);
    let want_r = wire_ohm(PARAMS.m1, 5_000, 1_000)
        + wire_ohm(PARAMS.m2, 5_000, 1_000)
        + PARAMS.v1.sheet / 2.0;
    let total: f64 = spef
        .lines()
        .find_map(|line| line.strip_prefix("*D_NET A "))
        .expect("a *D_NET for A")
        .parse()
        .expect("a number");
    assert!(
        (total - want_c).abs() <= 5e-7,
        "*D_NET A {total}, want {want_c}\n{spef}"
    );
    let mut in_res = false;
    let mut rows = 0;
    let mut ohms = 0.0;
    for line in spef.lines() {
        if line.starts_with('*') {
            in_res = line == "*RES";
            continue;
        }
        if in_res {
            rows += 1;
            ohms += line
                .rsplit(' ')
                .next()
                .and_then(|v| v.parse::<f64>().ok())
                .expect("a value");
        }
    }
    assert!(
        rows == 3 && (ohms - want_r).abs() <= 5e-7 * 3.0,
        "{rows} *RES rows summing to {ohms} ohm, want 3 summing to {want_r}\n{spef}"
    );
}
