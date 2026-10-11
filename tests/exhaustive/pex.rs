//! Parasitic extraction against closed forms and the laws a capacitance matrix
//! obeys (PEX-001 to PEX-005, PEX-010).
//!
//! Two stacks, each written into its deck from the [`Stack`] constants below,
//! so the deck text and every expectation read the same numbers:
//!
//! - [`PARAMS`]: the `met1`, `via1` and `met2` rows of
//!   `tests/fixtures/params.deck`, for the closed forms of the crate docs
//!   (`gpurify_extract`, "The closed forms"): `R = Rs·L/W` per conductor (a
//!   net's merged outline on one layer), as the rectangle with the outline's
//!   area and perimeter; `R = Rcut/n` per via array; `C = Ca·A + Cf·P` per
//!   conductor; lateral `ε₀εr·t·L/S`; interlayer `ε₀εr·A/d`.
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
//! - [`MUTUAL`], `1e-3` relative: Grover's mutual inductance of two
//!   filaments against two bars at least twelve widths apart, which their
//!   cross-sections move by 4e-4.
//! - The field-solve bounds (Thomson's principle: a flux tube's capacitance
//!   is a lower bound) and monotone laws are inequalities, held exactly.
//! - Mesh refinement (C6): the error against a cube's known capacitance
//!   stays inside `|e₀| (h/h₀)^(2/3)`, the rate a cube edge's charge
//!   singularity allows, from the coarsest mesh's own error `e₀`, and each
//!   refinement raises the capacitance (F77), held exactly.
//!
//! Every run's network is also held to passivity (C6), whatever the fixture
//! claims: no resistance, capacitance or inductance below zero
//! (`harness::violations_of`).
//!
//! What a fixture cannot state (coupling, the Maxwell matrix, SPEF) is a
//! `#[test]` at the end of the file, against the same closed forms.
//!
//! Known gaps get fixtures that state the correct physics and carry the
//! finding that breaks them. Every finding X6 marked here is fixed and its
//! fixtures hold: F23 (inductance filaments joined nothing but coincident
//! end points), F24 (the field solve had no substrate), `F30` (a layer with
//! no `pex` row read as a perfect wire), F31 (a net named twice aborted the
//! run), `F44` (closed forms read each drawn polygon, not the conductor),
//! `F45` (a field-solved polygon was one filament along its bounding box),
//! `F46` (the mesh depended on absolute position) and `F47` (the
//! reciprocity gate refused ordinary layouts).

#![allow(
    clippy::cast_precision_loss,
    reason = "test geometry is below 2^40 nm, exact in an f64"
)]

use crate::harness::{self, Depth, Expect, Fixture, Layout, Quantity, Ran, Symmetry, NONE};
use gpurify::check::topology::NetId;
use gpurify::engine::run::{Checks, StageStatus};
use gpurify::extract::field::CapMatrix;
use gpurify::extract::network::NodeId;
use gpurify::extract::{Parasitic, ParasiticNetwork};
use std::fmt::Write as _;

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
/// Grover's filament mutual inductance against two bars twelve widths apart:
/// the bars' geometric-mean distance is `d` less `(w² − t²)/(12 d²)` of `ln d`,
/// which moves `M` by 4e-4 at these sizes.
const MUTUAL: f64 = 1e-3;

/// ε₀ in aF/µm (CODATA 2018), the unit of the deck's capacitance coefficients.
const EPSILON0_AF_PER_UM: f64 = 8.854_187_812_8;

/// The translations a placement-invariant fixture is repeated at: the origin,
/// and far off it in the negative quadrant.
const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// One `pex` row: lengths in nm, sheet in Ω/□ (Ω per cut on a via layer),
/// area capacitance in aF/µm², fringe in aF/µm. A `k` of zero is a row that
/// states no dielectric, which the deck says by leaving the key out.
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
        let dielectric = if self.k == 0.0 {
            String::new()
        } else {
            format!(" dielectric {}", self.k)
        };
        format!(
            "pex {layer} thickness {}nm height {}nm sheet {}ohm{dielectric} area_cap {}aF/um2 \
             fringe_cap {}aF/um\n",
            self.thickness, self.height, self.sheet, self.area, self.fringe
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

/// [`COARSE`] with `m1` a junction, as a diffusion is: on the substrate
/// (height 0) and up to `v1`, so the field solve reads it in closed form.
const JUNCTION: Stack = Stack {
    m1: Row {
        thickness: 750.0,
        height: 0.0,
        ..COARSE.m1
    },
    ..COARSE
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

/// Grover's mutual inductance of two equal parallel filaments `length` long
/// and `distance` apart, side by side (Grover, *Inductance Calculations*,
/// 1946, ch. 6), in pH:
/// `(µ₀/2π) l [asinh(l/d) − √(1 + d²/l²) + d/l]`, `µ₀/2π = 2e-7 H/m`.
fn grover_mutual_ph(length: f64, distance: f64) -> f64 {
    let (l, d) = (length * 1e-9, distance * 1e-9);
    2e-7 * l * ((l / d).asinh() - (1.0 + (d / l).powi(2)).sqrt() + d / l) * 1e12
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
        temperature(),
        bends(depth),
        pieces(),
        vias(depth),
        stack_gaps(),
        field(depth),
        mutual(depth),
        extraction(),
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

/// PEX-007: [`bars`] at 85 °C, each `pex` row stated at 30 °C with sky130's
/// coefficients for met1, via and met2 (`tc1rm1`/`tc2rm1`, `tc1rvia`/
/// `tc2rvia`, `tc1rm2`/`tc2rm2`; met2's `tc2` is negative). R is the closed
/// form `Rs (1 + tc1 ΔT + tc2 ΔT²) L/W` with ΔT = 55 K; the ground
/// capacitance does not move with temperature.
fn temperature() -> Vec<Fixture> {
    let coefficients = [
        ("m1", 3.179e-3, 3.094e-7),
        ("v1", 1.081e-3, -1.903e-7),
        ("m2", 3.161e-3, -7.272e-7),
    ];
    let mut deck_text = String::from("temperature 85C nominal 30C\n");
    for line in deck(PARAMS, &[], "").lines() {
        deck_text.push_str(line);
        if let Some((_, tc1, tc2)) = coefficients
            .iter()
            .find(|(layer, ..)| line.starts_with(&format!("pex {layer} ")))
        {
            write!(deck_text, " tc1 {tc1}/K tc2 {tc2}/K2").expect("a String takes any write");
        }
        deck_text.push('\n');
    }
    let mut out = Vec::new();
    for (metal, (_, tc1, tc2)) in [(Metal::M1, coefficients[0]), (Metal::M2, coefficients[2])] {
        let row = metal.row(PARAMS);
        let factor = 1.0 + tc1 * 55.0 + tc2 * 55.0 * 55.0;
        for (w, l) in [(100, 1000), (1000, 1000)] {
            out.push(
                Fixture::new(
                    &format!("pex/temperature/{}/w{w}/l{l}", metal.name()),
                    &["PEX-007"],
                    &deck_text,
                    PEX,
                )
                .layout(Layout::default().rect(metal.name(), 0, 0, l, w).label(
                    metal.label(),
                    l / 2,
                    w / 2,
                    "A",
                ))
                .expect(claim(
                    "A",
                    Quantity::Resistance,
                    wire_ohm(row, l, w) * factor,
                    EXACT,
                ))
                .expect(claim(
                    "A",
                    Quantity::GroundCap,
                    ground_ff(row, (l * w) as f64, (2 * (l + w)) as f64),
                    EXACT,
                )),
            );
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
/// The closed forms read the merged outline of each net on each layer, so
/// abutting pieces share no fringe edge, overlapping ones count the overlap
/// once, and a piece shorter than it is wide is part of the bar, not a square
/// of its own. Per drawn polygon, the bar in pieces read C = 1.42, 1.50 and
/// 1.58 fF for 1.34 and the short pieces 0.533 ohm for 0.3 (`F44`, fixed).
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
        holds.push(case(&format!("bar_in_{k}/c"), layout).expect(claim(
            "A",
            Quantity::GroundCap,
            ground_ff(row, 12e6, 26_000.0),
            EXACT,
        )));
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
    holds.push(case("l_abutting/c", abutting).expect(claim(
        "A",
        Quantity::GroundCap,
        polygon_ff(row, &points),
        EXACT,
    )));
    // The same L as two full-length bars overlapping at the corner square.
    holds.push(
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
        )),
    );
    // A 3 x 1 um bar (three squares) cut across into four 750 nm pieces.
    let mut short = Layout::default();
    for i in 0..4 {
        short = short.rect("m1", i * 750, 0, (i + 1) * 750, 1_000);
    }
    holds.push(case("bar_in_short_pieces/r", short).expect(claim(
        "A",
        Quantity::Resistance,
        wire_ohm(row, 3_000, 1_000),
        EXACT,
    )));
    // F76: two 4 x 1 um bars meeting only at a corner are one net, but a
    // corner carries no current, so they are two conductors of four squares
    // each, chained as the closed forms chain a net's conductors; their C is
    // both bars' (the corner adds no edge). Read as one conductor they were
    // the rectangle of area 8 um² and perimeter 20 um, `(5 + √17) / (5 − √17)`
    // or 10.4 squares.
    holds.push(
        case(
            "corner_joined",
            Layout::default()
                .rect("m1", 0, 0, 4_000, 1_000)
                .rect("m1", 4_000, 1_000, 8_000, 2_000),
        )
        .expect(claim(
            "A",
            Quantity::Resistance,
            2.0 * wire_ohm(row, 4_000, 1_000),
            EXACT,
        ))
        .expect(claim(
            "A",
            Quantity::GroundCap,
            2.0 * ground_ff(row, 4e6, 10_000.0),
            EXACT,
        )),
    );

    every_placement(&holds)
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

/// F30 (fixed): a layer the stack does not describe is refused, never read as
/// a perfect wire, by the closed forms and the field solve alike.
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
        .expect(Expect::Passes(false)),
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
        .expect(Expect::Passes(false)),
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
/// - An L drawn as one polygon or as two touching rectangles has the R and L
///   of the conductor it draws: `F45` (one filament along the bounding box)
///   and the touching half of F23 are fixed.
/// - A bar pair joined by a via has the R of the bars and the cut in series,
///   not zero (F23, fixed).
/// - A plate's ground capacitance is at least the parallel-plate `ε₀εr·A/h`
///   to the substrate (F24, fixed).
/// - A net named twice is solved once, and the run passes (F31, fixed).
/// - A net on the substrate alone (a diffusion) is not in the field: its
///   ground capacitance is its closed form (F73, fixed).
/// - Four ordinary conductors solved together are not refused (F47, fixed).
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
    let bent = |name: &str, layout: Layout| {
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
    };
    out.push(bent(
        "pex/field/l_two_rectangles",
        Layout::default()
            .rect("m1", 0, 0, a, w)
            .rect("m1", a - w, w, a, b),
    ));
    out.push(bent(
        "pex/field/l_one_polygon",
        Layout::default().polygon("m1", &points),
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
        )),
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
        .expect(claim("A", Quantity::GroundCap, 1.5 * column, 1.0 / 3.0)),
    );

    // F73: a net on the substrate alone (a diffusion) has nothing in the
    // field: its ground capacitance is its closed form, and its resistance
    // the bar's, as any filament's. F94: the mesh asks nothing of a layer it
    // does not panel, so the junction needs no dielectric (the deck line
    // without one).
    let no_dielectric = Stack {
        m1: Row {
            k: 0.0,
            ..JUNCTION.m1
        },
        ..JUNCTION
    };
    for (name, stack) in [
        ("junction_only", JUNCTION),
        ("junction_without_dielectric", no_dielectric),
    ] {
        let mut junction = Fixture::new(
            &format!("pex/field/{name}"),
            &["PEX-002", "PEX-005"],
            &deck(stack, &[], ""),
            PEX,
        )
        .layout(
            Layout::default()
                .rect("m1", 0, 0, 5_000, 1_000)
                .label("m1_label", 500, 500, "A"),
        )
        .expect(claim(
            "A",
            Quantity::GroundCap,
            ground_ff(JUNCTION.m1, 5e6, 12_000.0),
            EXACT,
        ))
        .expect(claim(
            "A",
            Quantity::Resistance,
            wire_ohm(JUNCTION.m1, 5_000, 1_000),
            EXACT,
        ))
        .expect(Expect::Passes(true));
        junction.quasistatic = vec!["A".into()];
        out.push(junction);
    }

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
    .expect(Expect::Passes(true));
    twice.quasistatic = vec!["A".into(), "A".into()];
    out.push(twice);

    // Four ordinary conductors solved together. The matrix is reciprocal to
    // about 1e-11 of its diagonal; when the gate held each off-diagonal's
    // asymmetry relative to that entry alone, the most weakly coupled pair
    // refused the run (F47).
    out.push(
        solved(
            "pex/field/four_conductors",
            &["PEX-003", "PEX-005"],
            four_conductors(),
            &["A", "B", "C", "D"],
        )
        .expect(Expect::Passes(true)),
    );
    out
}

/// PEX-004: the mutual inductance between two field-solved nets. Two
/// parallel `m1` bars `l` long, each its own net, their centre lines `d`
/// apart and at least twelve widths, are Grover's two filaments
/// ([`grover_mutual_ph`]) on both nets, and positive: both ports run the
/// same way along the pair, under every symmetry (each port's current enters
/// at its lower end point).
fn mutual(depth: Depth) -> Vec<Fixture> {
    let cases: &[(i64, i64)] = match depth {
        Depth::Merge => &[(20_000, 12_000)],
        Depth::Nightly => &[(20_000, 12_000), (20_000, 16_000), (40_000, 12_000)],
    };
    let mut out = Vec::new();
    for &(l, d) in cases {
        let w = 1_000;
        let m = grover_mutual_ph(l as f64, d as f64);
        out.push(
            solved(
                &format!("pex/field/mutual/l{l}/d{d}"),
                &["PEX-004"],
                parallel(Metal::M1, l, w, d - w, 0),
                &["A", "B"],
            )
            .expect(claim("A", Quantity::Mutual, m, MUTUAL))
            .expect(claim("B", Quantity::Mutual, m, MUTUAL)),
        );
    }
    every_placement(&out)
}

/// PEX-008: the deck's extraction type, on two `m1` bars of [`PARAMS`]
/// 6 x 1 um, 1 um apart. Each bar alone is `Rs·L/W` and `Ca·A + Cf·P` to
/// ground; between them the facing sidewalls' `ε₀εr·t·L/S`, 0.083 fF. A
/// type that grounds the coupling (`rc`, `c`, or a threshold above it) adds
/// it to each bar's ground capacitance, one that drops resistance (`c`,
/// `cc`) leaves none, and `r` leaves no capacitance.
fn extraction() -> Vec<Fixture> {
    let row = PARAMS.m1;
    let (r, g) = (wire_ohm(row, 6_000, 1_000), ground_ff(row, 6e6, 14_000.0));
    let lateral = lateral_ff(row, 6_000, 1_000);
    assert!(
        lateral > 0.05 && lateral < 0.1,
        "the thresholds below bracket it"
    );
    let mut out = Vec::new();
    for (name, line, ohm, ground) in [
        ("rcc", "", r, g),
        (
            "rcc_threshold_above",
            "extraction rcc coupling_threshold 0.1fF\n",
            r,
            g + lateral,
        ),
        (
            "rcc_threshold_below",
            "extraction rcc coupling_threshold 50aF\n",
            r,
            g,
        ),
        ("rc", "extraction rc\n", r, g + lateral),
        ("r", "extraction r\n", r, 0.0),
        ("cc", "extraction cc\n", 0.0, g),
        ("c", "extraction c\n", 0.0, g + lateral),
    ] {
        out.push(
            Fixture::new(
                &format!("pex/extraction/{name}"),
                &["PEX-008"],
                &deck(PARAMS, &[], line),
                PEX,
            )
            .layout(parallel(Metal::M1, 6_000, 1_000, 1_000, 0))
            .expect(claim("A", Quantity::Resistance, ohm, EXACT))
            .expect(claim("A", Quantity::GroundCap, ground, EXACT))
            .expect(claim("B", Quantity::GroundCap, ground, EXACT)),
        );
    }
    every_placement(&out)
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
        &ran.loaded.deck.connectivity,
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

/// PEX-009: `rc` qualified against `rcc` on the two bars of [`extraction`].
/// Oracle: law, through `compare`: grounding a coupling conserves each net's
/// total capacitance and every node's capacitance, so each net's total C,
/// pin-to-pin resistance and Elmore delay agree to round-off; the one
/// coupling reads 0 in the candidate, an error of −100 %; each bar's ground
/// C grows by the coupling, `ε₀εr·t·L/S` over `Ca·A + Cf·P`. Fails if the
/// comparison leaves the coupling out of a total or a delay, or pairs the
/// wrong nets.
#[test]
fn a_qualification_of_rc_against_rcc_finds_every_net_s_totals_unchanged() {
    let layout = parallel(Metal::M1, 6_000, 1_000, 1_000, 0);
    let network = |line: &str| {
        run(&deck(PARAMS, &[], line), layout.clone(), PEX, &[])
            .outputs
            .parasitics
            .expect("PEX ran")
    };
    let out = gpurify::extract::compare::compare(&network(""), &network("extraction rc\n"));
    assert_eq!(out.only_reference, Vec::new());
    assert_eq!(out.only_candidate, Vec::new());
    for (what, metric) in [
        ("total C", &out.total_cap),
        ("resistance", &out.resistance),
        ("delay", &out.delay),
    ] {
        let errors = metric.errors(1e-12, 1e-9);
        assert_eq!((errors.count, errors.within), (2, 2), "{what}: {errors:?}");
    }
    let coupling = out.coupling.errors(1e-12, 1e-9);
    assert_eq!((coupling.count, coupling.within), (1, 0), "{coupling:?}");
    assert!((coupling.worst + 1.0).abs() < 1e-12, "{coupling:?}");
    let row = PARAMS.m1;
    let grown = lateral_ff(row, 6_000, 1_000) / ground_ff(row, 6e6, 14_000.0);
    let ground = out.ground_cap.errors(1.0, 1e-9);
    assert_eq!(ground.count, 2);
    assert!(
        relative(ground.worst, grown) < EXACT && relative(ground.mean, grown) < EXACT,
        "{ground:?}, want {grown}"
    );
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
///
/// Oracle: closed form, `ε₀εr·t·L/S` over the facing run as computed by
/// `lateral_ff` from the deck's row, zero past ten thicknesses; and the
/// metamorphic relation that every symmetry and translation leaves it
/// unchanged.
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
///
/// Oracle: closed form, `ε₀εr·A/d` over the overlap worked out from the
/// coordinates, under every symmetry.
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

/// PEX-003 (F93): the Liberty circuit places each analytical coupling between
/// the closest rectangles of the two regions the extractor measured it
/// between, whatever the drawn polygon count. Each layout is on [`PARAMS`],
/// `A` labelled on its rectangle `A1` and `B` an `m1` bar 200 above `A2`;
/// the only coupling is `A2`–`B`'s facing run, `ε₀εr·t·L/S`.
///
/// - Abutting: `A` is `A1` = (0, 0)–(1000, 200) and `A2` = (1000, 0)–(2000,
///   200) side by side, one region; `B` = (1500, 400)–(2500, 600) faces it
///   over x = 1500..2000, so L = 500, S = 200. `A2` is `A1`'s only resistor
///   neighbour. Read as one node per polygon, `A`'s two polygons outnumber
///   its one region and every later node shifts by one: `B`'s region read
///   as `A`'s closing node, and the coupling was dropped.
/// - Corner-joined: `A2` = (1000, 200)–(2000, 400) meets `A1` only at a
///   corner, so they are two regions, joined through an `m2` strap over both
///   by a `v1` cut each; `A2` is drawn first. `B` = (1000, 600)–(2000, 800)
///   faces `A2` over L = 1000, S = 200, and meets `A1` only diagonally. The
///   regions come in merge order (`A1` first) and the polygons in drawing
///   order (`A2` first), so read as one node per polygon the coupling landed
///   on `A1`. `A2` is the strap's other resistor neighbour.
///
/// Oracle: closed form and construct-from-answer, worked in the list above:
/// `ε₀εr·t·L/S` with L 500 and 1000, S 200, placed between `A2` and `B`, the
/// closest rectangles of the two regions.
#[test]
fn a_liberty_circuit_places_each_coupling_on_the_regions_it_joins() {
    use gpurify::liberty::circuit::{build, Wires};

    let deck = deck(PARAMS, &[], "");
    let spec = gpurify::liberty::spec::parse(
        r#"{"cell": "T", "pins": [{"name": "A", "role": "power"}, {"name": "B", "role": "ground"}],
            "corners": [{"name": "c", "temperature": 25, "supplies": {"A": 1.8, "B": 0}, "models": []}]}"#,
    )
    .expect("a valid spec");
    let abutting = Layout::default()
        .rect("m1", 0, 0, 1_000, 200)
        .rect("m1", 1_000, 0, 2_000, 200)
        .label("m1_label", 500, 100, "A")
        .rect("m1", 1_500, 400, 2_500, 600)
        .label("m1_label", 2_000, 500, "B");
    let corner = Layout::default()
        .rect("m1", 1_000, 200, 2_000, 400)
        .rect("m1", 0, 0, 1_000, 200)
        .rect("m2", 0, 0, 2_000, 400)
        .rect("v1", 100, 50, 200, 150)
        .rect("v1", 1_800, 250, 1_900, 350)
        .label("m1_label", 500, 100, "A")
        .rect("m1", 1_000, 600, 2_000, 800)
        .label("m1_label", 1_500, 700, "B");
    let mut broken = Vec::new();
    for (name, layout, hops, run_len) in
        [("abutting", abutting, 1, 500), ("corner", corner, 2, 1_000)]
    {
        let want = lateral_ff(PARAMS.m1, run_len, 200) * 1e-15;
        for symmetry in Symmetry::ALL {
            let ran = run(&deck, layout.transformed(symmetry, 0, 0), PEX, &[]);
            let analytical = ran.outputs.parasitics.as_ref().expect("PEX ran");
            let circuit = build(
                &ran.loaded,
                &ran.extracted,
                &spec,
                Wires::Distributed {
                    analytical,
                    field: None,
                },
            )
            .unwrap_or_else(|why| panic!("{name} {}: {why}", symmetry.name()));
            // Walk `hops` resistors out from A1, never back.
            let (mut at, mut from) = (circuit.pin_node[0], u32::MAX);
            for _ in 0..hops {
                let next: Vec<u32> = circuit
                    .resistors
                    .iter()
                    .filter_map(|&(a, b, _)| match (a == at, b == at) {
                        (true, _) => Some(b),
                        (_, true) => Some(a),
                        _ => None,
                    })
                    .filter(|&n| n != from)
                    .collect();
                assert_eq!(next.len(), 1, "{name}: one way on from {at}: {next:?}");
                (from, at) = (at, next[0]);
            }
            let (a2, b) = (at, circuit.pin_node[1]);
            let couplings: Vec<(u32, u32, f64)> = circuit
                .capacitors
                .iter()
                .copied()
                .filter(|&(_, to, _)| to != 0)
                .collect();
            let placed = matches!(
                couplings[..],
                [(p, q, f)] if (p, q) == (a2.max(b), a2.min(b)) && relative(f, want) <= EXACT
            );
            if !placed {
                broken.push(format!(
                    "{name} {}: couplings {couplings:?}, want {want:e} F between A2 {a2} and B {b}",
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
///
/// Oracle: law. A Maxwell capacitance matrix is symmetric, has a positive
/// diagonal and negative off-diagonals, and is strictly diagonally dominant;
/// and the network's documented reading of it (row sums as ground C, `-C_ij` as
/// coupling).
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

/// PEX-005 (F24): the field solve sees the substrate, a grounded plane at
/// height 0. An 8 um square `m1` plate 250, 500 and 1000 nm above it: its
/// capacitance never drops below the column under it, `ε₀εr·A/h` (Thomson's
/// principle); it falls strictly as the plate rises (a grounded conductor
/// brought closer only draws more charge); and the fringe share
/// `C·h / (ε₀εr·A)` grows as `W/h` falls from 32 to 8. With no plane the
/// field is the same at every height, which breaks all three.
///
/// Oracle: law. Thomson's principle bounds the plate's capacitance below by the
/// column `ε₀εr·A/h`; it falls strictly as the plate rises, and the fringe
/// share grows as `W/h` falls.
#[test]
fn a_field_solved_plate_sees_the_substrate() {
    let mut previous: Option<(f64, f64)> = None;
    for h in [250.0, 500.0, 1_000.0] {
        let stack = Stack {
            m1: Row {
                height: h,
                ..COARSE.m1
            },
            ..COARSE
        };
        let layout = Layout::default()
            .rect("m1", 0, 0, 8_000, 8_000)
            .label("m1_label", 500, 500, "A");
        let ran = run(&deck(stack, &[], ""), layout, NONE, &[]);
        let plate = net(&ran, "A");
        let (mut matrix, mut network) = (CapMatrix::default(), ParasiticNetwork::default());
        gpurify::extract::quasistatic::extract_into(
            &ran.loaded.store,
            &ran.extracted.nets,
            &ran.loaded.deck.connectivity,
            &[plate],
            &ran.loaded.deck.stack,
            ran.loaded.grid,
            &mut matrix,
            &mut network,
        )
        .expect("the field solve converges");
        let c = matrix.value[0] * 1e15;
        let column = EPSILON0_AF_PER_UM * COARSE.m1.k * 64.0 / (h / 1e3) / 1e3;
        assert!(c >= column, "h {h}: {c} fF below the column {column}");
        let share = c / column;
        if let Some((below, share_below)) = previous {
            assert!(c < below, "h {h}: {c} fF not below {below} one step lower");
            assert!(
                share > share_below,
                "h {h}: fringe share {share} not above {share_below} one step lower"
            );
        }
        previous = Some((c, share));
    }
}

/// PEX-003: field-solved coupling between two parallel bars falls strictly
/// as their gap grows, and their pair capacitance never drops below the flux
/// tube between the facing sidewalls, `ε₀εr·t·L/S`.
///
/// Oracle: law. Coupling falls strictly as the gap grows, and the pair
/// capacitance is bounded below by the sidewall flux tube `ε₀εr·t·L/S`.
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
///
/// Oracle: law. Coupling grows strictly with the overlap, and the pair
/// capacitance is bounded below by the parallel plate `ε₀εr·A/d` over it.
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

/// PEX-005 (F73): a net of metal and a junction field-solves its metal and
/// adds the junction in closed form. Its ground capacitance is the same
/// metal's solved alone (the junction is not in the field, so the metal's
/// mesh and solve are the same) plus the junction's `Ca·A + Cf·P`, to
/// round-off ([`EXACT`]); its resistance runs through the junction, the cut
/// and the metal in series, as `pex/field/via_joined`'s does ([`MODEL`]).
///
/// Oracle: closed form. The ground capacitance is the metal's solved alone plus
/// the junction's `Ca·A + Cf·P`, to round-off, and the resistance the junction,
/// the cut and the metal in series.
#[test]
fn a_junction_is_its_closed_form_beside_the_field_solved_metal() {
    let deck = deck(JUNCTION, &[], "");
    let total = |layout: Layout, quantity: Quantity| {
        let ran = run(&deck, layout, PEX, &["A"]);
        harness::parasitic_total(&ran, "A", quantity)
            .unwrap_or_else(|| panic!("no {quantity:?} for A: {:?}", ran.summary.pex))
    };
    let metal = Layout::default()
        .rect("m2", 4_000, 0, 9_000, 1_000)
        .label("m2_label", 8_500, 500, "A");
    let joined = joint(metal.clone().rect("m1", 0, 0, 5_000, 1_000), 0, 1);

    let alone = total(metal, Quantity::GroundCap);
    let both = total(joined.clone(), Quantity::GroundCap);
    let junction = ground_ff(JUNCTION.m1, 5e6, 12_000.0);
    assert!(
        relative(both - alone, junction) <= EXACT,
        "ground C {both} fF with the junction, {alone} fF without: {} fF, want {junction}",
        both - alone
    );

    let ohm = total(joined, Quantity::Resistance);
    let series = wire_ohm(JUNCTION.m1, 5_000, 1_000)
        + wire_ohm(JUNCTION.m2, 5_000, 1_000)
        + JUNCTION.v1.sheet;
    assert!(relative(ohm, series) <= MODEL, "R {ohm} ohm, want {series}");
}

/// PEX-004, PEX-005 (F79): a field-solved net that reaches a `connect global`
/// layer solves, and the global layer adds nothing to it. On the shipped
/// sky130 deck, `VSS` is a p-tap strapped to `li` by one contact; the tap is
/// also `psub` (global, no `pex` row) and joins it through `psub_tie`. A
/// global layer carries no parasitics (deck.md), so the network is the one
/// the same deck gives with `psub` not connected at all, where the tap's
/// `psub` shape is on no net: element for element, bit for bit. With the
/// global layer in the mesh the solve is refused for want of a `psub` row.
///
/// Oracle: differential against the same deck with `psub` not connected:
/// `docs/deck.md` says a global layer carries no parasitics, so the two
/// networks must be equal element for element, bit for bit.
#[test]
fn a_field_solved_net_on_the_substrate_net_leaves_the_global_layer_out() {
    let sky130 = include_str!("../../pdks/sky130.deck");
    let unconnected = sky130
        .replace("connect global psub\n", "")
        .replace("connect via psub_tie [ptap, psub]\n", "");
    assert!(
        unconnected.len() < sky130.len(),
        "both lines are in the deck"
    );
    let tap = Layout::default()
        .rect("tap", 0, 0, 1_000, 500)
        .rect("psdm", -125, -125, 1_125, 625)
        .rect("licon", 415, 165, 585, 335)
        .rect("li", 335, 85, 665, 415)
        .label("li_label", 500, 250, "VSS");
    let solve = |deck: &str| {
        let ran = run(deck, tap.clone(), PEX, &["VSS"]);
        assert_eq!(ran.summary.pex, StageStatus::Ran, "{:?}", ran.summary.pex);
        ran.outputs.parasitics.expect("PEX ran")
    };
    let tied = solve(sky130);
    assert!(
        tied.value
            .iter()
            .any(|value| matches!(value, Parasitic::Inductance(_))),
        "VSS was field-solved"
    );
    assert_eq!(tied, solve(&unconnected));
}

/// PEX-005, PEX-010 (F80): a net of junctions only has no panels, so solved
/// with another net it shares no field with it: their coupling is exactly
/// zero, and a positive zero, since SPEF prints `−0.0` as `-0.000000`. The
/// junction net `A` is a diffusion on [`JUNCTION`]'s `m1`; `B` is an `m2`
/// bar beside it.
///
/// Oracle: construct-from-answer. A net of junctions only has no panels, so it
/// shares no field and its coupling is exactly +0.0.
#[test]
fn a_junction_only_net_couples_by_a_positive_zero() {
    let layout = Layout::default()
        .rect("m1", 0, 0, 5_000, 1_000)
        .label("m1_label", 500, 500, "A")
        .rect("m2", 0, 3_000, 5_000, 4_000)
        .label("m2_label", 500, 3_500, "B");
    let ran = run(&deck(JUNCTION, &[], ""), layout, PEX, &["A", "B"]);
    let network = ran.outputs.parasitics.as_ref().expect("PEX ran");
    let couplings: Vec<f64> = network
        .value
        .iter()
        .filter_map(|value| match value {
            Parasitic::CouplingCap(q) => Some(q.raw()),
            _ => None,
        })
        .collect();
    assert!(
        couplings.len() == 1 && couplings[0].to_bits() == 0.0_f64.to_bits(),
        "couplings {couplings:?}, want one +0.0"
    );
    let header = gpurify::export::Header {
        tool_version: "test",
        deck_path: "pex.deck".into(),
        layout_path: "pex.gds".into(),
        timestamp: None,
    };
    let mut spef = String::new();
    gpurify::export::parasitic::write_spef(
        network,
        &ran.extracted.ports,
        &ran.loaded.strings,
        &header,
        &mut spef,
    )
    .expect("SPEF writes");
    assert!(!spef.contains("-0.000000"), "{spef}");
}

/// PEX-005 (F75): a field-solved net the mesh cannot take is a PEX refusal
/// naming the layer as the deck does, not an aborted run naming `LayerId`.
/// An `m1` row with no `dielectric` states no permittivity, which the closed
/// forms read as no coupling and the field solve cannot mesh.
///
/// Oracle: `docs/deck.md`, Parasitic stack: a line with no dielectric gives
/// "above the substrate, a layer the field solve refuses"; the refusal is
/// PEX's, naming the deck's layer.
#[test]
fn an_unmeshable_field_solved_net_is_refused_by_its_deck_layer() {
    let stack = Stack {
        m1: Row {
            k: 0.0,
            ..COARSE.m1
        },
        ..COARSE
    };
    let bar = Layout::default()
        .rect("m1", 0, 0, 4_000, 1_000)
        .label("m1_label", 500, 500, "A");
    let ran = run(&deck(stack, &[], ""), bar, PEX, &["A"]);
    match &ran.summary.pex {
        StageStatus::Refused(why) => assert!(
            why.starts_with("layer m1: ") && !why.contains("LayerId"),
            "{why}"
        ),
        status => panic!("PEX {status:?}, want a refusal naming m1"),
    }
    assert!(ran.outputs.parasitics.is_none() && !ran.summary.passed());
}

/// C6: a field-solved capacitance converges as the panel edge shrinks.
///
/// A 1 µm cube in vacuum (`k = 1`), its centre `H = 50` µm over the
/// substrate, cut into 2, 4, 8, 16 and 32 panels a side, each mesh the last
/// one with every panel quartered. The limit is the cube's capacitance in
/// free space, `0.66068 · 4πε₀a` (Read, *J. Comput. Phys.* 1997; Hwang,
/// Mascagni & Given 2004, to 1e-5), raised by its image in the plane: the
/// image charge `−Q` at `2H` lowers the potential by `Q / (4πε₀ · 2H)`, so
/// `C = C₀ / (1 − C₀ / (8πε₀H))`, a 0.66% rise whose next term is
/// `(a/2H)³ ≈ 1e-6`.
///
/// The rate: charge on a cube's edge, an exterior angle of 3π/2, grows as
/// `d^(−1/3)` with the distance `d` to it, so constant panels of edge `h`
/// misplace a share of the charge of order `h^(2/3)`, the slowest term.
/// The error against the limit therefore stays inside the envelope
/// `|e₀| (h/h₀)^(2/3)` set by the coarsest mesh's own error `e₀`, and at 32
/// panels a side is at most `16^(−2/3)`, 16%, of it.
///
/// Monotone, with no tolerance (F77): each refinement raises C. Collocation
/// with centroid-to-centroid far pairs is not a Galerkin solve, so
/// Thomson's principle does not promise it; it is what integrating near
/// panel pairs over both rectangles achieves, where the softened
/// centroid-to-centroid near field overshot (2% under at 2 panels a side,
/// 0.15–0.2% over at 8 to 32, falling back). Measured now: 1.8%, 0.75%,
/// 0.27%, 0.078% and 0.014% under the limit, rising, so each mesh is also
/// within the envelope with room to spare.
///
/// Oracle: published value and a convergence law: the unit cube's free-space
/// capacitance, 0.66068 · 4πε₀a (Read 1997; Hwang, Mascagni and Given 2004),
/// raised by its image in the plane, approached monotonically inside the
/// `h^(2/3)` envelope the coarsest mesh's error sets.
#[test]
fn a_field_solved_capacitance_converges_as_the_mesh_is_refined() {
    use gpurify::extract::field::mesh::MeshOptions;
    use gpurify::geom::Dbu;

    let (side, centre) = (1_000.0, 50_000.0);
    let cube = Stack {
        m1: Row {
            thickness: side,
            height: centre - side / 2.0,
            k: 1.0,
            ..COARSE.m1
        },
        ..COARSE
    };
    let layout = Layout::default()
        .rect("m1", 0, 0, 1_000, 1_000)
        .label("m1_label", 500, 500, "A");
    let ran = run(&deck(cube, &[], ""), layout, NONE, &[]);
    let solve = |edge: i64| {
        let mut matrix = CapMatrix::default();
        gpurify::extract::field::extract_meshed_into(
            &ran.loaded.store,
            &ran.extracted.nets,
            &ran.loaded.deck.connectivity,
            &[net(&ran, "A")],
            &ran.loaded.deck.stack,
            ran.loaded.grid,
            MeshOptions {
                max_edge: Dbu::new_unchecked(edge),
                proximity_refine: Dbu::new_unchecked(0),
                max_panels: 1 << 20,
            },
            &mut matrix,
        )
        .expect("the field solve converges");
        matrix.value[0] * 1e15
    };
    // 1000 nm over these edges is 2, 4, 8, 16 and 32 panels a side.
    let c = [500, 250, 125, 63, 32].map(solve);

    let four_pi_eps0_ff_per_um = 4.0 * std::f64::consts::PI * EPSILON0_AF_PER_UM / 1e3;
    let free = 0.660_68 * four_pi_eps0_ff_per_um * side / 1e3;
    let limit = free / (1.0 - free / (2.0 * four_pi_eps0_ff_per_um * centre / 1e3));
    // Each mesh's edge is the coarsest's over these.
    let e0 = (c[0] - limit).abs();
    let envelope = [1.0, 2.0, 4.0, 8.0, 16.0_f64].map(|finer| e0 / finer.powf(2.0 / 3.0));

    let shown = format!("C {c:?} fF, limit {limit} fF, envelope {envelope:?}");
    for k in 1..c.len() {
        assert!(
            (c[k] - limit).abs() <= envelope[k],
            "{} panels a side: outside the envelope: {shown}",
            2 << k
        );
        assert!(
            c[k] > c[k - 1],
            "{} panels a side did not raise C: {shown}",
            2 << k
        );
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

/// PEX-005: a field solve is a function of the geometry, not of how it is
/// drawn: every symmetry of the square gives the same matrix, and doubling
/// every length (layout and stack) doubles every capacitance, as it must in a
/// homogeneous dielectric.
///
/// Oracle: metamorphic relations. Every symmetry of the square gives the same
/// matrix, and doubling every length doubles every capacitance in a homogeneous
/// dielectric.
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
        ..Layout::default()
    };
    let (c, _) = maxwell(doubled, &labels, 2.0);
    broken.extend(differences("doubled", &c, &reference, 2.0));
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// PEX-005: moving a layout moves its field and changes nothing else. A face's
/// panel count once took round-off from absolute coordinates, so the same
/// three conductors 1 mm to the right read capacitances 1e-4 apart (F46).
///
/// Oracle: metamorphic relation. Translating the layout by 1 mm leaves the
/// matrix unchanged.
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
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// PEX-010: SPEF carries the network: a net's `*D_NET` total is its
/// closed-form capacitance and its `*RES` rows its closed-form resistances,
/// to the six decimals of fF and Ω the writer prints.
///
/// Oracle: closed form. Each net's `*D_NET` total and `*RES` rows are its
/// closed-form capacitance and resistances, to the six decimals the SPEF writer
/// prints.
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

/// One element a SPEF file states: its section, its node names, and its
/// value in SI (farads, ohms, henries).
#[derive(Debug, Clone)]
struct SpefElement {
    section: &'static str,
    nodes: Vec<String>,
    value: f64,
}

/// One `*D_NET` block: the net's name, its total capacitance in farads, and
/// its elements.
#[derive(Debug)]
struct SpefNet {
    name: String,
    total: f64,
    elements: Vec<SpefElement>,
}

/// A SPEF file as [`read_spef`] reads it: the SI size of one written unit of
/// capacitance, resistance and inductance, the node delimiter, and the nets.
#[derive(Debug)]
struct Spef {
    units: [f64; 3],
    delimiter: String,
    nets: Vec<SpefNet>,
}

/// The tokens of SPEF text: `//` comments dropped, a quoted string one
/// token with its quotes. (ponytail: a `//` inside a quoted string is not
/// read; no file here writes one.)
fn spef_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    for line in text.lines() {
        let mut rest = line.split("//").next().unwrap_or_default().trim_start();
        while !rest.is_empty() {
            let end = if let Some(quoted) = rest.strip_prefix('"') {
                quoted.find('"').map_or(rest.len(), |at| at + 2)
            } else {
                rest.find(char::is_whitespace).unwrap_or(rest.len())
            };
            tokens.push(&rest[..end]);
            rest = rest[end..].trim_start();
        }
    }
    tokens
}

/// A reader of the SPEF that IEEE 1481 defines (the 1998 edition the writer
/// names), written from the standard's grammar as the public `OpenSTA` parser
/// (`parasitics/SpefParse.yy`) transcribes it, and sharing nothing with
/// `gpurify::export`:
///
/// - `header_def`: `*SPEF`, `*DESIGN`, `*DATE`, `*VENDOR`, `*PROGRAM` and
///   `*VERSION`, each with one quoted string, then `*DESIGN_FLOW` with one or
///   more, in that order and every one required; `*DIVIDER` and
///   `*DELIMITER`, each an `hchar` (`.` `/` `:` `|`); `*BUS_DELIMITER` with
///   an opening bracket and an optional closing one; `*T_UNIT` (`NS`, `PS`),
///   `*C_UNIT` (`PF`, `FF`), `*R_UNIT` (`OHM`, `KOHM`) and `*L_UNIT`
///   (`HENRY`, `MH`, `UH`), each a positive number and a unit;
/// - `internal_def`: one or more `*D_NET net total_cap`, then an optional
///   `*CONN` with one or more `*P` or `*I` connections, each a name and a
///   direction (`I`, `O`, `B`), then the optional `*CAP`, `*RES` and
///   `*INDUC` sections in that order, then `*END`. A `*CAP` element is
///   `id node [node] value`, a `*RES` or `*INDUC` element `id node node
///   value`, the id a non-negative integer.
///
/// The optional header sections (`*NAME_MAP`, power and ground nets, ports,
/// `*DEFINE`), reduced nets, routing confidence, connection attributes and
/// value triplets are refused, not skipped: the writer states none of them,
/// so a reader that skipped them could pass a file it did not read.
fn read_spef(text: &str) -> Result<Spef, String> {
    let mut p = SpefParser {
        tokens: spef_tokens(text),
        at: 0,
    };
    for keyword in [
        "*SPEF",
        "*DESIGN",
        "*DATE",
        "*VENDOR",
        "*PROGRAM",
        "*VERSION",
        "*DESIGN_FLOW",
    ] {
        p.keyword(keyword)?;
        p.qstring()?;
    }
    while p.peek().starts_with('"') {
        p.qstring()?;
    }
    p.keyword("*DIVIDER")?;
    p.one_of(&[".", "/", ":", "|"])?;
    p.keyword("*DELIMITER")?;
    let delimiter = p.one_of(&[".", "/", ":", "|"])?.to_owned();
    p.keyword("*BUS_DELIMITER")?;
    p.one_of(&["[", "{", "(", "<", ":", "."])?;
    if ["]", "}", ")", ">"].contains(&p.peek()) {
        p.take()?;
    }
    let mut units = [0.0; 4];
    let tables: [(&str, &[(&str, f64)]); 4] = [
        ("*T_UNIT", &[("NS", 1e-9), ("PS", 1e-12)]),
        ("*C_UNIT", &[("PF", 1e-12), ("FF", 1e-15)]),
        ("*R_UNIT", &[("OHM", 1.0), ("KOHM", 1e3)]),
        ("*L_UNIT", &[("HENRY", 1.0), ("MH", 1e-3), ("UH", 1e-6)]),
    ];
    for (slot, (keyword, table)) in units.iter_mut().zip(tables) {
        p.keyword(keyword)?;
        let scale = p.number()?;
        if scale <= 0.0 {
            return Err(format!("{keyword} {scale} is not positive"));
        }
        let unit = p.take()?;
        let (_, si) = table
            .iter()
            .find(|(name, _)| *name == unit)
            .ok_or_else(|| format!("{keyword} {unit} is not a unit IEEE 1481 defines"))?;
        *slot = scale * si;
    }
    let mut nets = Vec::new();
    while !p.peek().is_empty() {
        p.keyword("*D_NET")?;
        let name = p.take()?.to_owned();
        let total = p.number()? * units[1];
        if p.peek() == "*CONN" {
            p.take()?;
            p.one_of(&["*P", "*I"])?;
            p.take()?;
            p.one_of(&["I", "O", "B"])?;
            while ["*P", "*I"].contains(&p.peek()) {
                p.take()?;
                p.take()?;
                p.one_of(&["I", "O", "B"])?;
            }
        }
        let mut elements = Vec::new();
        let sections = [
            ("*CAP", units[1], false),
            ("*RES", units[2], true),
            ("*INDUC", units[3], true),
        ];
        for (section, unit, two) in sections {
            if p.peek() != section {
                continue;
            }
            p.take()?;
            while !p.peek().is_empty() && p.peek().bytes().all(|b| b.is_ascii_digit()) {
                p.take()?;
                let mut nodes = vec![p.take()?.to_owned()];
                if two || p.peek().parse::<f64>().is_err() {
                    nodes.push(p.take()?.to_owned());
                }
                elements.push(SpefElement {
                    section,
                    nodes,
                    value: p.number()? * unit,
                });
            }
        }
        p.keyword("*END")?;
        nets.push(SpefNet {
            name,
            total,
            elements,
        });
    }
    if nets.is_empty() {
        return Err("internal_def needs one net at least".to_owned());
    }
    Ok(Spef {
        units: [units[1], units[2], units[3]],
        delimiter,
        nets,
    })
}

/// [`read_spef`]'s cursor over the tokens.
struct SpefParser<'a> {
    tokens: Vec<&'a str>,
    at: usize,
}

impl<'a> SpefParser<'a> {
    /// The next token, or `""` at the end.
    fn peek(&self) -> &'a str {
        self.tokens.get(self.at).copied().unwrap_or_default()
    }

    fn take(&mut self) -> Result<&'a str, String> {
        let token = self.peek();
        if token.is_empty() {
            return Err("unexpected end of file".to_owned());
        }
        self.at += 1;
        Ok(token)
    }

    fn keyword(&mut self, want: &str) -> Result<(), String> {
        let token = self.take()?;
        if token == want {
            Ok(())
        } else {
            Err(format!("want {want}, have {token}"))
        }
    }

    fn one_of(&mut self, allowed: &[&str]) -> Result<&'a str, String> {
        let token = self.take()?;
        if allowed.contains(&token) {
            Ok(token)
        } else {
            Err(format!("{token} is none of {allowed:?}"))
        }
    }

    fn qstring(&mut self) -> Result<&'a str, String> {
        let token = self.take()?;
        if token.len() >= 2 && token.starts_with('"') && token.ends_with('"') {
            Ok(token)
        } else {
            Err(format!("{token} is not a quoted string"))
        }
    }

    fn number(&mut self) -> Result<f64, String> {
        let token = self.take()?;
        token
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .ok_or_else(|| format!("{token} is not a number"))
    }
}

/// PEX-010: SPEF as IEEE 1481 defines it, read back by a reader written from
/// the standard ([`read_spef`]), states the extracted network.
///
/// Oracle: the standard's grammar (SE) and a round trip. On an analytical
/// network with resistance and capacitance, one with lateral coupling, and
/// a field-solved one with inductance, the file the writer produces (with no
/// timestamp, as the CLI writes it) parses under the standard's header and
/// net grammar; every element of the network appears exactly once, under
/// the section of its kind, in the `*D_NET` of its first node, named
/// `net<delimiter>index` by its index in its net, at its value to the six
/// written decimals; and each `*D_NET` total is the sum of every
/// capacitance with a node on the net, coupling included, which is what the
/// standard's `total_cap` is. A missing `*DATE`, a unit the standard does
/// not define, an element lost, moved or scaled, or a total without its
/// coupling breaks it.
#[test]
fn spef_reads_back_through_an_independent_reader_as_the_network() {
    let joined = joint(
        Layout::default()
            .rect("m1", 0, 0, 5_000, 1_000)
            .rect("m2", 4_000, 0, 9_000, 1_000)
            .label("m1_label", 500, 500, "A"),
        0,
        2,
    );
    let bars = parallel(Metal::M1, 3_000, 500, 500, 0);
    let runs = [
        ("joint", run(&deck(PARAMS, &[], ""), joined, PEX, &[])),
        (
            "coupled",
            run(&deck(PARAMS, &[], ""), bars.clone(), PEX, &[]),
        ),
        (
            "solved",
            run(&deck(COARSE, &[], ""), bars, PEX, &["A", "B"]),
        ),
    ];
    let header = gpurify::export::Header {
        tool_version: "test",
        deck_path: "pex.deck".into(),
        layout_path: "pex.gds".into(),
        timestamp: None,
    };
    let mut kinds = [false; 3];
    for (case, ran) in &runs {
        let network = ran.outputs.parasitics.as_ref().expect("PEX ran");
        let mut text = String::new();
        gpurify::export::parasitic::write_spef(
            network,
            &ran.extracted.ports,
            &ran.loaded.strings,
            &header,
            &mut text,
        )
        .expect("SPEF writes");
        let spef = read_spef(&text).unwrap_or_else(|why| panic!("{case}: {why}\n{text}"));

        let net_name = |net: NetId| {
            let name = ran.extracted.ports.name_of(net).expect("a labelled net");
            ran.loaded.strings.resolve(name).to_owned()
        };
        let node_name = |node: NodeId| {
            let row = node.0 as usize;
            let net = network.node_net[row];
            let first = network
                .node_net
                .iter()
                .position(|&n| n == net)
                .expect("its net");
            format!("{}{}{}", net_name(net), spef.delimiter, row - first)
        };
        let mut read: Vec<(String, SpefElement)> = spef
            .nets
            .iter()
            .flat_map(|net| net.elements.iter().map(|e| (net.name.clone(), e.clone())))
            .collect();
        for (k, value) in network.value.iter().enumerate() {
            let (section, slot, si) = match *value {
                Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => ("*CAP", 0, q.raw() * 1e-15),
                Parasitic::Resistance(q) => ("*RES", 1, q.raw()),
                Parasitic::Inductance(q) => ("*INDUC", 2, q.raw() * 1e-12),
            };
            kinds[slot] = true;
            let near = network.from[k];
            let mut nodes = vec![node_name(near)];
            nodes.extend(network.to[k].map(node_name));
            let tolerance = 5.1e-7 * spef.units[slot];
            let found = read.iter().position(|(block, e)| {
                *block == net_name(network.node_net[near.0 as usize])
                    && e.section == section
                    && e.nodes == nodes
                    && (e.value - si).abs() <= tolerance
            });
            let Some(found) = found else {
                panic!("{case}: no {section} {nodes:?} {si:e} in {read:?}\n{text}");
            };
            read.swap_remove(found);
        }
        assert!(
            read.is_empty(),
            "{case}: elements no network row states: {read:?}"
        );

        assert_eq!(
            spef.nets.len(),
            network.node_net.chunk_by(|a, b| a == b).count(),
            "{case}: one *D_NET per net"
        );
        for net in &spef.nets {
            let (sum, count) = spef
                .nets
                .iter()
                .flat_map(|n| &n.elements)
                .filter(|e| {
                    e.section == "*CAP"
                        && e.nodes.iter().any(|node| {
                            node.rsplit_once(spef.delimiter.as_str())
                                .is_some_and(|(owner, _)| owner == net.name)
                        })
                })
                .fold((0.0, 0.0), |(sum, count), e| (sum + e.value, count + 1.0));
            assert!(
                (net.total - sum).abs() <= 5.1e-7 * spef.units[0] * (count + 1.0),
                "{case}: *D_NET {} total {:e} F, its capacitances sum to {sum:e} F\n{text}",
                net.name,
                net.total
            );
        }
    }
    assert_eq!(kinds, [true; 3], "every section is exercised");
}

/// [`PARAMS`]' `m1` row at the `cmax` corner of [`CORNERS`].
const CMAX_M1: Row = Row {
    thickness: 440.0,
    sheet: 0.09,
    area: 30.0,
    fringe: 44.0,
    ..PARAMS.m1
};

/// Two corners: `cmax` varies four of `m1`'s values; `same` states `m1`'s
/// nominal sheet resistance, so it is the nominal stack.
const CORNERS: &str = "corner cmax m1 thickness 440nm sheet 0.09ohm area_cap 30aF/um2 \
                       fringe_cap 44aF/um\ncorner same m1 sheet 0.1ohm\n";

/// PEX-006: each process corner is extracted at its own values, the
/// nominal at the nominal's. Oracle: closed forms at the corner's
/// coefficients (two `m1` bars 6 x 1 um, 1 um apart: `Rs·L/W`,
/// `Ca·A + Cf·P`, `ε₀εr·t·L/S`), read through `compare`; and a law: a corner
/// that states the nominal values is the nominal network, bit for bit.
/// Fails if a corner reads the nominal stack, or the nominal a corner's.
#[test]
fn process_corners_extract_at_their_own_values() {
    let ran = run(
        &deck(PARAMS, &[], CORNERS),
        parallel(Metal::M1, 6_000, 1_000, 1_000, 0),
        PEX,
        &[],
    );
    let nominal = ran.outputs.parasitics.as_ref().expect("PEX ran");
    let names: Vec<&str> = ran
        .outputs
        .corners
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(names, ["cmax", "same"]);
    assert_eq!(&ran.outputs.corners[1].1, nominal, "the nominal values");

    let out = gpurify::extract::compare::compare(nominal, &ran.outputs.corners[0].1);
    for (metric, want_nominal, want_corner) in [
        (
            &out.resistance,
            wire_ohm(PARAMS.m1, 6_000, 1_000),
            wire_ohm(CMAX_M1, 6_000, 1_000),
        ),
        (
            &out.ground_cap,
            ground_ff(PARAMS.m1, 6e6, 14_000.0),
            ground_ff(CMAX_M1, 6e6, 14_000.0),
        ),
    ] {
        assert_eq!(metric.key.len(), 2, "both bars");
        for (&got_nominal, &got_corner) in metric.reference.iter().zip(&metric.candidate) {
            assert!(
                relative(got_nominal, want_nominal) < EXACT
                    && relative(got_corner, want_corner) < EXACT,
                "nominal {got_nominal} want {want_nominal}, cmax {got_corner} want {want_corner}"
            );
        }
    }
    assert_eq!(out.coupling.key.len(), 1);
    let lateral = (
        lateral_ff(PARAMS.m1, 6_000, 1_000),
        lateral_ff(CMAX_M1, 6_000, 1_000),
    );
    assert!(
        relative(out.coupling.reference[0], lateral.0) < EXACT
            && relative(out.coupling.candidate[0], lateral.1) < EXACT,
        "coupling {:?}, want {lateral:?}",
        out.coupling
    );
}

/// PEX-006, PEX-010: with process corners SPEF writes every value as an
/// IEEE 1481 triplet `min:typ:max`. Oracle: closed forms. Two `m1` bars
/// 3.9 um apart couple at the nominal `m1` (lateral coupling reaches ten
/// thicknesses, 4 um) and not at a 380 nm corner (3.8 um), so their
/// coupling's triplet runs from 0 to the 440 nm `cmax` corner's sidewall
/// coupling; `cmax`'s resistance is the low end of the resistance's (0.09
/// ohm per square against 0.1). And a
/// law: with no corners the corner writer is `write_spef` byte for byte.
#[test]
fn spef_writes_process_corners_as_triplets() {
    let corners = format!("{CORNERS}corner thin m1 thickness 380nm\n");
    let ran = run(
        &deck(PARAMS, &[], &corners),
        parallel(Metal::M1, 6_000, 1_000, 3_900, 0),
        PEX,
        &[],
    );
    let header = gpurify::export::Header {
        tool_version: "test",
        deck_path: "pex.deck".into(),
        layout_path: "pex.gds".into(),
        timestamp: None,
    };
    let nominal = ran.outputs.parasitics.as_ref().expect("PEX ran");
    let write = |corners: &[&ParasiticNetwork]| {
        let mut spef = String::new();
        gpurify::export::parasitic::write_spef_corners(
            nominal,
            corners,
            &ran.extracted.ports,
            &ran.loaded.strings,
            &header,
            &mut spef,
        )
        .expect("SPEF writes");
        spef
    };
    let mut plain = String::new();
    gpurify::export::parasitic::write_spef(
        nominal,
        &ran.extracted.ports,
        &ran.loaded.strings,
        &header,
        &mut plain,
    )
    .expect("SPEF writes");
    assert_eq!(write(&[]), plain, "no corners is plain SPEF");

    let all: Vec<&ParasiticNetwork> = ran.outputs.corners.iter().map(|(_, n)| n).collect();
    let spef = write(&all);
    let triplet = |line: &str| -> [f64; 3] {
        let values: Vec<f64> = line
            .rsplit(' ')
            .next()
            .expect("a value")
            .split(':')
            .map(|v| v.parse().expect("a number"))
            .collect();
        values.try_into().expect("a triplet")
    };
    let lateral = lateral_ff(PARAMS.m1, 6_000, 3_900);
    let thickest = lateral_ff(CMAX_M1, 6_000, 3_900);
    let coupling = spef
        .lines()
        .find(|line| line.split(' ').count() == 4 && line.contains("A:") && line.contains("B:"))
        .unwrap_or_else(|| panic!("a coupling row\n{spef}"));
    let [low, typical, high] = triplet(coupling);
    assert!(
        low == 0.0 && (typical - lateral).abs() <= 5e-7 && (high - thickest).abs() <= 5e-7,
        "{coupling}, want 0:{lateral}:{thickest}"
    );
    let resistance = spef
        .lines()
        .skip_while(|line| *line != "*RES")
        .nth(1)
        .unwrap_or_else(|| panic!("a *RES row\n{spef}"));
    let [low, typical, high] = triplet(resistance);
    let (r_min, r_nom) = (
        wire_ohm(CMAX_M1, 6_000, 1_000),
        wire_ohm(PARAMS.m1, 6_000, 1_000),
    );
    assert!(
        (low - r_min).abs() <= 5e-7
            && (typical - r_nom).abs() <= 5e-7
            && (high - r_nom).abs() <= 5e-7,
        "{resistance}, want {r_min}:{r_nom}:{r_nom}"
    );
}

mod fastcap;
mod fasthenry;
mod magic;
