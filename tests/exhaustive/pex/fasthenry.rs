//! The field-solved series inductance and resistance against `FastHenry`
//! 3.0.1 (testing-plan §4 L6, ledger F3), on X6's inductance geometries: the
//! bars at every nightly size on both metals, a bar drawn in halves, the L
//! drawn as two rectangles and as one polygon, and two bars joined by a via.
//!
//! **What `FastHenry` is given.** Each wire as segments along its centre
//! line, one filament each (`nwinc = nhinc = 1`), the conductivity
//! `1 / (Rs · t)` that gives the row's sheet resistance, and a port between
//! the wire's two ends, solved at 1 MHz as `GPurify` solves it. At 1 MHz
//! the skin depth in these metals is tens of µm, far above any cross-section
//! here, so one uniform filament per segment is the converged answer.
//! The via is a segment from one bar's centre line to the other's, as
//! `GPurify` models it, its conductivity giving the row's resistance per cut.
//!
//! Both sides model a bend as its centre line, turning at the corner square's
//! middle, and a via as a filament between the two centre lines it joins,
//! so the corner and the via are counted alike and need no modelling
//! allowance (X6's `MODEL`, 5 %).
//!
//! **Tolerances:**
//!
//! - [`SHEET`], 1e-4: every `R` is `Rs` times the centre line's squares,
//!   plus `Rcut` per via, on both sides; this is the five digits
//!   `FastHenry` prints;
//! - [`BAR`], 1 %: every `L`. `GPurify` takes Grover's closed form for each
//!   filament's partial self-inductance, `FastHenry` the exact integral over
//!   the rectangular cross-section (Hoer & Love); they differ by a fraction
//!   of a percent at a bar's aspect ratios (X6's `GROVER`), and most on the
//!   via's short, square filament.

use super::{bend, deck, joint, relative, Metal, Row, COARSE, PEX};
use crate::harness::{self, Fixture, Layout, Quantity};
use gpurify_testgen::oracle;
use std::f64::consts::PI;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

/// A resistance against `FastHenry`.
const SHEET: f64 = 1e-4;
/// An inductance against `FastHenry`.
const BAR: f64 = 1e-2;

/// The frequency both solve at, Hz.
const FREQUENCY: f64 = 1e6;

/// One straight `FastHenry` segment: from, to (nm, at the centre of the
/// cross-section), width and height (nm), and the row it is on.
struct Segment {
    from: [i64; 3],
    to: [i64; 3],
    width: i64,
    height: i64,
    /// Ω per square for a wire, Ω per cut for a via.
    ohms: f64,
    via: bool,
}

impl Segment {
    /// A wire on `row` along its centre line.
    fn wire(row: Row, from: [i64; 2], to: [i64; 2], width: i64) -> Self {
        #[allow(clippy::cast_possible_truncation, reason = "whole nanometres")]
        let z = (row.height + row.thickness / 2.0) as i64;
        #[allow(clippy::cast_possible_truncation, reason = "whole nanometres")]
        let height = row.thickness as i64;
        Segment {
            from: [from[0], from[1], z],
            to: [to[0], to[1], z],
            width,
            height,
            ohms: row.sheet,
            via: false,
        }
    }

    /// `1/(Ω·µm)`: a wire's `1 / (Rs · t)`, a via's `length / (R · area)`.
    fn sigma(&self) -> f64 {
        let um = |nm: i64| nm as f64 / 1e3;
        if self.via {
            let length = um(self.to[2] - self.from[2]);
            length / (self.ohms * um(self.width) * um(self.height))
        } else {
            1.0 / (self.ohms * um(self.height))
        }
    }
}

/// `FastHenry`'s port impedance of `segments` in a chain, from the first's
/// start to the last's end: `(R in Ω, L in pH)`.
fn fasthenry(tool: &Path, segments: &[Segment]) -> (f64, f64) {
    let um = |nm: i64| nm as f64 / 1e3;
    let mut input = String::from("* GPurify F3 differential\n.units um\n");
    let node = |out: &mut String, k: usize, p: [i64; 3]| {
        let _ = writeln!(out, "N{k} x={} y={} z={}", um(p[0]), um(p[1]), um(p[2]));
    };
    node(&mut input, 0, segments[0].from);
    for (k, s) in segments.iter().enumerate() {
        node(&mut input, k + 1, s.to);
        let _ = writeln!(
            input,
            "E{k} N{k} N{} w={} h={} sigma={} nwinc=1 nhinc=1",
            k + 1,
            um(s.width),
            um(s.height),
            s.sigma()
        );
    }
    let _ = write!(
        input,
        ".external N0 N{}\n.freq fmin={FREQUENCY} fmax={FREQUENCY} ndec=1\n.end\n",
        segments.len()
    );
    let dir = oracle::scratch("fasthenry");
    std::fs::write(dir.join("in.inp"), input).expect("the scratch directory is writable");
    oracle::run(tool, &["in.inp"], &dir, Duration::from_mins(1));
    let zc = std::fs::read_to_string(dir.join("Zc.mat")).expect("FastHenry writes Zc.mat");
    // The last line is the 1 x 1 impedance, `R +Xj`.
    let words: Vec<&str> = zc
        .lines()
        .last()
        .expect("an impedance")
        .split_whitespace()
        .collect();
    let r: f64 = words[0].parse().expect("a resistance");
    let x: f64 = words[1].trim_end_matches('j').parse().expect("a reactance");
    let _ = std::fs::remove_dir_all(&dir);
    (r, x / (2.0 * PI * FREQUENCY) * 1e12)
}

/// One case: the layout `GPurify` solves, the segments `FastHenry` solves,
/// both named by `name`.
struct Case {
    name: String,
    layout: Layout,
    segments: Vec<Segment>,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for metal in [Metal::M1, Metal::M2] {
        let row = metal.row(COARSE);
        for (l, w) in [
            (10_000, 500),
            (20_000, 1_000),
            (40_000, 2_000),
            (40_000, 500),
        ] {
            out.push(Case {
                name: format!("bar/{}/{l}x{w}", metal.name()),
                layout: Layout::default().rect(metal.name(), 0, 0, l, w).label(
                    metal.label(),
                    w / 2,
                    w / 2,
                    "A",
                ),
                segments: vec![Segment::wire(row, [0, w / 2], [l, w / 2], w)],
            });
        }
    }
    let m1 = COARSE.m1;
    out.push(Case {
        name: "bar_in_halves".into(),
        layout: Layout::default()
            .rect("m1", 0, 0, 20_000, 1_000)
            .rect("m1", 20_000, 0, 40_000, 1_000)
            .label("m1_label", 500, 500, "A"),
        segments: vec![Segment::wire(m1, [0, 500], [40_000, 500], 1_000)],
    });
    // X6's L: legs of 20 and 16 um, 1 um wide; its centre line turns at
    // (a - w/2, w/2).
    let (a, b, w) = (20_000, 16_000, 1_000);
    let (points, _) = bend("l", a, b, w);
    let corner = [a - w / 2, w / 2];
    let legs = || {
        vec![
            Segment::wire(m1, [0, w / 2], corner, w),
            Segment::wire(m1, corner, [a - w / 2, b], w),
        ]
    };
    for (name, layout) in [
        (
            "l_two_rectangles",
            Layout::default()
                .rect("m1", 0, 0, a, w)
                .rect("m1", a - w, w, a, b),
        ),
        ("l_one_polygon", Layout::default().polygon("m1", &points)),
    ] {
        out.push(Case {
            name: name.into(),
            layout: layout.label("m1_label", 500, 500, "A"),
            segments: legs(),
        });
    }
    // X6's via_joined: m1 over [0, 5] um, m2 over [4, 9] um, one 200 nm cut
    // at x = 4.1..4.3 um, y = 0.1..0.3 um; the cut's filament runs between
    // the two bars' centre lines.
    let (m2, v1) = (COARSE.m2, COARSE.v1);
    #[allow(clippy::cast_possible_truncation, reason = "whole nanometres")]
    let mid = |row: Row| (row.height + row.thickness / 2.0) as i64;
    let x = 4_200;
    out.push(Case {
        name: "via_joined".into(),
        layout: joint(
            Layout::default()
                .rect("m1", 0, 0, 5_000, 1_000)
                .rect("m2", 4_000, 0, 9_000, 1_000)
                .label("m1_label", 500, 500, "A"),
            0,
            1,
        ),
        segments: vec![
            Segment::wire(m1, [0, 500], [x, 500], 1_000),
            Segment {
                from: [x, 500, mid(m1)],
                to: [x, 500, mid(m2)],
                width: 200,
                height: 200,
                ohms: v1.sheet,
                via: true,
            },
            Segment::wire(m2, [x, 500], [9_000, 500], 1_000),
        ],
    });
    out
}

/// Every case's series `R` and `L` within its tolerance of `FastHenry`'s.
///
/// Oracle: differential against `FastHenry`, an independent inductance solver,
/// series R and L within each case's tolerance.
#[test]
#[ignore = "release tier: needs fasthenry (nix develop .#oracles)"]
fn fasthenry_differential_every_inductance_geometry() {
    let tool = oracle::tool("fasthenry");
    let mut broken = Vec::new();
    let cases = cases();
    for case in &cases {
        let (want_r, want_l) = fasthenry(&tool, &case.segments);
        let mut fixture = Fixture::new(
            &format!("pex/fasthenry/{}", case.name),
            &["PEX-004"],
            &deck(COARSE, &[], ""),
            PEX,
        )
        .layout(case.layout.clone());
        fixture.quasistatic = vec!["A".into()];
        let ran = harness::run(&fixture).unwrap_or_else(|why| panic!("{}: {why}", case.name));
        for (what, quantity, want, tolerance) in [
            ("R", Quantity::Resistance, want_r, SHEET),
            ("L", Quantity::Inductance, want_l, BAR),
        ] {
            let got = harness::parasitic_total(&ran, "A", quantity)
                .unwrap_or_else(|| panic!("{}: no {what}", case.name));
            println!(
                "{}: {what} {got:.6}, FastHenry {want:.6}, {:+.3} %",
                case.name,
                (got - want) / want * 100.0
            );
            if relative(got, want) > tolerance {
                broken.push(format!(
                    "{}: {what} = {got}, FastHenry {want} ({:.3} % > {} %)",
                    case.name,
                    relative(got, want) * 100.0,
                    tolerance * 100.0
                ));
            }
        }
    }
    assert_eq!(cases.len(), 12, "every case ran");
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}
