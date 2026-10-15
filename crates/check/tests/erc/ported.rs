//! The root crate's ERC fixtures (`tests/exhaustive/erc.rs`), run in this
//! crate through [`crate::fixture`] so that `cargo mutants`, which runs only
//! this crate's own tests, sees them. Each fixture's expectation is derived
//! in its doc comment from the rule's definition (a closed form, a
//! construction, the cited standard), exactly as in the root crate; only the
//! reader path differs (in memory here, GDSII there). The nightly-only
//! enumerations stay in the root crate, and the sampled ones draw about a
//! fifth of the root's merge sample (the first draws of the same seeded
//! shuffle): `cargo mutants` runs this suite once per mutant.

#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    reason = "ported fixtures: small test sizes, each group written out once"
)]

use crate::fixture::{check_all, Depth, Expect, Finding, Fixture, Layout, Symmetry, Want};
use gpurify_check::report::Measurement;
use gpurify_geom::{Dbu, Qty};
use gpurify_testgen::Rng;

/// The translations a placed case is repeated at.
const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];
fn measured(m: Measurement) -> Finding {
    Finding {
        measured: Some(m),
        at: None,
    }
}

fn ratio(x: f64) -> Finding {
    measured(Measurement::Ratio(x))
}

pub(crate) fn count(n: u32) -> Finding {
    measured(Measurement::Count(n))
}

pub(crate) fn millivolts(x: f64) -> Finding {
    measured(Measurement::Voltage(Qty::new(x)))
}

pub(crate) fn microamps(x: f64) -> Finding {
    measured(Measurement::Current(Qty::new(x)))
}

pub(crate) fn ohms(x: f64) -> Finding {
    measured(Measurement::Resistance(Qty::new(x)))
}

fn length(nm: i64) -> Finding {
    measured(Measurement::Length(Dbu::new_unchecked(nm)))
}

/// Where a limit sits against the value it is swept around.
pub(crate) fn side(limit: f64, value: f64) -> &'static str {
    match limit.total_cmp(&value) {
        std::cmp::Ordering::Less => "below",
        std::cmp::Ordering::Equal => "at",
        std::cmp::Ordering::Greater => "above",
    }
}

/// `value` and one part in a thousand either side: the three limits a value is
/// swept with. The middle one is the value itself, so a deck writing it with
/// `{}` reads back the same `f64`.
pub(crate) fn sweep(value: f64) -> [f64; 3] {
    [value * 0.999, value, value * 1.001]
}

/// A box `(xlo, ylo, xhi, yhi)` in nanometres.
pub(crate) type Rect = (i64, i64, i64, i64);

/// Adds a rectangle to a layout in place.
pub(crate) fn rect(layout: &mut Layout, layer: &str, (xlo, ylo, xhi, yhi): Rect) {
    *layout = std::mem::take(layout).rect(layer, xlo, ylo, xhi, yhi);
}

/// Each fixture as drawn, transposed (a quarter turn then a mirror: x and y
/// swap and orientation reverses) at the far offset, and turned half way
/// (both signs flip). The root crate places each under all eight symmetries
/// at both offsets; three placements keep this suite fast while still
/// moving every pinned marker off both axes.
fn every_placement(fixtures: &[Fixture]) -> Vec<Fixture> {
    let (dx, dy) = OFFSETS[1];
    let transpose = Symmetry {
        turns: 1,
        mirror: true,
    };
    let half = Symmetry {
        turns: 2,
        mirror: false,
    };
    fixtures
        .iter()
        .flat_map(|f| {
            [
                f.transformed(Symmetry::IDENTITY, 0, 0),
                f.transformed(transpose, dx, dy),
                f.transformed(half, 0, 0),
            ]
        })
        .collect()
}

/// Each fixture translated to every offset, unrotated.
fn every_offset(fixtures: &[Fixture]) -> Vec<Fixture> {
    fixtures
        .iter()
        .flat_map(|f| {
            OFFSETS
                .iter()
                .map(move |&(dx, dy)| f.transformed(Symmetry::IDENTITY, dx, dy))
        })
        .collect()
}

/// All of `items` at nightly depth, a seeded sample of `merge` at merge depth.
fn sample<T: Clone>(items: &[T], _depth: Depth, merge: usize, seed: u64) -> Vec<T> {
    if items.len() <= merge {
        return items.to_vec();
    }
    let mut rng = Rng::new(seed);
    let mut index: Vec<usize> = (0..items.len()).collect();
    for i in 0..merge {
        let j = i + rng.below((index.len() - i) as u64) as usize;
        index.swap(i, j);
    }
    index[..merge].iter().map(|&i| items[i].clone()).collect()
}

/// A design-intent file: `domains` as `(name, mV)`, `supplies` as
/// `(net, domain, role)`, and `limits` as raw JSON objects.
fn intent(domains: &[(&str, f64)], supplies: &[(&str, &str, &str)], limits: &[String]) -> String {
    let domains: Vec<String> = domains
        .iter()
        .map(|(name, mv)| format!(r#""{name}":{{"voltage_mv":{mv}}}"#))
        .collect();
    let supplies: Vec<String> = supplies
        .iter()
        .map(|(net, domain, role)| {
            format!(r#"{{"net":"{net}","domain":"{domain}","role":"{role}"}}"#)
        })
        .collect();
    format!(
        r#"{{"domains":{{{}}},"supplies":[{}],"limits":[{}]}}"#,
        domains.join(","),
        supplies.join(","),
        limits.join(",")
    )
}

/// Conductors bottom-up diff, poly, met1-met3, with a drawn gate marker (not a
/// conductor, so it joins the poly under it), a second gate oxide, a MIM
/// victim, and the derived `poly and diff` gate the rustdoc recommends.
const ANTENNA_PROCESS: &str = "grid 1nm
layer diff = gds(1, 0)
layer poly = gds(2, 0)
layer gate = gds(3, 0)
layer gate2 = gds(4, 0)
layer mim = gds(5, 0)
layer cont = gds(6, 0)
layer met1 = gds(7, 0)
layer via1 = gds(8, 0)
layer met2 = gds(9, 0)
layer via2 = gds(10, 0)
layer met3 = gds(11, 0)
layer gated = poly and diff
connect conductors [diff, poly, met1, met2, met3]
connect touch_within_layer
connect via cont [diff, met1]
connect via cont [poly, met1]
connect via via1 [met1, met2]
connect via via2 [met2, met3]
";

fn antenna_deck(rules: &str) -> String {
    format!("{ANTENNA_PROCESS}{rules}\n")
}

/// LEF/DEF 5.8 Appendix C, Figure C-20, at nanometre scale (1 µm² = 10^6
/// nm²): G1 = 1.0 and G2 = 2.0 gates, every contact and via 0.1, D1 = 0.5,
/// M1,1 = 1.0, M1,2 = 2.0, M1,3 = 3.0, M2,1 = 4.0, M2,2 = 5.0, M3,1 = 6.0,
/// M3,2 = 9.0. G1 reaches M1,2 through C1; G2 and D1 reach M1,3 through C2
/// and C3; V1,2 and V1,3 lift M1,2 to M2,1 and M2,2, V1,4 lifts M1,3 to M2,2,
/// V1,1 lifts M1,1 to M2,1; V2,1 and V2,2 lift M2,1 and M2,2 to M3,1 and M3,2.
/// No metal passes over a gate.
fn lef_c20() -> Layout {
    let mut l = Layout::default();
    // G1, the first gate drawn: the lowest-numbered gate of every net it joins.
    rect(&mut l, "poly", (0, 0, 1000, 2000));
    rect(&mut l, "gate", (0, 0, 1000, 1000));
    rect(&mut l, "cont", (300, 1500, 700, 1750));
    rect(&mut l, "met1", (0, 1250, 4000, 1750));
    rect(&mut l, "via1", (750, 1400, 1150, 1650));
    rect(&mut l, "via1", (3000, 1400, 3400, 1650));
    rect(&mut l, "met1", (-3000, 1250, -2000, 2250));
    rect(&mut l, "via1", (-2700, 1600, -2300, 1850));
    rect(&mut l, "met2", (-2800, 1400, 1200, 2400));
    // G2 and the diode D1.
    rect(&mut l, "poly", (6000, -1000, 7000, 1600));
    rect(&mut l, "gate", (6000, -1000, 7000, 1000));
    rect(&mut l, "cont", (6300, 1300, 6700, 1550));
    rect(&mut l, "diff", (7400, 1300, 7900, 2300));
    rect(&mut l, "cont", (7450, 1950, 7850, 2200));
    rect(&mut l, "met1", (5000, 1250, 8000, 2250));
    rect(&mut l, "via1", (5200, 1900, 5600, 2150));
    rect(&mut l, "met2", (2900, 1300, 7900, 2300));
    // The third metal.
    rect(&mut l, "via2", (-2000, 1900, -1600, 2150));
    rect(&mut l, "met3", (-3000, 1400, 0, 3400));
    rect(&mut l, "via2", (4000, 1900, 4400, 2150));
    rect(&mut l, "met3", (3000, 1300, 6000, 4300));
    l
}

/// One antenna row's value on each gate net it examines, with the centre of
/// the net's lowest-numbered gate polygon.
struct AntennaRow {
    id: &'static str,
    collectors: &'static str,
    /// `(ratio, marker)` per gate net, or per gate where the row's stages
    /// part them.
    nets: Vec<(f64, (i64, i64))>,
}

/// The LEF/DEF Appendix C ratios of Figure C-20, from the manual's own
/// formulas without its area factors (`GPurify` states none): PAR = collecting
/// area on the node / gate area connected to it at that etch. At met1 G1's
/// node holds M1,2 (PAR = 2.0/1.0, the manual's step 2) and G2's holds M1,3
/// (3.0/2.0); from met2 up one node holds both gates (step 8: 9/3 = 3.0, step
/// 14: 15/3 = 5.0). A cut stands on its lower conductor: the contacts on bare
/// poly (0.1/1.0, 0.1/2.0), via1 on met1 (V1,2 + V1,3 = 0.2 on G1, V1,4 = 0.1
/// on G2), via2 on met2 (0.2/3). The cumulative row over met1-met3 is the
/// manual's CAR, the sum of each gate's PARs: 2 + 3 + 5 = 10.0 for G1 and
/// 1.5 + 3 + 5 = 9.5 for G2, one value per gate (IHP's `AreaRatio` too).
/// Pooling all the metal over the gates at met3, 30/3 = 10.0, would report
/// one net and miss G2 below 9.5 (F59).
fn lef_c20_rows() -> Vec<AntennaRow> {
    let g1 = (500, 500);
    let g2 = (6500, 0);
    let r = |num: i64, den: i64| num as f64 / den as f64;
    vec![
        AntennaRow {
            id: "par.cont",
            collectors: "cont",
            nets: vec![(r(100_000, 1_000_000), g1), (r(100_000, 2_000_000), g2)],
        },
        AntennaRow {
            id: "par.met1",
            collectors: "met1",
            nets: vec![(r(2_000_000, 1_000_000), g1), (r(3_000_000, 2_000_000), g2)],
        },
        AntennaRow {
            id: "par.via1",
            collectors: "via1",
            nets: vec![(r(200_000, 1_000_000), g1), (r(100_000, 2_000_000), g2)],
        },
        AntennaRow {
            id: "par.met2",
            collectors: "met2",
            nets: vec![(r(9_000_000, 3_000_000), g1)],
        },
        AntennaRow {
            id: "par.via2",
            collectors: "via2",
            nets: vec![(r(200_000, 3_000_000), g1)],
        },
        AntennaRow {
            id: "par.met3",
            collectors: "met3",
            nets: vec![(r(15_000_000, 3_000_000), g1)],
        },
        AntennaRow {
            id: "car.met123",
            collectors: "met1, met2, met3",
            nets: vec![
                (r(2_000_000, 1_000_000) + 3.0 + 5.0, g1),
                (r(3_000_000, 2_000_000) + 3.0 + 5.0, g2),
            ],
        },
    ]
}

/// Findings of a ratio row at `limit`: every value strictly above it.
fn ratio_findings(values: &[(f64, (i64, i64))], limit: f64, pin: bool) -> Vec<Finding> {
    values
        .iter()
        .filter(|(v, _)| *v > limit)
        .map(|&(v, (x, y))| if pin { ratio(v).at(x, y) } else { ratio(v) })
        .collect()
}

/// Every row of Figure C-20 swept across each of its nets' values; the met1
/// row (the manual's PAR = 2.0/1.0) also under every placement.
fn antenna_lef() -> Vec<Fixture> {
    let mut out = Vec::new();
    let mut placed = Vec::new();
    for row in lef_c20_rows() {
        let catalog: &[&'static str] = match row.collectors {
            "met1" | "met2" | "met3" => &["ERC-A1"],
            "cont" | "via1" | "via2" => &["ERC-A1", "ERC-A4"],
            _ => &["ERC-A3"],
        };
        for (n, &(value, _)) in row.nets.iter().enumerate() {
            for limit in sweep(value) {
                let deck = antenna_deck(&format!(
                    "rule {} antenna(gate, {}; max_ratio: {limit}, sidewall: none, diode: none, diode_area: none, diode_min: none)",
                    row.id, row.collectors
                ));
                let fixture = Fixture::new(
                    &format!(
                        "erc/antenna/lef_c20/{}/net{n}/{}",
                        row.id,
                        side(limit, value)
                    ),
                    catalog,
                    &deck,
                )
                .layout(lef_c20())
                .expect(Expect::rule(row.id, ratio_findings(&row.nets, limit, true)));
                if row.id == "par.met1" && n == 1 && limit < value {
                    placed.push(fixture.clone());
                }
                out.push(fixture);
            }
        }
    }
    for mut f in placed {
        f.name = format!("{}/placed", f.name);
        out.extend(every_placement(&[f]));
    }
    out
}

/// A 1.0 µm² gate on poly, contacted at (400..600, 1700..1900) to whatever
/// `collect` draws on met1.
fn gate_stub(gate_layer: &str) -> Layout {
    let mut l = Layout::default();
    rect(&mut l, "poly", (0, 0, 1000, 2000));
    rect(&mut l, gate_layer, (0, 0, 1000, 1000));
    rect(&mut l, "cont", (400, 1700, 600, 1900));
    l
}

/// Side-area antenna: collecting area = merged perimeter × thickness (350
/// nm), over the 1.0 µm² gate. A 3000 × 400 bar has perimeter 6800 (ratio
/// 2.38) however it is drawn: whole, as two abutting halves (a per-polygon
/// perimeter would read 7600), or as two overlapping pieces (8800). An L of
/// arms 3000 × 400 and 400 × 2400 has perimeter 10 800 (ratio 3.78).
fn antenna_sidewall() -> Vec<Fixture> {
    let shapes: Vec<(&str, i64, Layout)> = vec![
        ("bar", 6800, {
            let mut l = gate_stub("gate");
            rect(&mut l, "met1", (0, 1600, 3000, 2000));
            l
        }),
        ("abutting_halves", 6800, {
            let mut l = gate_stub("gate");
            rect(&mut l, "met1", (0, 1600, 1500, 2000));
            rect(&mut l, "met1", (1500, 1600, 3000, 2000));
            l
        }),
        ("overlapping", 6800, {
            let mut l = gate_stub("gate");
            rect(&mut l, "met1", (0, 1600, 2000, 2000));
            rect(&mut l, "met1", (1000, 1600, 3000, 2000));
            l
        }),
        ("l_shape", 10_800, {
            gate_stub("gate").polygon(
                "met1",
                &[
                    (0, 1600),
                    (3000, 1600),
                    (3000, 4000),
                    (2600, 4000),
                    (2600, 2000),
                    (0, 2000),
                ],
            )
        }),
    ];
    let mut out = Vec::new();
    for (name, perimeter, layout) in shapes {
        let value = (perimeter * 350) as f64 / 1_000_000.0;
        for limit in sweep(value) {
            let f = Fixture::new(
                &format!("erc/antenna/sidewall/{name}/{}", side(limit, value)),
                &["ERC-A2"],
                &antenna_deck(&format!(
                    "rule ant.side antenna(gate, met1; max_ratio: {limit}, sidewall: 350nm, diode: none, diode_area: none, diode_min: none)"
                )),
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "ant.side",
                ratio_findings(&[(value, (500, 500))], limit, true),
            ));
            if limit < value && matches!(name, "bar" | "l_shape") {
                let mut placed = f.clone();
                placed.name = format!("{}/placed", f.name);
                out.extend(every_placement(&[placed]));
            }
            out.push(f);
        }
    }
    out
}

/// The derived `poly and diff` gate, oxide classes, a MIM victim, a
/// single-gate cumulative stack, the double-counting cases (F29) and IHP's
/// Figure 7.1 ([`ihp_area_ratio`]).
fn antenna_variants() -> Vec<Fixture> {
    let mut out = Vec::new();
    // A derived gate: poly over a wider diffusion; 2.0 µm² of met1 on 1.0.
    let derived = {
        let mut l = Layout::default();
        rect(&mut l, "diff", (-500, 0, 1500, 1000));
        rect(&mut l, "poly", (0, 0, 1000, 2000));
        rect(&mut l, "cont", (400, 1700, 600, 1900));
        rect(&mut l, "met1", (0, 1600, 4000, 2100));
        l
    };
    for limit in sweep(2.0) {
        out.push(
            Fixture::new(
                &format!("erc/antenna/derived_gate/{}", side(limit, 2.0)),
                &["ERC-A1"],
                &antenna_deck(&format!(
                    "rule ant.d antenna(gated, met1; max_ratio: {limit}, sidewall: none, diode: none, diode_area: none, diode_min: none)"
                )),
            )
            .layout(derived.clone())
            .expect(Expect::rule(
                "ant.d",
                ratio_findings(&[(2.0, (500, 500))], limit, true),
            )),
        );
    }

    // Oxide classes: a thin gate of 1.0 and a thick one of 2.0 share 2.4 of
    // met1; each row counts only its own gate layer (LEF ANTENNAMODEL OXIDEn).
    let oxides = {
        let mut l = gate_stub("gate");
        rect(&mut l, "poly", (2000, 0, 4000, 2000));
        rect(&mut l, "gate2", (2000, 0, 4000, 1000));
        rect(&mut l, "cont", (2900, 1700, 3100, 1900));
        rect(&mut l, "met1", (0, 1600, 6000, 2000));
        l
    };
    for (id, layer, value, at) in [
        ("ant.thin", "gate", 2.4, (500, 500)),
        ("ant.thick", "gate2", 1.2, (3000, 500)),
    ] {
        for limit in sweep(value) {
            out.push(
                Fixture::new(
                    &format!("erc/antenna/oxide/{id}/{}", side(limit, value)),
                    &["ERC-A12"],
                    &antenna_deck(&format!(
                        "rule {id} antenna({layer}, met1; max_ratio: {limit}, sidewall: none, diode: none, diode_area: none, diode_min: none)"
                    )),
                )
                .layout(oxides.clone())
                .expect(Expect::rule(
                    id,
                    ratio_findings(&[(value, at)], limit, true),
                )),
            );
        }
    }

    // A MIM capacitor as the victim: 1.0 µm² of dielectric under a 2.0 µm²
    // met2 plate.
    let mim = Layout::default()
        .rect("met2", 0, 0, 2000, 1000)
        .rect("mim", 0, 0, 1000, 1000);
    for limit in sweep(2.0) {
        out.push(
            Fixture::new(
                &format!("erc/antenna/mim/{}", side(limit, 2.0)),
                &["ERC-A11"],
                &antenna_deck(&format!(
                    "rule ant.mim antenna(mim, met2; max_ratio: {limit}, sidewall: none, diode: none, diode_area: none, diode_min: none)"
                )),
            )
            .layout(mim.clone())
            .expect(Expect::rule(
                "ant.mim",
                ratio_findings(&[(2.0, (500, 500))], limit, true),
            )),
        );
    }

    // One gate under a stack of 2.0 + 3.0 + 5.0: every cumulative reading is
    // 10.0.
    let stack = {
        let mut l = gate_stub("gate");
        rect(&mut l, "met1", (0, 1600, 4000, 2100));
        rect(&mut l, "via1", (3000, 1700, 3200, 1900));
        rect(&mut l, "met2", (3000, 1600, 6000, 2600));
        rect(&mut l, "via2", (5000, 1700, 5200, 1900));
        rect(&mut l, "met3", (5000, 1600, 10_000, 2600));
        l
    };
    for limit in sweep(10.0) {
        out.push(
            Fixture::new(
                &format!("erc/antenna/car_single_gate/{}", side(limit, 10.0)),
                &["ERC-A3"],
                &antenna_deck(&format!(
                    "rule car antenna(gate, met1, met2, met3; max_ratio: {limit}, sidewall: none, diode: none, diode_area: none, diode_min: none)"
                )),
            )
            .layout(stack.clone())
            .expect(Expect::rule(
                "car",
                ratio_findings(&[(10.0, (500, 500))], limit, true),
            )),
        );
    }

    // F29: the collecting area of a node is its drawn area, the union. Two
    // overlapping met1 pieces cover 1.5 µm², not their 2.0 sum: at a limit of
    // 1.75 the gate is clean.
    let mut over_collect = gate_stub("gate");
    rect(&mut over_collect, "met1", (0, 1600, 2000, 2100));
    rect(&mut over_collect, "met1", (1000, 1600, 3000, 2100));
    out.push(
        Fixture::new(
            "erc/antenna/f29/overlapping_collectors",
            &["ERC-A1"],
            &antenna_deck(
                "rule ant antenna(gate, met1; max_ratio: 1.75, sidewall: none, diode: none, diode_area: none, diode_min: none)",
            ),
        )
        .layout(over_collect)
        .expect(Expect::clean("ant")),
    );
    // F29, the other way: a gate drawn as two overlapping polygons is 1.5 µm²
    // of oxide, so 3.0 µm² of met1 is a ratio of 2.0, above 1.75. Summed per
    // polygon the gate reads 2.0 µm² and the ratio 1.5: a false clean.
    let mut over_gate = Layout::default();
    rect(&mut over_gate, "poly", (0, 0, 1500, 2000));
    rect(&mut over_gate, "gate", (0, 0, 1000, 1000));
    rect(&mut over_gate, "gate", (500, 0, 1500, 1000));
    rect(&mut over_gate, "cont", (400, 1700, 600, 1900));
    rect(&mut over_gate, "met1", (0, 1600, 6000, 2100));
    out.push(
        Fixture::new(
            "erc/antenna/f29/overlapping_gate",
            &["ERC-A1"],
            &antenna_deck(
                "rule ant antenna(gate, met1; max_ratio: 1.75, sidewall: none, diode: none, diode_area: none, diode_min: none)",
            ),
        )
        .layout(over_gate)
        .expect(Expect::rule("ant", vec![ratio(2.0).at(500, 500)])),
    );
    out.push(ihp_area_ratio());
    out.extend(metal_over_a_gate());
    out.push(gate_on_its_device_poly());
    out
}

/// F81: a deck with a direct diffusion-poly cut (`connect via bc [diff,
/// poly]`) reaches poly upward from the diffusion, so by conductors and vias
/// alone the poly is "over" a derived `poly and diff` gate and the gate fell
/// to the diffusion, a net with no met1: a false clean. The deck's `device
/// mos` row names poly as the gate terminal, so the gate is on its poly, which
/// the contact joins to 2.0 µm² of met1 over the 1.0 µm² gate: 2.0, as in
/// `derived_gate`. No `bc` shape is drawn, so diffusion and poly stay apart.
/// The device's source and drain are `diff not poly`, as extraction requires
/// of a channel; the antenna row reads only its gate terminal.
fn gate_on_its_device_poly() -> Fixture {
    let mut l = Layout::default();
    rect(&mut l, "diff", (-500, 0, 1500, 1000));
    rect(&mut l, "poly", (0, 0, 1000, 2000));
    rect(&mut l, "cont", (400, 1700, 600, 1900));
    rect(&mut l, "met1", (0, 1600, 4000, 2100));
    let deck = antenna_deck(
        "layer bc = gds(12, 0)
layer sd = diff not poly
connect via bc [diff, poly]
device mos gated model \"nfet\" terminals [poly, sd, sd]
rule ant antenna(gated, met1; max_ratio: 1.0, sidewall: none, diode: none, diode_area: none, diode_min: none)",
    );
    Fixture::new("erc/antenna/f81/direct_diff_poly_cut", &["ERC-A1"], &deck)
        .layout(l)
        .expect(Expect::rule("ant", vec![ratio(2.0).at(500, 500)]))
}

/// F72: a gate's net is that of the poly it lies on, never metal drawn over
/// it. The 1.0 µm² gate's poly is contacted to 2.0 µm² of met1, so the met1
/// ratio is 2.0 / 1.0 = 2.0, whatever unconnected met1 crosses the gate: a
/// 10 × 0.6 µm strip (6.0 µm²), a 2.5 × 1.8 µm plate wholly over it (4.5 µm²),
/// or the strip over a derived `poly and diff` gate. Joined to the metal
/// over it, the gate read 6.0, 4.5 and 6.0. A via1 cut sits on the met1 it
/// lands on, not on another net's poly under that met1: 0.04 µm² of via1 over
/// the 1.0 µm² gate's net is 0.04.
fn metal_over_a_gate() -> Vec<Fixture> {
    let contacted = |mut l: Layout| {
        rect(&mut l, "met1", (0, 1600, 2000, 2600));
        l
    };
    let strip = (-5000, 200, 5000, 800);
    let derived = {
        let mut l = Layout::default();
        rect(&mut l, "diff", (-500, 0, 1500, 1000));
        rect(&mut l, "poly", (0, 0, 1000, 2000));
        rect(&mut l, "cont", (400, 1700, 600, 1900));
        contacted(l)
    };
    let mut out = Vec::new();
    for (name, gate, mut layout, over) in [
        ("strip", "gate", contacted(gate_stub("gate")), strip),
        (
            "plate",
            "gate",
            contacted(gate_stub("gate")),
            (-1000, -500, 1500, 1300),
        ),
        ("derived_gate", "gated", derived, strip),
    ] {
        rect(&mut layout, "met1", over);
        out.push(
            Fixture::new(
                &format!("erc/antenna/f72/{name}"),
                &["ERC-A1"],
                &antenna_deck(&format!(
                    "rule ant antenna({gate}, met1; max_ratio: 1.0, sidewall: none, diode: none, diode_area: none, diode_min: none)"
                )),
            )
            .layout(layout)
            .expect(Expect::rule("ant", vec![ratio(2.0).at(500, 500)])),
        );
    }
    // A second poly line, on its own net, runs under the gate's met1; the
    // via1 cut over it lands on that met1.
    let mut cut = contacted(gate_stub("gate"));
    rect(&mut cut, "poly", (1200, 2000, 1800, 3000));
    rect(&mut cut, "via1", (1400, 2200, 1600, 2400));
    out.push(
        Fixture::new(
            "erc/antenna/f72/cut_over_other_poly",
            &["ERC-A1", "ERC-A4"],
            &antenna_deck(
                "rule ant antenna(gate, via1; max_ratio: 0.01, sidewall: none, diode: none, diode_area: none, diode_min: none)",
            ),
        )
        .layout(cut)
        .expect(Expect::rule("ant", vec![ratio(0.04).at(500, 500)])),
    );
    out
}

/// IHP SG13G2 layout rules §7.1, Figure 7.1 and its `AreaRatio` formula, the
/// catalog's oracle for the cumulative ratio (ERC-A3):
///
/// `AreaRatio(G1) = (M1(i) + M2(i)) / G1 + M3(i) / (G1 + G2 + G3)`,
/// `AreaRatio(G2) = M1(ii) / G2 + M2(ii) / (G2 + G3) + M3(i) / (G1 + G2 + G3)`,
///
/// one ratio per layer, each over the gates connected when that layer is
/// etched. With every gate 1.0 µm², M1(i) = 100, M2(i) = 50, M1(ii) = M1(iii)
/// = 2, M2(ii) = 4 and M3(i) = 30: G1 reads 150 + 10 = 160, G2 and G3 read
/// 2 + 2 + 10 = 14. Against Ant.b's limit, scaled to 100, G1 fails.
///
/// Dividing all collected area by the gate area at the highest stage,
/// (100 + 2 + 2 + 50 + 4 + 30) / 3 = 62.7, passes it: the false clean of
/// `F59`.
fn ihp_area_ratio() -> Fixture {
    let mut l = Layout::default();
    // G1 under a 100 µm² met1 plate and a 50 µm² met2 plate.
    rect(&mut l, "poly", (0, 0, 1000, 2000));
    rect(&mut l, "gate", (0, 0, 1000, 1000));
    rect(&mut l, "cont", (400, 1700, 600, 1900));
    rect(&mut l, "met1", (0, 1500, 10_000, 11_500));
    rect(&mut l, "via1", (2000, 5000, 2200, 5200));
    rect(&mut l, "met2", (0, 1500, 5000, 11_500));
    // G2 and G3, joined on met2.
    for x in [20_000, 30_000] {
        rect(&mut l, "poly", (x, 0, x + 1000, 2000));
        rect(&mut l, "gate", (x, 0, x + 1000, 1000));
        rect(&mut l, "cont", (x + 400, 1700, x + 600, 1900));
        rect(&mut l, "met1", (x, 1500, x + 2000, 2500));
    }
    rect(&mut l, "via1", (21_500, 2100, 21_700, 2300));
    rect(&mut l, "via1", (30_300, 2100, 30_500, 2300));
    rect(&mut l, "met2", (21_000, 2000, 31_000, 2400));
    // M3(i) joins the two met2 nodes.
    rect(&mut l, "via2", (4500, 2500, 4700, 2700));
    rect(&mut l, "via2", (22_000, 2100, 22_200, 2300));
    rect(&mut l, "met3", (4000, 2000, 24_000, 3500));
    let g1 = (100.0 + 50.0) / 1.0 + 30.0 / 3.0;
    Fixture::new(
        "erc/antenna/ihp_fig7_1",
        &["ERC-A3"],
        &antenna_deck("rule ant.b antenna(gate, met1, met2, met3; max_ratio: 100, sidewall: none, diode: none, diode_area: none, diode_min: none)"),
    )
    .layout(l)
    .expect(Expect::rule("ant.b", vec![ratio(g1).at(500, 500)]))
}

/// A 1.0 µm² gate under 2.0 µm² of met1, optionally with a 0.15 µm² diode
/// on diffusion contacted to the same met1.
fn diode_stub(diode: bool) -> Layout {
    let mut l = gate_stub("gate");
    rect(&mut l, "met1", (0, 1600, 5000, 2000));
    if diode {
        rect(&mut l, "diff", (4000, 1650, 4500, 1950));
        rect(&mut l, "cont", (4150, 1700, 4350, 1900));
    }
    l
}

/// `antenna_electrical`: `ratio - diode_credit × diode_area - diode_bonus`,
/// the subtractive credit of sky130's EGAR and LEF `ANTENNAAREAMINUSDIFF`.
///
/// - With no credit it is `antenna`: 2.0 swept.
/// - With a diode on the net and a bonus of 0.5: 1.5 swept.
/// - A bonus is credit for a diode, so a net without one keeps 2.0 (F35:
///   it was once subtracted from every gate net).
/// - The credit is per µm² of diode: SKY130's Table Ig limits
///   ([`sky130_table_ig`]).
/// - IHP Ant.b (without diode, 1.5 here) and Ant.e (with diode, 100): a net
///   with a diode is held to Ant.e only, so at 2.0 it is clean. Ant.b names
///   the diode layer it leaves to Ant.e; before `antenna` took one it held
///   the gate to Ant.b, the over-report of `F60`. Without the diode Ant.b
///   fails it and Ant.e (with diode) does not apply.
fn antenna_electrical() -> Vec<Fixture> {
    let mut out = Vec::new();
    for limit in sweep(2.0) {
        out.push(
            Fixture::new(
                &format!("erc/antenna_electrical/no_credit/{}", side(limit, 2.0)),
                &["ERC-A5", "ERC-A8"],
                &antenna_deck(&format!(
                    "rule ae antenna_electrical(gate, met1; max_ratio: {limit}, sidewall: none, cut_factor: 1, diode: none, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)"
                )),
            )
            .layout(diode_stub(false))
            .expect(Expect::rule("ae", ratio_findings(&[(2.0, (500, 500))], limit, true))),
        );
    }
    for limit in sweep(1.5) {
        out.push(
            Fixture::new(
                &format!("erc/antenna_electrical/bonus_with_diode/{}", side(limit, 1.5)),
                &["ERC-A5", "ERC-A8"],
                &antenna_deck(&format!(
                    "rule ae antenna_electrical(gate, met1; max_ratio: {limit}, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 0, diode_bonus: 0.5, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)"
                )),
            )
            .layout(diode_stub(true))
            .expect(Expect::rule("ae", ratio_findings(&[(1.5, (500, 500))], limit, true))),
        );
    }
    out.push(
        Fixture::new(
            "erc/antenna_electrical/bonus_without_diode",
            &["ERC-A5"],
            &antenna_deck(
                "rule ae antenna_electrical(gate, met1; max_ratio: 1.75, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 0, diode_bonus: 0.5, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)",
            ),
        )
        .layout(diode_stub(false))
        .expect(Expect::rule("ae", vec![ratio(2.0).at(500, 500)])),
    );
    out.extend(sky130_table_ig());
    out.extend(lef_c20_cumulative());
    out.extend(lef_gate_plus_diode());
    out.extend(gf180_ant16());
    out.extend(lef_example4());
    out.extend(lef_pwl_limit());
    out.extend(sky130_lef_agrees_with_egar());
    out.extend(sky130_ar1());
    out.extend(ihp_ant_g());
    let ihp = "rule Ant.b antenna(gate, met1; max_ratio: 1.5, sidewall: none, diode: diff, diode_area: none, diode_min: none)
rule Ant.e antenna_electrical(gate, met1; max_ratio: 100, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)";
    out.push(
        Fixture::new(
            "erc/antenna_electrical/ihp_b_e/with_diode",
            &["ERC-A8"],
            &antenna_deck(ihp),
        )
        .layout(diode_stub(true))
        .expect(Expect::clean("Ant.b"))
        .expect(Expect::clean("Ant.e")),
    );
    out.push(
        Fixture::new(
            "erc/antenna_electrical/ihp_b_e/without_diode",
            &["ERC-A8"],
            &antenna_deck(ihp),
        )
        .layout(diode_stub(false))
        .expect(Expect::rule("Ant.b", vec![ratio(2.0).at(500, 500)]))
        .expect(Expect::clean("Ant.e")),
    );
    out
}

/// A 1.0 µm² gate whose poly a 100 × 100 contact joins to met1 at (450..550,
/// 1750..1850), and, with `diode` in µm² (a 1000-nm-wide diffusion), a diode
/// contacted at (-1050..-950, 1750..1850) to the same met1.
fn egar_stub(diode_um2: Option<f64>) -> Layout {
    let mut l = Layout::default();
    rect(&mut l, "poly", (0, 0, 1000, 2000));
    rect(&mut l, "gate", (0, 0, 1000, 1000));
    rect(&mut l, "cont", (450, 1750, 550, 1850));
    if let Some(um2) = diode_um2 {
        let half = (um2 * 500.0).round() as i64;
        rect(&mut l, "diff", (-1500, 1800 - half, -500, 1800 + half));
        rect(&mut l, "cont", (-1050, 1750, -950, 1850));
    }
    l
}

/// `count` square via1 cuts of side `side` nm on a met1 plate over both
/// contacts of [`egar_stub`], 25 to a row at twice their side.
fn cut_array(diode_um2: Option<f64>, count: usize, side: i64) -> Layout {
    let mut l = egar_stub(diode_um2);
    let rows = count.div_ceil(25) as i64;
    rect(
        &mut l,
        "met1",
        (-1100, 1700, 1200 + 50 * side, 1900 + 2 * side * rows),
    );
    for i in 0..count as i64 {
        let (x, y) = (1200 + (i % 25) * 2 * side, 1900 + (i / 25) * 2 * side);
        rect(&mut l, "via1", (x, y, x + side, y + side));
    }
    l
}

/// A met1 line `width` × `length` nm from x = -1100, over both contacts of
/// [`egar_stub`]: perimeter `2 (length + width)`.
fn line(diode_um2: Option<f64>, width: i64, length: i64) -> Layout {
    let mut l = egar_stub(diode_um2);
    let ylo = 1800 - width / 2;
    rect(&mut l, "met1", (-1100, ylo, -1100 + length, ylo + width));
    l
}

/// SKY130 antenna rules, Table Ig (sky130A's flow) and its "design
/// limitations due to antenna rules (FET gate = 1um2)", the foundry's own
/// worked examples of `EGAR = EA / A_gate - K x (AntennaDiode_area in um2) -
/// diode_bonus`, each at its stated limit (clean) and one step past it
/// (flagged), with no diode and with a 1 µm² diode:
///
/// - Mcon (horizontal, max 3, K 18; 0.17 µm cuts, 0.0289 µm² each): 103
///   cuts without a diode (2.977), 726 with (20.981 - 18 = 2.981); 104
///   (3.006) and 727 (3.010) fail.
/// - LI (vertical, FLT 0.1 µm, max 75, K 450; minimum width 0.17 µm):
///   370 µm without (2 × 370.17 × 0.1 = 74.034), 2620 µm with (524.034 -
///   450); 375 µm and 2625 µm fail (75.034).
/// - Met1 (vertical, FLT 0.35 µm, max 400, K 400, bonus 2200; width 0.14
///   µm): 570 µm without (399.098), 4280 µm with (2996.098 - 400 - 2200 =
///   396.098); 572 µm (400.498) and 4286 µm (400.298) fail.
///
/// The table's lengths are "approx" (it rounds down); each is checked
/// against the exact limit it stands for. Then the closed form off the
/// table: a 0.5 µm² diode halves the credit, so with Via's K 36 and max 6,
/// 0.15 µm cuts (0.0225 µm²) pass at 1066 (23.985 - 18) and fail at 1067
/// (24.0075 - 18). A credit per square database unit would pass all of
/// these, and a credit refused, as it once was, would flag none.
fn sky130_table_ig() -> Vec<Fixture> {
    struct Case {
        name: &'static str,
        rule: &'static str,
        layout: Layout,
        /// The collecting area over the gate, before the credit.
        ratio: f64,
        /// `K × diode area + bonus`, or zero without a diode.
        credit: f64,
        max: f64,
    }
    let mcon = "rule ae antenna_electrical(gate, via1; max_ratio: 3, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 18, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)";
    let li = "rule ae antenna_electrical(gate, met1; max_ratio: 75, sidewall: 100nm, cut_factor: 1, diode: diff, diode_credit: 450, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)";
    let met1 = "rule ae antenna_electrical(gate, met1; max_ratio: 400, sidewall: 350nm, cut_factor: 1, diode: diff, diode_credit: 400, diode_bonus: 2200, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)";
    let via = "rule ae antenna_electrical(gate, via1; max_ratio: 6, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 36, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)";
    let cuts = |n: usize, side: f64| n as f64 * side * side / 1e6;
    let side = |width: i64, length: i64, flt: i64| (2 * (length + width) * flt) as f64 / 1e6;
    let mut cases = Vec::new();
    for (n, diode) in [(103, None), (104, None), (726, Some(1.0)), (727, Some(1.0))] {
        cases.push(Case {
            name: "mcon",
            rule: mcon,
            layout: cut_array(diode, n, 170),
            ratio: cuts(n, 170.0),
            credit: diode.map_or(0.0, |d| 18.0 * d),
            max: 3.0,
        });
    }
    for (um, diode) in [
        (370, None),
        (375, None),
        (2620, Some(1.0)),
        (2625, Some(1.0)),
    ] {
        cases.push(Case {
            name: "li",
            rule: li,
            layout: line(diode, 170, um * 1000),
            ratio: side(170, um * 1000, 100),
            credit: diode.map_or(0.0, |d| 450.0 * d),
            max: 75.0,
        });
    }
    for (um, diode) in [
        (570, None),
        (572, None),
        (4280, Some(1.0)),
        (4286, Some(1.0)),
    ] {
        cases.push(Case {
            name: "met1",
            rule: met1,
            layout: line(diode, 140, um * 1000),
            ratio: side(140, um * 1000, 350),
            credit: diode.map_or(0.0, |d| 400.0 * d + 2200.0),
            max: 400.0,
        });
    }
    for n in [1066, 1067] {
        cases.push(Case {
            name: "via_half_um2_diode",
            rule: via,
            layout: cut_array(Some(0.5), n, 150),
            ratio: cuts(n, 150.0),
            credit: 36.0 * 0.5,
            max: 6.0,
        });
    }
    cases
        .into_iter()
        .map(|case| {
            let value = case.ratio - case.credit;
            let verdict = if value > case.max { "fails" } else { "passes" };
            let diode = if case.credit > 0.0 {
                "diode"
            } else {
                "no_diode"
            };
            Fixture::new(
                &format!(
                    "erc/antenna_electrical/sky130_table_ig/{}/{diode}/{verdict}_{:.3}",
                    case.name, case.ratio
                ),
                &["ERC-A5"],
                &antenna_deck(case.rule),
            )
            .layout(case.layout)
            .expect(Expect::rule(
                "ae",
                ratio_findings(&[(value, (500, 500))], case.max, true),
            ))
        })
        .collect()
}

/// LEF/DEF 5.8 Appendix C's cumulative ratio, one partial ratio per layer in
/// etch order, each `(area - minus × diff_area) / gate_area` with the node's
/// areas at that layer, the running sum truncated at zero after each layer
/// (`ANTENNAAREAMINUSDIFF`, Example 2). `nodes` is `(area, diff_area,
/// gate_area)` per layer.
fn lef_car(minus: f64, nodes: &[(f64, f64, f64)]) -> f64 {
    nodes.iter().fold(0.0, |car, &(area, diff, gate)| {
        (car + (area - minus * diff) / gate).max(0.0)
    })
}

/// G1's and G2's nodes on Figure C-20 ([`lef_c20`]) in etch order, cont,
/// met1, via1, met2, via2, met3, as `(area, diff_area, gate_area)` in µm²,
/// each cut's area times `cut` (LEF's `ANTENNAAREAFACTOR` on a cut layer).
/// G1: C1 (0.1, 0, 1), M1,2 (2, 0, 1), V1,2 + V1,3 (0.2, 0, 1), M2 (9, 0.5,
/// 3), V2 (0.2, 0.5, 3), M3 (15, 0.5, 3); G2: C2 (0.1, 0, 2), M1,3 (3, 0.5,
/// 2) and V1,4 (0.1, 0.5, 2), D1 reaching M1,3 through C3, then the shared
/// nodes.
fn c20_nodes(cut: f64) -> [[(f64, f64, f64); 6]; 2] {
    [
        [
            (0.1 * cut, 0.0, 1.0),
            (2.0, 0.0, 1.0),
            (0.2 * cut, 0.0, 1.0),
            (9.0, 0.5, 3.0),
            (0.2 * cut, 0.5, 3.0),
            (15.0, 0.5, 3.0),
        ],
        [
            (0.1 * cut, 0.0, 2.0),
            (3.0, 0.5, 2.0),
            (0.1 * cut, 0.5, 2.0),
            (9.0, 0.5, 3.0),
            (0.2 * cut, 0.5, 3.0),
            (15.0, 0.5, 3.0),
        ],
    ]
}

/// LEF/DEF 5.8 Appendix C's cumulative model on Figure C-20, metal and cut
/// accumulated as one CAR (`ANTENNACUMROUTINGPLUSCUT`: CAR(m_i) = PAR(m_i) +
/// CAR(v_i-1), CAR(v_i) = PAR(v_i) + CAR(m_i)), each case's value from
/// [`lef_car`] over [`c20_nodes`] and swept a part in a thousand either
/// side:
///
/// - Example 1, cut factor 10: the manual's steps for G1 read CAR(C) = 1.0,
///   CAR(M1) = 3.0, CAR(V1) = 5.0, CAR(M2) = 8.0, CAR(V2) = 8.67 and CAR(M3)
///   = 13.67 (its "12.34" in step 15 is a slip for 5 + 8.67); G2 reads 2.5 at
///   via1 and 11.17 at met3.
/// - Example 2, adding `ANTENNAAREAMINUSDIFF 100`: G1's CAR(V1) is still
///   5.0, and from met2 up every sum truncates to 0 ("-8.67, truncate to
///   0"), as G2's does from met1; a value of 0 is clean at any limit.
/// - minus 4 with no cut factor: G1 8.367, G2 6.067, G2's sum truncated at
///   via1 (0.55 - 0.95). Without the truncation G2 reads 5.667; with the
///   minus once per stage instead of per layer, G1 reads 9.033.
/// - `antenna` itself, listing the cuts with the metals: one stage's metal
///   and the cut on it share a denominator, so its per-stage sum is the same
///   CAR with factor 1, G1 10.367 and G2 9.667.
fn lef_c20_cumulative() -> Vec<Fixture> {
    let (g1, g2) = ((500, 500), (6500, 0));
    let all = "cont, met1, via1, met2, via2, met3";
    // (name, catalog, collectors, layers counted, minus, cut factor)
    let cases: [(&str, &[&'static str], &str, usize, f64, f64); 6] = [
        ("example1", &["ERC-A4"], all, 6, 0.0, 10.0),
        (
            "example1_via1",
            &["ERC-A4"],
            "cont, met1, via1",
            3,
            0.0,
            10.0,
        ),
        ("example2", &["ERC-A4", "ERC-A5"], all, 6, 100.0, 10.0),
        (
            "example2_via1",
            &["ERC-A4", "ERC-A5"],
            "cont, met1, via1",
            3,
            100.0,
            10.0,
        ),
        ("minus4", &["ERC-A5"], all, 6, 4.0, 1.0),
        ("antenna", &["ERC-A3", "ERC-A4"], all, 6, 0.0, 1.0),
    ];
    let mut out = Vec::new();
    for (name, catalog, collectors, layers, minus, cut) in cases {
        let [g1_nodes, g2_nodes] = c20_nodes(cut);
        let nets = vec![
            (lef_car(minus, &g1_nodes[..layers]), g1),
            (lef_car(minus, &g2_nodes[..layers]), g2),
        ];
        let positive: Vec<f64> = nets.iter().map(|n| n.0).filter(|&v| v > 0.0).collect();
        // A value of zero is clean at any positive limit.
        let limits: Vec<f64> = if positive.is_empty() {
            vec![1e-3]
        } else {
            positive
                .iter()
                .flat_map(|&v| [v * 0.999, v * 1.001])
                .collect()
        };
        for limit in limits {
            let rule = if name == "antenna" {
                format!("rule ae antenna(gate, {collectors}; max_ratio: {limit}, sidewall: none, diode: none, diode_area: none, diode_min: none)")
            } else {
                format!(
                    "rule ae antenna_electrical(gate, {collectors}; max_ratio: {limit}, sidewall: none, cut_factor: {cut}, diode: diff, diode_credit: 0, diode_bonus: 0, area_minus_diode: {minus}, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)"
                )
            };
            out.push(
                Fixture::new(
                    &format!("erc/antenna_electrical/lef_c20_cumulative/{name}/{limit:.4}"),
                    catalog,
                    &antenna_deck(&rule),
                )
                .layout(lef_c20())
                .expect(Expect::rule("ae", ratio_findings(&nets, limit, true))),
            );
        }
    }
    out
}

/// LEF/DEF 5.8 Appendix C, Example 3 (`ANTENNAGATEPLUSDIFF 2.0`) on Figure
/// C-20 ([`lef_c20`]): `PAR = metal_area / (gate_area + 2.0 × diff_area)`.
/// The manual's own steps for G1: PAR(M1) = 2 / 1 = 2, PAR(M2) = (4 + 5) /
/// ((1 + 2) + 2 × 0.5) = 2.25 (CAR 4.25), PAR(M3) = (6 + 9) / 4 = 3.75 (CAR
/// 8.0). G2's node at met1 already reaches D1: 3 / (2 + 2 × 0.5) = 1.0, CAR
/// 7.0 at met3. Every value is exact in binary, so each is swept below, at
/// and above. Without the factor PAR(M2) reads 3.0 and the met3 CARs 10.0
/// and 9.5 ([`lef_c20_rows`]).
fn lef_gate_plus_diode() -> Vec<Fixture> {
    let (g1, g2) = ((500, 500), (6500, 0));
    let rows: [(&str, &str, Vec<(f64, (i64, i64))>); 4] = [
        ("par.met1", "met1", vec![(2.0, g1), (1.0, g2)]),
        ("par.met2", "met2", vec![(2.25, g1)]),
        ("par.met3", "met3", vec![(3.75, g1)]),
        ("car.met123", "met1, met2, met3", vec![(8.0, g1), (7.0, g2)]),
    ];
    let mut out = Vec::new();
    for (id, collectors, nets) in rows {
        for (n, &(value, _)) in nets.iter().enumerate() {
            for limit in sweep(value) {
                out.push(
                    Fixture::new(
                        &format!(
                            "erc/antenna_electrical/lef_example3/{id}/net{n}/{}",
                            side(limit, value)
                        ),
                        &["ERC-A6"],
                        &antenna_deck(&format!(
                            "rule ae antenna_electrical(gate, {collectors}; max_ratio: {limit}, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 2, diode_reduce: none, diode_max_ratio: none, exempt: none)"
                        )),
                    )
                    .layout(lef_c20())
                    .expect(Expect::rule("ae", ratio_findings(&nets, limit, true))),
                );
            }
        }
    }
    out
}

/// GF180MCU DRM ANT.16: a metal or via ratio is checked with "gate area =
/// (thin gate area + MF * (COMP area directly connection that node))", MF 2
/// for a thin gate and 15 for a thick (dual-gate) one, each against its own
/// oxide's gate area (ERC-A12). A 1.0 µm² thin gate and a 2.0 µm² thick
/// gate share 2.4 µm² of met1 and a 0.5 µm² diode: the thin row reads 2.4 /
/// (1 + 2 × 0.5) = 1.2 and the thick row 2.4 / (2 + 15 × 0.5) = 0.2526,
/// each swept. Without the diode term they read 2.4 and 1.2 (the oxide
/// fixtures of [`antenna_variants`]); counting both oxides' gates in one
/// denominator would read 2.4 / 3.0 for both rows before any credit.
fn gf180_ant16() -> Vec<Fixture> {
    let layout = {
        let mut l = gate_stub("gate");
        rect(&mut l, "poly", (2000, 0, 4000, 2000));
        rect(&mut l, "gate2", (2000, 0, 4000, 1000));
        rect(&mut l, "cont", (2900, 1700, 3100, 1900));
        rect(&mut l, "met1", (0, 1600, 6000, 2000));
        rect(&mut l, "diff", (4500, 1500, 5500, 2000));
        rect(&mut l, "cont", (4900, 1700, 5100, 1900));
        l
    };
    let r = |num: i64, den: i64| num as f64 / den as f64;
    let mut out = Vec::new();
    for (id, layer, mf, value, at) in [
        ("thin", "gate", 2, r(4_800_000, 4_000_000), (500, 500)),
        ("thick", "gate2", 15, r(4_800_000, 19_000_000), (3000, 500)),
    ] {
        for limit in sweep(value) {
            out.push(
                Fixture::new(
                    &format!("erc/antenna_electrical/gf180_ant16/{id}/{}", side(limit, value)),
                    &["ERC-A6", "ERC-A12"],
                    &antenna_deck(&format!(
                        "rule ae antenna_electrical({layer}, met1; max_ratio: {limit}, sidewall: none, cut_factor: 1, diode: diff, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: {mf}, diode_reduce: none, diode_max_ratio: none, exempt: none)"
                    )),
                )
                .layout(layout.clone())
                .expect(Expect::rule("ae", ratio_findings(&[(value, at)], limit, true))),
            );
        }
    }
    out
}

/// GF180MCU ANT.14 and ANT.15 (ERC-A11) on the DRM's MIM topology: the
/// FuseTop top plate is a conductor of its own, reached from above by Via2
/// to Metal3 (MIM.4), over a Metal2 bottom plate it does not touch (§10.4.1).
/// "Maximum ratio of each of the metal layer (Metal (n+1) to MetalTop)
/// perimeter area to related MIM area" is one `antenna` row per layer with
/// the perimeter area `2 [(t x z) + (t x y)]`, t = 0.54 µm for Metal1-5,
/// against 400; "Maximum ratio of each of Via (Vian to most top Via) area to
/// related MIM area" one row per cut layer against 20. Hand-derived, the MIM
/// 1 µm²:
///
/// - a Metal3 line 1 µm wide and `L` long from the plate: perimeter area
///   `2 (L + 1) x 0.54` µm²: 399.6 at L = 369 µm (clean), 401.76 at 371 µm;
/// - a Via3 cut `s` square on a Metal3 pad joined to the plate: 19.36 µm² at
///   s = 4.4 µm (clean), 20.25 at 4.5 µm;
/// - the Metal2 bottom plate is another net: a Metal2 row sees no MIM.
fn gf180_mim() -> Vec<Fixture> {
    let deck = "grid 1nm
layer metal2 = gds(1, 0)
layer fusetop = gds(2, 0)
layer via2 = gds(3, 0)
layer metal3 = gds(4, 0)
layer via3 = gds(5, 0)
layer metal4 = gds(6, 0)
connect conductors [metal2, fusetop, metal3, metal4]
connect touch_within_layer
connect via via2 [metal2, metal3]
connect via via2 [fusetop, metal3]
connect via via3 [metal3, metal4]
rule ant14.m3 antenna(fusetop, metal3; max_ratio: 400, sidewall: 540nm, diode: none, diode_area: none, diode_min: none)
rule ant14.m2 antenna(fusetop, metal2; max_ratio: 400, sidewall: 540nm, diode: none, diode_area: none, diode_min: none)
rule ant15.v3 antenna(fusetop, via3; max_ratio: 20, sidewall: none, diode: none, diode_area: none, diode_min: none)
";
    let plates = |l: &mut Layout| {
        rect(l, "metal2", (-500, -500, 1500, 1500));
        rect(l, "fusetop", (0, 0, 1000, 1000));
        rect(l, "via2", (400, 400, 600, 600));
    };
    let mut out = Vec::new();
    for length in [369_000, 371_000] {
        let value = 2.0 * (length as f64 + 1000.0) * 540.0 / 1e6;
        let mut l = Layout::default();
        plates(&mut l);
        rect(&mut l, "metal3", (0, 0, length, 1000));
        let f = Fixture::new(
            &format!("erc/antenna/gf180_ant14/{length}"),
            &["ERC-A11"],
            deck,
        )
        .layout(l)
        .expect(Expect::rule(
            "ant14.m3",
            ratio_findings(&[(value, (500, 500))], 400.0, true),
        ))
        .expect(Expect::clean("ant14.m2"))
        .expect(Expect::clean("ant15.v3"));
        out.extend(every_placement(&[f]));
    }
    for side_nm in [4400, 4500] {
        let value = (side_nm * side_nm) as f64 / 1e6;
        let mut l = Layout::default();
        plates(&mut l);
        rect(&mut l, "metal3", (0, 0, 7000, 5000));
        rect(&mut l, "via3", (2200, 200, 2200 + side_nm, 200 + side_nm));
        rect(&mut l, "metal4", (2000, 0, 7000, 5000));
        let f = Fixture::new(
            &format!("erc/antenna/gf180_ant15/{side_nm}"),
            &["ERC-A11"],
            deck,
        )
        .layout(l)
        .expect(Expect::rule(
            "ant15.v3",
            ratio_findings(&[(value, (500, 500))], 20.0, true),
        ))
        .expect(Expect::clean("ant14.m2"));
        out.extend(every_placement(&[f]));
    }
    out
}

/// An `antenna_electrical` row with every factor neutral but the two
/// piecewise-linear tables, written as given (`none` or `[(area, n), ..]`).
fn pwl_row(
    id: &str,
    collectors: &str,
    max: f64,
    sidewall: &str,
    reduce: &str,
    diode_max: &str,
) -> String {
    format!(
        "rule {id} antenna_electrical(gate, {collectors}; max_ratio: {max}, sidewall: {sidewall}, cut_factor: 1, diode: diff, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: {reduce}, diode_max_ratio: {diode_max}, exempt: none)"
    )
}

/// LEF/DEF 5.8 Appendix C, Example 4 (`ANTENNAAREADIFFREDUCEPWL ((0.0 1.0)
/// (0.0999 1.0) (0.1 0.2) (1.0 0.1) (1000.0 0.1))`, cumulative over the
/// metals) on Figure C-20 ([`lef_c20`]). The factor at D1's 0.5 µm² is
/// interpolated between (0.1, 0.2) and (1.0, 0.1): 0.2 - 0.1 × 0.4 / 0.9 =
/// 0.1556 (the manual's "0.155"). G1's node at met1 reaches no diffusion, so
/// the manual's steps read CAR(M1) = 2, CAR(M2) = 2 + 3 × 0.1556 = 2.467 and
/// CAR(M3) = 2.467 + 5 × 0.1556 = 3.244 ("3.24"); G2's node reaches D1 from
/// met1, so it reads (1.5 + 3 + 5) × 0.1556 = 1.478. Both are swept a part
/// in a thousand either side; without the factor they read 10.0 and 9.5.
fn lef_example4() -> Vec<Fixture> {
    let factor = 0.2 + (0.1 - 0.2) * ((0.5 - 0.1) / (1.0 - 0.1));
    let nets = vec![(2.0 + 8.0 * factor, (500, 500)), (9.5 * factor, (6500, 0))];
    let reduce = "[(0um2, 1.0), (0.0999um2, 1.0), (0.1um2, 0.2), (1um2, 0.1), (1000um2, 0.1)]";
    let mut out = Vec::new();
    for (n, &(value, _)) in nets.iter().enumerate() {
        for limit in [value * 0.999, value * 1.001] {
            out.push(
                Fixture::new(
                    &format!(
                        "erc/antenna_electrical/lef_example4/net{n}/{}",
                        side(limit, value)
                    ),
                    &["ERC-A7"],
                    &antenna_deck(&pwl_row(
                        "ae",
                        "met1, met2, met3",
                        limit,
                        "none",
                        reduce,
                        "none",
                    )),
                )
                .layout(lef_c20())
                .expect(Expect::rule("ae", ratio_findings(&nets, limit, true))),
            );
        }
    }
    out
}

/// LEF/DEF 5.8 Appendix C, "Example Using the Antenna Keywords": a
/// cumulative metal ratio of 1000, and "if a diode of greater than .1 microns
/// is connected to the metal, the maximum metal ratio is: ratio = diode_area
/// x 2000 + 5000", written `ANTENNACUMDIFFAREARATIO PWL ((0 1000) (0.099
/// 1000) (0.1 5200) (100 205000))`. A 1.0 µm² gate under a met1 plate of `X`
/// µm²: with a 0.5 µm² diode the limit is 0.5 × 2000 + 5000 = 6000, so 5994
/// passes and 6006 fails; with a 0.05 µm² diode, below the table's step, it
/// is 1000, so 999 passes and 1001 fails, as without a diode; and with no
/// table a diode changes nothing, so 5994 fails against `max_ratio`.
fn lef_pwl_limit() -> Vec<Fixture> {
    let table = "[(0um2, 1000), (0.099um2, 1000), (0.1um2, 5200), (100um2, 205000)]";
    let mut out = Vec::new();
    for (diode, width, height, diode_max, fails) in [
        (Some(0.5), 99_900, 60_000, table, false),
        (Some(0.5), 100_100, 60_000, table, true),
        (Some(0.05), 99_900, 10_000, table, false),
        (Some(0.05), 100_100, 10_000, table, true),
        (None, 99_900, 10_000, table, false),
        (None, 100_100, 10_000, table, true),
        (Some(0.5), 99_900, 60_000, "none", true),
    ] {
        let mut layout = egar_stub(diode);
        rect(
            &mut layout,
            "met1",
            (-1100, 1700, -1100 + width, 1700 + height),
        );
        let value = (width * height) as f64 / 1e6;
        let with = diode.map_or("no_diode".to_owned(), |d| format!("diode_{d}"));
        let rows = if diode_max == "none" {
            "no_table"
        } else {
            "table"
        };
        out.push(
            Fixture::new(
                &format!("erc/antenna_electrical/lef_pwl_limit/{rows}/{with}/{value}"),
                &["ERC-A7"],
                &antenna_deck(&pwl_row("ae", "met1", 1000.0, "none", "none", diode_max)),
            )
            .layout(layout)
            .expect(Expect::rule(
                "ae",
                if fails {
                    vec![ratio(value).at(500, 500)]
                } else {
                    Vec::new()
                },
            )),
        );
    }
    out
}

/// Two public statements of sky130's met1 antenna limit agree: SKY130's EGAR
/// (Table Ig: max 400, K 400, bonus 2200, 0.35 µm sidewall) and the sky130
/// technology LEF's `ANTENNADIFFSIDEAREARATIO PWL ((0 400) (0.0125 400)
/// (0.0225 2609) (22.5 11600))`, whose slope past 0.0225 µm² is 8991 /
/// 22.4775 = 400 per µm²: both allow 2600 + 400 × D for a diode of D ≥
/// 0.0225 µm², and 400 without. One deck states both as rows; on 0.14 µm
/// met1 lines (ratio 0.7 × (L + 0.14)) with a 1 µm² diode both pass 4280 µm
/// and fail 4286 µm (limit 3000), with a 0.5 µm² diode both pass 3990 µm and
/// fail 4000 µm (limit 2800), and without one both pass 570 µm and fail 572
/// µm. Each row reports its own form: EGAR the credited ratio against 400,
/// the LEF row the plain ratio against its interpolated limit.
fn sky130_lef_agrees_with_egar() -> Vec<Fixture> {
    let egar = "rule egar antenna_electrical(gate, met1; max_ratio: 400, sidewall: 350nm, cut_factor: 1, diode: diff, diode_credit: 400, diode_bonus: 2200, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)";
    let lef = pwl_row(
        "lef",
        "met1",
        400.0,
        "350nm",
        "none",
        "[(0um2, 400), (0.0125um2, 400), (0.0225um2, 2609), (22.5um2, 11600)]",
    );
    let deck = antenna_deck(&format!("{egar}\n{lef}"));
    let mut out = Vec::new();
    for (diode, um, fails) in [
        (Some(1.0), 4280, false),
        (Some(1.0), 4286, true),
        (Some(0.5), 3990, false),
        (Some(0.5), 4000, true),
        (None, 570, false),
        (None, 572, true),
    ] {
        let ratio_of = (2 * (um * 1000 + 140) * 350) as f64 / 1e6;
        let credit = diode.map_or(0.0, |d| 400.0 * d + 2200.0);
        let with = diode.map_or("no_diode".to_owned(), |d| format!("diode_{d}"));
        let found = |value: f64| {
            if fails {
                vec![ratio(value).at(500, 500)]
            } else {
                Vec::new()
            }
        };
        out.push(
            Fixture::new(
                &format!("erc/antenna_electrical/sky130_lef_vs_egar/{with}/{um}um"),
                &["ERC-A5", "ERC-A7"],
                &deck,
            )
            .layout(line(diode, 140, um * 1000))
            .expect(Expect::rule("egar", found(ratio_of - credit)))
            .expect(Expect::rule("lef", found(ratio_of))),
        );
    }
    out
}

/// SKY130 antenna rule .ar.1, "antenna rules not checked for features
/// connected to a pAntennaShort" (a p+ tap shorting to the substrate,
/// `(tap AndNot poly) AndNot nwell`), with AntennaDiode excluding it. Table
/// Ig's met1 row on a 4286 µm line with a 1 µm² diode reads 400.298 against
/// 400 ([`sky130_table_ig`]); a 1 µm² `ptap` contacted to the same line
/// exempts the gate from `antenna_electrical`'s `exempt` and from
/// `antenna`'s `diode`, which skips the same way: both rows are clean.
/// Without the tap both flag the gate, `antenna` at the plain ratio
/// 3000.298.
fn sky130_ar1() -> Vec<Fixture> {
    let rules = "layer ptap = gds(13, 0)
layer adiode = diff not ptap
rule ae antenna_electrical(gate, met1; max_ratio: 400, sidewall: 350nm, cut_factor: 1, diode: adiode, diode_credit: 400, diode_bonus: 2200, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: ptap)
rule an antenna(gate, met1; max_ratio: 400, sidewall: 350nm, diode: ptap, diode_area: none, diode_min: none)";
    let ratio_of = (2 * (4_286_000_i64 + 140) * 350) as f64 / 1e6;
    let mut out = Vec::new();
    for tap in [false, true] {
        let mut layout = line(Some(1.0), 140, 4_286_000);
        if tap {
            rect(&mut layout, "diff", (2000, 1300, 3000, 2300));
            rect(&mut layout, "ptap", (2000, 1300, 3000, 2300));
            rect(&mut layout, "cont", (2450, 1750, 2550, 1850));
        }
        let (ae, an) = if tap {
            (Vec::new(), Vec::new())
        } else {
            (
                vec![ratio(ratio_of - 2600.0).at(500, 500)],
                vec![ratio(ratio_of).at(500, 500)],
            )
        };
        out.push(
            Fixture::new(
                &format!(
                    "erc/antenna_electrical/sky130_ar1/{}",
                    if tap { "tap_exempts" } else { "no_tap" }
                ),
                &["ERC-A13"],
                &antenna_deck(rules),
            )
            .layout(layout)
            .expect(Expect::rule("ae", ae))
            .expect(Expect::rule("an", an)),
        );
    }
    out
}

/// IHP SG13G2 layout rules §7.1, Ant.g: "size of protection diode (µm²)
/// 0.16", the least diode that lets a gate's net be held to Ant.e (with
/// protection diode) instead of Ant.b. A deck writes it with the derived
/// selection `diff.with_area(>= 0.16um2)` as the `diode` both rows read, and
/// the size itself as a DRC `area` rule. A 1.0 µm² gate under 2.0 µm² of
/// met1 (Ant.b scaled to 1.5, Ant.e to 100): a 0.15 µm² diode is too small,
/// so Ant.b flags 2.0 and Ant.g flags the diode; a 0.16 µm² diode, the
/// manual's minimum itself, protects the gate (IHP's own KLayout deck counts
/// a diode only above 0.16, `area(d) > 0.16`: at exactly 0.16 the two
/// differ), so both rows are clean, and so is Ant.g.
fn ihp_ant_g() -> Vec<Fixture> {
    let deck = antenna_deck(
        "layer prot = diff.with_area(>= 0.16um2)
rule Ant.b antenna(gate, met1; max_ratio: 1.5, sidewall: none, diode: prot, diode_area: none, diode_min: none)
rule Ant.e antenna_electrical(gate, met1; max_ratio: 100, sidewall: none, cut_factor: 1, diode: prot, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, diode_reduce: none, diode_max_ratio: none, exempt: none)
rule Ant.g area(diff) >= 0.16um2",
    );
    let mut out = Vec::new();
    for (name, diff, area) in [
        ("0.15um2", (4000, 1650, 4500, 1950), 150_000),
        ("0.16um2", (4000, 1600, 4400, 2000), 160_000),
    ] {
        let mut layout = gate_stub("gate");
        rect(&mut layout, "met1", (0, 1600, 5000, 2000));
        rect(&mut layout, "diff", diff);
        rect(&mut layout, "cont", (4150, 1700, 4350, 1900));
        let small = area < 160_000;
        out.push(
            Fixture::new(
                &format!("erc/antenna_electrical/ihp_ant_g/{name}/erc"),
                &["ERC-A8", "ERC-A9"],
                &deck,
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "Ant.b",
                if small {
                    vec![ratio(2.0).at(500, 500)]
                } else {
                    Vec::new()
                },
            ))
            .expect(Expect::clean("Ant.e")),
        );
    }
    out
}

// ------------------------------------------------------------------ density

/// A die outline and one metal; no connectivity.
const DENSITY_PROCESS: &str = "grid 1nm
layer die = gds(1, 0)
layer met1 = gds(2, 0)
";

/// Disjoint metal rectangles on a 4 µm die: 0.25, 0.5, 0.75 and 0.125 of the
/// four 2 µm windows (lower-left, lower-right, upper-left, upper-right).
const DENSITY_METAL: [Rect; 4] = [
    (0, 0, 1000, 1000),
    (2000, 0, 4000, 1000),
    (0, 2000, 2000, 3500),
    (2000, 2000, 3000, 2500),
];

/// The limits of one `density_cmp` row; `None` is unchecked.
#[derive(Clone, Copy, Default)]
struct DensityRow {
    min: Option<f64>,
    max: Option<f64>,
    delta: Option<f64>,
    /// `(target, sensitivity nm, max excursion nm)`.
    cmp: Option<(f64, i64, i64)>,
    partial: bool,
}

impl DensityRow {
    fn deck(&self, window: i64, step: i64) -> String {
        let opt = |v: Option<f64>| v.map_or_else(|| "none".to_owned(), |v| v.to_string());
        let cmp = self.cmp.map_or_else(
            || "none".to_owned(),
            |(t, s, m)| format!("(target: {t}, sensitivity: {s}nm, max_delta: {m}nm)"),
        );
        format!(
            "{DENSITY_PROCESS}rule den density_cmp(met1; window: {window}nm x {window}nm, step: {step}nm x {step}nm, min: {}, max: {}, max_delta: {}, partial_windows: {}, cmp: {cmp})\n",
            opt(self.min),
            opt(self.max),
            opt(self.delta),
            self.partial
        )
    }
}

/// The overlap area of two boxes.
fn clip(a: Rect, b: Rect) -> i64 {
    let w = (a.2.min(b.2) - a.0.max(b.0)).max(0);
    let h = (a.3.min(b.3) - a.1.max(b.1)).max(0);
    w * h
}

/// The `density_cmp` definition over `metal` (disjoint rectangles) on a
/// square die `[0, die]²`: windows from the lower-left corner every `step`
/// while their origin is inside the die, density over the die-clipped window,
/// a partial window held to min, max and CMP only with `partial_windows`, and
/// every right and upper neighbour pair compared for the delta, reported at
/// the lower-left window of the pair. Findings at the clipped window's centre.
fn density_oracle(
    metal: &[Rect],
    die: i64,
    window: i64,
    step: i64,
    row: DensityRow,
) -> Vec<Finding> {
    let n = ((die - 1) / step + 1) as usize;
    let boxes: Vec<Vec<(Rect, bool)>> = (0..n)
        .map(|j| {
            (0..n)
                .map(|i| {
                    let (x, y) = (i as i64 * step, j as i64 * step);
                    let full = (x, y, x + window, y + window);
                    let clipped = (x, y, (x + window).min(die), (y + window).min(die));
                    (clipped, full == clipped)
                })
                .collect()
        })
        .collect();
    let density = |i: usize, j: usize| {
        let (b, _) = boxes[j][i];
        let area: i64 = metal.iter().map(|&m| clip(m, b)).sum();
        area as f64 / ((b.2 - b.0) * (b.3 - b.1)) as f64
    };
    let mut out = Vec::new();
    for (j, windows) in boxes.iter().enumerate() {
        for (i, &(b, whole)) in windows.iter().enumerate() {
            let d = density(i, j);
            let (x, y) = (i64::midpoint(b.0, b.2), i64::midpoint(b.1, b.3));
            let counted = row.partial || whole;
            if counted && row.min.is_some_and(|m| d < m) {
                out.push(ratio(d).at(x, y));
            }
            if counted && row.max.is_some_and(|m| d > m) {
                out.push(ratio(d).at(x, y));
            }
            if let Some((t, s, m)) = row.cmp {
                let excursion = (s as f64 * (d - t)).abs() as i64;
                if counted && excursion > m {
                    out.push(length(excursion).at(x, y));
                }
            }
            if let Some(delta) = row.delta {
                for (ni, nj) in [(i + 1, j), (i, j + 1)] {
                    if ni < n && nj < n {
                        let gap = (d - density(ni, nj)).abs();
                        if gap > delta {
                            out.push(ratio(gap).at(x, y));
                        }
                    }
                }
            }
        }
    }
    out
}

fn density_layout(metal: &[Rect]) -> Layout {
    let mut l = Layout::default();
    rect(&mut l, "die", (0, 0, 4000, 4000));
    for &m in metal {
        rect(&mut l, "met1", m);
    }
    l
}

/// `density_cmp` (ERC-B1) on four 2 µm windows of densities 0.25, 0.5, 0.75
/// and 0.125: `min` and `max` swept across each density, `max_delta` across
/// each neighbour gap (0.25, 0.5, 0.375, 0.625), the CMP excursion
/// `|400 nm × (d - 0.5)|` (100, 0, 100, 150 nm) across each value; the gap
/// and excursion cases also prove DRC-113's density-step and CMP hotspots. Window
/// placement on 3 µm windows stepped by 2 µm: three of four are die-clipped
/// and count only with `partial_windows`. Overlapping metal counts once.
fn density() -> Vec<Fixture> {
    let mut out = Vec::new();
    let layout = density_layout(&DENSITY_METAL);
    let mut placed = Vec::new();
    let mut case = |name: String, row: DensityRow, window: i64, step: i64, place: bool| {
        // A density step between neighbouring windows and a CMP thickness
        // excursion are the CMP hotspots public models define (DRC-113).
        let rows: &[&'static str] = if row.delta.is_some() || row.cmp.is_some() {
            &["ERC-B1", "DRC-113"]
        } else {
            &["ERC-B1"]
        };
        let f = Fixture::new(&name, rows, &row.deck(window, step))
            .layout(layout.clone())
            .expect(Expect::rule(
                "den",
                density_oracle(&DENSITY_METAL, 4000, window, step, row),
            ));
        if place {
            placed.push(f.clone());
        }
        out.push(f);
    };
    // Placed: min just above 0.25 (two windows) and max just below 0.5 (two).
    for (k, d) in [0.125, 0.25, 0.5, 0.75].into_iter().enumerate() {
        for limit in [d - 0.001, d, d + 0.001] {
            let s = side(limit, d);
            let row = DensityRow {
                min: Some(limit),
                partial: true,
                ..DensityRow::default()
            };
            case(
                format!("erc/density/min/{d}/{s}"),
                row,
                2000,
                2000,
                k == 1 && s == "above",
            );
            let row = DensityRow {
                max: Some(limit),
                partial: true,
                ..DensityRow::default()
            };
            case(
                format!("erc/density/max/{d}/{s}"),
                row,
                2000,
                2000,
                k == 2 && s == "below",
            );
        }
    }
    for gap in [0.25, 0.375, 0.5, 0.625] {
        for limit in [gap - 0.001, gap, gap + 0.001] {
            let row = DensityRow {
                delta: Some(limit),
                partial: true,
                ..DensityRow::default()
            };
            case(
                format!("erc/density/delta/{gap}/{}", side(limit, gap)),
                row,
                2000,
                2000,
                false,
            );
        }
    }
    for excursion in [100, 150] {
        for limit in [excursion - 1, excursion, excursion + 1] {
            let row = DensityRow {
                cmp: Some((0.5, 400, limit)),
                partial: true,
                ..DensityRow::default()
            };
            case(
                format!(
                    "erc/density/cmp/{excursion}/{}",
                    side(limit as f64, excursion as f64)
                ),
                row,
                2000,
                2000,
                excursion == 100 && limit == 99,
            );
        }
    }
    for partial in [true, false] {
        let row = DensityRow {
            min: Some(0.45),
            max: Some(0.55),
            partial,
            ..DensityRow::default()
        };
        case(
            format!("erc/density/partial/{partial}/min_max"),
            row,
            3000,
            2000,
            false,
        );
    }
    let row = DensityRow {
        delta: Some(0.05),
        partial: true,
        ..DensityRow::default()
    };
    case(
        "erc/density/partial/true/delta".to_owned(),
        row,
        3000,
        2000,
        false,
    );
    out.extend(every_placement(&placed).into_iter().map(|mut f| {
        f.name = format!("{}/placed", f.name);
        f
    }));
    let mut fixtures = Vec::new();
    // F35: without partial windows a die-clipped window is not evaluated, so
    // no neighbour difference involving one is either.
    let row = DensityRow {
        delta: Some(0.05),
        partial: false,
        ..DensityRow::default()
    };
    fixtures.push(
        Fixture::new(
            "erc/density/partial/false/delta",
            &["ERC-B1"],
            &row.deck(3000, 2000),
        )
        .layout(layout.clone())
        .expect(Expect::clean("den")),
    );
    // Two overlapping pieces in the lower-left window cover their union.
    let overlap = {
        let mut l = density_layout(&DENSITY_METAL[1..]);
        rect(&mut l, "met1", (0, 0, 1000, 1000));
        rect(&mut l, "met1", (500, 0, 1500, 1000));
        l
    };
    let union = [
        (0, 0, 1500, 1000),
        DENSITY_METAL[1],
        DENSITY_METAL[2],
        DENSITY_METAL[3],
    ];
    let row = DensityRow {
        min: Some(0.4),
        partial: true,
        ..DensityRow::default()
    };
    fixtures.push(
        Fixture::new(
            "erc/density/overlapping_metal",
            &["ERC-B1"],
            &row.deck(2000, 2000),
        )
        .layout(overlap)
        .expect(Expect::rule(
            "den",
            density_oracle(&union, 4000, 2000, 2000, row),
        )),
    );
    // No die layer: the die is the drawn layout's extent, `[0, 4000]^2` from a
    // marker, so the same four windows. A derived layer grown 500 nm past the
    // metal is not layout and must not widen it to `[-500, 4500]^2` (F40).
    let row = DensityRow {
        min: Some(0.2),
        partial: true,
        ..DensityRow::default()
    };
    let mut halo = Layout::default();
    rect(&mut halo, "marker", (0, 0, 4000, 4000));
    for &m in &DENSITY_METAL {
        rect(&mut halo, "met1", m);
    }
    fixtures.push(
        Fixture::new(
            "erc/density/derived_halo",
            &["ERC-B1"],
            &row.deck(2000, 2000)
                .replace("layer die =", "layer marker =")
                .replace("rule den", "layer halo = met1.sized(500nm)\nrule den"),
        )
        .layout(halo)
        .expect(Expect::rule(
            "den",
            density_oracle(&DENSITY_METAL, 4000, 2000, 2000, row),
        )),
    );
    out.extend(every_offset(&fixtures));
    out
}

// --------------------------------------------------------------- power grid

/// `rule <id> <row>` lines.
fn rule_lines(rows: &[(&str, &str)]) -> String {
    rows.iter()
        .map(|(id, row)| format!("rule {id} {row}\n"))
        .collect::<Vec<_>>()
        .concat()
}

/// Transistors (diffusion source and drain, a poly gate, a channel marker;
/// the `_b` models add a well bulk), tap stubs, pads and markers, wired by
/// cuts and met1 risers to one met2 track per net, every conductor with a
/// sheet resistance.
const TOPO_PROCESS: &str = "grid 1nm
layer diff = gds(1, 0)
layer poly = gds(2, 0)
layer well = gds(3, 0)
layer ntap = gds(4, 0)
layer ptap = gds(5, 0)
layer cont = gds(6, 0)
layer met1 = gds(7, 0)
layer via1 = gds(8, 0)
layer met2 = gds(9, 0)
layer m2txt = gds(9, 1)
layer padv = gds(10, 0)
layer pad = gds(11, 0)
layer mkn = gds(20, 0)
layer mkp = gds(21, 0)
layer mkc = gds(22, 0)
layer mknb = gds(23, 0)
layer mkpb = gds(24, 0)
layer nwpm = gds(30, 0)
layer ring = gds(31, 0)
layer iso = gds(32, 0)
layer mkcn = gds(25, 0)
layer mkcp = gds(26, 0)
connect conductors [diff, poly, well, ntap, ptap, met1, met2, pad]
connect touch_within_layer
connect via cont [diff, met1]
connect via cont [poly, met1]
connect via cont [well, met1]
connect via cont [ntap, met1]
connect via cont [ptap, met1]
connect via via1 [met1, met2]
connect via padv [met2, pad]
connect label m2txt names met2
device mos mkn model \"nfet\" terminals [poly, diff, diff]
device mos mkp model \"pfet\" terminals [poly, diff, diff]
device mos mkc model \"clamp\" terminals [poly, diff, diff]
device mos mknb model \"nfet_b\" terminals [poly, diff, diff, well]
device mos mkpb model \"pfet_b\" terminals [poly, diff, diff, well]
device mos mkcn model \"nfet_c\" terminals [poly, diff, diff] on_gate_min 1V
device mos mkcp model \"pfet_c\" terminals [poly, diff, diff] on_gate_max 2.5V
pex well thickness 100nm height 5nm sheet 1000ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex diff thickness 100nm height 10nm sheet 100ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex ntap thickness 100nm height 10nm sheet 100ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex ptap thickness 100nm height 10nm sheet 100ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex poly thickness 100nm height 20nm sheet 10ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex cont thickness 100nm height 50nm sheet 5ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met1 thickness 100nm height 100nm sheet 0.125ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex via1 thickness 100nm height 200nm sheet 1ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met2 thickness 100nm height 300nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex padv thickness 100nm height 400nm sheet 1ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex pad thickness 100nm height 500nm sheet 0.01ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
";

/// Every rule a [`Board`] is checked against, and whether it needs intent.
const TOPO_RULES: [(&str, &str, bool); 26] = [
    ("fg", "floating_gate(; labels_are_ports: false)", false),
    ("fgp", "floating_gate(; labels_are_ports: true)", false),
    ("md1", "multiple_drivers(; max: 1)", true),
    ("md2", "multiple_drivers(; max: 2)", true),
    ("thl", "tie_high_low()", true),
    ("up", "unconnected_pin(met1, met2)", false),
    ("ss", "supply_short(ntap, ptap)", false),
    ("ssw", "supply_short(ntap, ptap, nwpm)", false),
    ("soft", "soft_connection(well)", false),
    ("fo", "fanout(; max: 1)", false),
    ("sp1", "supply_path(; both: false, labels_are_ports: false)", true),
    ("sp2", "supply_path(; both: true, labels_are_ports: false)", true),
    ("sp3", "supply_path(; both: true, labels_are_ports: true)", true),
    ("gp0", "gate_path(; ground: true, max_devices: 0)", true),
    ("gp1", "gate_path(; ground: false, max_devices: 1)", true),
    ("cl", "combinational_loop()", true),
    ("ug", "undriven_gate()", true),
    ("iso", "missing_isolation(; isolation: [\"pfet\"])", true),
    (
        "gox",
        "gate_oxide(; models: [\"nfet\", \"nfet_b\", \"pfet_b\"], max: {gox})",
        true,
    ),
    (
        "vds",
        "drain_source(; models: [\"nfet\", \"pfet\", \"nfet_b\", \"pfet_b\"], max: {vds})",
        true,
    ),
    ("ls", "missing_level_shifter(; shifters: [\"pfet\"])", true),
    ("xing", "domain_crossing()", true),
    ("hv", "hv_domain(; max_delta: {hv}, isolation: iso)", true),
    ("wb", "well_bias(; pmos: [\"pfet_b\"], nmos: [\"nfet_b\"])", true),
    ("esd", "esd_topological(pad; clamps: [\"clamp\"])", true),
    (
        "esdl",
        "esd_latchup(pad, ring; min_guard_ring_width: 500nm, max_tap_distance: 2000nm, clamps: [\"clamp\"])",
        true,
    ),
];

/// The catalog rows every board proves: the intent-free connectivity kinds,
/// which judge every net of every board.
const TOPO_CATALOG: &[&str] = &["ERC-G1", "ERC-G6", "ERC-E9", "ERC-H4"];
/// The rows a board with intent proves too: the kinds the rails orient,
/// propagation and the voltage kinds.
const VOLTAGE_CATALOG: &[&str] = &[
    "ERC-G3", "ERC-G7", "ERC-G8", "ERC-G9", "ERC-H3", "ERC-F1", "ERC-F2", "ERC-F3", "ERC-F6",
    "ERC-F9", "ERC-F10",
];

/// The voltage limits of a board's `gate_oxide`, `drain_source` and
/// `hv_domain` rows, mV.
#[derive(Clone, Copy, Debug)]
struct Limits {
    gox: f64,
    vds: f64,
    hv: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            gox: 1800.0,
            vds: 1800.0,
            hv: 1000.0,
        }
    }
}

fn topo_deck(limits: Limits) -> String {
    let rows: Vec<String> = TOPO_RULES
        .iter()
        .map(|(_, row, _)| {
            row.replace("{gox}", &format!("{}mV", limits.gox))
                .replace("{vds}", &format!("{}mV", limits.vds))
                .replace("{hv}", &format!("{}mV", limits.hv))
        })
        .collect();
    let pairs: Vec<(&str, &str)> = TOPO_RULES
        .iter()
        .zip(&rows)
        .map(|((id, _, _), row)| (*id, row.as_str()))
        .collect();
    format!("{TOPO_PROCESS}{}", rule_lines(&pairs))
}

/// Nets per board: one met2 track each.
const NETS: usize = 4;
const TRACK_Y0: i64 = 3000;
const TRACK_PITCH: i64 = 1000;
pub(crate) const TRACK_H: i64 = 400;
const PITCH: i64 = 4000;

pub(crate) fn track_y(net: usize) -> i64 {
    TRACK_Y0 + net as i64 * TRACK_PITCH
}

/// A met1 riser at column `x` (200 wide) from a cut at `base` to a via in
/// `net`'s track.
fn riser(l: &mut Layout, x: i64, base: i64, net: usize) {
    let ty = track_y(net);
    rect(l, "cont", (x + 50, base + 50, x + 150, base + 150));
    rect(l, "met1", (x, base, x + 200, ty + TRACK_H));
    rect(l, "via1", (x + 50, ty + 150, x + 150, ty + 250));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Model {
    Nfet,
    Pfet,
    Clamp,
    NfetB,
    PfetB,
    /// `nfet_c`: conducts while its gate can reach 1 V or more.
    NfetC,
    /// `pfet_c`: conducts while its gate can fall to 2.5 V or less.
    PfetC,
}

impl Model {
    fn marker(self) -> &'static str {
        match self {
            Model::Nfet => "mkn",
            Model::Pfet => "mkp",
            Model::Clamp => "mkc",
            Model::NfetB => "mknb",
            Model::PfetB => "mkpb",
            Model::NfetC => "mkcn",
            Model::PfetC => "mkcp",
        }
    }

    /// The deck row's gate condition: `(on at or above?, mV)`, as
    /// `TOPO_PROCESS` states it.
    fn condition(self) -> Option<(bool, f64)> {
        match self {
            Model::NfetC => Some((true, 1000.0)),
            Model::PfetC => Some((false, 2500.0)),
            _ => None,
        }
    }
}

/// One transistor: the nets of its gate, its source (the diffusion drawn
/// first, which extraction calls the source) and drain, and its bulk for the
/// `_b` models.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dev {
    model: Model,
    g: usize,
    s: usize,
    d: usize,
    b: Option<usize>,
}

pub(crate) fn dev(model: Model, g: usize, s: usize, d: usize) -> Dev {
    Dev {
        model,
        g,
        s,
        d,
        b: None,
    }
}

/// A supply as the intent declares it.
#[derive(Clone, Copy, Debug)]
struct Supply {
    net: usize,
    power: bool,
    /// The domain's index in name order: its bit in a power mask.
    domain: u32,
    nominal: f64,
}

/// What a net can reach from the supplies (`erc::voltage`'s model).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Reach {
    lo: f64,
    hi: f64,
    nominal_lo: f64,
    nominal_hi: f64,
    power: u64,
}

/// A circuit of transistors and taps on [`NETS`] nets, drawn as layout and
/// judged by a naive oracle of every rule in [`TOPO_RULES`].
#[derive(Clone, Debug, Default)]
struct Board {
    devs: Vec<Dev>,
    /// `(n-tap?, net)` per tap stub.
    taps: Vec<(bool, usize)>,
    /// Tap indices an `nwpm` polygon covers.
    nwpm: Vec<usize>,
    /// The net a pad sits on.
    pad: Option<usize>,
    /// A guard ring's box.
    ring: Option<Rect>,
    /// Device indices an `iso` polygon covers.
    iso: Vec<usize>,
    labels: [Option<&'static str>; NETS],
    supplies: Vec<Supply>,
    /// Domains `(name, mV)` in name order.
    domains: Vec<(&'static str, f64)>,
    with_intent: bool,
    limits: Limits,
    /// Power states the intent declares.
    states: Vec<BoardState>,
}

/// A power state of a [`Board`]: the supply nets it switches off and the
/// nets it holds, at mV.
#[derive(Clone, Debug)]
struct BoardState {
    name: &'static str,
    off: Vec<usize>,
    inputs: Vec<(usize, f64)>,
}

impl Board {
    fn columns(&self) -> usize {
        self.devs.len() + self.taps.len()
    }

    fn layout(&self) -> Layout {
        let mut l = Layout::default();
        for (i, dv) in self.devs.iter().enumerate() {
            let x0 = i as i64 * PITCH;
            rect(&mut l, "diff", (x0, 0, x0 + 1000, 1000));
            rect(&mut l, "diff", (x0 + 1200, 0, x0 + 2200, 1000));
            rect(&mut l, "poly", (x0 + 1000, 0, x0 + 1200, 1600));
            rect(&mut l, dv.model.marker(), (x0 + 1000, 0, x0 + 1200, 1000));
            riser(&mut l, x0 + 400, 400, dv.s);
            riser(&mut l, x0 + 1600, 400, dv.d);
            riser(&mut l, x0 + 1000, 1400, dv.g);
            if let Some(b) = dv.b {
                rect(&mut l, "well", (x0 + 1000, -600, x0 + 2700, 0));
                riser(&mut l, x0 + 2400, -500, b);
            }
            if self.iso.contains(&i) {
                rect(&mut l, "iso", (x0 + 900, -100, x0 + 1300, 1100));
            }
        }
        for (j, &(n, net)) in self.taps.iter().enumerate() {
            let x0 = (self.devs.len() + j) as i64 * PITCH;
            rect(
                &mut l,
                if n { "ntap" } else { "ptap" },
                (x0, 0, x0 + 600, 600),
            );
            riser(&mut l, x0 + 200, 200, net);
            if self.nwpm.contains(&j) {
                rect(&mut l, "nwpm", (x0 - 100, -100, x0 + 700, 700));
            }
        }
        let right = self.columns() as i64 * PITCH + 1000;
        for net in 0..NETS {
            let ty = track_y(net);
            rect(&mut l, "met2", (-1000, ty, right, ty + TRACK_H));
            if let Some(name) = self.labels[net] {
                l = l.label("m2txt", -900, ty + 200, name);
            }
        }
        if let Some(net) = self.pad {
            let ty = track_y(net);
            rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
            rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
        }
        if let Some(ring) = self.ring {
            rect(&mut l, "ring", ring);
        }
        l
    }

    fn intent(&self) -> String {
        let supplies: Vec<(&str, &str, &str)> = self
            .supplies
            .iter()
            .map(|s| {
                (
                    self.labels[s.net].expect("a supply is labelled"),
                    self.domains[s.domain as usize].0,
                    if s.power { "power" } else { "ground" },
                )
            })
            .collect();
        let base = intent(&self.domains, &supplies, &[]);
        if self.states.is_empty() {
            return base;
        }
        let name = |net: usize| self.labels[net].expect("a state names a labelled net");
        let states: Vec<String> = self
            .states
            .iter()
            .map(|st| {
                let off: Vec<String> = st
                    .off
                    .iter()
                    .map(|&n| format!(r#""{}""#, name(n)))
                    .collect();
                let inputs: Vec<String> = st
                    .inputs
                    .iter()
                    .map(|&(n, mv)| format!(r#"{{"net":"{}","voltage_mv":{mv}}}"#, name(n)))
                    .collect();
                format!(
                    r#"{{"name":"{}","off":[{}],"inputs":[{}]}}"#,
                    st.name,
                    off.join(","),
                    inputs.join(",")
                )
            })
            .collect();
        format!(
            "{},\"states\":[{}]}}",
            &base[..base.len() - 1],
            states.join(",")
        )
    }

    /// The supplies of power state `st`, as `IntentMap::in_state` states
    /// them: every supply it does not switch off and does not hold, and each
    /// held net as a supply at its voltage (a ground at 0 V, otherwise power
    /// of domain 0).
    fn state_supplies(&self, st: &BoardState) -> Vec<Supply> {
        let mut out: Vec<Supply> = self
            .supplies
            .iter()
            .filter(|s| !st.off.contains(&s.net) && !st.inputs.iter().any(|i| i.0 == s.net))
            .copied()
            .collect();
        out.extend(st.inputs.iter().map(|&(net, mv)| Supply {
            net,
            power: mv != 0.0,
            domain: 0,
            nominal: mv,
        }));
        out
    }

    fn supply(&self, net: usize) -> Option<&Supply> {
        self.supplies.iter().find(|s| s.net == net)
    }

    /// The voltage model of `erc::voltage`, by brute force (NV): a supply net
    /// sits at its nominal (power) or 0 V (ground) and never changes; every
    /// conducting transistor widens each of its source and drain nets that is
    /// not a supply to the union of both, swept over every transistor until
    /// nothing changes. Gates and bulks pass nothing. A transistor of a
    /// [`Model::condition`] conducts while its gate's range reaches the
    /// condition (Siemens 81822, figure 1), or when its gate is free: no
    /// supply reaches it even with every channel conducting, or, after a
    /// sweep, still none does (it floats behind switches that never turn on).
    fn reach(&self) -> Vec<Option<Reach>> {
        self.reach_with(&self.supplies)
    }

    /// [`Board::reach`] from `supplies` in place of the board's own.
    fn reach_with(&self, supplies: &[Supply]) -> Vec<Option<Reach>> {
        let supply = |net: usize| supplies.iter().find(|s| s.net == net);
        let sweep = |free: &[bool]| -> Vec<Option<Reach>> {
            let mut r: Vec<Option<Reach>> = (0..NETS)
                .map(|net| {
                    supply(net).map(|s| Reach {
                        lo: if s.power { s.nominal } else { 0.0 },
                        hi: if s.power { s.nominal } else { 0.0 },
                        nominal_lo: s.nominal,
                        nominal_hi: s.nominal,
                        power: if s.power { 1 << s.domain } else { 0 },
                    })
                })
                .collect();
            let union = |a: Option<Reach>, b: Option<Reach>| match (a, b) {
                (Some(a), Some(b)) => Some(Reach {
                    lo: a.lo.min(b.lo),
                    hi: a.hi.max(b.hi),
                    nominal_lo: a.nominal_lo.min(b.nominal_lo),
                    nominal_hi: a.nominal_hi.max(b.nominal_hi),
                    power: a.power | b.power,
                }),
                (a, None) => a,
                (None, b) => b,
            };
            loop {
                let mut changed = false;
                for (i, dv) in self.devs.iter().enumerate() {
                    let on = match dv.model.condition() {
                        None => true,
                        Some(_) if free[i] => true,
                        Some((at_least, v)) => {
                            r[dv.g].is_some_and(|g| if at_least { g.hi >= v } else { g.lo <= v })
                        }
                    };
                    if !on {
                        continue;
                    }
                    let both = union(r[dv.s], r[dv.d]);
                    for n in [dv.s, dv.d] {
                        let widened = union(r[n], both);
                        if supply(n).is_none() && widened != r[n] {
                            r[n] = widened;
                            changed = true;
                        }
                    }
                }
                if !changed {
                    return r;
                }
            }
        };
        let everything = sweep(&vec![true; self.devs.len()]);
        let mut free: Vec<bool> = self
            .devs
            .iter()
            .map(|d| everything[d.g].is_none())
            .collect();
        loop {
            let r = sweep(&free);
            let floating: Vec<usize> = (0..self.devs.len())
                .filter(|&i| !free[i] && r[self.devs[i].g].is_none())
                .collect();
            if floating.is_empty() {
                return r;
            }
            for i in floating {
                free[i] = true;
            }
        }
    }

    /// Every rule's expectation, from the definitions in each kind's rustdoc.
    fn expect(&self) -> Vec<Expect> {
        let mut out = Vec::new();
        let terminals = |net: usize| -> (bool, bool, bool, bool) {
            let g = self.devs.iter().any(|d| d.g == net);
            let s = self.devs.iter().any(|d| d.s == net);
            let dr = self.devs.iter().any(|d| d.d == net);
            let b = self.devs.iter().any(|d| d.b == Some(net));
            (g, s, dr, b)
        };
        // floating_gate: a net whose every terminal is a gate.
        let floating: Vec<usize> = (0..NETS)
            .filter(|&n| terminals(n) == (true, false, false, false))
            .collect();
        out.push(Expect::rule(
            "fg",
            floating.iter().map(|_| count(0)).collect(),
        ));
        out.push(Expect::rule(
            "fgp",
            floating
                .iter()
                .filter(|&&n| self.labels[n].is_none())
                .map(|_| count(0))
                .collect(),
        ));
        // unconnected_pin(met1, met2): every met1 and met2 polygon of a net no
        // device terminal reaches: its track, and the riser of each tap on it.
        let mut unconnected = Vec::new();
        for n in 0..NETS {
            let (g, s, d, b) = terminals(n);
            if !(g || s || d || b) {
                let taps = self.taps.iter().filter(|t| t.1 == n).count();
                unconnected.extend((0..=taps).map(|_| count(0)));
            }
        }
        out.push(Expect::rule("up", unconnected));
        // supply_short: a net holding an n-tap and a p-tap; with `within`,
        // only n-taps inside an nwpm polygon count.
        for (id, within) in [("ss", false), ("ssw", true)] {
            let findings = (0..NETS)
                .filter(|&n| {
                    let a = self
                        .taps
                        .iter()
                        .enumerate()
                        .any(|(j, t)| t.0 && t.1 == n && (!within || self.nwpm.contains(&j)));
                    let b = self.taps.iter().any(|t| !t.0 && t.1 == n);
                    a && b
                })
                .map(|_| count(2))
                .collect();
            out.push(Expect::rule(id, findings));
        }
        // soft_connection: every well here hangs off a riser that also holds
        // the rest of its net.
        out.push(Expect::clean("soft"));
        // fanout(; max: 1): a net with two or more transistor gates on it,
        // measuring the count.
        out.push(Expect::rule(
            "fo",
            (0..NETS)
                .filter_map(|n| {
                    let gates = self.devs.iter().filter(|d| d.g == n).count() as u32;
                    (gates > 1).then(|| count(gates))
                })
                .collect(),
        ));
        if !self.with_intent {
            for (id, _, needs) in TOPO_RULES {
                if needs {
                    out.push(Expect::outcome(id, Want::Skipped));
                }
            }
            return out;
        }
        out.extend(self.expect_states());
        // multiple_drivers: a transistor with either channel end on a net that
        // is not a rail pulls it when a walk from its other end, through every
        // transistor with a channel end on the nets reached, stopping at rails
        // and never back through the net, reaches a rail; its gates are those
        // of every transistor the walk passes. Networks sharing a gate net are
        // one driver.
        let rail = |n: usize| self.supply(n).is_some();
        let far = |d: &Dev, n: usize| if d.s == n { d.d } else { d.s };
        for (id, max) in [("md1", 1), ("md2", 2)] {
            let findings = (0..NETS)
                .filter(|&n| !rail(n))
                .filter_map(|n| {
                    let gates: Vec<Vec<usize>> = self
                        .devs
                        .iter()
                        .filter(|d| d.s == n || d.d == n)
                        .filter_map(|m| {
                            let (mut gates, mut seen, mut walk) =
                                (vec![m.g], [false; NETS], vec![far(m, n)]);
                            let mut reached = false;
                            while let Some(at) = walk.pop() {
                                if at == n || seen[at] {
                                    continue;
                                }
                                seen[at] = true;
                                if rail(at) {
                                    reached = true;
                                    continue;
                                }
                                for u in self.devs.iter().filter(|u| u.s == at || u.d == at) {
                                    gates.push(u.g);
                                    walk.push(far(u, at));
                                }
                            }
                            reached.then_some(gates)
                        })
                        .collect();
                    let mut group: Vec<usize> = (0..gates.len()).collect();
                    let mut changed = true;
                    while changed {
                        changed = false;
                        for i in 0..gates.len() {
                            for j in 0..gates.len() {
                                let shared = gates[i].iter().any(|g| gates[j].contains(g));
                                if shared && group[j] > group[i] {
                                    let (old, new) = (group[j], group[i]);
                                    group
                                        .iter_mut()
                                        .filter(|g| **g == old)
                                        .for_each(|g| *g = new);
                                    changed = true;
                                }
                            }
                        }
                    }
                    group.sort_unstable();
                    group.dedup();
                    (group.len() > max).then(|| count(group.len() as u32))
                })
                .collect();
            out.push(Expect::rule(id, findings));
        }
        // supply_path: from each non-rail net a device terminal reaches,
        // walk source to drain through every transistor, stopping at rails
        // (a rail ends the path and gives it its role). `sp1` flags a net
        // that reaches no rail, measuring 0 against 1; `sp2` one that misses
        // power or ground, measuring the roles reached against 2. `sp3` is
        // `sp2` with every labelled net that is not a rail a top-cell port
        // (P12 [0262]: "a path continues until it reaches ... a port in the
        // top cell"): a port is a break like a rail but carries no role, so
        // a walk never steps past a port it reaches, and a walk from a port
        // takes one step only, a rail it lands on giving that rail's role.
        let (mut sp1, mut sp2, mut sp3) = (Vec::new(), Vec::new(), Vec::new());
        let is_port = |n: usize| self.labels[n].is_some() && self.supply(n).is_none();
        let roles_from = |n: usize, ports: bool| -> u32 {
            let (mut seen, mut walk, mut roles) = ([false; NETS], vec![n], [false; 2]);
            while let Some(at) = walk.pop() {
                if seen[at] {
                    continue;
                }
                seen[at] = true;
                if let Some(supply) = self.supply(at) {
                    roles[usize::from(!supply.power)] = true;
                    continue;
                }
                // A port ends the walk that reaches it, and a walk that
                // starts at one ends one device out.
                if ports && at != n && (is_port(at) || is_port(n)) {
                    continue;
                }
                for u in self.devs.iter().filter(|u| u.s == at || u.d == at) {
                    walk.push(far(u, at));
                }
            }
            roles.iter().filter(|&&r| r).count() as u32
        };
        for n in 0..NETS {
            let (g, s, d, b) = terminals(n);
            if rail(n) || !(g || s || d || b) {
                continue;
            }
            let found = roles_from(n, false);
            if found == 0 {
                sp1.push(count(0));
            }
            if found < 2 {
                sp2.push(count(found));
            }
            let found = roles_from(n, true);
            if found < 2 {
                sp3.push(count(found));
            }
        }
        out.push(Expect::rule("sp1", sp1));
        out.push(Expect::rule("sp2", sp2));
        out.push(Expect::rule("sp3", sp3));
        // gate_path: the fewest transistors a walk from a gate's net through
        // sources and drains passes to reach a rail of the asked role, rails
        // of the other role passed like any net. More than `max` measures
        // that count; no walk at all measures 0 against 1.
        for (id, ground, max) in [("gp0", true, 0u32), ("gp1", false, 1)] {
            let mut dist = [u32::MAX; NETS];
            let mut frontier: Vec<usize> = (0..NETS)
                .filter(|&n| self.supply(n).is_some_and(|s| s.power != ground))
                .collect();
            for &n in &frontier {
                dist[n] = 0;
            }
            let mut step = 0;
            while !frontier.is_empty() {
                step += 1;
                let mut next = Vec::new();
                for &at in &frontier {
                    for u in self.devs.iter().filter(|u| u.s == at || u.d == at) {
                        let to = far(u, at);
                        if dist[to] == u32::MAX {
                            dist[to] = step;
                            next.push(to);
                        }
                    }
                }
                frontier = next;
            }
            let findings = (0..NETS)
                .filter(|&n| self.devs.iter().any(|d| d.g == n))
                .filter_map(|n| match dist[n] {
                    u32::MAX => Some(count(0)),
                    d if d > max => Some(count(d)),
                    _ => None,
                })
                .collect();
            out.push(Expect::rule(id, findings));
        }
        // combinational_loop: components are the non-rail nets joined by
        // transistors with both channel ends off the rails; a transistor
        // whose channel touches a component belongs to it, and its gate's
        // component (when the gate is a channel end) drives it. A loop is a
        // set of components each reaching every other by that relation, of
        // two or more, or one driving itself; it measures its components.
        let mut comp: [usize; NETS] = std::array::from_fn(|n| n);
        loop {
            let mut changed = false;
            for d in self.devs.iter().filter(|d| !rail(d.s) && !rail(d.d)) {
                let low = comp[d.s].min(comp[d.d]);
                for n in 0..NETS {
                    if (comp[n] == comp[d.s] || comp[n] == comp[d.d]) && comp[n] != low {
                        comp[n] = low;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let end = |n: usize| !rail(n) && self.devs.iter().any(|d| d.s == n || d.d == n);
        let mut drives = [[false; NETS]; NETS];
        for d in &self.devs {
            let to = [d.s, d.d].into_iter().find(|&n| !rail(n));
            if let (Some(to), true) = (to, end(d.g)) {
                drives[comp[d.g]][comp[to]] = true;
            }
        }
        for k in 0..NETS {
            for i in 0..NETS {
                for j in 0..NETS {
                    drives[i][j] |= drives[i][k] && drives[k][j];
                }
            }
        }
        let roots: Vec<usize> = (0..NETS).filter(|&n| end(n) && comp[n] == n).collect();
        let mut done = [false; NETS];
        let mut loops = Vec::new();
        for &c in &roots {
            if done[c] || !drives[c][c] {
                continue;
            }
            let members: Vec<usize> = roots
                .iter()
                .copied()
                .filter(|&o| o == c || drives[c][o] && drives[o][c])
                .collect();
            for &m in &members {
                done[m] = true;
            }
            loops.push(count(members.len() as u32));
        }
        out.push(Expect::rule("cl", loops));
        // tie_high_low: a rail that reaches a gate.
        out.push(Expect::rule(
            "thl",
            (0..NETS)
                .filter(|&n| rail(n) && self.devs.iter().any(|d| d.g == n))
                .map(|_| count(0))
                .collect(),
        ));
        let reach = self.reach();
        let worst = |a: usize, b: usize| -> Option<f64> {
            let (a, b) = (reach[a]?, reach[b]?);
            Some((a.hi - b.lo).max(b.hi - a.lo))
        };
        let power = |n: usize| reach[n].map_or(0, |r| r.power);
        let in_models = |m: Model, list: &[Model]| list.contains(&m);
        // gate_oxide: the worst gate-to-source, -drain or -bulk difference.
        let mut gox = Vec::new();
        let mut vds = Vec::new();
        let mut ls = Vec::new();
        let mut xing = Vec::new();
        let mut hv = Vec::new();
        let mut wb = Vec::new();
        for (i, dv) in self.devs.iter().enumerate() {
            if in_models(dv.model, &[Model::Nfet, Model::NfetB, Model::PfetB]) {
                let stress = [Some(dv.s), Some(dv.d), dv.b]
                    .into_iter()
                    .flatten()
                    .filter_map(|x| worst(dv.g, x))
                    .reduce(f64::max);
                if let Some(v) = stress.filter(|&v| v > self.limits.gox) {
                    gox.push(millivolts(v));
                }
            }
            if in_models(
                dv.model,
                &[Model::Nfet, Model::Pfet, Model::NfetB, Model::PfetB],
            ) {
                if let Some(v) = worst(dv.s, dv.d).filter(|&v| v > self.limits.vds) {
                    vds.push(millivolts(v));
                }
            }
            // missing_level_shifter: a gate domain neither channel end has.
            if dv.model != Model::Pfet {
                let (gate, channel) = (power(dv.g), power(dv.s) | power(dv.d));
                if gate != 0 && channel != 0 && gate & !channel != 0 {
                    ls.push(count((gate & !channel).count_ones()));
                }
            }
            // domain_crossing: two power domains on one channel.
            let mask = power(dv.s) | power(dv.d);
            if mask.count_ones() > 1 {
                xing.push(count(mask.count_ones()));
            }
            // hv_domain: the domain span over every terminal, all reached.
            let all: Vec<Reach> = [Some(dv.g), Some(dv.s), Some(dv.d), dv.b]
                .into_iter()
                .flatten()
                .map(|n| reach[n])
                .collect::<Option<Vec<Reach>>>()
                .unwrap_or_default();
            if !all.is_empty() && !self.iso.contains(&i) {
                let lo = all
                    .iter()
                    .map(|r| r.nominal_lo)
                    .fold(f64::INFINITY, f64::min);
                let hi = all
                    .iter()
                    .map(|r| r.nominal_hi)
                    .fold(f64::NEG_INFINITY, f64::max);
                if hi - lo > self.limits.hv {
                    hv.push(millivolts(hi - lo));
                }
            }
            // well_bias: a pmos end above its well's lowest, an nmos end below
            // its substrate's highest.
            if let (Some(b), true) = (dv.b, matches!(dv.model, Model::NfetB | Model::PfetB)) {
                let ends: Vec<Reach> = [dv.s, dv.d].iter().filter_map(|&n| reach[n]).collect();
                if let (Some(bulk), false) = (reach[b], ends.is_empty()) {
                    let excess = if dv.model == Model::PfetB {
                        ends.iter().map(|r| r.hi).fold(f64::NEG_INFINITY, f64::max) - bulk.lo
                    } else {
                        bulk.hi - ends.iter().map(|r| r.lo).fold(f64::INFINITY, f64::min)
                    };
                    if excess > 0.0 {
                        wb.push(millivolts(excess));
                    }
                }
            }
        }
        out.push(Expect::rule("gox", gox));
        out.push(Expect::rule("vds", vds));
        out.push(Expect::rule("ls", ls));
        out.push(Expect::rule("xing", xing));
        out.push(Expect::rule("hv", hv));
        out.push(Expect::rule("wb", wb));
        // esd: from the pad, any clamp terminal; from a supply, onward
        // through clamps; another signal net ends the path.
        let mut esd = Vec::new();
        if let Some(pad) = self.pad {
            let mut seen = [false; NETS];
            let mut stack = vec![pad];
            seen[pad] = true;
            let (mut p, mut g) = (false, false);
            while let Some(net) = stack.pop() {
                match self.supply(net) {
                    Some(s) if s.power => p = true,
                    Some(_) => g = true,
                    None if net != pad => continue,
                    None => {}
                }
                for dv in self.devs.iter().filter(|d| d.model == Model::Clamp) {
                    let all = [Some(dv.g), Some(dv.s), Some(dv.d), dv.b];
                    if !all.contains(&Some(net)) {
                        continue;
                    }
                    for next in all.into_iter().flatten() {
                        if !seen[next] {
                            seen[next] = true;
                            stack.push(next);
                        }
                    }
                }
            }
            let rails = u32::from(p) + u32::from(g);
            if rails < 2 {
                esd.push(count(rails));
            }
        }
        out.push(Expect::rule("esd", esd.clone()));
        // esd_latchup: the pad check, then the ring's box: its narrow side
        // against 500 nm, its gap to the nearest supply track against 2 µm.
        let mut esdl = esd;
        if let Some((xlo, ylo, xhi, yhi)) = self.ring {
            let width = (xhi - xlo).min(yhi - ylo);
            if width < 500 {
                esdl.push(length(width));
            }
            let right = self.columns() as i64 * PITCH + 1000;
            let gap = self
                .supplies
                .iter()
                .map(|s| {
                    let (tlo, thi) = (track_y(s.net), track_y(s.net) + TRACK_H);
                    let dx = (-1000 - xhi).max(xlo - right).max(0);
                    let dy = (tlo - yhi).max(ylo - thi).max(0);
                    dx.max(dy)
                })
                .min();
            match gap {
                None => esdl.push(count(0)),
                Some(gap) if gap > 2000 => esdl.push(length(gap)),
                Some(_) => {}
            }
        }
        out.push(Expect::rule("esdl", esdl));
        out
    }

    /// `undriven_gate` and `missing_isolation(; isolation: ["pfet"])`, from
    /// their rustdoc: per declared state, the board's reach from that
    /// state's supplies ([`Board::state_supplies`]). A gate net reached with
    /// every supply on that a state leaves unreached floats there; a
    /// transistor (not a pfet) whose gate floats in a state while a power
    /// supply reaches its source or drain there leaks. Each measures the
    /// count of such states. Without states both are Skipped.
    fn expect_states(&self) -> Vec<Expect> {
        if self.states.is_empty() {
            return vec![
                Expect::outcome("ug", Want::Skipped),
                Expect::outcome("iso", Want::Skipped),
            ];
        }
        let base = self.reach();
        let states: Vec<Vec<Option<Reach>>> = self
            .states
            .iter()
            .map(|st| self.reach_with(&self.state_supplies(st)))
            .collect();
        let floats =
            |reach: &[Option<Reach>], net: usize| base[net].is_some() && reach[net].is_none();
        let undriven = (0..NETS)
            .filter(|&n| self.devs.iter().any(|d| d.g == n))
            .filter_map(|n| {
                let off = states.iter().filter(|r| floats(r.as_slice(), n)).count() as u32;
                (off > 0).then(|| count(off))
            })
            .collect();
        let power = |reach: &[Option<Reach>], net: usize| reach[net].map_or(0, |r| r.power);
        let leaking = self
            .devs
            .iter()
            .filter(|d| d.model != Model::Pfet)
            .filter_map(|d| {
                let off = states
                    .iter()
                    .filter(|r| {
                        floats(r.as_slice(), d.g)
                            && (power(r.as_slice(), d.s) | power(r.as_slice(), d.d)) != 0
                    })
                    .count() as u32;
                (off > 0).then(|| count(off))
            })
            .collect();
        vec![Expect::rule("ug", undriven), Expect::rule("iso", leaking)]
    }

    fn fixture(&self, name: &str) -> Fixture {
        // The rows this board's content exercises: taps for supply shorts, a
        // pad for the clamp path, a ring for its limits, a bulk for well bias.
        let mut catalog = TOPO_CATALOG.to_vec();
        if !self.taps.is_empty() {
            catalog.push("ERC-G4");
        }
        if self.with_intent {
            catalog.extend_from_slice(VOLTAGE_CATALOG);
            if self.devs.iter().any(|d| d.b.is_some()) {
                catalog.extend(["ERC-F12", "ERC-D3"]);
            }
            if self.pad.is_some() {
                catalog.push("ERC-C1");
            }
            if self.ring.is_some() {
                catalog.push("ERC-D2");
            }
            if !self.states.is_empty() {
                catalog.extend(["ERC-F7", "ERC-F8", "ERC-H1"]);
            }
        }
        let mut f = Fixture::new(name, &catalog, &topo_deck(self.limits)).layout(self.layout());
        for e in self.expect() {
            f = f.expect(e);
        }
        if self.with_intent {
            f.intent = Some(self.intent());
        }
        f
    }
}

/// Nets 0-3 as VDD (1.8 V, domain a), VSS (ground, a), VDDH (3.3 V, domain
/// b) and an unlabelled signal.
fn three_rails(with_intent: bool) -> Board {
    Board {
        labels: [Some("VDD"), Some("VSS"), Some("VDDH"), None],
        supplies: vec![
            Supply {
                net: 0,
                power: true,
                domain: 0,
                nominal: 1800.0,
            },
            Supply {
                net: 1,
                power: false,
                domain: 0,
                nominal: 1800.0,
            },
            Supply {
                net: 2,
                power: true,
                domain: 1,
                nominal: 3300.0,
            },
        ],
        domains: vec![("a", 1800.0), ("b", 3300.0)],
        with_intent,
        ..Board::default()
    }
}

/// Nets 0-3 as VDD (1.8 V, domain a), VSS (ground, a) and two unlabelled
/// signals.
fn two_rails() -> Board {
    let mut board = three_rails(true);
    board.labels = [Some("VDD"), Some("VSS"), None, None];
    board.supplies.truncate(2);
    board.domains.truncate(1);
    board
}

/// Every assignment of `terminals` terminals to at most [`NETS`] nets up to
/// renaming the nets: restricted growth strings, each first use of a net
/// numbered one past the largest so far.
fn canonical_assignments(terminals: usize) -> Vec<Vec<usize>> {
    fn grow(terminals: usize, current: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if current.len() == terminals {
            out.push(current.clone());
            return;
        }
        let next = current.iter().max().map_or(0, |m| m + 1).min(NETS - 1);
        for net in 0..=next {
            current.push(net);
            grow(terminals, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    grow(terminals, &mut Vec::with_capacity(terminals), &mut out);
    out
}

/// Every assignment of `terminals` terminals to the [`NETS`] nets, as base-4
/// digits of `0 .. 4^terminals`.
fn all_assignments(terminals: u32) -> Vec<Vec<usize>> {
    (0..NETS.pow(terminals))
        .map(|mut code| {
            (0..terminals)
                .map(|_| {
                    let net = code % NETS;
                    code /= NETS;
                    net
                })
                .collect()
        })
        .collect()
}

fn assignment_name(nets: &[usize]) -> String {
    nets.iter().map(ToString::to_string).collect()
}

/// The enumerations over small circuits, each checked by [`Board::expect`]:
///
/// - three nfets with every gate, source and drain on any of four nets, up to
///   renaming the nets (11 051 circuits), without intent: the intent-free
///   kinds judged and every intent kind Skipped;
/// - an nfet and a pfet (exempt as a level shifter, not checked for gate
///   oxide) on four nets, every one of the 4^6 assignments, against VDD, VSS
///   and VDDH;
/// - three transistors against the same rails, sampled, and against VDD and
///   VSS alone, so a pull network can run through two signal nets;
/// - one four-terminal transistor of each polarity, every 4^4 assignment,
///   for the bulk-reading kinds.
fn topology_enumerations(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    for a in sample(&canonical_assignments(9), depth, 60, 0x7_0001) {
        let mut board = three_rails(false);
        board.devs = a
            .chunks(3)
            .map(|t| dev(Model::Nfet, t[0], t[1], t[2]))
            .collect();
        out.push(board.fixture(&format!("erc/topology/no_intent/{}", assignment_name(&a))));
    }
    for a in sample(&all_assignments(6), depth, 60, 0x7_0002) {
        let mut board = three_rails(true);
        board.devs = vec![
            dev(Model::Nfet, a[0], a[1], a[2]),
            dev(Model::Pfet, a[3], a[4], a[5]),
        ];
        out.push(board.fixture(&format!("erc/topology/intent2/{}", assignment_name(&a))));
    }
    let mut rng = Rng::new(0x7_0003);
    let three = 30;
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < three {
        let a: Vec<usize> = (0..9).map(|_| rng.below(NETS as u64) as usize).collect();
        if !seen.insert(a.clone()) {
            continue;
        }
        let mut board = three_rails(true);
        board.devs = vec![
            dev(Model::Nfet, a[0], a[1], a[2]),
            dev(Model::Pfet, a[3], a[4], a[5]),
            dev(Model::Nfet, a[6], a[7], a[8]),
        ];
        out.push(board.fixture(&format!("erc/topology/intent3/{}", assignment_name(&a))));
    }
    let mut rng = Rng::new(0x7_0005);
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < three {
        let a: Vec<usize> = (0..9).map(|_| rng.below(NETS as u64) as usize).collect();
        if !seen.insert(a.clone()) {
            continue;
        }
        let mut board = two_rails();
        board.devs = vec![
            dev(Model::Nfet, a[0], a[1], a[2]),
            dev(Model::Pfet, a[3], a[4], a[5]),
            dev(Model::Nfet, a[6], a[7], a[8]),
        ];
        out.push(board.fixture(&format!("erc/topology/rails2/{}", assignment_name(&a))));
    }
    // The same with net 2 labelled: a top-cell port under `labels_are_ports`
    // (`fgp`, `sp3`), between the rails and the unlabelled net 3, so a path
    // through it is cut there.
    let mut rng = Rng::new(0x7_000a);
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < three {
        let a: Vec<usize> = (0..9).map(|_| rng.below(NETS as u64) as usize).collect();
        if !seen.insert(a.clone()) {
            continue;
        }
        let mut board = two_rails();
        board.labels[2] = Some("P");
        board.devs = vec![
            dev(Model::Nfet, a[0], a[1], a[2]),
            dev(Model::Pfet, a[3], a[4], a[5]),
            dev(Model::Nfet, a[6], a[7], a[8]),
        ];
        out.push(board.fixture(&format!("erc/topology/port/{}", assignment_name(&a))));
    }
    // Gate-conditioned switches (ERC-F1): an nfet_c (on at 1 V or more) and a
    // pfet_c (on at 2.5 V or less), every 4^6 assignment against VDD, VSS and
    // VDDH, so each gate sits on 0, 1.8 or 3.3 V, on the signal, or on a
    // channel of its own; then with a plain nfet, sampled, against those
    // rails and against VDD and VSS alone, so a gate can be driven through
    // another switch or float behind one that never turns on.
    for a in sample(&all_assignments(6), depth, 60, 0x7_0006) {
        let mut board = three_rails(true);
        board.devs = vec![
            dev(Model::NfetC, a[0], a[1], a[2]),
            dev(Model::PfetC, a[3], a[4], a[5]),
        ];
        out.push(board.fixture(&format!(
            "erc/topology/conditional2/{}",
            assignment_name(&a)
        )));
    }
    for (seed, rails) in [(0x7_0007, 3), (0x7_0008, 2)] {
        let mut rng = Rng::new(seed);
        let mut seen = std::collections::BTreeSet::new();
        while seen.len() < three {
            let a: Vec<usize> = (0..9).map(|_| rng.below(NETS as u64) as usize).collect();
            if !seen.insert(a.clone()) {
                continue;
            }
            let mut board = if rails == 3 {
                three_rails(true)
            } else {
                two_rails()
            };
            board.devs = vec![
                dev(Model::NfetC, a[0], a[1], a[2]),
                dev(Model::PfetC, a[3], a[4], a[5]),
                dev(Model::Nfet, a[6], a[7], a[8]),
            ];
            out.push(board.fixture(&format!(
                "erc/topology/conditional3/rails{rails}/{}",
                assignment_name(&a)
            )));
        }
    }
    // Power states (ERC-F7, ERC-F8, ERC-H1): net 3 is the labelled input IN;
    // VDDH switched off, IN held at 0 V, and IN held at 1.8 V, over the same
    // two switches and a plain nfet, sampled.
    let mut rng = Rng::new(0x7_0009);
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < three {
        let a: Vec<usize> = (0..9).map(|_| rng.below(NETS as u64) as usize).collect();
        if !seen.insert(a.clone()) {
            continue;
        }
        let mut board = three_rails(true);
        board.labels[3] = Some("IN");
        board.states = vec![
            BoardState {
                name: "sleep",
                off: vec![2],
                inputs: Vec::new(),
            },
            BoardState {
                name: "in_low",
                off: Vec::new(),
                inputs: vec![(3, 0.0)],
            },
            BoardState {
                name: "in_high",
                off: Vec::new(),
                inputs: vec![(3, 1800.0)],
            },
        ];
        board.devs = vec![
            dev(Model::NfetC, a[0], a[1], a[2]),
            dev(Model::PfetC, a[3], a[4], a[5]),
            dev(Model::Nfet, a[6], a[7], a[8]),
        ];
        out.push(board.fixture(&format!("erc/topology/states/{}", assignment_name(&a))));
    }
    let bulk: Vec<(Model, Vec<usize>)> = [Model::NfetB, Model::PfetB]
        .into_iter()
        .flat_map(|m| all_assignments(4).into_iter().map(move |a| (m, a)))
        .collect();
    for (model, a) in sample(&bulk, depth, 32, 0x7_0004) {
        let mut board = three_rails(true);
        board.devs = vec![Dev {
            model,
            g: a[0],
            s: a[1],
            d: a[2],
            b: Some(a[3]),
        }];
        out.push(board.fixture(&format!(
            "erc/topology/bulk/{model:?}/{}",
            assignment_name(&a)
        )));
    }
    out
}

/// Named circuits: an inverter pair, a NAND2 (F28), a pmos drawn drain-first
/// (F28), hv isolation, and the well-bias cases one at a time.
fn topology_cases() -> Vec<Fixture> {
    let mut out = Vec::new();
    let (vdd, vss, vddh, sig) = (0, 1, 2, 3);
    // An nfet straddling both domains, isolated, half-isolated, and bare.
    let mut board = three_rails(true);
    board.devs = vec![dev(Model::Nfet, vddh, vss, vdd)];
    out.push(board.fixture("erc/topology/hv/bare"));
    // Its gate oxide sees 3.3 V (VDDH over VSS), its channel 1.8 V, its
    // domains a 1.5 V span: each limit swept a microvolt either side.
    for (kind, value) in [("gox", 3300.0), ("vds", 1800.0), ("hv", 1500.0)] {
        for limit in [value - 0.001, value, value + 0.001] {
            let mut swept = board.clone();
            match kind {
                "gox" => swept.limits.gox = limit,
                "vds" => swept.limits.vds = limit,
                _ => swept.limits.hv = limit,
            }
            out.push(swept.fixture(&format!("erc/topology/limit/{kind}/{}", side(limit, value))));
        }
    }
    // Isolation covering half the marker exempts nothing; one drawn exactly
    // on the marker covers all of it, so the device is "wholly covered" and
    // exempt by the definition (F62: the shared edge once counted as a
    // crossing).
    for (name, iso, exempt) in [
        ("half_isolated", (1100, -100, 1300, 1100), false),
        ("isolation_on_marker", (1000, 0, 1200, 1000), true),
    ] {
        let mut f = board.fixture(&format!("erc/topology/hv/{name}"));
        rect(&mut f.layout, "iso", iso);
        if exempt {
            f.expect
                .retain(|e| !matches!(e, Expect::Rule { id, .. } if id == "hv"));
            f.expect.push(Expect::clean("hv"));
        }
        out.push(f);
    }
    // The keyhole-outline case stays in the root crate: it proves the GDS
    // reader turns a keyhole into a hole, which this in-memory path skips.
    board.iso = vec![0];
    out.push(board.fixture("erc/topology/hv/isolated"));
    // Well bias: a pmos in a well at VDD with its source on VDD and its drain
    // on the signal (reached only from VDD): clean; its source on VDDH: 1.5 V
    // over; its well at VSS: 1.8 V over. An nmos on VSS: clean; its
    // substrate at VDD: 1.8 V over.
    for (name, d) in [
        (
            "pmos_ok",
            Dev {
                model: Model::PfetB,
                g: sig,
                s: vdd,
                d: sig,
                b: Some(vdd),
            },
        ),
        (
            "pmos_source_high",
            Dev {
                model: Model::PfetB,
                g: sig,
                s: vddh,
                d: sig,
                b: Some(vdd),
            },
        ),
        (
            "pmos_well_low",
            Dev {
                model: Model::PfetB,
                g: sig,
                s: vdd,
                d: sig,
                b: Some(vss),
            },
        ),
        (
            "nmos_ok",
            Dev {
                model: Model::NfetB,
                g: sig,
                s: vss,
                d: sig,
                b: Some(vss),
            },
        ),
        (
            "nmos_substrate_high",
            Dev {
                model: Model::NfetB,
                g: sig,
                s: vss,
                d: sig,
                b: Some(vdd),
            },
        ),
    ] {
        let mut board = three_rails(true);
        board.devs = vec![d];
        out.push(board.fixture(&format!("erc/topology/well_bias/{name}")));
    }
    // Two inverters with their own inputs: VDD and VSS are each one
    // transistor's source; OUT nets are driven once each.
    let mut board = three_rails(true);
    board.labels = [Some("VDD"), Some("VSS"), Some("A"), None];
    board.supplies.truncate(2);
    board.domains.truncate(1);
    board.devs = vec![dev(Model::Pfet, 2, vdd, 3), dev(Model::Nfet, 2, vss, 3)];
    out.push(board.fixture("erc/topology/inverter"));
    out.push(nand2_fixture(false));
    out.push(nand2_fixture(true));

    // F28: a pmos whose output diffusion is drawn first is extracted with its
    // source on OUT and its drain on VDD; read in that order, two inverters
    // with different inputs "drive" VDD twice. VDD is a rail, driven by its
    // supply, and each output has one driver.
    let mut swapped = two_rails();
    swapped.devs = vec![dev(Model::Pfet, 2, 3, vdd), dev(Model::Pfet, 3, 2, vdd)];
    out.push(swapped.fixture("erc/topology/f28/drawing_order"));

    // F28 on tie_high_low: an inverter pair in a loop (A drives B, B drives
    // A) whose first inverter is drawn output-first, so A is extracted as both
    // its transistors' source. A is a gate and a drain, never tied to a rail.
    let mut ring = two_rails();
    let (a, b) = (2, 3);
    ring.devs = vec![
        dev(Model::Pfet, b, a, vdd),
        dev(Model::Nfet, b, a, vss),
        dev(Model::Pfet, a, vdd, b),
        dev(Model::Nfet, a, vss, b),
    ];
    out.push(ring.fixture("erc/topology/f28/tie_drawing_order"));

    // Power states, hand-derived. The white paper's tristate (Siemens 81822,
    // figure 3): an `on_gate_min 1V` switch from VDD to Y gated by the input
    // EN, and a load nfet gated by Y between VSS and VDD. With EN held at
    // 0 V the switch never turns on and Y "becomes floating. Subsequent
    // gates connected to pin Y become un-driven": Y is undriven in one state,
    // and the load, its channel on VDD, leaks in one. EN at 1.8 V drives Y.
    let mut tristate = two_rails();
    tristate.labels = [Some("VDD"), Some("VSS"), Some("EN"), Some("Y")];
    tristate.devs = vec![dev(Model::NfetC, 2, vdd, 3), dev(Model::Nfet, 3, vss, vdd)];
    tristate.states = vec![
        BoardState {
            name: "en_low",
            off: Vec::new(),
            inputs: vec![(2, 0.0)],
        },
        BoardState {
            name: "en_high",
            off: Vec::new(),
            inputs: vec![(2, 1800.0)],
        },
    ];
    // VDDH drives the signal through an always-on nfet; a pfet (the
    // isolation model) and an nfet load it. Switching VDDH off floats the
    // signal: undriven once, the nfet leaks once, the pfet is exempt.
    let mut sleep = three_rails(true);
    sleep.devs = vec![
        dev(Model::Nfet, vss, vddh, sig),
        dev(Model::Pfet, sig, vdd, vss),
        dev(Model::Nfet, sig, vss, vdd),
    ];
    sleep.states = vec![BoardState {
        name: "sleep",
        off: vec![vddh],
        inputs: Vec::new(),
    }];
    for (name, board) in [("tristate", tristate), ("sleep", sleep)] {
        let mut f = board.fixture(&format!("erc/topology/states/{name}"));
        f.expect
            .retain(|e| !matches!(e, Expect::Rule { id, .. } if id == "ug" || id == "iso"));
        f.expect.push(Expect::rule("ug", vec![count(1)]));
        f.expect.push(Expect::rule("iso", vec![count(1)]));
        out.push(f);
    }

    // A layer listed twice is checked, and reported, twice.
    out.push(
        Fixture::new(
            "erc/topology/unconnected_listed_twice",
            &["ERC-G6"],
            "grid 1nm\nlayer met1 = gds(1, 0)\nconnect conductors [met1]\nrule up unconnected_pin(met1, met1)\n",
        )
        .layout(Layout::default().rect("met1", 0, 0, 1000, 1000))
        .expect(Expect::rule("up", vec![count(0), count(0)])),
    );
    out
}

/// F28: a NAND2 on six tracks (VDD, VSS, OUT, A, B and the pull-down stack's
/// inner node X): two parallel pmos from VDD to OUT gated by A and B, nmos A
/// from X to OUT, nmos B from VSS to X. OUT has one driver, the gate, and
/// Yosys's "conflicting drivers" asks for one cell output per net; counting
/// gate nets per drain read two. With `output_first`, every transistor is
/// drawn with its output side (OUT, or X for nmos B) first, so extraction
/// calls that end the source; the rails still orient each channel, and VDD,
/// VSS and X are not driven twice.
fn nand2_fixture(output_first: bool) -> Fixture {
    const SIX: usize = 6;
    let ty = |net: usize| TRACK_Y0 + net as i64 * TRACK_PITCH;
    let (vdd, vss, out_, a, b, x) = (0, 1, 2, 3, 4, 5);
    let devs = [
        (Model::Pfet, a, vdd, out_),
        (Model::Pfet, b, vdd, out_),
        (Model::Nfet, a, x, out_),
        (Model::Nfet, b, vss, x),
    ]
    .map(|(model, g, s, d)| {
        if output_first {
            (model, g, d, s)
        } else {
            (model, g, s, d)
        }
    });
    let mut l = Layout::default();
    let riser6 = |l: &mut Layout, x0: i64, base: i64, net: usize| {
        rect(l, "cont", (x0 + 50, base + 50, x0 + 150, base + 150));
        rect(l, "met1", (x0, base, x0 + 200, ty(net) + TRACK_H));
        rect(l, "via1", (x0 + 50, ty(net) + 150, x0 + 150, ty(net) + 250));
    };
    for (i, &(model, g, s, d)) in devs.iter().enumerate() {
        let x0 = i as i64 * PITCH;
        rect(&mut l, "diff", (x0, 0, x0 + 1000, 1000));
        rect(&mut l, "diff", (x0 + 1200, 0, x0 + 2200, 1000));
        rect(&mut l, "poly", (x0 + 1000, 0, x0 + 1200, 1600));
        rect(&mut l, model.marker(), (x0 + 1000, 0, x0 + 1200, 1000));
        riser6(&mut l, x0 + 400, 400, s);
        riser6(&mut l, x0 + 1600, 400, d);
        riser6(&mut l, x0 + 1000, 1400, g);
    }
    for net in 0..SIX {
        rect(
            &mut l,
            "met2",
            (-1000, ty(net), 4 * PITCH + 1000, ty(net) + TRACK_H),
        );
    }
    l = l
        .label("m2txt", -900, ty(vdd) + 200, "VDD")
        .label("m2txt", -900, ty(vss) + 200, "VSS");
    let mut f = Fixture::new(
        if output_first {
            "erc/topology/f28/nand2_output_first"
        } else {
            "erc/topology/f28/nand2"
        },
        &["ERC-G3"],
        &topo_deck(Limits::default()),
    )
    .layout(l)
    .expect(Expect::clean("md1"));
    f.intent = Some(intent(
        &[("a", 1800.0)],
        &[("VDD", "a", "power"), ("VSS", "a", "ground")],
        &[],
    ));
    f
}

/// ESD clamp paths (ERC-C1): a pad on net 0, VDD and VSS supplies, and a
/// labelled signal; a guard ring 1 µm square, 1 µm left of the VDD track.
/// Two clamps with every terminal on any net (4^6), then a clamp beside a
/// transistor of another model, which is no path. Named cases: a diode pair
/// to both rails, a clamp to VDD and a rail clamp, a path broken by a signal
/// net, and no supply at all.
fn esd(depth: Depth) -> Vec<Fixture> {
    let (pad, vdd, vss, sig) = (0, 1, 2, 3);
    let base = |with_intent: bool| Board {
        labels: [Some("PAD"), Some("VDD"), Some("VSS"), Some("SIG")],
        supplies: vec![
            Supply {
                net: vdd,
                power: true,
                domain: 0,
                nominal: 1800.0,
            },
            Supply {
                net: vss,
                power: false,
                domain: 0,
                nominal: 1800.0,
            },
        ],
        domains: vec![("a", 1800.0)],
        pad: Some(pad),
        ring: Some((-3000, track_y(vdd), -2000, track_y(vdd) + 1000)),
        with_intent,
        ..Board::default()
    };
    let mut out = Vec::new();
    for a in sample(&all_assignments(6), depth, 50, 0xe5d_0001) {
        let mut board = base(true);
        board.devs = vec![
            dev(Model::Clamp, a[0], a[1], a[2]),
            dev(Model::Clamp, a[3], a[4], a[5]),
        ];
        out.push(board.fixture(&format!("erc/esd/two_clamps/{}", assignment_name(&a))));
    }
    for a in sample(&all_assignments(6), depth, 25, 0xe5d_0002) {
        let mut board = base(true);
        board.devs = vec![
            dev(Model::Clamp, a[0], a[1], a[2]),
            dev(Model::Nfet, a[3], a[4], a[5]),
        ];
        out.push(board.fixture(&format!("erc/esd/clamp_and_nfet/{}", assignment_name(&a))));
    }
    for (name, devs) in [
        (
            "diode_pair",
            vec![
                dev(Model::Clamp, vdd, pad, vdd),
                dev(Model::Clamp, vss, vss, pad),
            ],
        ),
        (
            "rail_clamp",
            vec![
                dev(Model::Clamp, vdd, pad, vdd),
                dev(Model::Clamp, vss, vdd, vss),
            ],
        ),
        (
            "through_signal",
            vec![
                dev(Model::Clamp, sig, pad, sig),
                dev(Model::Clamp, vss, sig, vss),
                dev(Model::Clamp, vdd, pad, vdd),
            ],
        ),
        ("none", vec![dev(Model::Nfet, vdd, pad, vss)]),
    ] {
        let mut board = base(true);
        board.devs = devs;
        out.push(board.fixture(&format!("erc/esd/{name}")));
    }
    // The guard ring's two limits, each swept by a nanometre: its narrow
    // side against 500 nm, its gap to the VDD track against 2 µm.
    for width in [499, 500, 501] {
        let mut board = base(true);
        board.devs = vec![
            dev(Model::Clamp, vdd, pad, vdd),
            dev(Model::Clamp, vss, vss, pad),
        ];
        board.ring = Some((-2000 - width, track_y(vdd), -2000, track_y(vdd) + 1000));
        out.push(board.fixture(&format!("erc/esd/ring_width/{width}")));
    }
    for gap in [1999, 2000, 2001] {
        let mut board = base(true);
        board.devs = vec![
            dev(Model::Clamp, vdd, pad, vdd),
            dev(Model::Clamp, vss, vss, pad),
        ];
        board.ring = Some((
            -1000 - gap - 1000,
            track_y(vdd),
            -1000 - gap,
            track_y(vdd) + 1000,
        ));
        out.push(board.fixture(&format!("erc/esd/ring_gap/{gap}")));
    }
    // F26: a guard ring drawn as one C-shaped polygon, 3 µm across with a
    // 100 nm band: its width is the band, not its bounding box.
    let mut board = base(true);
    board.devs = vec![
        dev(Model::Clamp, vdd, pad, vdd),
        dev(Model::Clamp, vss, vss, pad),
    ];
    board.ring = None;
    let (x, y) = (-5000, track_y(vdd));
    let layout = board.layout().polygon(
        "ring",
        &[
            (x, y),
            (x + 3000, y),
            (x + 3000, y + 100),
            (x + 100, y + 100),
            (x + 100, y + 2900),
            (x + 3000, y + 2900),
            (x + 3000, y + 3000),
            (x, y + 3000),
        ],
    );
    let mut f = Fixture::new(
        "erc/esd/f26/c_shaped_ring",
        &["ERC-D2"],
        &topo_deck(Limits::default()),
    )
    .layout(layout)
    .expect(Expect::rule("esdl", vec![length(100)]));
    f.intent = Some(board.intent());
    out.push(f);
    // The band is the material: a 500 nm ring drawn as two abutting 250 nm
    // bars is 500 nm wide, legal at the 500 nm limit.
    let (x, y) = (-2500, track_y(vdd));
    let layout = board.layout().rect("ring", x, y, x + 250, y + 1000).rect(
        "ring",
        x + 250,
        y,
        x + 500,
        y + 1000,
    );
    let mut f = Fixture::new(
        "erc/esd/f26/abutting_bars",
        &["ERC-D2"],
        &topo_deck(Limits::default()),
    )
    .layout(layout)
    .expect(Expect::clean("esdl"));
    f.intent = Some(board.intent());
    out.push(f);
    // No supply declared (only a limit on the signal): every pad reaches no
    // rail and the ring has no tap.
    let mut board = base(true);
    board.devs = vec![dev(Model::Clamp, sig, pad, sig)];
    board.supplies.clear();
    let mut f = Fixture::new(
        "erc/esd/no_supply",
        &["ERC-C1", "ERC-D2"],
        &topo_deck(Limits::default()),
    )
    .layout(board.layout())
    .expect(Expect::rule("esd", vec![count(0)]))
    .expect(Expect::rule("esdl", vec![count(0), count(0)]));
    f.intent = Some(intent(
        &[],
        &[],
        &[r#"{"net":"SIG","max_drop_mv":1}"#.to_owned()],
    ));
    out.push(f);
    out
}

// ---------------------------------------------------------------- ESD paths

/// A pad and its two supplies as three strips on three conductors, joined only
/// by diode clamps whose markers span two of them: the pad on `pad` (0.0625
/// Ω/sq), the ground rail VSS on `met1` (0.125 Ω/sq), the power rail VDD on
/// `met2` (0.0625 Ω/sq). Each recogniser fixes a diode's anode and cathode by
/// layer: `mkd` a down diode (anode on the ground rail, cathode on the pad),
/// `mku` an up diode (pad to power rail), `mkr` a rail diode (ground to
/// power), and `mkx`, `mky` the up and rail diodes reversed. `padv` joins a
/// supply's own pad pin to its rail.
pub(crate) const ESD_PROCESS: &str = "grid 1nm
layer pad = gds(1, 0)
layer met1 = gds(2, 0)
layer met2 = gds(3, 0)
layer padv = gds(4, 0)
layer padtxt = gds(1, 1)
layer m1txt = gds(2, 1)
layer m2txt = gds(3, 1)
layer mkd = gds(10, 0)
layer mku = gds(11, 0)
layer mkr = gds(12, 0)
layer mkx = gds(13, 0)
layer mky = gds(14, 0)
connect conductors [pad, met1, met2]
connect touch_within_layer
connect via padv [met1, pad]
connect label padtxt names pad
connect label m1txt names met1
connect label m2txt names met2
device diode mkd model \"down\" terminals [met1, pad]
device diode mku model \"up\" terminals [pad, met2]
device diode mkr model \"rail\" terminals [met1, met2]
device diode mkx model \"up_rev\" terminals [met2, pad]
device diode mky model \"rail_rev\" terminals [met2, met1]
pex pad thickness 100nm height 500nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met1 thickness 100nm height 100nm sheet 0.125ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met2 thickness 100nm height 300nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex padv thickness 100nm height 400nm sheet 0.25ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
";

/// Every diode model of [`ESD_PROCESS`], as a deck's `clamps` list.
pub(crate) const ESD_CLAMPS: &str = "[\"down\", \"up\", \"rail\", \"up_rev\", \"rail_rev\"]";

/// Every strip's length: x from 0 to 20 µm, tapped at its centre, 10 µm.
pub(crate) const STRIP: i64 = 20_000;

/// Where each strip's lower edge sits: the pad at 0, VSS 3 µm below, VDD 3 µm
/// above.
pub(crate) const STRIP_Y: [i64; 3] = [0, -3000, 3000];

/// One diode clamp of [`ESD_PROCESS`] by its recogniser, which fixes the two
/// strips it joins (anode first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Diode {
    /// `mkd`: VSS to the pad.
    Down,
    /// `mku`: the pad to VDD.
    Up,
    /// `mkr`: VSS to VDD.
    Rail,
    /// `mkx`: VDD to the pad, forward-biased in operation.
    UpReversed,
    /// `mky`: VDD to VSS, drawn the other way round; between two supplies, it
    /// is taken as wired.
    RailReversed,
}

impl Diode {
    /// The marker layer, and the strips (0 pad, 1 VSS, 2 VDD) the marker spans.
    pub(crate) fn marker(self) -> (&'static str, usize, usize) {
        match self {
            Diode::Down => ("mkd", 1, 0),
            Diode::Up => ("mku", 0, 2),
            Diode::Rail => ("mkr", 1, 2),
            Diode::UpReversed => ("mkx", 0, 2),
            Diode::RailReversed => ("mky", 1, 2),
        }
    }
}

/// The three strips, widths `w` (pad, VSS, VDD), labelled PAD, VSS and VDD,
/// with a 200 nm diode marker centred on `x` for each `(diode, x)`, reaching
/// 100 nm into both strips it spans.
pub(crate) fn esd_layout(w: [i64; 3], diodes: &[(Diode, i64)]) -> Layout {
    let mut l = Layout::default();
    for (k, (layer, text, name)) in [
        ("pad", "padtxt", "PAD"),
        ("met1", "m1txt", "VSS"),
        ("met2", "m2txt", "VDD"),
    ]
    .into_iter()
    .enumerate()
    {
        rect(&mut l, layer, (0, STRIP_Y[k], STRIP, STRIP_Y[k] + w[k]));
        l = l.label(text, 100, STRIP_Y[k] + w[k] / 2, name);
    }
    for &(diode, x) in diodes {
        let (layer, a, b) = diode.marker();
        let (lo, hi) = if STRIP_Y[a] < STRIP_Y[b] {
            (a, b)
        } else {
            (b, a)
        };
        rect(
            &mut l,
            layer,
            (
                x - 100,
                STRIP_Y[lo] + w[lo] - 100,
                x + 100,
                STRIP_Y[hi] + 100,
            ),
        );
    }
    l
}

/// VDD a 1.8 V power supply and VSS its ground.
pub(crate) fn esd_intent() -> String {
    intent(
        &[("a", 1800.0)],
        &[("VDD", "a", "power"), ("VSS", "a", "ground")],
        &[],
    )
}

/// `esd_topological` (ERC-C1) over diode clamps: a diode between the pad and
/// a supply counts only wired reverse-biased in operation, the pad sitting
/// between ground and power. An up diode drawn reversed (anode on VDD,
/// cathode on the pad) conducts in operation, so it is no clamp: the pad
/// reaches only what the rest reaches. A diode between two supplies is taken
/// as wired either way round (a deck may model a rail clamp as one), so a
/// reversed rail diode still completes the path.
fn esd_wiring() -> Vec<Fixture> {
    let deck = format!("{ESD_PROCESS}rule esd esd_topological(pad; clamps: {ESD_CLAMPS})\n");
    let w = [1000; 3];
    let mut out = Vec::new();
    for (name, diodes, rails) in [
        ("down_up", vec![(Diode::Down, 4000), (Diode::Up, 8000)], 2),
        (
            "down_up_reversed",
            vec![(Diode::Down, 4000), (Diode::UpReversed, 8000)],
            1,
        ),
        (
            "down_up_reversed_rail",
            vec![
                (Diode::Down, 4000),
                (Diode::UpReversed, 8000),
                (Diode::Rail, 12_000),
            ],
            2,
        ),
        (
            "down_up_reversed_rail_reversed",
            vec![
                (Diode::Down, 4000),
                (Diode::UpReversed, 8000),
                (Diode::RailReversed, 12_000),
            ],
            2,
        ),
        ("up_reversed", vec![(Diode::UpReversed, 8000)], 0),
    ] {
        let mut f = Fixture::new(&format!("erc/esd/wiring/{name}"), &["ERC-C1"], &deck)
            .layout(esd_layout(w, &diodes))
            .expect(Expect::rule(
                "esd",
                if rails < 2 {
                    vec![count(rails)]
                } else {
                    Vec::new()
                },
            ));
        f.intent = Some(esd_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// The limits an `esd_path` row states, each `none` unless a fixture sets it.
const ESD_LIMITS: [&str; 7] = [
    "max_resistance",
    "clamp_it2",
    "max_density",
    "max_current_per_cut",
    "max_voltage",
    "min_width",
    "clamp_voltage",
];

/// A deck of [`ESD_PROCESS`] with one `esd_path` row `ep`, 1.33 A forced, each
/// clamp 1 Ω, the limits in `limits` as `(name, value)` and every other one
/// `none`.
fn esd_path_deck(limits: &[(&str, String)]) -> String {
    let stated: Vec<String> = ESD_LIMITS
        .iter()
        .map(|&name| {
            let value = limits
                .iter()
                .find(|limit| limit.0 == name)
                .map_or("none", |limit| limit.1.as_str());
            format!("{name}: {value}")
        })
        .collect();
    format!(
        "{ESD_PROCESS}rule ep esd_path(pad; clamps: {ESD_CLAMPS}, current: 1330mA, \
         clamp_resistance: 1ohm, {})\n",
        stated.join(", ")
    )
}

/// `esd_path` (ERC-C6) on closed forms. Each strip is tapped at its centre
/// (10 µm, the entry on the pad and the feed point of a supply with no pin)
/// and under each diode marker's centre; a strip of width `w` costs
/// `sheet * Δx / w` between taps, a diode 1 Ω.
///
/// - One down diode at 2 µm, every strip 1 µm wide: the pad's 8 squares
///   (0.5 Ω), the diode (1 Ω) and VSS's 8 squares (1 Ω) in series, 2.5 Ω
///   from the pad to VSS. VDD is not reached, so it is no pair.
/// - With an up diode drawn reversed beside it the answer is the same: a
///   forward-biased diode carries nothing.
/// - VSS given its own pin, a `pad` square centred at 18 µm joined to the
///   rail by one `padv` cut (0.25 Ω) under its centre: VSS's run is now 16
///   squares (2 Ω), 3.75 Ω in all. The pin is a pin of VSS too, stressed
///   against VSS itself: 0 Ω.
/// - A down diode at 2 µm, an up diode at 18 µm and a rail diode at 10 µm:
///   to VSS, the 2.5 Ω path in parallel with the pad's other 0.5 Ω, the up
///   diode, VDD's 8 squares (0.5 Ω) and the rail diode, 3 Ω: 15/11 Ω. To
///   VDD, the 2 Ω path through the up diode in parallel with 3.5 Ω through
///   the down and rail diodes: 14/11 Ω. The network has a loop, so its solve
///   is iterative: the sweep (a part in a thousand) bounds the value, and
///   the dense nodal oracle of `erc_reference` measures it.
///
/// The tree cases are exact in binary and swept below, at and above; a
/// finding sits at the pad's first vertex, and is placed under every symmetry.
fn esd_path() -> Vec<Fixture> {
    let mut out = Vec::new();
    let w = [1000; 3];
    let pinned = {
        let mut l = esd_layout(w, &[(Diode::Down, 2000)]);
        rect(&mut l, "pad", (17_500, -3000, 18_500, -2000));
        rect(&mut l, "padv", (17_900, -2600, 18_100, -2400));
        l
    };
    let cases = [
        ("series", esd_layout(w, &[(Diode::Down, 2000)]), vec![2.5]),
        (
            "reversed_up",
            esd_layout(w, &[(Diode::Down, 2000), (Diode::UpReversed, 6000)]),
            vec![2.5],
        ),
        ("pinned", pinned, vec![3.75]),
        (
            "parallel",
            esd_layout(
                w,
                &[
                    (Diode::Down, 2000),
                    (Diode::Up, 18_000),
                    (Diode::Rail, 10_000),
                ],
            ),
            vec![15.0 / 11.0, 14.0 / 11.0],
        ),
    ];
    let mut placed = Vec::new();
    for (name, layout, values) in cases {
        let exact = values.len() == 1;
        for (k, &value) in values.iter().enumerate() {
            let limits: Vec<f64> = if exact {
                sweep(value).to_vec()
            } else {
                vec![value * 0.999, value * 1.001]
            };
            for limit in limits {
                let flagged = values.iter().filter(|&&v| v > limit);
                let findings: Vec<Finding> = if exact {
                    flagged.map(|&v| ohms(v).at(0, 0)).collect()
                } else {
                    flagged.map(|_| Finding::any().at(0, 0)).collect()
                };
                let mut f = Fixture::new(
                    &format!("erc/esd_path/{name}/{k}/{}", side(limit, value)),
                    &["ERC-C6"],
                    &esd_path_deck(&[("max_resistance", format!("{limit}ohm"))]),
                )
                .layout(layout.clone())
                .expect(Expect::rule("ep", findings.clone()));
                f.intent = Some(esd_intent());
                if exact && !findings.is_empty() {
                    let mut g = f.clone();
                    g.name = format!("{}/placed", f.name);
                    g.expect = vec![Expect::rule("ep", vec![ohms(value)])];
                    placed.push(g);
                }
                out.push(f);
            }
        }
    }
    out.extend(every_placement(&placed));
    // Without intent nothing names the rails.
    out.push(
        Fixture::new(
            "erc/esd_path/no_intent",
            &["ERC-C6"],
            &esd_path_deck(&[("max_resistance", "1ohm".to_owned())]),
        )
        .layout(esd_layout(w, &[(Diode::Down, 2000)]))
        .expect(Expect::outcome("ep", Want::Skipped)),
    );
    out
}

/// `esd_path`'s clamp sizing (ERC-C2): a clamp carries its share of the
/// 1.33 A and may carry `clamp_it2` times its size, a diode's perimeter. Each
/// diode marker here is 200 nm by 2.2 µm, 4.8 µm round.
///
/// - One down diode carries all of it: rated below 1.33 A / 4.8 µm it is
///   flagged, measuring 1.33 A at its marker's corner.
/// - Two down diodes placed symmetrically about the pad's centre and VSS's
///   feed point carry half each: flagged only below 0.665 A / 4.8 µm. Their
///   network is a loop, so only the sweep (a part in a thousand) bounds the
///   share.
fn esd_clamp_size() -> Vec<Fixture> {
    let mut out = Vec::new();
    let w = [1000; 3];
    let perimeter_m = 4.8e-6;
    let mut placed = Vec::new();
    for (name, diodes, share) in [
        ("whole", vec![(Diode::Down, 2000)], 1.33),
        (
            "shared",
            vec![(Diode::Down, 6000), (Diode::Down, 14_000)],
            0.665,
        ),
    ] {
        let rated = share / perimeter_m;
        for it2 in [rated * 0.999, rated * 1.001] {
            let flagged = it2 < rated;
            let findings: Vec<Finding> = if !flagged {
                Vec::new()
            } else if diodes.len() == 1 {
                vec![microamps(share * 1e6).at(1900, -2100)]
            } else {
                diodes.iter().map(|_| Finding::any()).collect()
            };
            let mut f = Fixture::new(
                &format!("erc/esd_path/clamp_it2/{name}/{}", side(it2, rated)),
                &["ERC-C2"],
                &esd_path_deck(&[("clamp_it2", format!("{it2}A/m"))]),
            )
            .layout(esd_layout(w, &diodes))
            .expect(Expect::rule("ep", findings.clone()));
            f.intent = Some(esd_intent());
            if flagged && diodes.len() == 1 {
                let mut g = f.clone();
                g.name = format!("{}/placed", f.name);
                g.expect = vec![Expect::rule("ep", vec![microamps(share * 1e6)])];
                placed.push(g);
            }
            out.push(f);
        }
    }
    out.extend(every_placement(&placed));
    out
}

/// `esd_path`'s pulse rating of the path's wires and cuts (ERC-C7): the
/// whole 1.33 A runs through the series path of one down diode, so each
/// segment carries it. The pad strip is 1 µm wide (1.33 A/µm), VSS 2 µm
/// (0.665 A/µm): a `max_density` swept around each flags the pad's segment
/// below 1.33 A/µm and VSS's too below 0.665 A/µm, each at its segment's
/// first tap (the diode's, at 2 µm, on the strip's centre line). VSS given a
/// pin through one `padv` cut: the cut carries all of it, flagged below
/// 1.33 A per cut.
fn esd_interconnect() -> Vec<Fixture> {
    let mut out = Vec::new();
    let layout = esd_layout([1000, 2000, 1000], &[(Diode::Down, 2000)]);
    let pad = microamps(1.33e6).at(2000, 500);
    let vss = microamps(1.33e6).at(2000, -2000);
    let mut placed = Vec::new();
    for (k, (per_um, flagged)) in [(1.33e6, vec![pad]), (0.665e6, vec![pad, vss])]
        .into_iter()
        .enumerate()
    {
        for density in [per_um * 0.999, per_um * 1.001] {
            let findings: Vec<Finding> = if density < per_um {
                flagged.clone()
            } else {
                flagged[..k].to_vec()
            };
            let mut f = Fixture::new(
                &format!("erc/esd_path/max_density/{k}/{}", side(density, per_um)),
                &["ERC-C7"],
                &esd_path_deck(&[("max_density", format!("{density}A/m"))]),
            )
            .layout(layout.clone())
            .expect(Expect::rule("ep", findings.clone()));
            f.intent = Some(esd_intent());
            let mut g = f.clone();
            g.name = format!("{}/placed", f.name);
            g.expect = vec![Expect::rule(
                "ep",
                findings.iter().map(|_| microamps(1.33e6)).collect(),
            )];
            placed.push(g);
            out.push(f);
        }
    }
    out.extend(every_placement(&placed));
    let pinned = {
        let mut l = esd_layout([1000; 3], &[(Diode::Down, 2000)]);
        rect(&mut l, "pad", (17_500, -3000, 18_500, -2000));
        rect(&mut l, "padv", (17_900, -2600, 18_100, -2400));
        l
    };
    for per_cut in [1.33e6 * 0.999, 1.33e6 * 1.001] {
        let mut f = Fixture::new(
            &format!("erc/esd_path/per_cut/{}", side(per_cut, 1.33e6)),
            &["ERC-C7"],
            &esd_path_deck(&[("max_current_per_cut", format!("{per_cut}uA"))]),
        )
        .layout(pinned.clone())
        .expect(Expect::rule(
            "ep",
            if per_cut < 1.33e6 {
                vec![microamps(1.33e6)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(esd_intent());
        out.push(f);
    }
    out
}

/// The ESD layout rules on recognised devices (ERC-C14), hand-derived on
/// [`esd_layout`]'s strips, limits deck-supplied:
///
/// - `esd_clamp_resistance`: a unit current from the pad, tapped at its
///   strip's centre (10 µm), to each `down` clamp's attach point on the pad
///   strip: `0.0625 Ω/sq × |x − 10 µm| / 1 µm`, 0.5 Ω for a clamp at 2 µm
///   and 0.25 Ω at 14 µm, swept either side; a clamp of an unlisted model
///   is not measured.
/// - `esd_path`'s `min_width`: 1.33 A from the pad through the clamp at
///   2 µm to VSS's feed point at its centre crosses the pad strip and the
///   VSS strip between 2 and 10 µm; with both 1 µm wide a limit of 1001 nm
///   flags both, 1000 nm (strict) and 999 nm neither, and with the pad strip
///   2 µm wide a 1500 nm limit flags only VSS. The strips' dead ends past
///   the taps carry no current and are never flagged.
fn esd_layout_rules() -> Vec<Fixture> {
    let mut out = Vec::new();
    let clamp_deck = |limit: f64| {
        format!(
            "{ESD_PROCESS}rule cr esd_clamp_resistance(pad; clamps: [\"down\"], max_resistance: {limit}ohm)\n"
        )
    };
    for (name, diodes, values) in [
        ("one", vec![(Diode::Down, 2000)], vec![0.5]),
        (
            "two",
            vec![(Diode::Down, 2000), (Diode::Down, 14_000)],
            vec![0.5, 0.25],
        ),
        (
            "unlisted",
            vec![(Diode::Down, 14_000), (Diode::Up, 2000)],
            vec![0.25],
        ),
    ] {
        let layout = esd_layout([1000; 3], &diodes);
        let mut limits = Vec::new();
        for &v in &values {
            limits.extend(sweep(v));
        }
        for limit in limits {
            let f = Fixture::new(
                &format!("erc/esd_clamp_resistance/{name}/{limit}"),
                &["ERC-C14"],
                &clamp_deck(limit),
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "cr",
                values
                    .iter()
                    .filter(|&&v| v > limit)
                    .map(|&v| ohms(v))
                    .collect(),
            ));
            out.extend(every_placement(&[f]));
        }
    }
    for (name, widths, min_width, flagged) in [
        ("below", [1000, 1000, 1000], 999, 0),
        ("at", [1000, 1000, 1000], 1000, 0),
        ("above", [1000, 1000, 1000], 1001, 2),
        ("wide_pad", [2000, 1000, 1000], 1500, 1),
    ] {
        let mut f = Fixture::new(
            &format!("erc/esd_path/min_width/{name}"),
            &["ERC-C14"],
            &esd_path_deck(&[("min_width", format!("{min_width}nm"))]),
        )
        .layout(esd_layout(widths, &[(Diode::Down, 2000)]))
        .expect(Expect::rule("ep", vec![length(1000); flagged]));
        f.intent = Some(esd_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// `esd_pin_pair` (ERC-C6), hand-derived on [`ESD_PROCESS`]: pad strips
/// PADA at y 0 and PADB at 6 µm, VSS (met1) at -3 µm and VDD (met2) at
/// 3 µm, every strip 20 µm long and 1 µm wide. A `down` diode joins PADA
/// to VSS at x 2 µm, a `rail` VSS to VDD at 10 µm and an `up` PADB to VDD
/// at 18 µm, each 1 Ω. 1.33 A from PADA (tapped at its centre, 10 µm) to
/// PADB (held at its centre) crosses 8 µm of PADA (0.0625 Ω/sq: 0.5 Ω),
/// the down diode, 8 µm of VSS (0.125 Ω/sq: 1 Ω), the rail clamp, 8 µm of
/// VDD (0.5 Ω), the up diode and 8 µm of PADB (0.5 Ω): 5.5 Ω, swept a part
/// in a thousand either side. Without the rail clamp the two pins share no
/// supply and the pair is not examined.
fn esd_pin_pair() -> Vec<Fixture> {
    let board = |rail: bool| {
        let mut l = Layout::default();
        for (layer, text, name, y) in [
            ("pad", "padtxt", "PADA", 0),
            ("met1", "m1txt", "VSS", -3000),
            ("met2", "m2txt", "VDD", 3000),
            ("pad", "padtxt", "PADB", 6000),
        ] {
            rect(&mut l, layer, (0, y, STRIP, y + 1000));
            l = l.label(text, 100, y + 500, name);
        }
        rect(&mut l, "mkd", (1900, -2100, 2100, 100));
        if rail {
            rect(&mut l, "mkr", (9900, -2100, 10_100, 3100));
        }
        rect(&mut l, "mku", (17_900, 3900, 18_100, 6100));
        l
    };
    let deck = |limit: f64| {
        format!(
            "{ESD_PROCESS}rule pp esd_pin_pair(pad; clamps: {ESD_CLAMPS}, current: 1330mA, \
             clamp_resistance: 1ohm, max_resistance: {limit}ohm)\n"
        )
    };
    let value = 5.5;
    let mut out = Vec::new();
    for limit in [value * 0.999, value * 1.001] {
        let mut f = Fixture::new(
            &format!("erc/esd_pin_pair/{}", side(limit, value)),
            &["ERC-C6"],
            &deck(limit),
        )
        .layout(board(true))
        .expect(Expect::rule(
            "pp",
            if value > limit {
                vec![ohms(value)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(esd_intent());
        out.extend(every_placement(&[f]));
    }
    let mut f = Fixture::new("erc/esd_pin_pair/no_rail", &["ERC-C6"], &deck(1.0))
        .layout(board(false))
        .expect(Expect::Rule {
            id: "pp".to_owned(),
            outcome: Want::Ran,
            findings: Vec::new(),
            examined: Some(0),
        });
    f.intent = Some(esd_intent());
    out.push(f);
    out
}

/// `esd_path`'s voltage window (ERC-C8): the pin's rise under the forced
/// current, its path resistance times the current. One down diode in series,
/// 2.5 Ω, so 1.33 A raises the pad to 3325 mV exactly (binary-exact on the
/// tree), swept below, at and above, at the pad's first vertex and placed.
/// With the up diode, rail diode and a second supply the pin rises to
/// 1.33 A times 15/11 Ω toward VSS and 14/11 Ω toward VDD: a limit between
/// the two flags only the VSS pair.
fn esd_window() -> Vec<Fixture> {
    let mut out = Vec::new();
    let w = [1000; 3];
    let rise = 3325.0;
    let mut placed = Vec::new();
    for limit in sweep(rise) {
        let mut f = Fixture::new(
            &format!("erc/esd_path/max_voltage/series/{}", side(limit, rise)),
            &["ERC-C8"],
            &esd_path_deck(&[("max_voltage", format!("{limit}mV"))]),
        )
        .layout(esd_layout(w, &[(Diode::Down, 2000)]))
        .expect(Expect::rule(
            "ep",
            if limit < rise {
                vec![millivolts(rise).at(0, 0)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(esd_intent());
        if limit < rise {
            let mut g = f.clone();
            g.name = format!("{}/placed", f.name);
            g.expect = vec![Expect::rule("ep", vec![millivolts(rise)])];
            placed.push(g);
        }
        out.push(f);
    }
    out.extend(every_placement(&placed));
    let (to_vss, to_vdd) = (1330.0 * 15.0 / 11.0, 1330.0 * 14.0 / 11.0);
    let mut f = Fixture::new(
        "erc/esd_path/max_voltage/parallel",
        &["ERC-C8"],
        &esd_path_deck(&[(
            "max_voltage",
            format!("{}mV", f64::midpoint(to_vss, to_vdd)),
        )]),
    )
    .layout(esd_layout(
        w,
        &[
            (Diode::Down, 2000),
            (Diode::Up, 18_000),
            (Diode::Rail, 10_000),
        ],
    ))
    .expect(Expect::rule("ep", vec![Finding::any().at(0, 0)]));
    f.intent = Some(esd_intent());
    out.push(f);
    out.extend(esd_turn_on());
    out
}

/// `esd_path`'s `clamp_voltage` (ERC-C8): each conducting clamp holds
/// 700 mV besides its 1 Ω, White Paper 2's `Vpad = Vdiode_on + Rdiode_on
/// I + Rbus I + Vclamp_on + Rclamp_on I`, hand-derived on [`esd_layout`]:
///
/// - the down diode alone: 1.33 A over 2.5 Ω plus one turn-on, 4025 mV;
/// - an up diode at 18 µm and a rail clamp at 10 µm, no down diode: to VDD
///   the pad strip 0.5 Ω, the up diode, VDD back to its centre 0.5 Ω and
///   one turn-on, 3360 mV; to VSS also the rail clamp and a second
///   turn-on, 3 Ω and 1400 mV, 5390 mV.
///
/// Each limit is a part in a thousand either side of a value.
fn esd_turn_on() -> Vec<Fixture> {
    let w = [1000; 3];
    let mut out = Vec::new();
    let deck = |limit: f64| {
        esd_path_deck(&[
            ("max_voltage", format!("{limit}mV")),
            ("clamp_voltage", "700mV".to_owned()),
        ])
    };
    let series = 1330.0 * 2.5 + 700.0;
    for limit in [series * 0.999, series * 1.001] {
        let mut f = Fixture::new(
            &format!("erc/esd_path/clamp_voltage/series/{}", side(limit, series)),
            &["ERC-C8"],
            &deck(limit),
        )
        .layout(esd_layout(w, &[(Diode::Down, 2000)]))
        .expect(Expect::rule(
            "ep",
            if limit < series {
                vec![millivolts(series)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(esd_intent());
        out.extend(every_placement(&[f]));
    }
    let (to_vdd, to_vss) = (1330.0 * 2.0 + 700.0, 1330.0 * 3.0 + 1400.0);
    for limit in [to_vdd * 0.999, to_vdd * 1.001, to_vss * 1.001] {
        let findings = [to_vdd, to_vss]
            .into_iter()
            .filter(|&v| v > limit)
            .map(millivolts)
            .collect();
        let mut f = Fixture::new(
            &format!("erc/esd_path/clamp_voltage/rail/{limit}"),
            &["ERC-C8"],
            &deck(limit),
        )
        .layout(esd_layout(w, &[(Diode::Up, 18_000), (Diode::Rail, 10_000)]))
        .expect(Expect::rule("ep", findings));
        f.intent = Some(esd_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// [`TOPO_PROCESS`] with a diode recogniser `mkdi` (model `dio`): its anode
/// the first diffusion under the marker, its cathode the second; and a
/// resistor recogniser `mkres` (model `rs`) drawn the same way.
pub(crate) fn diode_process() -> String {
    format!(
        "{TOPO_PROCESS}layer mkdi = gds(27, 0)\n\
         layer mkres = gds(28, 0)\n\
         device diode mkdi model \"dio\" terminals [diff, diff]\n\
         device resistor mkres model \"rs\" terminals [diff, diff]\n"
    )
}

/// Transistors and diodes on any number of nets, drawn as [`Board`] draws its
/// transistors: one met2 track per net, labelled `labels[net]`, from x -1 µm
/// to past the last column (20 µm at least). A diode
/// `(anode, cathode)` is two diffusion boxes, the anode's drawn first, under
/// one `mkdi` marker, each wired to its net's track by a riser.
fn circuit(labels: &[&str], devs: &[Dev], diodes: &[(usize, usize)]) -> Layout {
    let pins: Vec<(&str, usize, usize)> = diodes.iter().map(|&(a, c)| ("mkdi", a, c)).collect();
    circuit_pins(labels, devs, &pins)
}

/// [`circuit`] with two-pin devices of any recogniser: `(marker, first pin's
/// net, second pin's net)`, the first pin's diffusion drawn first.
pub(crate) fn circuit_pins(labels: &[&str], devs: &[Dev], pins: &[(&str, usize, usize)]) -> Layout {
    let mut l = Layout::default();
    for (i, dv) in devs.iter().enumerate() {
        let x0 = i as i64 * PITCH;
        rect(&mut l, "diff", (x0, 0, x0 + 1000, 1000));
        rect(&mut l, "diff", (x0 + 1200, 0, x0 + 2200, 1000));
        rect(&mut l, "poly", (x0 + 1000, 0, x0 + 1200, 1600));
        rect(&mut l, dv.model.marker(), (x0 + 1000, 0, x0 + 1200, 1000));
        riser(&mut l, x0 + 400, 400, dv.s);
        riser(&mut l, x0 + 1600, 400, dv.d);
        riser(&mut l, x0 + 1000, 1400, dv.g);
    }
    for (j, &(marker, anode, cathode)) in pins.iter().enumerate() {
        let x0 = (devs.len() + j) as i64 * PITCH;
        rect(&mut l, "diff", (x0, 0, x0 + 1000, 1000));
        rect(&mut l, "diff", (x0 + 1200, 0, x0 + 2200, 1000));
        rect(&mut l, marker, (x0 + 900, 400, x0 + 1300, 600));
        riser(&mut l, x0 + 400, 400, anode);
        riser(&mut l, x0 + 1600, 400, cathode);
    }
    // At least 20 µm, so a riser beside the columns still lands on its track.
    let right = ((devs.len() + pins.len()) as i64 * PITCH + 1000).max(20_000);
    for (net, name) in labels.iter().enumerate() {
        let ty = track_y(net);
        rect(&mut l, "met2", (-1000, ty, right, ty + TRACK_H));
        // An empty name leaves the net unlabelled.
        if !name.is_empty() {
            l = l.label("m2txt", -900, ty + 200, name);
        }
    }
    l
}

/// `supply_path` (ERC-G9) stopping at a top-cell port, hand-derived from
/// the PERC patent's "a path continues until it reaches an unqualified
/// device or a port in the top cell" (US20100306720A1 \[0262\]). Nets VDD,
/// VSS, A, Y, an unlabelled net Z and G: an inverter from A to Y, and an
/// nfet passing Y to Z under gate G.
///
/// - Labels are names (`labels_are_ports: false`): Y and Z are one path,
///   which reaches both rails; A and G are gates alone. `both: false`
///   flags A and G (0 roles against 1); `both: true` the same, 0 against 2.
/// - Labels are ports: the path stops at Y, so Z is a path of its own that
///   reaches no rail. `both: false` flags A, G and Z; `both: true` the
///   same three. Y keeps both rails through its own pull-up and pull-down.
///
/// Breaks if a port stops nothing (Z is clean under `labels_are_ports:
/// true`) or if a port stops its own rails (Y is flagged).
fn path_stops_at_port() -> Vec<Fixture> {
    let labels = ["VDD", "VSS", "A", "Y", "", "G"];
    let (vdd, vss, a, y, z, g) = (0, 1, 2, 3, 4, 5);
    let devs = [
        dev(Model::Pfet, a, vdd, y),
        dev(Model::Nfet, a, vss, y),
        dev(Model::Nfet, g, y, z),
    ];
    let deck = format!(
        "{TOPO_PROCESS}rule names1 supply_path(; both: false, labels_are_ports: false)\n\
         rule names2 supply_path(; both: true, labels_are_ports: false)\n\
         rule ports1 supply_path(; both: false, labels_are_ports: true)\n\
         rule ports2 supply_path(; both: true, labels_are_ports: true)\n"
    );
    let mut f = Fixture::new("erc/supply_path/stops_at_port", &["ERC-G9"], &deck)
        .layout(circuit(&labels, &devs, &[]))
        .expect(Expect::rule("names1", vec![count(0), count(0)]))
        .expect(Expect::rule("names2", vec![count(0), count(0)]))
        .expect(Expect::rule("ports1", vec![count(0); 3]))
        .expect(Expect::rule("ports2", vec![count(0); 3]));
    f.intent = Some(intent(
        &[("d", 1800.0)],
        &[("VDD", "d", "power"), ("VSS", "d", "ground")],
        &[],
    ));
    every_placement(&[f])
}

/// `supply_path` (ERC-G9) and `gate_path` (ERC-H3) through a resistor and
/// not through a diode, hand-derived. Nets VDD, VSS, A, B, G, C: an nfet
/// pulls A to VSS (gate G), a resistor joins A to B, a diode joins B to C,
/// and a second nfet has its gate on B and both channel ends on VSS. So A
/// and B reach ground and never power (B through the resistor and the
/// pull-down, two devices), C reaches nothing (a diode passes no path), and
/// G is a gate alone.
///
/// - `supply_path(; both: false, labels_are_ports: false)`: G and C, 0 roles against 1.
/// - `supply_path(; both: true, labels_are_ports: false)`: A and B 1 role, G and C 0, against 2.
/// - `gate_path(; ground: true, max_devices: 1)`: B's path passes 2
///   devices; G has none (0 against 1).
/// - with `max_devices: 2`: only G.
fn path_through_resistor() -> Vec<Fixture> {
    let labels = ["VDD", "VSS", "A", "B", "G", "C"];
    let (vss, a, b, g, c) = (1, 2, 3, 4, 5);
    let devs = [dev(Model::Nfet, g, vss, a), dev(Model::Nfet, b, vss, vss)];
    let layout = circuit_pins(&labels, &devs, &[("mkres", a, b), ("mkdi", b, c)]);
    let deck = format!(
        "{}rule sp1 supply_path(; both: false, labels_are_ports: false)\n\
         rule sp2 supply_path(; both: true, labels_are_ports: false)\n\
         rule gp1 gate_path(; ground: true, max_devices: 1)\n\
         rule gp2 gate_path(; ground: true, max_devices: 2)\n",
        diode_process()
    );
    let mut f = Fixture::new(
        "erc/supply_path/through_resistor",
        &["ERC-G9", "ERC-H3"],
        &deck,
    )
    .layout(layout)
    .expect(Expect::rule("sp1", vec![count(0), count(0)]))
    .expect(Expect::rule(
        "sp2",
        vec![count(1), count(1), count(0), count(0)],
    ))
    .expect(Expect::rule("gp1", vec![count(2), count(0)]))
    .expect(Expect::rule("gp2", vec![count(0)]));
    f.intent = Some(intent(
        &[("d", 1800.0)],
        &[("VDD", "d", "power"), ("VSS", "d", "ground")],
        &[],
    ));
    every_placement(&[f])
}

/// `combinational_loop` (ERC-G8) on CMOS inverters between VDD and VSS,
/// hand-derived: each inverter's output net is a channel-connected
/// component of its own, driven by the component holding its input.
///
/// - a chain A -> B -> C: no cycle, clean;
/// - a ring of three, A -> B -> C -> A: one loop of 3 components;
/// - two cross-coupled inverters (a latch), A -> B -> A: one loop of 2;
/// - an nfet with its gate on its own drain A (diode-connected): A drives
///   itself, one loop of 1.
fn combinational_loop() -> Vec<Fixture> {
    let labels = ["VDD", "VSS", "A", "B", "C"];
    let (vdd, vss, a, b, c) = (0, 1, 2, 3, 4);
    let inverter = |input: usize, output: usize| {
        [
            dev(Model::Pfet, input, vdd, output),
            dev(Model::Nfet, input, vss, output),
        ]
    };
    let cases: [(&str, Vec<Dev>, Vec<Finding>); 4] = [
        ("chain", [inverter(a, b), inverter(b, c)].concat(), vec![]),
        (
            "ring3",
            [inverter(a, b), inverter(b, c), inverter(c, a)].concat(),
            vec![count(3)],
        ),
        (
            "latch",
            [inverter(a, b), inverter(b, a)].concat(),
            vec![count(2)],
        ),
        ("diode", vec![dev(Model::Nfet, a, vss, a)], vec![count(1)]),
    ];
    let deck = format!("{TOPO_PROCESS}rule cl combinational_loop()\n");
    let mut out = Vec::new();
    for (name, devs, findings) in cases {
        let mut f = Fixture::new(
            &format!("erc/combinational_loop/{name}"),
            &["ERC-G8"],
            &deck,
        )
        .layout(circuit(&labels, &devs, &[]))
        .expect(Expect::rule("cl", findings));
        f.intent = Some(intent(
            &[("d", 1800.0)],
            &[("VDD", "d", "power"), ("VSS", "d", "ground")],
            &[],
        ));
        out.extend(every_placement(&[f]));
    }
    out
}

/// One matched unit at column `x0` of [`TOPO_PROCESS`], `w` wide, its
/// channel along x (diffusions left and right of a vertical gate, as
/// [`Board`] draws) or, `rotated`, along y (diffusions below and above a
/// horizontal gate), wired by risers to the met2 tracks of `g`, `s`, `d`.
fn matched_unit(l: &mut Layout, x0: i64, rotated: bool, w: i64, (g, s, d): (usize, usize, usize)) {
    if rotated {
        rect(l, "diff", (x0, 0, x0 + w, 1000));
        rect(l, "diff", (x0, 1200, x0 + w, 2200));
        rect(l, "poly", (x0 - 700, 1000, x0 + w, 1200));
        rect(l, "mkn", (x0, 1000, x0 + w, 1200));
        riser(l, x0 - 700, 1000, g);
        riser(l, x0 + 100, 400, s);
        riser(l, x0 + w - 300, 1600, d);
    } else {
        rect(l, "diff", (x0, 0, x0 + 1000, w));
        rect(l, "diff", (x0 + 1200, 0, x0 + 2200, w));
        rect(l, "poly", (x0 + 1000, 0, x0 + 1200, w + 600));
        rect(l, "mkn", (x0 + 1000, 0, x0 + 1200, w));
        riser(l, x0 + 400, 400, s);
        riser(l, x0 + 1600, 400, d);
        riser(l, x0 + 1000, w + 400, g);
    }
}

/// `matching` (ERC-H2), hand-derived. Units sit 4 µm apart in a row inside
/// one `grp` polygon; device A has its gate on net 1 and device B on net 2,
/// both from net 0 to net 3, every unit 1 µm wide and 200 nm long, its
/// marker 200 x 1000 nm (area-weighted centroid = mean of equal markers).
///
/// - ABBA: A's centroid (0 + 12 µm) / 2 and B's (4 + 8 µm) / 2 coincide:
///   clean.
/// - ABAB: A at (0 + 8) / 2 = 4 µm, B at (4 + 12) / 2 = 8 µm: 4000 nm
///   apart, flagged against tolerance 3999 nm, clean at 4000 nm.
/// - a 1.2 µm wide B unit beside a 1 µm A: the widths differ by 200 nm.
/// - an A unit turned 90°, its channel along y beside one along x: one
///   crossing unit, both one device (no centroid to compare).
/// - units outside the polygon are not in the group: ABAB with the last B
///   outside reads A at 4 µm and B at 4 µm, clean.
fn matching() -> Vec<Fixture> {
    let deck = |tolerance: i64| {
        format!(
            "{TOPO_PROCESS}layer grp = gds(40, 0)\nrule mt matching(grp; tolerance: {tolerance}nm)\n"
        )
    };
    let (a, b) = ((1, 0, 3), (2, 0, 3));
    let board = |units: &[((usize, usize, usize), bool, i64)], inside: usize| {
        let mut l = Layout::default();
        for (k, &(nets, rotated, w)) in units.iter().enumerate() {
            matched_unit(&mut l, k as i64 * PITCH, rotated, w, nets);
        }
        let right = units.len() as i64 * PITCH + 1000;
        for net in 0..NETS {
            let ty = track_y(net);
            rect(&mut l, "met2", (-2000, ty, right, ty + TRACK_H));
        }
        rect(
            &mut l,
            "grp",
            (-1000, -500, inside as i64 * PITCH - 500, 2500),
        );
        l
    };
    let unit = |nets, w| (nets, false, w);
    let cases: Vec<(&str, Layout, i64, Vec<Finding>)> = vec![
        (
            "abba",
            board(
                &[unit(a, 1000), unit(b, 1000), unit(b, 1000), unit(a, 1000)],
                4,
            ),
            0,
            vec![],
        ),
        (
            "abab/below",
            board(
                &[unit(a, 1000), unit(b, 1000), unit(a, 1000), unit(b, 1000)],
                4,
            ),
            3999,
            vec![length(4000)],
        ),
        (
            "abab/at",
            board(
                &[unit(a, 1000), unit(b, 1000), unit(a, 1000), unit(b, 1000)],
                4,
            ),
            4000,
            vec![],
        ),
        (
            "width",
            board(&[unit(a, 1000), unit(b, 1200)], 2),
            100_000,
            vec![length(200)],
        ),
        (
            "crossing",
            board(&[unit(a, 1000), (a, true, 1000)], 2),
            100_000,
            vec![count(1)],
        ),
        (
            "outside",
            board(
                &[unit(a, 1000), unit(b, 1000), unit(a, 1000), unit(b, 1000)],
                3,
            ),
            0,
            vec![],
        ),
    ];
    let mut out = Vec::new();
    for (name, layout, tolerance, findings) in cases {
        let f = Fixture::new(
            &format!("erc/matching/{name}"),
            &["ERC-H2"],
            &deck(tolerance),
        )
        .layout(layout)
        .expect(Expect::rule("mt", findings));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `power_switch` (ERC-F14), hand-derived. VDD, VDDV, VSS and VDD2 are
/// supplies of one 1.8 V domain; the state `sleep` turns VDDV and VDD2 off,
/// so they are switched and VDD and VSS always on. The switch is the
/// `clamp` model, its gate on EN; a pfet from a supply to EN drives the
/// control.
///
/// - VDD to VDDV, EN driven from VDD: clean.
/// - VDD to OUT (not a supply), or VDD to VSS (another role): the wiring
///   is flagged, 0 against 1.
/// - VDD to VDDV, EN driven only from VDD2: in `sleep` nothing reaches EN,
///   so the control floats in 1 state.
/// - without power states the row is skipped.
fn power_switch() -> Vec<Fixture> {
    let labels = ["VDD", "VDDV", "VSS", "VDD2", "EN", "OUT", "IN"];
    let (vdd, vddv, vss, vdd2, en, out_net, input) = (0, 1, 2, 3, 4, 5, 6);
    let deck = format!("{TOPO_PROCESS}rule ps power_switch(; models: [\"clamp\"])\n");
    let supplies = intent(
        &[("d", 1800.0)],
        &[
            ("VDD", "d", "power"),
            ("VDDV", "d", "power"),
            ("VSS", "d", "ground"),
            ("VDD2", "d", "power"),
        ],
        &[],
    );
    let with_sleep = format!(
        r#"{},"states":[{{"name":"sleep","off":["VDDV","VDD2"],"inputs":[]}}]}}"#,
        &supplies[..supplies.len() - 1]
    );
    let cases = [
        ("good", vddv, vdd, vec![]),
        ("to_signal", out_net, vdd, vec![count(0)]),
        ("across_roles", vss, vdd, vec![count(0)]),
        ("switched_control", vddv, vdd2, vec![count(1)]),
    ];
    let mut out = Vec::new();
    for (name, output, control, findings) in cases {
        let devs = [
            dev(Model::Clamp, en, vdd, output),
            dev(Model::Pfet, input, control, en),
        ];
        let layout = circuit(&labels, &devs, &[]);
        let mut f = Fixture::new(&format!("erc/power_switch/{name}"), &["ERC-F14"], &deck)
            .layout(layout.clone())
            .expect(Expect::rule("ps", findings));
        f.intent = Some(with_sleep.clone());
        out.extend(every_placement(&[f]));
        if name == "good" {
            let mut g = Fixture::new("erc/power_switch/no_states", &["ERC-F14"], &deck)
                .layout(layout)
                .expect(Expect::outcome("ps", Want::Skipped));
            g.intent = Some(supplies.clone());
            out.push(g);
        }
    }
    out
}

/// Nets of the domain fixtures: two 1.8 V domains and a third ground.
const DOMAIN_NETS: [&str; 7] = ["VDD1", "VSS1", "VDD2", "VSS2", "VSS3", "SIG", "OUT"];

/// VDD1 and VSS1 are domain `d1`, VDD2 and VSS2 domain `d2`, VSS3 the only
/// supply of `d3`, each at 1.8 V.
pub(crate) fn domain_intent() -> String {
    intent(
        &[("d1", 1800.0), ("d2", 1800.0), ("d3", 1800.0)],
        &[
            ("VDD1", "d1", "power"),
            ("VSS1", "d1", "ground"),
            ("VDD2", "d2", "power"),
            ("VSS2", "d2", "ground"),
            ("VSS3", "d3", "ground"),
        ],
        &[],
    )
}

/// `esd_ground_coupling` (ERC-C5) over the three grounds VSS1, VSS2, VSS3:
/// the groups an anti-parallel pair of `dio` diodes (one each way) joins,
/// and one finding per group but one. A single diode couples nothing, a
/// chain of pairs couples all three, and a pair between a ground and a power
/// supply couples no ground.
fn ground_coupling() -> Vec<Fixture> {
    let (vdd2, vss1, vss2, vss3) = (2, 1, 3, 4);
    let deck = format!(
        "{}rule gc esd_ground_coupling(; diodes: [\"dio\"])\n",
        diode_process()
    );
    let mut out = Vec::new();
    for (name, diodes, findings) in [
        ("none", vec![], 2),
        ("one_way", vec![(vss1, vss2)], 2),
        ("pair", vec![(vss1, vss2), (vss2, vss1)], 1),
        (
            "chain",
            vec![(vss1, vss2), (vss2, vss1), (vss3, vss2), (vss2, vss3)],
            0,
        ),
        (
            "pair_to_power",
            vec![(vss1, vss2), (vss2, vss1), (vss3, vdd2), (vdd2, vss3)],
            1,
        ),
    ] {
        let mut f = Fixture::new(
            &format!("erc/esd_ground_coupling/{name}"),
            &["ERC-C5"],
            &deck,
        )
        .layout(circuit(&DOMAIN_NETS, &[], &diodes))
        .expect(Expect::rule(
            "gc",
            (0..findings).map(|_| count(0)).collect(),
        ));
        f.intent = Some(domain_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// `esd_cross_domain` (ERC-C4), the pseudocode of Hogan 2012 §II: an
/// inverter in domain `d1` (VDD1, VSS1) drives SIG, the gate of an inverter
/// in `d2` (VDD2, VSS2) whose output is OUT. Both receiver transistors see
/// `d1` at the gate and `d2` on the channel: "IF different power domains
/// THEN check for anti-parallel diodes", between VSS1 and VSS2. Unprotected,
/// both are flagged; with the pair, neither; with one diode, both. An
/// inverter whose gate SIG is reached by its own domain is no receiver.
fn cross_domain() -> Vec<Fixture> {
    let (vdd1, vss1, vdd2, vss2, sig, out_net, vss3) = (0, 1, 2, 3, 5, 6, 4);
    let deck = format!(
        "{}rule xd esd_cross_domain(; diodes: [\"dio\"], local: none, resistors: none, \
         min_series: none, max_ground_resistance: none, coupling_resistance: none)\n",
        diode_process()
    );
    // The driver's input sits on VSS3, a supply of its own domain, so only
    // SIG and OUT cross.
    let devs = [
        dev(Model::Pfet, vss3, vdd1, sig),
        dev(Model::Nfet, vss3, vss1, sig),
        dev(Model::Pfet, sig, vdd2, out_net),
        dev(Model::Nfet, sig, vss2, out_net),
    ];
    let mut out = Vec::new();
    for (name, diodes, findings) in [
        ("unprotected", vec![], 2),
        ("one_diode", vec![(vss1, vss2)], 2),
        ("pair", vec![(vss1, vss2), (vss2, vss1)], 0),
        (
            "pair_through_vss3",
            vec![(vss1, vss3), (vss3, vss1), (vss3, vss2), (vss2, vss3)],
            0,
        ),
    ] {
        let mut f = Fixture::new(&format!("erc/esd_cross_domain/{name}"), &["ERC-C4"], &deck)
            .layout(circuit(&DOMAIN_NETS, &devs, &diodes))
            .expect(Expect::rule(
                "xd",
                (0..findings).map(|_| count(0)).collect(),
            ));
        f.intent = Some(domain_intent());
        out.extend(every_placement(&[f]));
    }
    // Both inverters in one domain: no receiver crosses.
    let same = [
        dev(Model::Pfet, vss3, vdd1, sig),
        dev(Model::Nfet, vss3, vss1, sig),
        dev(Model::Pfet, sig, vdd1, out_net),
        dev(Model::Nfet, sig, vss1, out_net),
    ];
    let mut f = Fixture::new("erc/esd_cross_domain/one_domain", &["ERC-C4"], &deck)
        .layout(circuit(&DOMAIN_NETS, &same, &[]))
        .expect(Expect::clean("xd"));
    f.intent = Some(domain_intent());
    out.push(f);
    out.extend(local_clamp());
    out.extend(cross_domain_resistance());
    out
}

/// A crossing drawn as metal strips, for `esd_cross_domain`'s series and
/// ground resistances: every net a 1 µm met1 strip (0.125 Ω per µm), each
/// transistor a 200 nm marker in the gap between the two strips it joins,
/// its gate a poly bar contacted to SIG. Domain 1 (VDD1 at y 4 µm, VSS1 at
/// 0) drives SIG (2 µm) at x 2 µm; domain 2 (VSS2 at -2 µm, OUT at -4 µm,
/// VDD2 at -6 µm) receives it, the nfet at x 18 µm and the pfet at 16 µm.
/// `dio` diodes join VSS1 to VSS2 at the given x. With `resistor`, SIG is
/// cut at 5 µm and a `rs` resistor (100 Ω/sq, 400 x 200 nm: 200 Ω) joins
/// the drivers' piece to the receivers'.
fn strip_crossing(diodes: &[i64], resistor: bool) -> Layout {
    let mut l = Layout::default();
    let strip = |l: &mut Layout, name: &str, y: i64, from: i64, to: i64| {
        rect(l, "m1", (from, y, to, y + 1000));
        *l = std::mem::take(l).label("txt", from + 100, y + 500, name);
    };
    strip(&mut l, "VDD1", 4000, 0, 20_000);
    strip(&mut l, "VSS1", 0, 0, 20_000);
    strip(&mut l, "VSS2", -2000, 0, 20_000);
    strip(&mut l, "OUT", -4000, 0, 20_000);
    strip(&mut l, "VDD2", -6000, 0, 20_000);
    if resistor {
        strip(&mut l, "SIGD", 2000, 0, 5000);
        strip(&mut l, "SIG", 2000, 5400, 20_000);
        rect(&mut l, "mkr", (5000, 2400, 5400, 2600));
    } else {
        strip(&mut l, "SIG", 2000, 0, 20_000);
    }
    // Drivers: the nfet from VSS1 to SIG, the pfet from SIG to VDD1.
    for (marker, ylo) in [("mkn", 1000), ("mkp", 3000)] {
        rect(&mut l, marker, (2000, ylo, 2200, ylo + 1000));
        rect(&mut l, "poly", (2000, ylo, 2200, ylo + 1000));
    }
    // Receivers, gated by SIG through a contacted poly bar.
    for (marker, x, ylo) in [("mkn", 18_000, -3000), ("mkp", 16_000, -5000)] {
        rect(&mut l, marker, (x, ylo, x + 200, ylo + 1000));
        rect(&mut l, "poly", (x, ylo, x + 200, 2700));
        rect(&mut l, "ct", (x + 50, 2400, x + 150, 2600));
    }
    for &x in diodes {
        rect(&mut l, "mkd", (x - 100, -1000, x + 100, 0));
    }
    l
}

/// The strip crossing's process: met1 strips, poly gates contacted by `ct`.
const STRIP_PROCESS: &str = "grid 1nm
layer m1 = gds(1, 0)
layer poly = gds(2, 0)
layer ct = gds(3, 0)
layer mkn = gds(4, 0)
layer mkp = gds(5, 0)
layer mkd = gds(6, 0)
layer mkr = gds(7, 0)
layer txt = gds(1, 1)
connect conductors [m1, poly]
connect touch_within_layer
connect via ct [poly, m1]
connect label txt names m1
device mos mkn model \"nfet\" terminals [poly, m1, m1]
device mos mkp model \"pfet\" terminals [poly, m1, m1]
device diode mkd model \"dio\" terminals [m1, m1]
device resistor mkr model \"rs\" terminals [m1, m1] sheet 100ohm
pex m1 thickness 100nm height 100nm sheet 0.125ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex poly thickness 100nm height 50nm sheet 10ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex ct thickness 100nm height 75nm sheet 1ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
";

/// `esd_cross_domain`'s series resistor (ERC-C4) and driver/receiver
/// ground resistance (ERC-C9), limits deck-supplied, on
/// [`strip_crossing`], hand-derived. Every case's two `dio` diodes face the
/// same way, so TR18-01 5.1.3 flags both receivers (0 against 1) whatever
/// else is checked.
///
/// - Ground: the driver nfet attaches to VSS1 at 2.1 µm and the receiver
///   nfet to VSS2 at 18.1 µm; diodes at 10 and 10.4 µm, 1 Ω each. VSS1 to
///   10 µm is 0.9875 Ω, VSS2 from 10.4 µm 0.9625 Ω, and between them two
///   paths of 1 + 0.05 Ω in parallel, 0.525 Ω: 2.475 Ω, swept a part in a
///   thousand either side. The receiver pfet has no ground end and the
///   driver pfet's other end is a power: no other pair.
/// - Series: SIG driven straight reads 0 Ω for both receivers (flagged at
///   150 Ω); through the 200 Ω resistor both read 200 (flagged at 300,
///   clean at 150).
fn cross_domain_resistance() -> Vec<Fixture> {
    let intent_text = intent(
        &[("d1", 1800.0), ("d2", 1800.0)],
        &[
            ("VDD1", "d1", "power"),
            ("VSS1", "d1", "ground"),
            ("VDD2", "d2", "power"),
            ("VSS2", "d2", "ground"),
        ],
        &[],
    );
    let deck = |resistors: &str, series: &str, ground: &str, coupling: &str| {
        format!(
            "{STRIP_PROCESS}rule xd esd_cross_domain(; diodes: [\"dio\"], local: none, \
             resistors: {resistors}, min_series: {series}, max_ground_resistance: {ground}, \
             coupling_resistance: {coupling})\n"
        )
    };
    let unprotected = || vec![count(0), count(0)];
    let mut out = Vec::new();
    let ground = 2.475;
    for limit in [ground * 0.999, ground * 1.001] {
        let mut findings = unprotected();
        if ground > limit {
            findings.push(ohms(ground));
        }
        let mut f = Fixture::new(
            &format!("erc/esd_cross_domain/ground/{}", side(limit, ground)),
            &["ERC-C9"],
            &deck("none", "none", &format!("{limit}ohm"), "1ohm"),
        )
        .layout(strip_crossing(&[10_000, 10_400], false))
        .expect(Expect::rule("xd", findings));
        f.intent = Some(intent_text.clone());
        out.extend(every_placement(&[f]));
    }
    for (name, resistor, min, series) in [
        ("direct", false, 150.0, Some(0.0)),
        ("through/below", true, 300.0, Some(200.0)),
        ("through/above", true, 150.0, None),
    ] {
        let mut findings = unprotected();
        if let Some(value) = series {
            findings.extend([ohms(value), ohms(value)]);
        }
        let mut f = Fixture::new(
            &format!("erc/esd_cross_domain/series/{name}"),
            &["ERC-C4"],
            &deck("[\"rs\"]", &format!("{min}ohm"), "none", "none"),
        )
        .layout(strip_crossing(&[10_000, 10_400], resistor))
        .expect(Expect::rule("xd", findings));
        f.intent = Some(intent_text.clone());
        out.extend(every_placement(&[f]));
    }
    out
}

/// `esd_cross_domain`'s local clamp (ERC-C9): Hogan's crossing with its
/// grounds coupled, and `local: ["dio"]`. With no diode at SIG, both receiver
/// transistors lack one; a `dio` from VSS2 (the receivers' own ground) to SIG
/// clamps both; one from VSS1 (the driver's ground) clamps neither.
fn local_clamp() -> Vec<Fixture> {
    let (vdd1, vss1, vdd2, vss2, vss3, sig, out_net) = (0, 1, 2, 3, 4, 5, 6);
    let deck = format!(
        "{}rule xd esd_cross_domain(; diodes: [\"dio\"], local: [\"dio\"], resistors: none, \
         min_series: none, max_ground_resistance: none, coupling_resistance: none)\n",
        diode_process()
    );
    let devs = [
        dev(Model::Pfet, vss3, vdd1, sig),
        dev(Model::Nfet, vss3, vss1, sig),
        dev(Model::Pfet, sig, vdd2, out_net),
        dev(Model::Nfet, sig, vss2, out_net),
    ];
    let pair = [(vss1, vss2), (vss2, vss1)];
    let mut out = Vec::new();
    for (name, local, findings) in [
        ("none", None, 2),
        ("own_ground", Some((vss2, sig)), 0),
        ("driver_ground", Some((vss1, sig)), 2),
    ] {
        let mut diodes = pair.to_vec();
        diodes.extend(local);
        let mut f = Fixture::new(
            &format!("erc/esd_cross_domain/local/{name}"),
            &["ERC-C9"],
            &deck,
        )
        .layout(circuit(&DOMAIN_NETS, &devs, &diodes))
        .expect(Expect::rule(
            "xd",
            (0..findings).map(|_| count(0)).collect(),
        ));
        f.intent = Some(domain_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// `guard_ring_bias` (ERC-D3): a guard ring drawn on `layer` as four
/// abutting bars round a 1.2 µm hole (one net), tied by one riser to the
/// track of `net`, beside the domain nets' tracks.
fn ring_on(layer: &str, net: usize) -> Layout {
    let mut l = circuit(&DOMAIN_NETS, &[], &[]);
    for bar in [
        (-1000, 0, 1000, 400),
        (-1000, 1600, 1000, 2000),
        (-1000, 400, -600, 1600),
        (600, 400, 1000, 1600),
    ] {
        rect(&mut l, layer, bar);
    }
    riser(&mut l, -200, 1600, net);
    l
}

/// `guard_ring_bias` (ERC-D3, GF180MCU LU.9, LU.10, IO.1 (a2), IO.3 (a2)):
/// an n-tap ring must sit on the most positive supply, a p-tap ring on a
/// ground. Each ring is four polygons, so a ring on the wrong net is four
/// findings: on a supply, its voltage against the one it needs; off every
/// supply, a count of 0. With domain `d2` at 3.3 V, VDD1 (1.8 V) is no longer
/// the most positive supply.
fn guard_ring_bias() -> Vec<Fixture> {
    let (vdd1, vss1, vdd2, vss2, sig) = (0, 1, 2, 3, 5);
    let deck = format!(
        "{}rule gn guard_ring_bias(ntap; power: true)\n\
         rule gp guard_ring_bias(ptap; power: false)\n",
        diode_process()
    );
    let high = intent(
        &[("d1", 1800.0), ("d2", 3300.0), ("d3", 1800.0)],
        &[
            ("VDD1", "d1", "power"),
            ("VSS1", "d1", "ground"),
            ("VDD2", "d2", "power"),
            ("VSS2", "d2", "ground"),
            ("VSS3", "d3", "ground"),
        ],
        &[],
    );
    let four = |f: Finding| vec![f; 4];
    let cases = [
        ("n_on_vdd1", "ntap", vdd1, domain_intent(), "gn", Vec::new()),
        (
            "n_on_vss1",
            "ntap",
            vss1,
            domain_intent(),
            "gn",
            four(millivolts(0.0)),
        ),
        (
            "n_on_sig",
            "ntap",
            sig,
            domain_intent(),
            "gn",
            four(count(0)),
        ),
        (
            "n_on_vdd1_low",
            "ntap",
            vdd1,
            high.clone(),
            "gn",
            four(millivolts(1800.0)),
        ),
        ("n_on_vdd2_high", "ntap", vdd2, high, "gn", Vec::new()),
        ("p_on_vss2", "ptap", vss2, domain_intent(), "gp", Vec::new()),
        (
            "p_on_vdd2",
            "ptap",
            vdd2,
            domain_intent(),
            "gp",
            four(millivolts(1800.0)),
        ),
        (
            "p_on_sig",
            "ptap",
            sig,
            domain_intent(),
            "gp",
            four(count(0)),
        ),
    ];
    let mut out = Vec::new();
    for (name, layer, net, intent_text, rule, findings) in cases {
        let other = if rule == "gn" { "gp" } else { "gn" };
        let mut f = Fixture::new(&format!("erc/guard_ring_bias/{name}"), &["ERC-D3"], &deck)
            .layout(ring_on(layer, net))
            .expect(Expect::rule(rule, findings))
            .expect(Expect::clean(other));
        f.intent = Some(intent_text);
        out.extend(every_placement(&[f]));
    }
    out
}

/// `tie_area` (ERC-D1b, GF180MCU LU.7 and IO.2/IO.4) on marker layers: a
/// 10 µm well holds two 1 × 2 µm gates (4 µm² of channel) and three 200 nm
/// contacts (0.12 µm²); a fourth contact half outside the well adds only its
/// inside half (0.02 µm²), and two overlapping contacts their union (0.06
/// µm²): 0.2 µm², a ratio of 5% exactly, swept below, at and above. A second well holds a gate and no contact (ratio 0), a third a
/// contact and no gate (not examined). A guard ring 1 µm wide round a 4 µm
/// hole (20 µm² of ring) with ten 200 nm contacts on it: 2%, against IO.2's
/// 5%.
fn tie_area() -> Vec<Fixture> {
    let deck = |min: f64| {
        format!(
            "grid 1nm\nlayer well = gds(1, 0)\nlayer cont = gds(2, 0)\nlayer gate = gds(3, 0)\n\
             layer ring = gds(4, 0)\n\
             rule ta tie_area(well, cont, gate; min_ratio: {min})\n\
             rule tr tie_area(ring, cont, ring; min_ratio: 5%)\n"
        )
    };
    let mut l = Layout::default();
    rect(&mut l, "well", (0, 0, 10_000, 10_000));
    rect(&mut l, "gate", (1000, 1000, 2000, 3000));
    rect(&mut l, "gate", (4000, 1000, 5000, 3000));
    for x in [6000, 7000, 8000] {
        rect(&mut l, "cont", (x, 6000, x + 200, 6200));
    }
    // Half outside the well, and an overlapping pair whose union is 300 x 200.
    rect(&mut l, "cont", (9900, 8000, 10_100, 8200));
    rect(&mut l, "cont", (2000, 8000, 2200, 8200));
    rect(&mut l, "cont", (2100, 8000, 2300, 8200));
    // 0.12 + 0.02 + 0.06 = 0.2 µm² against 4 µm²: 5%.
    let value = 0.05;
    rect(&mut l, "well", (20_000, 0, 30_000, 10_000));
    rect(&mut l, "gate", (21_000, 1000, 22_000, 3000));
    rect(&mut l, "well", (40_000, 0, 50_000, 10_000));
    rect(&mut l, "cont", (41_000, 1000, 41_200, 1200));
    for bar in [
        (60_000, 0, 66_000, 1000),
        (60_000, 5000, 66_000, 6000),
        (60_000, 1000, 61_000, 5000),
        (65_000, 1000, 66_000, 5000),
    ] {
        rect(&mut l, "ring", bar);
    }
    for k in 0..10 {
        let x = 60_100 + 500 * k;
        rect(&mut l, "cont", (x, 200, x + 200, 400));
    }
    let mut out = Vec::new();
    for min_ratio in sweep(value) {
        let mut findings = vec![ratio(0.0)];
        if min_ratio > value {
            findings.push(ratio(value));
        }
        let f = Fixture::new(
            &format!("erc/tie_area/{}", side(min_ratio, value)),
            &["ERC-D1b"],
            &deck(min_ratio),
        )
        .layout(l.clone())
        .expect(Expect::rule("ta", findings))
        .expect(Expect::rule("tr", vec![ratio(0.02)]));
        out.extend(every_placement(&[f]));
    }
    out
}

/// A closed ring of band `band` on layer `layer` round the box `hole`: four
/// bars that merge into one figure with that hole.
fn ring_round(l: &mut Layout, layer: &str, hole: Rect, band: i64) {
    let (x0, y0, x1, y1) = hole;
    for bar in [
        (x0 - band, y0 - band, x1 + band, y0),
        (x0 - band, y1, x1 + band, y1 + band),
        (x0 - band, y0, x0, y1),
        (x1, y0, x1 + band, y1),
    ] {
        rect(l, layer, bar);
    }
}

/// `guard_ring` (ERC-D2, GF180MCU IO.1 (a2) and IO.2): a 2 × 1 µm diffusion
/// wired by a riser to a net carrying a pad must sit in a closed `ring` no
/// more than 15 µm from it on any side and at least 2 µm wide. The ring's
/// hole is the diffusion grown by `gap` on every side, so the space is `gap`;
/// both swept a nanometre either side. A ring with one bar missing (a C)
/// surrounds nothing; a diffusion on a net with no pad is not selected.
fn guard_ring() -> Vec<Fixture> {
    let (pad_net, other) = (5, 6);
    let deck = format!(
        "{}rule gr guard_ring(diff, ring; max_space: 15um, min_width: 2um, pad: pad, \
         near: none, within: none, clear: none)\n",
        diode_process()
    );
    let target: Rect = (0, -6000, 2000, -5000);
    let board = |net: usize, gap: i64, band: i64, closed: bool| {
        let mut l = circuit(&DOMAIN_NETS, &[], &[]);
        rect(&mut l, "diff", target);
        riser(&mut l, 900, -5900, net);
        let ty = track_y(pad_net);
        rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
        rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
        let (x0, y0, x1, y1) = target;
        let hole = (x0 - gap, y0 - gap, x1 + gap, y1 + gap);
        if closed {
            ring_round(&mut l, "ring", hole, band);
        } else {
            // The right bar left out: a C open on one side.
            let (hx0, hy0, hx1, hy1) = hole;
            rect(&mut l, "ring", (hx0 - band, hy0 - band, hx1 + band, hy0));
            rect(&mut l, "ring", (hx0 - band, hy1, hx1 + band, hy1 + band));
            rect(&mut l, "ring", (hx0 - band, hy0, hx0, hy1));
        }
        l
    };
    let mut cases: Vec<(String, Layout, Vec<Finding>)> = Vec::new();
    for gap in [14_999, 15_000, 15_001] {
        cases.push((
            format!("space/{}", side(15_000.0, gap as f64)),
            board(pad_net, gap, 2000, true),
            if gap > 15_000 {
                vec![length(gap)]
            } else {
                Vec::new()
            },
        ));
    }
    for band in [1999, 2000, 2001] {
        cases.push((
            format!("width/{}", side(2000.0, band as f64)),
            board(pad_net, 10_000, band, true),
            if band < 2000 {
                vec![length(band)]
            } else {
                Vec::new()
            },
        ));
    }
    cases.push((
        "open_ring".to_owned(),
        board(pad_net, 10_000, 2000, false),
        vec![count(0)],
    ));
    cases.push((
        "no_pad".to_owned(),
        board(other, 10_000, 2000, false),
        Vec::new(),
    ));
    let mut out = Vec::new();
    for (name, layout, findings) in cases {
        let f = Fixture::new(&format!("erc/guard_ring/{name}"), &["ERC-D2"], &deck)
            .layout(layout)
            .expect(Expect::rule("gr", findings));
        out.extend(every_placement(&[f]));
    }
    out.extend(native_ring());
    out.extend(native_clear());
    out.extend(double_ring());
    out
}

/// `guard_ring` for GF180MCU §14.3.4 (ERC-D6): a high-voltage device `hv`
/// inside an n-well ring inside a p-substrate ring, two rows. Both rings
/// drawn: clean; the outer one left out: the p-ring row finds the device
/// unsurrounded.
fn double_ring() -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer hv = gds(1, 0)\nlayer nring = gds(2, 0)\nlayer pring = gds(3, 0)\n\
                rule dn guard_ring(hv, nring; max_space: none, min_width: none, pad: none, \
                near: none, within: none, clear: none)\n\
                rule dp guard_ring(hv, pring; max_space: none, min_width: none, pad: none, \
                near: none, within: none, clear: none)\n";
    let mut out = Vec::new();
    for outer in [true, false] {
        let mut l = Layout::default();
        rect(&mut l, "hv", (0, 0, 4000, 4000));
        ring_round(&mut l, "nring", (-1000, -1000, 5000, 5000), 1000);
        if outer {
            ring_round(&mut l, "pring", (-3000, -3000, 7000, 7000), 1000);
        }
        let f = Fixture::new(&format!("erc/guard_ring/double/{outer}"), &["ERC-D6"], deck)
            .layout(l)
            .expect(Expect::clean("dn"))
            .expect(Expect::rule(
                "dp",
                if outer { Vec::new() } else { vec![count(0)] },
            ));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `guard_ring` for GF180MCU LU.5 (ERC-D7): a native device (`nat`) with an
/// n-well within 50 µm must sit in a closed p-substrate ring. The well is
/// `gap` to the right of the device, swept about 50 µm; with a ring the
/// device is clean whatever the well.
fn native_ring() -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer nat = gds(1, 0)\nlayer well = gds(2, 0)\nlayer ring = gds(3, 0)\n\
                rule lu5 guard_ring(nat, ring; max_space: none, min_width: none, pad: none, \
                near: well, within: 50um, clear: none)\n";
    let mut out = Vec::new();
    for (gap, ringed) in [
        (49_999, false),
        (50_000, false),
        (50_001, false),
        (1000, true),
    ] {
        let mut l = Layout::default();
        rect(&mut l, "nat", (0, 0, 2000, 2000));
        rect(&mut l, "well", (2000 + gap, 0, 6000 + gap, 4000));
        if ringed {
            ring_round(&mut l, "ring", (-200, -200, 2200, 2200), 300);
        }
        let findings = if gap <= 50_000 && !ringed {
            vec![count(0)]
        } else {
            Vec::new()
        };
        let f = Fixture::new(
            &format!("erc/guard_ring/native/{gap}_{ringed}"),
            &["ERC-D7"],
            deck,
        )
        .layout(l)
        .expect(Expect::rule("lu5", findings));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `guard_ring` with `clear` for GF180MCU LU.5's "No other NCOMP, NWELL in
/// between the NAT and PCOMP guard ring" (ERC-D7): `clear` is the derived
/// `ncomp or well`. The ring's hole is (-200, -200)-(2200, 2200) round a NAT
/// at (0, 0)-(2000, 2000), its band 300 wide; the near well sits 1 µm
/// right of the ring. Hand-derived: a clear figure counts when it has area
/// in the hole outside the NAT, so an NCOMP inside the NAT, or one lying on
/// the ring's band, is clean, and one in the gap, one straddling the NAT's
/// edge into the gap, or a well island in the gap each count once.
fn native_clear() -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer nat = gds(1, 0)\nlayer well = gds(2, 0)\nlayer ring = gds(3, 0)\n\
                layer ncomp = gds(4, 0)\nlayer between = ncomp or well\n\
                rule lu5 guard_ring(nat, ring; max_space: none, min_width: none, pad: none, \
                near: well, within: 50um, clear: between)\n";
    let cases: [(&str, &[(&str, Rect)], u32); 7] = [
        ("empty", &[], 0),
        ("ncomp_in_nat", &[("ncomp", (500, 500, 1500, 1500))], 0),
        ("ncomp_on_ring", &[("ncomp", (-450, 0, -250, 200))], 0),
        ("ncomp_in_gap", &[("ncomp", (2050, 0, 2150, 100))], 1),
        (
            "ncomp_straddles_nat",
            &[("ncomp", (1900, 500, 2100, 600))],
            1,
        ),
        ("well_in_gap", &[("well", (0, 2050, 100, 2150))], 1),
        (
            "two_in_gap",
            &[
                ("ncomp", (2050, 0, 2150, 100)),
                ("ncomp", (-150, 0, -50, 100)),
            ],
            2,
        ),
    ];
    let mut out = Vec::new();
    for (name, extra, between) in cases {
        let mut l = Layout::default();
        rect(&mut l, "nat", (0, 0, 2000, 2000));
        rect(&mut l, "well", (3500, 0, 7500, 4000));
        ring_round(&mut l, "ring", (-200, -200, 2200, 2200), 300);
        for &(layer, r) in extra {
            rect(&mut l, layer, r);
        }
        let findings = if between > 0 {
            vec![count(between)]
        } else {
            Vec::new()
        };
        let f = Fixture::new(
            &format!("erc/guard_ring/native_clear/{name}"),
            &["ERC-D7"],
            deck,
        )
        .layout(l)
        .expect(Expect::rule("lu5", findings));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `forward_diode` (ERC-D8, GF180MCU §14.3.3) with the `iso` layer as
/// `Latchup_MK`: a `dio` diode is forward-biased when its anode can sit above
/// its cathode. Anode on VDD1 (1.8 V), cathode on VSS1: 1800 mV forward,
/// flagged unless `iso` covers it. Drawn the other way round it is reverse
/// biased (-1.8 V), clean. Anode on SIG, which a PMOS joins to VDD1 and the
/// diode itself to VSS1 (0 to 1.8 V), cathode on VSS1: 1800 mV. A diode with
/// its anode on OUT, which only its own cathode's ground reaches, sits at
/// 0 mV forward and is never forward-biased.
fn forward_diode() -> Vec<Fixture> {
    let (vdd1, vss1, vss3, sig, out_net) = (0, 1, 4, 5, 6);
    let deck = format!(
        "{}rule fd forward_diode(iso; models: [\"dio\"])\n",
        diode_process()
    );
    let pmos = [dev(Model::Pfet, vss3, vdd1, sig)];
    let mut out = Vec::new();
    for (name, diode, marked, findings) in [
        ("vdd_to_vss", (vdd1, vss1), false, vec![millivolts(1800.0)]),
        ("vdd_to_vss_marked", (vdd1, vss1), true, Vec::new()),
        ("vss_to_vdd", (vss1, vdd1), false, Vec::new()),
        (
            "signal_to_vss",
            (sig, vss1),
            false,
            vec![millivolts(1800.0)],
        ),
        ("grounded_anode", (out_net, vss1), false, Vec::new()),
    ] {
        let mut l = circuit(&DOMAIN_NETS, &pmos, &[diode]);
        if marked {
            // The diode column follows the one transistor's.
            let x0 = PITCH;
            rect(&mut l, "iso", (x0 + 800, 300, x0 + 1400, 700));
        }
        let mut f = Fixture::new(&format!("erc/forward_diode/{name}"), &["ERC-D8"], &deck)
            .layout(l)
            .expect(Expect::rule("fd", findings));
        f.intent = Some(domain_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// `conditional_tie` (ERC-D1a) as GF180MCU LU.4 for LV devices: a PCOMP
/// strip `pc` from x 0 to `reach`, tapped only at its left end, so its
/// furthest point is exactly `reach` from the tap; an n-well round it with
/// its top edge at y 3 µm; an NCOMP `nc` (outside the well) `y` above that
/// edge, 2 µm + `y` from the strip, within 50 µm. Bands: `y` below 1 µm
/// allows 15 µm, from 1 µm to below 2 µm 30 µm, from 2 µm 50 µm. Each band's
/// limit is swept a nanometre either side, the thresholds are tested on the
/// band edge (y = 1 µm and 2 µm exactly), and an NCOMP beyond 50 µm leaves
/// the loosest band.
fn conditional_tie() -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer pc = gds(1, 0)\nlayer tap = gds(2, 0)\nlayer nw = gds(3, 0)\n\
                layer nc = gds(4, 0)\n\
                rule lu4 conditional_tie(pc, tap, nw, nc; within: 50um, spacing: [1um, 2um], \
                max_distance: [15um, 30um, 50um])\n";
    let board = |reach: i64, y: i64, far: bool| {
        let mut l = Layout::default();
        rect(&mut l, "tap", (-1000, 0, 0, 1000));
        rect(&mut l, "pc", (0, 0, reach, 1000));
        rect(&mut l, "nw", (-2000, -2000, reach + 2000, 3000));
        let x0 = if far { reach + 60_000 } else { 0 };
        rect(&mut l, "nc", (x0, 3000 + y, x0 + 1000, 4000 + y));
        l
    };
    let mut cases: Vec<(String, Layout, i64, i64)> = Vec::new();
    for (y, limit) in [(500, 15_000), (1500, 30_000), (2500, 50_000)] {
        for reach in [limit - 1, limit, limit + 1] {
            cases.push((
                format!("y{y}/{reach}"),
                board(reach, y, false),
                reach,
                limit,
            ));
        }
    }
    cases.push((
        "edge_1um".to_owned(),
        board(30_001, 1000, false),
        30_001,
        30_000,
    ));
    cases.push((
        "edge_2um".to_owned(),
        board(30_001, 2000, false),
        30_001,
        50_000,
    ));
    cases.push(("far".to_owned(), board(30_001, 500, true), 30_001, 50_000));
    let mut out = Vec::new();
    for (name, layout, reach, limit) in cases {
        let findings = if reach > limit {
            vec![length(reach)]
        } else {
            Vec::new()
        };
        let f = Fixture::new(&format!("erc/conditional_tie/{name}"), &["ERC-D1a"], deck)
            .layout(layout)
            .expect(Expect::rule("lu4", findings));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `latchup_victim` (ERC-D5) as GF180MCU IO.1 (b): a PCOMP strip `pv` of
/// length `reach`, tapped only at its far end, `gap` from an aggressor
/// NCOMP `agg`. Within 15 µm (inclusive) it is a victim held to 2 µm, swept
/// a nanometre either side; 15 µm + 1 nm away it is not examined. With `pad`,
/// the same diffusion is an aggressor only on a net that carries a pad.
fn latchup_victim() -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer agg = gds(1, 0)\nlayer pv = gds(2, 0)\nlayer tap = gds(3, 0)\n\
                rule io1 latchup_victim(agg, pv, tap; within: 15um, max_distance: 2um, pad: none, \
                bias: none, forward: none)\n";
    let board = |gap: i64, reach: i64| {
        let mut l = Layout::default();
        rect(&mut l, "agg", (0, 0, 1000, 1000));
        let x0 = 1000 + gap;
        rect(&mut l, "pv", (x0, 0, x0 + reach, 1000));
        rect(&mut l, "tap", (x0 + reach, 0, x0 + reach + 500, 1000));
        l
    };
    let mut out = Vec::new();
    for (gap, reach, flagged) in [
        (15_000, 1999, false),
        (15_000, 2000, false),
        (15_000, 2001, true),
        (15_001, 2001, false),
    ] {
        let findings = if flagged {
            vec![length(reach)]
        } else {
            Vec::new()
        };
        let f = Fixture::new(
            &format!("erc/latchup_victim/{gap}/{reach}"),
            &["ERC-D5"],
            deck,
        )
        .layout(board(gap, reach))
        .expect(Expect::rule("io1", findings));
        out.extend(every_placement(&[f]));
    }
    // With pad selection, on the domain fixtures' tracks: a diffusion on a
    // net with a pad is an aggressor, the same on another net is not.
    let pad_deck = format!(
        "{}rule io1 latchup_victim(diff, nwpm, ntap; within: 15um, max_distance: 2um, pad: pad, \
         bias: none, forward: none)\n",
        diode_process()
    );
    let (pad_net, other) = (5, 6);
    for (name, net, flagged) in [("pad", pad_net, true), ("no_pad", other, false)] {
        let mut l = circuit(&DOMAIN_NETS, &[], &[]);
        rect(&mut l, "diff", (0, -6000, 2000, -5000));
        riser(&mut l, 900, -5900, net);
        let ty = track_y(pad_net);
        rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
        rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
        rect(&mut l, "nwpm", (7000, -6000, 10_000, -5000));
        rect(&mut l, "ntap", (10_000, -6000, 10_500, -5000));
        let f = Fixture::new(
            &format!("erc/latchup_victim/{name}"),
            &["ERC-D5"],
            &pad_deck,
        )
        .layout(l)
        .expect(Expect::rule(
            "io1",
            if flagged {
                vec![length(3000)]
            } else {
                Vec::new()
            },
        ));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `latchup_victim` with `bias` and `forward` (ERC-D5): an aggressor is a
/// diffusion the intent's voltages can forward-bias against the well it
/// lies in, hand-derived. A `pdiff` square sits in an `nw` well labelled
/// VDD (1.8 V); the victim 1.2 µm to its right has its tap on its far
/// edge, so its worst point is 1 µm from a tap, flagged against 500 nm
/// whenever the diffusion is an aggressor.
///
/// - `forward: above`, the diffusion on VDDH (3.3 V): 3300 > 1800, flagged;
/// - the diffusion on VDD itself: 1800 is not above 1800, clean;
/// - the diffusion on VDDH with the well drawn away from it: no well holds
///   it, clean;
/// - `forward: below`, the diffusion on VSS: 0 < 1800, flagged;
/// - without intent the row is skipped.
fn voltage_aggressor() -> Vec<Fixture> {
    let deck = |forward: &str| {
        format!(
            "grid 1nm
layer pdiff = gds(1, 0)
layer nw = gds(2, 0)
layer victim = gds(3, 0)
layer tap = gds(4, 0)
layer pdtxt = gds(1, 1)
layer nwtxt = gds(2, 1)
connect conductors [pdiff, nw]
connect label pdtxt names pdiff
connect label nwtxt names nw
rule lv latchup_victim(pdiff, victim, tap; within: 2um, max_distance: 500nm, pad: none, \
bias: nw, forward: {forward})
"
        )
    };
    let board = |net: &str, well_round: bool| {
        let mut l = Layout::default();
        let well = if well_round {
            (0, 0, 2000, 2000)
        } else {
            (-5000, 0, -3000, 2000)
        };
        rect(&mut l, "nw", well);
        l = l.label("nwtxt", well.0 + 100, 100, "VDD");
        rect(&mut l, "pdiff", (500, 500, 1000, 1000));
        l = l.label("pdtxt", 600, 600, net);
        rect(&mut l, "victim", (2200, 0, 3200, 1000));
        rect(&mut l, "tap", (3200, 0, 3300, 1000));
        l
    };
    let supplies = intent(
        &[("a", 1800.0), ("b", 3300.0)],
        &[
            ("VDD", "a", "power"),
            ("VSS", "a", "ground"),
            ("VDDH", "b", "power"),
        ],
        &[],
    );
    let mut out = Vec::new();
    for (name, forward, net, round, flagged) in [
        ("above", "above", "VDDH", true, true),
        ("same", "above", "VDD", true, false),
        ("no_well", "above", "VDDH", false, false),
        ("below", "below", "VSS", true, true),
    ] {
        let mut f = Fixture::new(
            &format!("erc/latchup_victim/voltage/{name}"),
            &["ERC-D5"],
            &deck(forward),
        )
        .layout(board(net, round))
        .expect(Expect::rule(
            "lv",
            if flagged {
                vec![length(1000)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(supplies.clone());
        out.extend(every_placement(&[f]));
    }
    out.push(
        Fixture::new(
            "erc/latchup_victim/voltage/no_intent",
            &["ERC-D5"],
            &deck("above"),
        )
        .layout(board("VDDH", true))
        .expect(Expect::outcome("lv", Want::Skipped)),
    );
    out
}

/// `esd_parasitic` (ERC-C10) on the domain fixtures' tracks with a pad on
/// SIG: a 1 µm diffusion riser-wired to SIG and another `gap` to its right
/// wired to `net`. Against a 5 µm spacing the pair is flagged when the gap is
/// below it and the nets differ: on OUT at 4 999 nm, not at 5 000; on SIG
/// itself never; two diffusions on OUT and VSS1, no pad between them, never.
fn esd_parasitic() -> Vec<Fixture> {
    let (vss1, sig, out_net) = (1, 5, 6);
    let deck = format!(
        "{}rule par esd_parasitic(pad, diff; min_spacing: 5um)\n",
        diode_process()
    );
    let board = |first: usize, gap: i64, net: usize| {
        let mut l = circuit(&DOMAIN_NETS, &[], &[]);
        rect(&mut l, "diff", (0, -6000, 1000, -5000));
        riser(&mut l, 400, -5900, first);
        let x0 = 1000 + gap;
        rect(&mut l, "diff", (x0, -6000, x0 + 1000, -5000));
        riser(&mut l, x0 + 400, -5900, net);
        let ty = track_y(sig);
        rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
        rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
        l
    };
    let mut out = Vec::new();
    for (name, first, gap, net, findings) in [
        ("other_net/4999", sig, 4999, out_net, vec![length(4999)]),
        ("other_net/5000", sig, 5000, out_net, Vec::new()),
        ("same_net", sig, 1000, sig, Vec::new()),
        ("no_pad", vss1, 1000, out_net, Vec::new()),
    ] {
        let f = Fixture::new(&format!("erc/esd_parasitic/{name}"), &["ERC-C10"], &deck)
            .layout(board(first, gap, net))
            .expect(Expect::rule("par", findings));
        out.extend(every_placement(&[f]));
    }
    out
}

/// `esd_exposed` (ERC-C3, Khazhinsky 2012's "input buffer gates and output
/// buffer drains") with a pad on SIG, `dio` clamps and an `rs` series
/// resistor from SIG to OUT. An input gate on SIG is protected by the
/// primary diodes (VSS1 to SIG, SIG to VDD1) and flagged without them
/// (rails 0) or with only the down one (rails 1); a gate on OUT behind the
/// resistor needs local diodes on OUT. An NMOS with its drain on SIG is an
/// output driver: flagged as `nfet`, protected as the ESD-rated `clamp`.
fn esd_exposed() -> Vec<Fixture> {
    type Case<'a> = (
        &'a str,
        Vec<Dev>,
        Vec<(&'a str, usize, usize)>,
        Vec<Finding>,
    );
    let (vdd1, vss1, vss3, sig, out_net) = (0, 1, 4, 5, 6);
    let deck = format!(
        "{}rule exp esd_exposed(pad; clamps: [\"dio\"], resistors: [\"rs\"], \
         rated: [\"clamp\"], min_series: none)\n",
        diode_process()
    );
    let down = ("mkdi", vss1, sig);
    let up = ("mkdi", sig, vdd1);
    let series = ("mkres", sig, out_net);
    let local = [("mkdi", vss1, out_net), ("mkdi", out_net, vdd1)];
    let input = dev(Model::Nfet, sig, vss1, vss3);
    let behind = dev(Model::Nfet, out_net, vss1, vss3);
    let mut cases: Vec<Case> = vec![
        ("input_primary", vec![input], vec![down, up], Vec::new()),
        ("input_bare", vec![input], Vec::new(), vec![count(0)]),
        ("input_down_only", vec![input], vec![down], vec![count(1)]),
        (
            "behind_bare",
            vec![behind],
            vec![down, up, series],
            vec![count(0)],
        ),
        (
            "output_unrated",
            vec![dev(Model::Nfet, vss3, vss1, sig)],
            vec![down, up],
            vec![count(0)],
        ),
        (
            "output_rated",
            vec![dev(Model::Clamp, vss3, vss1, sig)],
            vec![down, up],
            Vec::new(),
        ),
    ];
    let mut behind_local = vec![down, up, series];
    behind_local.extend(local);
    cases.push(("behind_local", vec![behind], behind_local, Vec::new()));
    let mut out = Vec::new();
    for (name, devs, pins, findings) in cases {
        let mut l = circuit_pins(&DOMAIN_NETS, &devs, &pins);
        let ty = track_y(sig);
        rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
        rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
        let mut f = Fixture::new(&format!("erc/esd_exposed/{name}"), &["ERC-C3"], &deck)
            .layout(l)
            .expect(Expect::rule("exp", findings));
        f.intent = Some(domain_intent());
        out.extend(every_placement(&[f]));
    }
    out
}

/// `esd_exposed`'s `min_series` (ERC-C3), the secondary stage, hand-derived.
/// The `rs` resistor states `sheet 100ohm`; [`circuit_pins`] draws its
/// marker 400 nm along its ends and 200 nm across, so each is 200 Ω. The pad
/// is on SIG; every gate behind a resistor has local clamps on its net.
///
/// - a gate on the pad net: 0 Ω, flagged against 150 Ω;
/// - behind one resistor: 200 Ω, flagged against 300 Ω, clean at 150 Ω;
/// - behind two in parallel: 100 Ω (effective), flagged against 150 Ω;
/// - behind two in series through MID: 400 Ω, clean against 300 Ω;
/// - a resistor with no `sheet` cannot be valued: the row is refused.
fn esd_secondary() -> Vec<Fixture> {
    let labels = ["VDD1", "VSS1", "VDD2", "VSS2", "VSS3", "SIG", "OUT", "MID"];
    let (vdd1, vss1, vss3, sig, out_net, mid) = (0, 1, 4, 5, 6, 7);
    let valued = diode_process().replace(
        "model \"rs\" terminals [diff, diff]",
        "model \"rs\" terminals [diff, diff] sheet 100ohm",
    );
    let deck = |process: &str, min: f64| {
        format!(
            "{process}rule exp esd_exposed(pad; clamps: [\"dio\"], resistors: [\"rs\"], \
             rated: none, min_series: {min}ohm)\n"
        )
    };
    let primary = [("mkdi", vss1, sig), ("mkdi", sig, vdd1)];
    let local = [("mkdi", vss1, out_net), ("mkdi", out_net, vdd1)];
    let input = dev(Model::Nfet, sig, vss1, vss3);
    let behind = dev(Model::Nfet, out_net, vss1, vss3);
    let one = [("mkres", sig, out_net)];
    let parallel = [("mkres", sig, out_net), ("mkres", sig, out_net)];
    let chain = [("mkres", sig, mid), ("mkres", mid, out_net)];
    let pins = |extra: &[(&'static str, usize, usize)], with_local: bool| {
        let mut all: Vec<(&str, usize, usize)> = primary.to_vec();
        all.extend_from_slice(extra);
        if with_local {
            all.extend_from_slice(&local);
        }
        all
    };
    let cases: Vec<(&str, Dev, Vec<(&str, usize, usize)>, f64, Vec<Finding>)> = vec![
        ("on_pad", input, pins(&[], false), 150.0, vec![ohms(0.0)]),
        (
            "one/below",
            behind,
            pins(&one, true),
            300.0,
            vec![ohms(200.0)],
        ),
        ("one/above", behind, pins(&one, true), 150.0, vec![]),
        (
            "parallel",
            behind,
            pins(&parallel, true),
            150.0,
            vec![ohms(100.0)],
        ),
        ("series", behind, pins(&chain, true), 300.0, vec![]),
    ];
    let mut out = Vec::new();
    for (name, device, all, min, findings) in cases {
        let mut l = circuit_pins(&labels, &[device], &all);
        let ty = track_y(sig);
        rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
        rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
        let mut f = Fixture::new(
            &format!("erc/esd_exposed/secondary/{name}"),
            &["ERC-C3"],
            &deck(&valued, min),
        )
        .layout(l.clone())
        .expect(Expect::rule("exp", findings));
        f.intent = Some(domain_intent());
        out.extend(every_placement(&[f]));
        if name == "one/below" {
            let mut g = Fixture::new(
                "erc/esd_exposed/secondary/unvalued",
                &["ERC-C3"],
                &deck(&diode_process(), min),
            )
            .layout(l)
            .expect(Expect::outcome("exp", Want::Refused));
            g.intent = Some(domain_intent());
            out.push(g);
        }
    }
    out
}

/// `esd_path` with a source layer (ERC-D4, JESD78's injection into a guard
/// ring): `met1` as the ring layer, so VSS's strip is the ring; 100 mA forced
/// in at its centre and out at VSS's own pin, a `pad` square at 18 µm joined
/// by one 0.25 Ω cut, with no clamps. Its path is 8 squares of met1 (1 Ω)
/// and the cut: 1.25 Ω exactly, swept below, at and above; the 1 µm strip
/// carries the whole 100 mA, flagged below 0.1 A/µm. With no pin VSS is fed
/// at the strip's centre, where the current enters: 0 Ω.
fn ring_injection() -> Vec<Fixture> {
    let deck = |limits: &str| {
        format!(
            "{ESD_PROCESS}rule ring esd_path(pad, met1; clamps: none, current: 100mA, \
             clamp_resistance: 1ohm, {limits}, clamp_it2: none, max_current_per_cut: none, \
             max_voltage: none, min_width: none, clamp_voltage: none)\n"
        )
    };
    let pinned = {
        let mut l = esd_layout([1000; 3], &[]);
        rect(&mut l, "pad", (17_500, -3000, 18_500, -2000));
        rect(&mut l, "padv", (17_900, -2600, 18_100, -2400));
        l
    };
    let mut out = Vec::new();
    for limit in sweep(1.25) {
        let mut f = Fixture::new(
            &format!("erc/esd_path/ring/{}", side(limit, 1.25)),
            &["ERC-D4"],
            &deck(&format!("max_resistance: {limit}ohm, max_density: none")),
        )
        .layout(pinned.clone())
        .expect(Expect::rule(
            "ring",
            if limit < 1.25 {
                vec![ohms(1.25).at(0, -3000)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(esd_intent());
        out.push(f);
    }
    for density in [1e5 * 0.999, 1e5 * 1.001] {
        let mut f = Fixture::new(
            &format!("erc/esd_path/ring/density/{}", side(density, 1e5)),
            &["ERC-D4"],
            &deck(&format!("max_resistance: none, max_density: {density}A/m")),
        )
        .layout(pinned.clone())
        .expect(Expect::rule(
            "ring",
            if density < 1e5 {
                vec![microamps(1e5)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(esd_intent());
        out.extend(every_placement(&[f]));
    }
    let mut f = Fixture::new(
        "erc/esd_path/ring/unpinned",
        &["ERC-D4"],
        &deck("max_resistance: 0.001ohm, max_density: none"),
    )
    .layout(esd_layout([1000; 3], &[]))
    .expect(Expect::clean("ring"));
    f.intent = Some(esd_intent());
    out.push(f);
    out
}

/// Two labelled metals with a via between them, and two voltage tables:
/// met1 to met1 needs 200 nm from 0 V, 400 nm from 1.5 V and 800 nm from 3 V;
/// met1 to met2 needs 500 nm from 1 V.
const VS_DECK: &str = "grid 1nm
layer met1 = gds(1, 0)
layer m1txt = gds(1, 1)
layer met2 = gds(2, 0)
layer m2txt = gds(2, 1)
layer v1 = gds(3, 0)
connect conductors [met1, met2]
connect touch_within_layer
connect via v1 [met1, met2]
connect label m1txt names met1
connect label m2txt names met2
rule vs voltage_space(met1; voltage: [0V, 1.5V, 3V], space: [200nm, 400nm, 800nm])
rule vs2 voltage_space(met1, met2; voltage: [1V], space: [500nm])
";

const VS_CATALOG: &[&str] = &["DRC-082", "ERC-F11"];

/// The space `vs` needs between two nets `delta` mV apart, read off the
/// table in its definition: the last step whose voltage `delta` reaches.
fn vs_need(delta: i64) -> Option<i64> {
    [(0, 200), (1500, 400), (3000, 800)]
        .iter()
        .rev()
        .find(|&&(volts, _)| volts <= delta)
        .map(|&(_, space)| space)
}

/// Intent putting net A at `1000 + delta` mV (domain `hi`) and net B at
/// 1000 mV (domain `lo`), both power: `delta` apart at worst.
fn vs_intent(delta: i64) -> String {
    intent(
        &[("hi", (1000 + delta) as f64), ("lo", 1000.0)],
        &[("A", "hi", "power"), ("B", "lo", "power")],
        &[],
    )
}

/// `voltage_space` (DRC-082, ERC-F11) on two met1 bars `gap` apart, nets A
/// and B `delta` mV apart, swept against both: every step's voltage a
/// millivolt either side, every step's space and one nanometre under it.
/// Oracle: the table by hand ([`vs_need`]); a pair is flagged, measuring its
/// gap, exactly when the gap is below the space the voltage needs. The
/// boundary of each delta's own step is placed under every symmetry and
/// offset. Then: a net no supply reaches and two shapes of one net are not
/// judged however close; a met1 shape on A and a met2 shape on B, 1 V apart
/// or a millivolt less, overlapping or `499`/`500` nm apart (`vs2`); a ground
/// at 0 V against 3 V; and no intent, Skipped.
fn voltage_spacing() -> Vec<Fixture> {
    let mut out = Vec::new();
    for delta in [0, 1499, 1500, 1501, 2999, 3000, 3001, 5000] {
        let need = vs_need(delta).expect("the first step is at 0 V");
        for gap in [199, 200, 399, 400, 799, 800] {
            let mut f = Fixture::new(
                &format!("erc/voltage_spacing/{delta}mV/{gap}nm"),
                VS_CATALOG,
                VS_DECK,
            )
            .layout(
                Layout::default()
                    .rect("met1", 0, 0, 1000, 500)
                    .rect("met1", 1000 + gap, 0, 2000 + gap, 500)
                    .label("m1txt", 500, 250, "A")
                    .label("m1txt", 1500 + gap, 250, "B"),
            )
            .expect(Expect::rule(
                "vs",
                if gap < need {
                    vec![length(gap)]
                } else {
                    Vec::new()
                },
            ))
            .expect(Expect::clean("vs2"));
            f.intent = Some(vs_intent(delta));
            if gap == need || gap == need - 1 {
                out.extend(every_placement(&[f]));
            } else {
                out.push(f);
            }
        }
    }
    // A, then 100 nm off it an unlabelled bar no supply reaches; B far away.
    let mut f = Fixture::new("erc/voltage_spacing/unreached", VS_CATALOG, VS_DECK)
        .layout(
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .rect("met1", 1100, 0, 2100, 500)
                .rect("met1", 20_000, 0, 21_000, 500)
                .label("m1txt", 500, 250, "A")
                .label("m1txt", 20_500, 250, "B"),
        )
        .expect(Expect::clean("vs"))
        .expect(Expect::clean("vs2"));
    f.intent = Some(vs_intent(5000));
    out.extend(every_placement(&[f]));
    // Two met1 bars of A 100 nm apart, bridged on met2 through vias: one
    // net, at one voltage, so neither table judges them.
    let mut f = Fixture::new("erc/voltage_spacing/same_net", VS_CATALOG, VS_DECK)
        .layout(
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .rect("met1", 1100, 0, 2100, 500)
                .rect("met2", 0, 0, 2100, 500)
                .rect("v1", 400, 200, 500, 300)
                .rect("v1", 1600, 200, 1700, 300)
                .rect("met1", 20_000, 0, 21_000, 500)
                .label("m1txt", 200, 250, "A")
                .label("m1txt", 20_500, 250, "B"),
        )
        .expect(Expect::clean("vs"))
        .expect(Expect::clean("vs2"));
    f.intent = Some(vs_intent(5000));
    out.extend(every_placement(&[f]));
    // met1 on A against met2 on B: a cross (overlap, distance 0), or a met2
    // bar 499 or 500 nm off the met1 bar's end.
    for delta in [999, 1000] {
        for (name, met2, gap) in [
            ("overlap", (400, -1000, 600, 1500), 0),
            ("499nm", (1499, 0, 2499, 500), 499),
            ("500nm", (1500, 0, 2500, 500), 500),
        ] {
            let mut layout = Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .label("m1txt", 200, 250, "A");
            rect(&mut layout, "met2", met2);
            let layout = layout.label("m2txt", met2.2 - 50, 250, "B");
            let mut f = Fixture::new(
                &format!("erc/voltage_spacing/two_layers/{delta}mV/{name}"),
                VS_CATALOG,
                VS_DECK,
            )
            .layout(layout)
            .expect(Expect::clean("vs"))
            .expect(Expect::rule(
                "vs2",
                if delta >= 1000 && gap < 500 {
                    vec![length(gap)]
                } else {
                    Vec::new()
                },
            ));
            f.intent = Some(vs_intent(delta));
            out.extend(every_placement(&[f]));
        }
    }
    // A ground at 0 V against a 3 V power net: 3 V apart, 800 nm needed.
    for gap in [799, 800] {
        let mut f = Fixture::new(
            &format!("erc/voltage_spacing/ground/{gap}nm"),
            VS_CATALOG,
            VS_DECK,
        )
        .layout(
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .rect("met1", 1000 + gap, 0, 2000 + gap, 500)
                .label("m1txt", 500, 250, "A")
                .label("m1txt", 1500 + gap, 250, "B"),
        )
        .expect(Expect::rule(
            "vs",
            if gap < 800 {
                vec![length(gap)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(intent(
            &[("hi", 3000.0), ("lo", 1800.0)],
            &[("A", "hi", "power"), ("B", "lo", "ground")],
            &[],
        ));
        out.push(f);
    }
    out.push(
        Fixture::new("erc/voltage_spacing/no_intent", VS_CATALOG, VS_DECK)
            .layout(
                Layout::default()
                    .rect("met1", 0, 0, 1000, 500)
                    .rect("met1", 1100, 0, 2100, 500),
            )
            .expect(Expect::outcome("vs", Want::Skipped))
            .expect(Expect::outcome("vs2", Want::Skipped)),
    );
    out
}

// ------------------------------------------------------- hv_tag, mixed_tag

/// A transistor whose source and drain diffusions reach met1 through
/// contacts, its poly through a poly contact; `hvi` tags; `sw` conducts
/// only while its gate can reach 1 V.
const TAG_DECK: &str = "grid 1nm
layer diff = gds(1, 0)
layer poly = gds(2, 0)
layer mk = gds(3, 0)
layer mks = gds(4, 0)
layer cont = gds(5, 0)
layer pcont = gds(6, 0)
layer met1 = gds(7, 0)
layer m1txt = gds(7, 1)
layer met2 = gds(8, 0)
layer v1 = gds(9, 0)
layer res = gds(10, 0)
layer hvi = gds(11, 0)
connect conductors [diff, poly, met1, met2]
connect touch_within_layer
connect via cont [diff, met1]
connect via pcont [poly, met1]
connect via v1 [met1, met2]
connect label m1txt names met1
device mos mk model \"n\" terminals [poly, diff, diff]
device mos mks model \"sw\" terminals [poly, diff, diff] on_gate_min 1V
device resistor res model \"r\" terminals [met1, met1]
rule hvt hv_tag(met1, hvi; voltage: 3V)
rule mix mixed_tag(met1, hvi)
";

/// A transistor of marker `marker` at the origin: source diffusion on met1
/// pad S (0..1000), drain on met1 pad D (1200..2200), the gate's poly out
/// to a met1 pad G above, each pad 1000 × 500.
fn tagged_transistor(marker: &str) -> Layout {
    let mut l = Layout::default();
    rect(&mut l, "diff", (0, 0, 1000, 1000));
    rect(&mut l, "diff", (1200, 0, 2200, 1000));
    rect(&mut l, "poly", (1000, 0, 1200, 2000));
    rect(&mut l, marker, (1000, 0, 1200, 1000));
    rect(&mut l, "cont", (400, 400, 600, 600));
    rect(&mut l, "cont", (1600, 400, 1800, 600));
    rect(&mut l, "pcont", (1050, 1700, 1150, 1800));
    rect(&mut l, "met1", (0, 250, 1000, 750));
    rect(&mut l, "met1", (1200, 250, 2200, 750));
    rect(&mut l, "met1", (900, 1600, 1300, 2100));
    l
}

/// `hv_tag(met1, hvi; voltage: 3V)` (DRC-083). Oracle: the definition by
/// hand: a met1 figure whose net can reach 3 V or more lies inside `hvi`,
/// or is reported with the area it leaves outside. A pad on a supply swept
/// a millivolt either side of 3 V, uncovered and half covered; a pad joined
/// to the 3.3 V supply through a transistor channel is high-voltage too
/// (sky130 hv.X.4), unless the transistor is a switch whose gate, tied to
/// ground, never turns it on (ERC-F1); a 1.8 V pad is never judged; no
/// intent, Skipped. Every case under every symmetry and offset.
fn hv_tag() -> Vec<Fixture> {
    let mut cases = Vec::new();
    let pad = Layout::default()
        .rect("met1", 0, 0, 1000, 500)
        .label("m1txt", 100, 250, "HV");
    for mv in [2999.0, 3000.0, 3001.0] {
        for (name, hvi, outside) in [
            ("bare", None, 500_000),
            ("half", Some((500, -100, 1100, 600)), 250_000),
            ("covered", Some((-100, -100, 1100, 600)), 0),
        ] {
            let mut layout = pad.clone();
            if let Some(hvi) = hvi {
                rect(&mut layout, "hvi", hvi);
            }
            let findings = if mv >= 3000.0 && outside > 0 {
                vec![Finding::area(outside)]
            } else {
                Vec::new()
            };
            let mut f = Fixture::new(
                &format!("erc/hv_tag/pad/{}/{name}", side(3000.0, mv)),
                &["DRC-083"],
                TAG_DECK,
            )
            .layout(layout)
            .expect(Expect::rule("hvt", findings));
            f.intent = Some(intent(&[("hv", mv)], &[("HV", "hv", "power")], &[]));
            cases.push(f);
        }
    }
    // HV on S, the 1.8 V core supply on G, VSS on nothing: D reaches 3.3 V
    // through the channel. `hvi` covers S only, so D (500 000 nm²) is
    // reported; with the switch and G on VSS the channel never conducts.
    for (name, marker, gate_net, findings) in [
        ("through_channel", "mk", "VDD", vec![Finding::area(500_000)]),
        ("switch_on", "mks", "VDD", vec![Finding::area(500_000)]),
        ("switch_off", "mks", "VSS", Vec::new()),
    ] {
        let mut layout = tagged_transistor(marker)
            .label("m1txt", 100, 500, "HV")
            .label("m1txt", 1000, 2000, gate_net);
        rect(&mut layout, "hvi", (-100, 150, 1100, 850));
        let mut f = Fixture::new(
            &format!("erc/hv_tag/propagated/{name}"),
            &["DRC-083"],
            TAG_DECK,
        )
        .layout(layout)
        .expect(Expect::rule("hvt", findings));
        f.intent = Some(intent(
            &[("core", 1800.0), ("hv", 3300.0)],
            &[
                ("HV", "hv", "power"),
                ("VDD", "core", "power"),
                ("VSS", "core", "ground"),
            ],
            &[],
        ));
        cases.push(f);
    }
    let mut f = Fixture::new("erc/hv_tag/low_voltage", &["DRC-083"], TAG_DECK)
        .layout(
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .label("m1txt", 100, 250, "VDD"),
        )
        .expect(Expect::clean("hvt"));
    f.intent = Some(intent(
        &[("core", 1800.0)],
        &[("VDD", "core", "power")],
        &[],
    ));
    cases.push(f);
    let mut out = every_placement(&cases);
    out.push(
        Fixture::new("erc/hv_tag/no_intent", &["DRC-083"], TAG_DECK)
            .layout(pad)
            .expect(Expect::outcome("hvt", Want::Skipped)),
    );
    out
}

/// `mixed_tag(met1, hvi)` (ERC-F10, sky130 hvnwell.10). Oracle: the
/// definition by hand: a met1 figure sharing no area with `hvi`, on a net
/// (nets joined through a resistor counted as one) that holds a figure
/// sharing area with it, is reported with the count of such figures. Two
/// pads, one under `hvi`, joined on met2 through vias, joined through a
/// resistor, or apart; a pad that only abuts `hvi` is untagged; two tagged
/// pads on one net; no `hvi` at all. Needs no intent. Every case under every
/// symmetry and offset.
fn mixed_tag() -> Vec<Fixture> {
    let pads = |joined: &str| {
        let mut l = Layout::default()
            .rect("met1", 0, 0, 1000, 500)
            .rect("met1", 3000, 0, 4000, 500);
        match joined {
            "strapped" => {
                rect(&mut l, "met2", (0, 0, 4000, 500));
                rect(&mut l, "v1", (400, 200, 500, 300));
                rect(&mut l, "v1", (3400, 200, 3500, 300));
            }
            "resistor" => {
                rect(&mut l, "met1", (1000, 0, 1500, 500));
                rect(&mut l, "res", (1500, 0, 2500, 500));
                rect(&mut l, "met1", (2500, 0, 3000, 500));
            }
            _ => {}
        }
        l
    };
    let mut cases = Vec::new();
    for (joined, hvi, findings) in [
        ("strapped", Some((-100, -100, 1100, 600)), vec![count(1)]),
        ("resistor", Some((-100, -100, 1100, 600)), vec![count(1)]),
        ("apart", Some((-100, -100, 1100, 600)), Vec::new()),
        ("strapped", None, Vec::new()),
        ("strapped", Some((-1000, -100, 0, 600)), Vec::new()),
        ("strapped", Some((-100, -100, 4100, 600)), Vec::new()),
    ] {
        let mut layout = pads(joined);
        let tag = match hvi {
            None => "untagged".to_owned(),
            Some(hvi) => {
                rect(&mut layout, "hvi", hvi);
                format!("{}_{}", hvi.0, hvi.2)
            }
        };
        cases.push(
            Fixture::new(
                &format!("erc/mixed_tag/{joined}/{tag}"),
                &["ERC-F10"],
                TAG_DECK,
            )
            .layout(layout)
            .expect(Expect::rule("mix", findings)),
        );
    }
    every_placement(&cases)
}

// ---------------------------------------------------------- dielectric_field

/// Two labelled metals in a stack: met1 from 1000 to 1300 nm, met2 from
/// 1700 nm, so 400 nm of dielectric between them; met3 states no stack row.
/// Each table allows 10 V/µm (10 mV per nm).
const FIELD_DECK: &str = "grid 1nm
layer met1 = gds(1, 0)
layer m1txt = gds(1, 1)
layer met2 = gds(2, 0)
layer m2txt = gds(2, 1)
layer met3 = gds(3, 0)
connect conductors [met1, met2, met3]
connect touch_within_layer
connect label m1txt names met1
connect label m2txt names met2
pex met1 thickness 300nm height 1000nm sheet 0.1ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met2 thickness 300nm height 1700nm sheet 0.1ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
rule df dielectric_field(met1; max_field: 10V/um)
rule df2 dielectric_field(met1, met2; max_field: 10V/um)
rule df3 dielectric_field(met1, met3; max_field: 10V/um)
";

/// `dielectric_field` (ERC-F13). Oracle: the closed form, field = ΔV over
/// the separation (CF), by hand: on met1, nets 3 V apart need
/// 3000 mV / (10 mV/nm) = 300 nm, and 3.01 V apart 301 nm; between met1
/// and met2, 400 nm of dielectric under nets 5 V apart needs a 500 nm
/// separation, a lateral 300 nm (the 3-4-5 triangle), and 4 V is exactly
/// held by the 400 nm alone, 4.001 V not (a lateral 9 nm: sqrt(400.1² -
/// 400²) = 8.94, rounded up). A pair is flagged, measuring its lateral gap,
/// below its limit. met3 has no stack row: refused. Every case under every
/// symmetry and offset.
fn dielectric_field() -> Vec<Fixture> {
    let mut cases = Vec::new();
    let bars = |layer_b: &str, text_b: &str, gap: i64| {
        Layout::default()
            .rect("met1", 0, 0, 1000, 500)
            .rect(layer_b, 1000 + gap, 0, 2000 + gap, 500)
            .label("m1txt", 500, 250, "A")
            .label(text_b, 1500 + gap, 250, "B")
    };
    for (delta, gap, flagged) in [
        (3000, 299, true),
        (3000, 300, false),
        (3010, 300, true),
        (2990, 299, false),
    ] {
        let mut f = Fixture::new(
            &format!("erc/dielectric_field/one_layer/{delta}mV/{gap}nm"),
            &["ERC-F13"],
            FIELD_DECK,
        )
        .layout(bars("met1", "m1txt", gap))
        .expect(Expect::rule(
            "df",
            if flagged {
                vec![length(gap)]
            } else {
                Vec::new()
            },
        ))
        .expect(Expect::clean("df2"))
        .expect(Expect::outcome("df3", Want::Refused));
        f.intent = Some(vs_intent(delta));
        cases.push(f);
    }
    for (delta, gap, flagged) in [(5000, 299, true), (5000, 300, false)] {
        let mut f = Fixture::new(
            &format!("erc/dielectric_field/two_layers/{delta}mV/{gap}nm"),
            &["ERC-F13"],
            FIELD_DECK,
        )
        .layout(bars("met2", "m2txt", gap))
        .expect(Expect::clean("df"))
        .expect(Expect::rule(
            "df2",
            if flagged {
                vec![length(gap)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(vs_intent(delta));
        cases.push(f);
    }
    for (delta, flagged) in [(4000, false), (4001, true)] {
        let mut f = Fixture::new(
            &format!("erc/dielectric_field/crossing/{delta}mV"),
            &["ERC-F13"],
            FIELD_DECK,
        )
        .layout(
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .rect("met2", 400, -1000, 600, 1500)
                .label("m1txt", 100, 250, "A")
                .label("m2txt", 500, 1400, "B"),
        )
        .expect(Expect::rule(
            "df2",
            if flagged { vec![length(0)] } else { Vec::new() },
        ));
        f.intent = Some(vs_intent(delta));
        cases.push(f);
    }
    every_placement(&cases)
}

// ------------------------------------------------- dynamic drop, thermal EM

// ------------------------------------------------------------------ tests

/// Oracle: LEF/DEF 5.8 Appendix C's antenna ratios (its example C-20 worked
/// by hand), the foundry tables each fixture cites, and the PWL, diode and
/// cut-factor arithmetic in each group's doc comment.
#[test]
fn antenna_rows_match_lef_and_the_foundry_tables() {
    let mut all = antenna_lef();
    all.extend(antenna_sidewall());
    all.extend(antenna_variants());
    all.extend(antenna_electrical());
    all.extend(gf180_mim());
    check_all(&all);
}

/// Oracle: `density_oracle`, the window density computed by clipping each
/// metal rectangle to each window, written from the rule's definition.
#[test]
fn density_rows_match_a_window_by_window_clip() {
    check_all(&density());
}

/// Oracle: `Board`'s naive judge of every topology rule on a small circuit
/// as planted (a graph search over the nets it wired), on every sampled
/// assignment of devices to nets.
#[test]
fn topology_boards_match_a_naive_judge_of_the_planted_circuit() {
    check_all(&topology_enumerations(Depth::Merge));
}

/// Oracle: the named circuits' hand-derived findings (the gate paths, loops,
/// matched pairs and switches each group's doc comment derives).
#[test]
fn named_topology_circuits_report_their_derived_findings() {
    let mut all = topology_cases();
    all.extend(path_through_resistor());
    all.extend(path_stops_at_port());
    all.extend(combinational_loop());
    all.extend(matching());
    all.extend(power_switch());
    check_all(&all);
}

/// Oracle: `Board`'s naive judge for `esd_topological` and `esd_latchup`,
/// and the closed forms of the strip circuits: series and parallel
/// resistances of strips of known sheet resistance, Kirchhoff's current law
/// for clamp shares, White Paper 2's turn-on sum, each limit swept a part in
/// a thousand either side, placed under the symmetries of the square.
#[test]
fn esd_paths_match_their_closed_forms() {
    let mut all = esd(Depth::Merge);
    all.extend(esd_wiring());
    all.extend(esd_path());
    all.extend(esd_clamp_size());
    all.extend(esd_interconnect());
    all.extend(esd_layout_rules());
    all.extend(esd_pin_pair());
    all.extend(esd_window());
    check_all(&all);
}

/// Oracle: the constructions in each group's doc comment: which grounds an
/// anti-parallel pair couples, which crossings a domain's clamps protect,
/// ring widths and tap distances against GF180MCU's latch-up rules, junction
/// spacings, exposed gates and their series resistance.
#[test]
fn esd_domains_and_latchup_rows_report_their_derived_findings() {
    let mut all = ring_injection();
    all.extend(ground_coupling());
    all.extend(cross_domain());
    all.extend(guard_ring_bias());
    all.extend(tie_area());
    all.extend(guard_ring());
    all.extend(forward_diode());
    all.extend(conditional_tie());
    all.extend(latchup_victim());
    all.extend(voltage_aggressor());
    all.extend(esd_parasitic());
    all.extend(esd_exposed());
    all.extend(esd_secondary());
    check_all(&all);
}

/// Oracle: the voltage tables, tags and field limits each group's doc
/// comment derives from LEF58_VOLTAGESPACING and the dielectric's rating.
#[test]
fn voltage_spacing_tags_and_fields_report_their_derived_findings() {
    let mut all = voltage_spacing();
    all.extend(hv_tag());
    all.extend(mixed_tag());
    all.extend(dielectric_field());
    check_all(&all);
}
