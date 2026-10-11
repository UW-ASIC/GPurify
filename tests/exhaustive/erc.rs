//! Electrical rules: all twenty-four ERC kinds, each against an oracle written
//! here from its definition, never from a run.
//!
//! - Electrical kinds against closed forms worked out in this file: Ohm's law
//!   on resistor ladders and a current divider (`ir_drop`, `p2p_resistance`),
//!   current per width and per cut (`em_current_density`), Black's equation
//!   with the Blech exemption and the GF180MCU §14.2.2 derating table
//!   (`electromigration`), the inverse power law times Arrhenius
//!   (`reliability`), the antenna ratios of LEF/DEF 5.8 Appendix C and IHP
//!   SG13G2 §7.1 (`antenna`, `antenna_electrical`), and window densities
//!   (`density_cmp`). Each is swept below, at and above its limit.
//! - Topological and voltage kinds against a naive graph oracle ([`Board`]):
//!   transistors are drawn as diffusion, poly and a channel marker, wired by
//!   met1 risers to one met2 track per net, and every assignment of terminals
//!   to nets is enumerated (a seeded sample at merge depth). The oracle
//!   re-derives each rule from its rustdoc: role masks per net, pull networks
//!   to the declared rails per net, supply reach over the transistor channels
//!   that can conduct (gate-conditioned switches swept to a fixed point), the
//!   clamp path from a pad.
//! - Geometric kinds (`floating_well`, `missing_tie`, `supply_short`,
//!   `soft_connection`, the `esd_latchup` guard ring) on shapes whose answer is
//!   known by construction, and the three expressible rows on DRC kinds.
//! - Every kind that needs design intent records Skipped without it.
//!
//! A fixture that fails because `GPurify` disagrees with the definition carries
//! the finding it fails on; none is left. A fixed finding's fixtures name it
//! in their comments: F25 to F29 (F28's drawing-order cases in
//! [`topology_cases`]), F35, F72 ([`metal_over_a_gate`]) and F81
//! ([`gate_on_its_device_poly`]) from
//! `docs/testing-plan.md`, and four found here:
//!
//! - `F59`: the cumulative antenna ratio pooled all gates of the net at the
//!   top stage, where IHP's `AreaRatio` sums one ratio per layer over the
//!   gates joined at that layer ([`ihp_area_ratio`]).
//! - `F60`: an `antenna` row could not see a protection diode, so a gate
//!   with one was held to IHP's no-diode limit Ant.b ([`antenna_electrical`]).
//! - `F61`: a ground rail's solve was one ulp off an exactly representable
//!   drop, so a node exactly at its `max_drop_mv` was flagged ([`ir_drop`]).
//! - `F62`: `hv_domain` isolation drawn exactly on a device's marker did not
//!   exempt it, though the marker is wholly covered ([`topology_cases`]).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test geometry: counts and coordinates far below 2^31, areas below 2^53"
)]

use crate::harness::{Depth, Expect, Finding, Fixture, Layout, Want, NONE};
use gpurify::check::report::Measurement;
use gpurify::engine::run::Checks;
use gpurify::geom::{Dbu, Qty, MAX_ABS_DBU};
use gpurify_testgen::Rng;

/// ERC alone.
const ERC: Checks = Checks { erc: true, ..NONE };
/// DRC alone, for the ERC rows the catalog marks expressible as DRC kinds.
const DRC: Checks = Checks { drc: true, ..NONE };
/// The translations a placed case is repeated at.
const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];
/// Boltzmann's constant in eV/K (CODATA 2018).
const K_EV: f64 = 8.617_333_262e-5;
/// The engine's sign-off temperature, 85 °C, in kelvin.
const T_SIGNOFF: f64 = 85.0 + 273.15;

/// Every fixture this module generates at `depth`.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    out.extend(antenna_lef());
    out.extend(antenna_sidewall());
    out.extend(antenna_variants());
    out.extend(antenna_electrical());
    out.extend(density());
    out.extend(ir_drop(depth));
    out.extend(em_current_density(depth));
    out.extend(electromigration());
    out.extend(reliability());
    out.extend(p2p(depth));
    out.extend(grid_outcomes());
    out.extend(topology_enumerations(depth));
    out.extend(topology_cases());
    out.extend(esd(depth));
    out.extend(supply_short(depth));
    out.extend(soft_connection());
    out.extend(floating_well(depth));
    out.extend(missing_tie());
    out.extend(expressible());
    out
}

// ------------------------------------------------------------------ helpers

fn measured(m: Measurement) -> Finding {
    Finding {
        measured: Some(m),
        at: None,
    }
}

fn ratio(x: f64) -> Finding {
    measured(Measurement::Ratio(x))
}

fn count(n: u32) -> Finding {
    measured(Measurement::Count(n))
}

fn millivolts(x: f64) -> Finding {
    measured(Measurement::Voltage(Qty::new(x)))
}

fn microamps(x: f64) -> Finding {
    measured(Measurement::Current(Qty::new(x)))
}

fn ohms(x: f64) -> Finding {
    measured(Measurement::Resistance(Qty::new(x)))
}

fn length(nm: i64) -> Finding {
    measured(Measurement::Length(Dbu::new_unchecked(nm)))
}

/// Where a limit sits against the value it is swept around.
fn side(limit: f64, value: f64) -> &'static str {
    match limit.total_cmp(&value) {
        std::cmp::Ordering::Less => "below",
        std::cmp::Ordering::Equal => "at",
        std::cmp::Ordering::Greater => "above",
    }
}

/// `value` and one part in a thousand either side: the three limits a value is
/// swept with. The middle one is the value itself, so a deck writing it with
/// `{}` reads back the same `f64`.
fn sweep(value: f64) -> [f64; 3] {
    [value * 0.999, value, value * 1.001]
}

/// A box `(xlo, ylo, xhi, yhi)` in nanometres.
type Rect = (i64, i64, i64, i64);

/// Adds a rectangle to a layout in place.
fn rect(layout: &mut Layout, layer: &str, (xlo, ylo, xhi, yhi): Rect) {
    *layout = std::mem::take(layout).rect(layer, xlo, ylo, xhi, yhi);
}

/// Each fixture under every symmetry of the square at every offset.
fn every_placement(fixtures: &[Fixture]) -> Vec<Fixture> {
    fixtures
        .iter()
        .flat_map(|f| {
            OFFSETS
                .iter()
                .flat_map(move |&(dx, dy)| f.every_symmetry(dx, dy))
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
                .map(move |&(dx, dy)| f.transformed(crate::harness::Symmetry::IDENTITY, dx, dy))
        })
        .collect()
}

/// All of `items` at nightly depth, a seeded sample of `merge` at merge depth.
fn sample<T: Clone>(items: &[T], depth: Depth, merge: usize, seed: u64) -> Vec<T> {
    if depth == Depth::Nightly || items.len() <= merge {
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

// ------------------------------------------------------------------ antenna

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
                    "rule {} antenna(gate, {}; max_ratio: {limit}, sidewall: none, diode: none)",
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
                    ERC,
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
                    "rule ant.side antenna(gate, met1; max_ratio: {limit}, sidewall: 350nm, diode: none)"
                )),
                ERC,
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
                    "rule ant.d antenna(gated, met1; max_ratio: {limit}, sidewall: none, diode: none)"
                )),
                ERC,
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
                        "rule {id} antenna({layer}, met1; max_ratio: {limit}, sidewall: none, diode: none)"
                    )),
                    ERC,
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
                    "rule ant.mim antenna(mim, met2; max_ratio: {limit}, sidewall: none, diode: none)"
                )),
                ERC,
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
                    "rule car antenna(gate, met1, met2, met3; max_ratio: {limit}, sidewall: none, diode: none)"
                )),
                ERC,
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
                "rule ant antenna(gate, met1; max_ratio: 1.75, sidewall: none, diode: none)",
            ),
            ERC,
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
                "rule ant antenna(gate, met1; max_ratio: 1.75, sidewall: none, diode: none)",
            ),
            ERC,
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
rule ant antenna(gated, met1; max_ratio: 1.0, sidewall: none, diode: none)",
    );
    Fixture::new(
        "erc/antenna/f81/direct_diff_poly_cut",
        &["ERC-A1"],
        &deck,
        ERC,
    )
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
                    "rule ant antenna({gate}, met1; max_ratio: 1.0, sidewall: none, diode: none)"
                )),
                ERC,
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
                "rule ant antenna(gate, via1; max_ratio: 0.01, sidewall: none, diode: none)",
            ),
            ERC,
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
        &antenna_deck("rule ant.b antenna(gate, met1, met2, met3; max_ratio: 100, sidewall: none, diode: none)"),
        ERC,
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
/// - A diode with a non-zero credit is refused, as its rustdoc and
///   limitations.md state.
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
                    "rule ae antenna_electrical(gate, met1; max_ratio: {limit}, diode: none, diode_credit: 0, diode_bonus: 0)"
                )),
                ERC,
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
                    "rule ae antenna_electrical(gate, met1; max_ratio: {limit}, diode: diff, diode_credit: 0, diode_bonus: 0.5)"
                )),
                ERC,
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
                "rule ae antenna_electrical(gate, met1; max_ratio: 1.75, diode: diff, diode_credit: 0, diode_bonus: 0.5)",
            ),
            ERC,
        )
        .layout(diode_stub(false))
        .expect(Expect::rule("ae", vec![ratio(2.0).at(500, 500)])),
    );
    out.push(
        Fixture::new(
            "erc/antenna_electrical/credit_is_refused",
            &["ERC-A5"],
            &antenna_deck(
                "rule ae antenna_electrical(gate, met1; max_ratio: 1000, diode: diff, diode_credit: 1, diode_bonus: 0)",
            ),
            ERC,
        )
        .layout(diode_stub(true))
        .expect(Expect::outcome("ae", Want::Refused)),
    );
    let ihp = "rule Ant.b antenna(gate, met1; max_ratio: 1.5, sidewall: none, diode: diff)
rule Ant.e antenna_electrical(gate, met1; max_ratio: 100, diode: diff, diode_credit: 0, diode_bonus: 0)";
    out.push(
        Fixture::new(
            "erc/antenna_electrical/ihp_b_e/with_diode",
            &["ERC-A8"],
            &antenna_deck(ihp),
            ERC,
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
            ERC,
        )
        .layout(diode_stub(false))
        .expect(Expect::rule("Ant.b", vec![ratio(2.0).at(500, 500)]))
        .expect(Expect::clean("Ant.e")),
    );
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
        let f = Fixture::new(&name, rows, &row.deck(window, step), ERC)
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
            ERC,
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
            ERC,
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
            ERC,
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

/// met1 0.125 Ω/sq at 100 nm, via1 0.0625 Ω per cut, met2 0.0625 Ω/sq at
/// 300 nm, poly 8 Ω/sq. A `load` is a resistor marker over one rail and a
/// private poly stub; it draws its share of its rail's budget where its
/// marker's centre lands on the rail. Nets are named by text on met1 or met2.
const RAIL_PROCESS: &str = "grid 1nm
layer met1 = gds(1, 0)
layer via1 = gds(2, 0)
layer met2 = gds(3, 0)
layer poly = gds(4, 0)
layer mk = gds(5, 0)
layer m1txt = gds(1, 1)
layer m2txt = gds(3, 1)
connect conductors [met1, met2, poly]
connect touch_within_layer
connect via via1 [met1, met2]
connect label m1txt names met1
connect label m2txt names met2
device resistor mk model \"load\" terminals [met1, poly]
pex met1 thickness 100nm height 100nm sheet 0.125ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex via1 thickness 100nm height 200nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met2 thickness 100nm height 300nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
";

/// The poly row, kept apart so a fixture can leave it out.
const RAIL_POLY_PEX: &str =
    "pex poly thickness 100nm height 50nm sheet 8ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um\n";

fn rail_deck(rules: &str) -> String {
    format!("{RAIL_PROCESS}{RAIL_POLY_PEX}{rules}\n")
}

/// met1 sheet resistance, Ω per square.
const MET1_SHEET: f64 = 0.125;

/// A load whose marker is centred on `(x, y)`, the lower edge of a rail.
fn load(l: &mut Layout, x: i64, y: i64) {
    rect(l, "mk", (x - 100, y - 100, x + 100, y + 100));
    rect(l, "poly", (x - 100, y - 400, x + 100, y - 50));
}

/// A met1 rail `[0, len] × [y, y + width]` named `net`, with loads on its
/// lower edge at `loads`.
fn rail(l: &mut Layout, net: &str, len: i64, y: i64, width: i64, loads: &[i64]) {
    rect(l, "met1", (0, y, len, y + width));
    *l = std::mem::take(l).label("m1txt", len / 4, y + width / 2, net);
    for &x in loads {
        load(l, x, y);
    }
}

/// A rail segment between adjacent nodes: `(lower x, upper x, current µA)`.
type Edge = (i64, i64, f64);

/// One rail fed at its centre `len / 2`, each of its loads drawing
/// `budget / loads` µA: Ohm's law along the series ladder. Returns the nodes
/// (the pad and every load) with their drop, mV, and the edges between
/// adjacent nodes as `(lower x, upper x, current µA)`.
fn ladder(len: i64, width: i64, loads: &[i64], budget: f64) -> (Vec<(i64, f64)>, Vec<Edge>) {
    let pad = len / 2;
    let share = budget / loads.len() as f64;
    let mut nodes: Vec<i64> = loads.to_vec();
    nodes.push(pad);
    nodes.sort_unstable();
    nodes.dedup();
    let edges: Vec<Edge> = nodes
        .windows(2)
        .map(|w| {
            let (a, b) = (w[0], w[1]);
            // The loads on the far side of the edge from the pad.
            let beyond = if b <= pad {
                loads.iter().filter(|&&x| x <= a).count()
            } else {
                loads.iter().filter(|&&x| x >= b).count()
            };
            (a, b, share * beyond as f64)
        })
        .collect();
    let drops = nodes
        .iter()
        .map(|&x| {
            let drop: f64 = edges
                .iter()
                .filter(|&&(a, b, _)| {
                    if x > pad {
                        a >= pad && b <= x
                    } else {
                        b <= pad && a >= x
                    }
                })
                .map(|&(a, b, current)| {
                    MET1_SHEET * (b - a) as f64 / width as f64 * current / 1000.0
                })
                .sum();
            (x, drop)
        })
        .collect();
    (drops, edges)
}

/// The limits between and around a set of values: below the least, between
/// each adjacent distinct pair, above the greatest. Values within a part in a
/// million are one value: equal in exact arithmetic, they differ only by the
/// order of a floating-point sum, and a limit between them would sit on both.
fn between(values: &[f64]) -> Vec<f64> {
    let mut v: Vec<f64> = values.to_vec();
    v.sort_by(f64::total_cmp);
    v.dedup_by(|b, a| (*b - *a).abs() <= 1e-6 * a.abs());
    let mut out = vec![v[0] * 0.5];
    out.extend(v.windows(2).map(|w| f64::midpoint(w[0], w[1])));
    out.push(v[v.len() - 1] * 1.5 + 1.0);
    out
}

/// `ir_drop` (ERC-E8): the closed-form ladder of `tests/erc_closed_form.rs`
/// (20 µm × 1 µm, pad at 10 µm, loads at 12, 14 and 18 µm sharing 3 mA:
/// drops 0.75, 1.25 and 1.75 mV) swept across every node by `max_drop_mv`,
/// by `max_drop_fraction` of the 1.8 V domain, by both at once (a node breaks
/// both), on a ground rail (bounce, the rise above 0 V), and against
/// `max_overvoltage_mv`, which a resistive grid with only sinks can never
/// break (no node rises above its pad). A current divider through two vias.
/// Random ladders swept between every pair of adjacent node drops.
fn ir_drop(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    let loads = [12_000, 14_000, 18_000];
    let (drops, _) = ladder(20_000, 1000, &loads, 3000.0);
    let layout_of = |net: &str| {
        let mut l = Layout::default();
        rail(&mut l, net, 20_000, 0, 1000, &loads);
        l
    };
    let flagged = |limit: f64| -> Vec<Finding> {
        drops
            .iter()
            .filter(|(_, d)| *d > limit)
            .map(|&(x, d)| millivolts(d).at(x, 500))
            .collect()
    };
    let mut placed = Vec::new();
    for (k, limit) in [0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 1.8]
        .into_iter()
        .enumerate()
    {
        for (net, role) in [("VDD", "power"), ("VSS", "ground")] {
            let f = Fixture::new(
                &format!("erc/ir_drop/ladder/{role}/max_drop/{limit}"),
                &["ERC-E8"],
                &rail_deck("rule ir ir_drop()"),
                ERC,
            )
            .layout(layout_of(net))
            .expect(Expect::rule("ir", flagged(limit)));
            let mut f = f;
            f.intent = Some(intent(
                &[("core", 1800.0)],
                &[(net, "core", role)],
                &[format!(
                    r#"{{"net":"{net}","max_drop_mv":{limit},"budget_current_ua":3000}}"#
                )],
            ));
            if k == 2 && role == "power" {
                placed.push(f.clone());
            }
            // The worst node is exactly 1.75 mV, legal at a 1.75 mV limit, on
            // either rail (F61: the ground rail's solve once read it one ulp
            // high).
            out.push(f);
        }
    }
    // A fraction of the domain: 1/1800 of 1.8 V is 1 mV, between the 0.75
    // and 1.25 mV nodes; with both limits stated those nodes break both.
    for (name, limits, findings) in [
        (
            "fraction",
            r#""max_drop_fraction":0.000555555555555556"#,
            flagged(1.0),
        ),
        (
            "drop_and_fraction",
            r#""max_drop_mv":1.0,"max_drop_fraction":0.000555555555555556"#,
            [flagged(1.0), flagged(1.0)].concat(),
        ),
        ("overvoltage", r#""max_overvoltage_mv":0.001"#, Vec::new()),
    ] {
        let mut f = Fixture::new(
            &format!("erc/ir_drop/ladder/power/{name}"),
            &["ERC-E8"],
            &rail_deck("rule ir ir_drop()"),
            ERC,
        )
        .layout(layout_of("VDD"))
        .expect(Expect::rule("ir", findings));
        f.intent = Some(intent(
            &[("core", 1800.0)],
            &[("VDD", "core", "power")],
            &[format!(
                r#"{{"net":"VDD",{limits},"budget_current_ua":3000}}"#
            )],
        ));
        out.push(f);
    }
    for mut f in placed {
        f.name = format!("{}/placed", f.name);
        out.extend(every_placement(&[f]));
    }

    // The divider: met2 (pad, centre 6 µm) over met1, vias at 5 and 11 µm,
    // one load on met1 at 6 µm drawing 5 mA. Branch A is 1 square of met2, a
    // cut and 1 square of met1, 0.25 Ω; branch B 5 + 1 cut + 5 squares, 1 Ω.
    // A carries 4 mA, B 1 mA. Node drops: met2 at 5 µm 4 mA × 0.0625 Ω =
    // 0.25 mV, met2 at 11 µm 1 mA × 0.3125 Ω = 0.3125 mV, met1 at 5 µm 0.25 +
    // 4 × 0.0625 = 0.5 mV, met1 at 11 µm 0.3125 + 0.0625 = 0.375 mV, the load
    // node 1.0 mV.
    let divider = {
        let mut l = Layout::default();
        rect(&mut l, "met1", (0, 0, 12_000, 1000));
        rect(&mut l, "met2", (0, 500, 12_000, 1500));
        rect(&mut l, "via1", (4900, 650, 5100, 850));
        rect(&mut l, "via1", (10_900, 650, 11_100, 850));
        l = l
            .label("m1txt", 2000, 200, "VDD")
            .label("m2txt", 2000, 1200, "VDD");
        load(&mut l, 6000, 0);
        l
    };
    let nodes = [
        (0.25, (5000, 1000)),
        (0.3125, (11_000, 1000)),
        (0.5, (5000, 500)),
        (0.375, (11_000, 500)),
        (1.0, (6000, 500)),
    ];
    for limit in [0.2, 0.3, 0.4, 0.99, 1.01] {
        let mut f = Fixture::new(
            &format!("erc/ir_drop/divider/{limit}"),
            &["ERC-E8"],
            &rail_deck("rule ir ir_drop()"),
            ERC,
        )
        .layout(divider.clone())
        .expect(Expect::rule(
            "ir",
            nodes
                .iter()
                .filter(|(d, _)| *d > limit)
                .map(|&(d, (x, y))| millivolts(d).at(x, y))
                .collect(),
        ));
        f.intent = Some(intent(
            &[("core", 1800.0)],
            &[("VDD", "core", "power")],
            &[format!(
                r#"{{"net":"VDD","max_drop_mv":{limit},"budget_current_ua":5000}}"#
            )],
        ));
        out.push(f);
    }

    // Random ladders on a 16 µm rail.
    let mut rng = Rng::new(0x1d_0001);
    let cases = match depth {
        Depth::Merge => 30,
        Depth::Nightly => 300,
    };
    for case in 0..cases {
        let n = 1 + rng.below(4) as usize;
        let mut loads: Vec<i64> = Vec::new();
        while loads.len() < n {
            let x = 500 * (1 + rng.below(31) as i64);
            if x != 8000 && !loads.contains(&x) {
                loads.push(x);
            }
        }
        let budget = (100 + rng.below(4900)) as f64;
        let ground = rng.below(2) == 1;
        let (net, role) = if ground {
            ("VSS", "ground")
        } else {
            ("VDD", "power")
        };
        let (drops, _) = ladder(16_000, 1000, &loads, budget);
        let values: Vec<f64> = drops.iter().map(|d| d.1).filter(|&d| d > 0.0).collect();
        let mut layout = Layout::default();
        rail(&mut layout, net, 16_000, 0, 1000, &loads);
        for limit in between(&values) {
            let mut f = Fixture::new(
                &format!("erc/ir_drop/random/{case}/{limit}"),
                &["ERC-E8"],
                &rail_deck("rule ir ir_drop()"),
                ERC,
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "ir",
                drops
                    .iter()
                    .filter(|(_, d)| *d > limit)
                    .map(|&(x, d)| millivolts(d).at(x, 500))
                    .collect(),
            ));
            f.intent = Some(intent(
                &[("core", 1800.0)],
                &[(net, "core", role)],
                &[format!(
                    r#"{{"net":"{net}","max_drop_mv":{limit},"budget_current_ua":{budget}}}"#
                )],
            ));
            out.push(f);
        }
    }
    out
}

/// One VDD power rail in a 1.8 V domain carrying `budget` µA.
fn vdd_intent(budget: f64) -> String {
    intent(
        &[("core", 1800.0)],
        &[("VDD", "core", "power")],
        &[format!(r#"{{"net":"VDD","budget_current_ua":{budget}}}"#)],
    )
}

/// `em_current_density` (ERC-E1, E2, E3, E10, C7, D4): the limit is
/// `max_density × width` on metal and `max_current_per_cut` on a cut, no
/// derating. One 8 µm edge of width 0.2, 0.5, 1 and 2 µm carrying 1 mA,
/// swept by a density one part in a thousand either side of `1 mA / width`
/// (the narrowest is IHP's narrow-line band, which this kind holds to the
/// same per-width limit, ERC-E3). A cut carrying 1 mA swept exactly across
/// 1000 µA. Random ladders swept between every edge's `current / width`.
fn em_current_density(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    for width in [200, 500, 1000, 2000] {
        let per_um = 1000.0 / (width as f64 / 1000.0);
        let mut layout = Layout::default();
        rail(&mut layout, "VDD", 20_000, 0, width, &[18_000]);
        let catalog: &[&'static str] = if width == 200 {
            &["ERC-E1", "ERC-E3", "ERC-E10"]
        } else {
            &["ERC-E1", "ERC-E10", "ERC-C7", "ERC-D4"]
        };
        for density in [per_um * 0.999, per_um * 1.001] {
            let mut f = Fixture::new(
                &format!("erc/em_current_density/width_{width}/{}", side(density, per_um)),
                catalog,
                &rail_deck(&format!(
                    "rule em em_current_density(met1; max_density: {density}uA/um, max_current_per_cut: 1000uA)"
                )),
                ERC,
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "em",
                if density < per_um {
                    vec![microamps(1000.0).at(10_000, width / 2)]
                } else {
                    Vec::new()
                },
            ));
            f.intent = Some(vdd_intent(1000.0));
            out.push(f);
        }
    }

    // A met2 pad bar over met1, one cut at 6 µm, one load on met1 at 2 µm:
    // the cut and every metal edge carry the whole 1 mA (met1 is tapped at its
    // centre, 4 µm, so it has two edges).
    let stack = {
        let mut l = Layout::default();
        rect(&mut l, "met1", (0, 0, 8000, 1000));
        rect(&mut l, "met2", (0, 500, 8000, 1500));
        rect(&mut l, "via1", (5900, 650, 6100, 850));
        l = l
            .label("m1txt", 1000, 200, "VDD")
            .label("m2txt", 1000, 1200, "VDD");
        load(&mut l, 2000, 0);
        l
    };
    for per_cut in [999.0, 1000.0, 1001.0] {
        let mut f = Fixture::new(
            &format!("erc/em_current_density/per_cut/{}", side(per_cut, 1000.0)),
            &["ERC-E2", "ERC-E10"],
            &rail_deck(&format!(
                "rule em em_current_density(via1; max_density: 1000mA/um, max_current_per_cut: {per_cut}uA)"
            )),
            ERC,
        )
        .layout(stack.clone())
        .expect(Expect::rule(
            "em",
            if per_cut < 1000.0 {
                vec![microamps(1000.0)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(vdd_intent(1000.0));
        out.push(f);
    }
    // One row over met1 and the cut: per width on metal (999 µA/µm × 1 µm,
    // both met1 edges fail), per cut on the cut (2 mA, clean); met2 is not
    // listed and not checked.
    let mut f = Fixture::new(
        "erc/em_current_density/metal_and_cut",
        &["ERC-E1", "ERC-E2"],
        &rail_deck(
            "rule em em_current_density(met1, via1; max_density: 999uA/um, max_current_per_cut: 2000uA)",
        ),
        ERC,
    )
    .layout(stack)
    .expect(Expect::rule(
        "em",
        vec![microamps(1000.0).at(2000, 500), microamps(1000.0).at(4000, 500)],
    ));
    f.intent = Some(vdd_intent(1000.0));
    out.push(f);

    let mut rng = Rng::new(0xe_0001);
    let cases = match depth {
        Depth::Merge => 20,
        Depth::Nightly => 200,
    };
    for case in 0..cases {
        let n = 1 + rng.below(4) as usize;
        let mut loads: Vec<i64> = Vec::new();
        while loads.len() < n {
            let x = 500 * (1 + rng.below(31) as i64);
            if x != 8000 && !loads.contains(&x) {
                loads.push(x);
            }
        }
        let budget = (100 + rng.below(4900)) as f64;
        let width = 500 * (1 + rng.below(4) as i64);
        let (_, edges) = ladder(16_000, width, &loads, budget);
        let per_um = |current: f64| current / (width as f64 / 1000.0);
        let values: Vec<f64> = edges.iter().map(|e| per_um(e.2)).collect();
        let mut layout = Layout::default();
        rail(&mut layout, "VDD", 16_000, 0, width, &loads);
        for density in between(&values) {
            let mut f = Fixture::new(
                &format!("erc/em_current_density/random/{case}/{density}"),
                &["ERC-E1", "ERC-E10"],
                &rail_deck(&format!(
                    "rule em em_current_density(met1; max_density: {density}uA/um, max_current_per_cut: 1000uA)"
                )),
                ERC,
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "em",
                edges
                    .iter()
                    .filter(|e| per_um(e.2) > density)
                    .map(|&(a, _, current)| microamps(current).at(a, width / 2))
                    .collect(),
            ));
            f.intent = Some(vdd_intent(budget));
            out.push(f);
        }
    }
    out
}

/// GF180MCU DRM Table 14.3, maximum DC current per drawn width (mA/µm) at
/// 85, 110 and 125 °C: the rows the §14.2.2 formula reproduces. The two
/// `MetalTop` 11 kÅ rows (4.5/2.2/1.5 and 7/3/2.2) disagree with the formula by
/// 2-10 % and are not used.
#[allow(
    clippy::approx_constant,
    reason = "3.14 mA/µm is the manual's Metal 1 bi-directional limit, not π"
)]
const GF180_TABLE_14_3: [(&str, f64, f64, f64); 8] = [
    ("m1_uni", 2.09, 1.0, 0.67),
    ("m1_bi", 3.14, 1.5, 1.0),
    ("mt6k_uni", 3.3, 1.6, 1.07),
    ("mt6k_bi", 5.03, 2.4, 1.6),
    ("mt9k_uni", 3.77, 1.8, 1.21),
    ("mt9k_bi", 5.66, 2.7, 1.82),
    ("mt30k_uni", 16.52, 8.01, 5.37),
    ("mt30k_bi", 24.78, 12.02, 8.06),
];

/// GF180MCU §14.2.2: `I = I0 [exp(Ea/k (1/T - 1/T0))]^(1/n)`, with the
/// manual's own Ea = 0.7 eV, n = 2 and k = 8.62e-5 eV/K.
fn gf180_derating(t: f64, t0: f64) -> f64 {
    (0.7 / 8.62e-5 * (1.0 / t - 1.0 / t0)).exp().powf(0.5)
}

/// Black's equation held at equal lifetime: the factor a limit rated at
/// `t_ref` is multiplied by at the sign-off temperature.
fn black_derating(t_ref: f64, ea: f64, n: f64) -> f64 {
    (ea / (n * K_EV) * (1.0 / T_SIGNOFF - 1.0 / t_ref)).exp()
}

/// The oracle itself: the §14.2.2 formula reproduces Table 14.3's 85 °C
/// column from its 110 °C (T0) and 125 °C columns within the table's
/// rounding, at worst 1.64 % (`MetalTop` 6 kÅ and 30 kÅ).
///
/// Oracle: foundry example. GF180MCU's own Table 14.3: the §14.2.2 formula must
/// reproduce its 85 C column from the 110 C and 125 C columns within the
/// table's rounding.
#[test]
fn the_gf180_derating_formula_reproduces_its_table() {
    let (t85, t110, t125) = (358.15, 383.15, 398.15);
    for (row, at85, at110, at125) in GF180_TABLE_14_3 {
        // 85 °C from 110 °C (T0) and from 125 °C, and 125 °C from T0.
        for (derived, table) in [
            (at110 * gf180_derating(t85, t110), at85),
            (at125 * gf180_derating(t85, t125), at85),
            (at110 * gf180_derating(t125, t110), at125),
        ] {
            let error = (derived / table - 1.0).abs();
            assert!(error < 0.0165, "{row}: {derived} against {table}, {error}");
        }
    }
}

/// `electromigration` (ERC-E4, E5, E6): Black's derating, the Blech
/// exemption and the GF180MCU table.
///
/// - GF180MCU Table 14.3: each row rated at its 110 °C (T0) value and at its
///   125 °C value, Ea 0.7 eV, n 2, run at 85 °C on a 1 µm line: the manual's
///   85 °C column within its 1.64 % rounding, so 2 % under it passes and 2 %
///   over fails.
/// - Black: `allowed = J × W × exp(Ea / (n k) (1/T - 1/T_ref))` from this
///   file's formula, swept a part in a thousand either side, over rated
///   temperatures cooler and hotter than sign-off.
/// - Blech: `|I| L / W` at or below the limit is immortal, whatever the
///   density limit says; one µA under it is mortal.
/// - F25: the Blech length is via to line end, not tap to tap.
fn electromigration() -> Vec<Fixture> {
    let mut out = Vec::new();
    let em = |density: &str, blech: &str, t_ref: &str, ea: f64, n: f64| {
        format!(
            "rule em electromigration(met1; max_density: {density}, max_current_per_cut: 1000uA, blech_limit: {blech}, reference_temperature: {t_ref}, activation_energy: {ea}eV, current_exponent: {n})"
        )
    };
    let mut line = Layout::default();
    rail(&mut line, "VDD", 20_000, 0, 1000, &[18_000]);
    let case =
        |name: String, catalog: &[&'static str], rules: String, budget: f64, flagged: bool| {
            let mut f = Fixture::new(&name, catalog, &rail_deck(&rules), ERC)
                .layout(line.clone())
                .expect(Expect::rule(
                    "em",
                    if flagged {
                        vec![microamps(budget).at(10_000, 500)]
                    } else {
                        Vec::new()
                    },
                ));
            f.intent = Some(vdd_intent(budget));
            f
        };
    for (row, at85, at110, at125) in GF180_TABLE_14_3 {
        for (t_ref, rated) in [("110C", at110), ("125C", at125)] {
            for (s, factor) in [("below", 0.98), ("above", 1.02)] {
                let budget = at85 * 1000.0 * factor;
                out.push(case(
                    format!("erc/electromigration/gf180_table_14_3/{row}/{t_ref}/{s}"),
                    &["ERC-E4", "ERC-E5"],
                    em(&format!("{rated}mA/um"), "1nA", t_ref, 0.7, 2.0),
                    budget,
                    factor > 1.0,
                ));
            }
        }
    }
    for (t_ref, kelvin, ea, n) in [
        ("25C", 298.15, 0.7, 2.0),
        ("85C", 358.15, 0.9, 2.0),
        ("105C", 378.15, 0.9, 2.0),
        ("125C", 398.15, 0.7, 1.0),
        ("423.15K", 423.15, 0.85, 1.5),
    ] {
        // 1 mA/µm over 1 µm, derated.
        let allowed = 1000.0 * black_derating(kelvin, ea, n);
        for factor in [0.999, 1.001] {
            let budget = allowed * factor;
            out.push(case(
                format!(
                    "erc/electromigration/black/{t_ref}_{ea}eV_n{n}/{}",
                    side(factor, 1.0)
                ),
                &["ERC-E4", "ERC-E5"],
                em("1mA/um", "1nA", t_ref, ea, n),
                budget,
                factor > 1.0,
            ));
        }
    }
    // The deck's `temperature` is the one Black's derating reads: rated at
    // 105 °C, run at 125 °C (398.15 K), not at the 85 °C a deck without one
    // gets. The coefficients are zero, so the rail's resistance does not move.
    let hot = format!(
        "temperature 125C nominal 25C\n{}",
        rail_deck(&em("1mA/um", "1nA", "105C", 0.9, 2.0)).replace(
            " fringe_cap 1aF/um\n",
            " fringe_cap 1aF/um tc1 0/K tc2 0/K2\n"
        )
    );
    let allowed = 1000.0 * (0.9 / (2.0 * K_EV) * (1.0 / 398.15 - 1.0 / 378.15)).exp();
    for factor in [0.999, 1.001] {
        let budget = allowed * factor;
        let mut f = Fixture::new(
            &format!(
                "erc/electromigration/deck_temperature/{}",
                side(factor, 1.0)
            ),
            &["ERC-E4", "ERC-E5"],
            &hot,
            ERC,
        )
        .layout(line.clone())
        .expect(Expect::rule(
            "em",
            if factor > 1.0 {
                vec![microamps(budget).at(10_000, 500)]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(vdd_intent(budget));
        out.push(f);
    }
    // Blech: 1 mA over an 8 µm edge 1 µm wide is 8000 µA; a 4 µm edge (load
    // at 14 µm) 4000 µA; a 2 µm-wide line 4000 µA.
    for (name, loads, width, product) in [
        ("8um", 18_000, 1000, 8000.0),
        ("4um", 14_000, 1000, 4000.0),
        ("8um_wide", 18_000, 2000, 4000.0),
    ] {
        let mut layout = Layout::default();
        rail(&mut layout, "VDD", 20_000, 0, width, &[loads]);
        for blech in [product - 1.0, product, product + 1.0] {
            let mut f = Fixture::new(
                &format!("erc/electromigration/blech/{name}/{}", side(blech, product)),
                &["ERC-E6"],
                &rail_deck(&em("1uA/um", &format!("{blech}uA"), "85C", 0.9, 2.0)),
                ERC,
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "em",
                if blech < product {
                    vec![microamps(1000.0).at(10_000, width / 2)]
                } else {
                    Vec::new()
                },
            ));
            f.intent = Some(vdd_intent(1000.0));
            out.push(f);
        }
    }
    // F25: a met1 line from a via at 0.5 µm (under the met2 pad) to its end
    // at 18 µm, loaded at 17.5 µm. The line between its diffusion barriers
    // carries 1 mA over 17 µm: a Blech product of at least 17 000 µA, mortal
    // against a 10 000 µA limit, and far over a 1 µA/µm density. Tapped at
    // its centre the line once read two 8.5 µm segments of 8500 µA, each
    // called immortal, and nothing was reported.
    let mut f25 = Layout::default();
    rect(&mut f25, "met1", (0, 0, 18_000, 1000));
    rect(&mut f25, "met2", (0, 0, 1000, 1000));
    rect(&mut f25, "via1", (400, 400, 600, 600));
    f25 = f25.label("m1txt", 9000, 500, "VDD");
    load(&mut f25, 17_500, 0);
    let mut f = Fixture::new(
        "erc/electromigration/f25/via_to_line_end",
        &["ERC-E6"],
        &rail_deck(&em("1uA/um", "10000uA", "85C", 0.9, 2.0)),
        ERC,
    )
    .layout(f25.clone())
    .expect(Expect::Passes(false));
    f.intent = Some(vdd_intent(1000.0));
    out.push(f);
    // The same line swept across its Blech product, 1000 µA × 17 µm / 1 µm =
    // 17 000 µA: below it both segments (via to centre tap, centre tap to the
    // load) are mortal and over 1 µA, reported at their first nodes; at or
    // above it the whole line is immortal.
    for blech in [16_999.0, 17_000.0, 17_001.0] {
        let mut f = Fixture::new(
            &format!(
                "erc/electromigration/f25/line_product/{}",
                side(blech, 17_000.0)
            ),
            &["ERC-E6"],
            &rail_deck(&em("1uA/um", &format!("{blech}uA"), "85C", 0.9, 2.0)),
            ERC,
        )
        .layout(f25.clone())
        .expect(Expect::rule(
            "em",
            if blech < 17_000.0 {
                vec![
                    microamps(1000.0).at(500, 500),
                    microamps(1000.0).at(9000, 500),
                ]
            } else {
                Vec::new()
            },
        ));
        f.intent = Some(vdd_intent(1000.0));
        out.push(f);
    }
    out
}

/// `reliability` (ERC-E5, F5): `t = t_ref (V_ref / V)^n exp(Ea / k (1/T -
/// 1/T_ref)) / duty`, rated 1000 h at 1.8 V, against every combination of a
/// 1.8 or 3.3 V domain, n of 2 or 4, rating at 85 or 125 °C, and full or half
/// duty, the required lifetime a part in a million either side. The VSS rail
/// sits at 0 V, unstressed. `max_abs_voltage` swept at the VDD voltage. A
/// loaded rail stresses its pad (1.8 V) harder than its far node (1.799 V):
/// a requirement between the two lifetimes flags the pad only.
fn reliability() -> Vec<Fixture> {
    let mut out = Vec::new();
    let mut two = Layout::default();
    rail(&mut two, "VDD", 4000, 0, 1000, &[]);
    rail(&mut two, "VSS", 4000, 3000, 1000, &[]);
    let row = |required: f64, t_ref: &str, n: f64, duty: f64, cap: &str| {
        format!(
            "rule rel reliability(required_lifetime: {required}h, reference_lifetime: 1000h, reference_stress: 1800mV, stress_exponent: {n}, reference_temperature: {t_ref}, activation_energy: 0.7eV, max_abs_voltage: {cap}, duty_cycle: {duty})"
        )
    };
    let lifetime = |v: f64, n: f64, t_ref: f64, duty: f64| {
        1000.0 * (1800.0 / v).powf(n) * (0.7 / K_EV * (1.0 / T_SIGNOFF - 1.0 / t_ref)).exp() / duty
    };
    let rails = |v: f64| {
        intent(
            &[("core", v)],
            &[("VDD", "core", "power"), ("VSS", "core", "ground")],
            &[],
        )
    };
    for v in [1800.0, 3300.0] {
        for n in [2.0, 4.0] {
            for (t_ref, kelvin) in [("85C", 358.15), ("125C", 398.15)] {
                for duty in [1.0, 0.5] {
                    let t = lifetime(v, n, kelvin, duty);
                    for factor in [1.0 - 1e-6, 1.0 + 1e-6] {
                        let mut f = Fixture::new(
                            &format!(
                                "erc/reliability/lifetime/{v}mV/n{n}/{t_ref}/duty{duty}/{}",
                                side(factor, 1.0)
                            ),
                            &["ERC-E5", "ERC-F5"],
                            &rail_deck(&row(t * factor, t_ref, n, duty, "10V")),
                            ERC,
                        )
                        .layout(two.clone())
                        .expect(Expect::rule(
                            "rel",
                            if factor > 1.0 {
                                vec![ratio(t).at(2000, 500)]
                            } else {
                                Vec::new()
                            },
                        ));
                        f.intent = Some(rails(v));
                        out.push(f);
                    }
                }
            }
        }
        for cap in [v - 0.5, v, v + 0.5] {
            let mut f = Fixture::new(
                &format!("erc/reliability/max_abs_voltage/{v}mV/{}", side(cap, v)),
                &["ERC-F5"],
                &rail_deck(&row(1.0, "85C", 2.0, 1.0, &format!("{cap}mV"))),
                ERC,
            )
            .layout(two.clone())
            .expect(Expect::rule(
                "rel",
                if cap < v {
                    vec![millivolts(v).at(2000, 500)]
                } else {
                    Vec::new()
                },
            ));
            f.intent = Some(rails(v));
            out.push(f);
        }
    }
    // A 20 µm rail with 1 mA at 18 µm: 8 squares, 1 Ω, so the far node sits
    // at 1799 mV.
    let mut loaded = Layout::default();
    rail(&mut loaded, "VDD", 20_000, 0, 1000, &[18_000]);
    let (pad, far) = (
        lifetime(1800.0, 4.0, 358.15, 1.0),
        lifetime(1799.0, 4.0, 358.15, 1.0),
    );
    let mut f = Fixture::new(
        "erc/reliability/loaded_rail",
        &["ERC-E5", "ERC-F5"],
        &rail_deck(&row(f64::midpoint(pad, far), "85C", 4.0, 1.0, "10V")),
        ERC,
    )
    .layout(loaded)
    .expect(Expect::rule("rel", vec![ratio(pad).at(10_000, 500)]));
    f.intent = Some(vdd_intent(1000.0));
    out.push(f);
    out
}

/// `p2p_resistance` (ERC-C6, D4): the largest effective resistance between
/// two device attach points of one net. On a 1 µm met1 rail the extreme loads
/// are `0.125 Ω × Δx / 1 µm` apart (2.0 Ω for 2 and 18 µm, exact). A met2
/// strap through two cuts in parallel: 0.75 Ω of met1 against 0.375 Ω of
/// met2 plus two 0.0625 Ω cuts, 0.75 ‖ 0.5 = 0.3 Ω; without it 0.75 Ω. Two
/// nets each over the limit report once each. Random rails swept around
/// their extreme pair.
fn p2p(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    let deck = |max: f64| rail_deck(&format!("rule p2p p2p_resistance(; max: {max}ohm)"));
    let mut two = Layout::default();
    rail(&mut two, "VDD", 20_000, 0, 1000, &[2000, 18_000]);
    let mut placed = Vec::new();
    for limit in sweep(2.0) {
        let f = Fixture::new(
            &format!("erc/p2p/rail/{}", side(limit, 2.0)),
            &["ERC-C6", "ERC-D4"],
            &deck(limit),
            ERC,
        )
        .layout(two.clone())
        .expect(Expect::rule(
            "p2p",
            if limit < 2.0 {
                vec![ohms(2.0).at(2000, 500)]
            } else {
                Vec::new()
            },
        ));
        if limit < 2.0 {
            placed.push(f.clone());
        }
        out.push(f);
    }
    // The finding sits at the worst pair's first attach point in chain order,
    // which a mirror or half turn reverses: placed, only the value is pinned.
    for mut f in placed {
        f.name = format!("{}/placed", f.name);
        f.expect = vec![Expect::rule("p2p", vec![ohms(2.0)])];
        out.extend(every_placement(&[f]));
    }
    let strap = |with: bool| {
        let mut l = Layout::default();
        rect(&mut l, "met1", (0, 0, 8000, 1000));
        l = l.label("m1txt", 3000, 200, "VDD");
        if with {
            rect(&mut l, "met2", (0, 500, 8000, 1500));
            rect(&mut l, "via1", (900, 650, 1100, 850));
            rect(&mut l, "via1", (6900, 650, 7100, 850));
        }
        load(&mut l, 1000, 0);
        load(&mut l, 7000, 0);
        l
    };
    for (with, value) in [(true, 0.3), (false, 0.75)] {
        for limit in [value * 0.999, value * 1.001] {
            out.push(
                Fixture::new(
                    &format!("erc/p2p/strap_{with}/{}", side(limit, value)),
                    &["ERC-C6"],
                    &deck(limit),
                    ERC,
                )
                .layout(strap(with))
                .expect(Expect::rule(
                    "p2p",
                    if limit < value {
                        vec![ohms(value).at(1000, 500)]
                    } else {
                        Vec::new()
                    },
                )),
            );
        }
    }
    let mut pair = Layout::default();
    rail(&mut pair, "VDD", 20_000, 0, 1000, &[2000, 18_000]);
    rail(&mut pair, "VSS", 20_000, 3000, 1000, &[6000, 10_000]);
    out.push(
        Fixture::new("erc/p2p/two_nets", &["ERC-C6"], &deck(0.4), ERC)
            .layout(pair)
            .expect(Expect::rule(
                "p2p",
                vec![ohms(2.0).at(2000, 500), ohms(0.5).at(6000, 3500)],
            )),
    );
    let mut rng = Rng::new(0x22_0001);
    let cases = match depth {
        Depth::Merge => 20,
        Depth::Nightly => 200,
    };
    for case in 0..cases {
        let n = 2 + rng.below(3) as usize;
        let mut loads: Vec<i64> = Vec::new();
        while loads.len() < n {
            let x = 500 * (1 + rng.below(31) as i64);
            if !loads.contains(&x) {
                loads.push(x);
            }
        }
        let width = 500 * (1 + rng.below(4) as i64);
        let (lo, hi) = (
            *loads.iter().min().expect("two loads"),
            *loads.iter().max().expect("two loads"),
        );
        let value = MET1_SHEET * (hi - lo) as f64 / width as f64;
        let mut layout = Layout::default();
        rail(&mut layout, "VDD", 16_000, 0, width, &loads);
        for limit in [value * 0.999, value * 1.001] {
            out.push(
                Fixture::new(
                    &format!("erc/p2p/random/{case}/{}", side(limit, value)),
                    &["ERC-C6"],
                    &deck(limit),
                    ERC,
                )
                .layout(layout.clone())
                .expect(Expect::rule(
                    "p2p",
                    if limit < value {
                        vec![ohms(value).at(lo, width / 2)]
                    } else {
                        Vec::new()
                    },
                )),
            );
        }
    }
    out
}

/// Every kind that needs design intent, with the deck spelling of one row.
const INTENT_ROWS: [(&str, &str); 12] = [
    ("s.ir", "ir_drop()"),
    (
        "s.emcd",
        "em_current_density(met1; max_density: 1mA/um, max_current_per_cut: 1mA)",
    ),
    (
        "s.em",
        "electromigration(met1; max_density: 1mA/um, max_current_per_cut: 1mA, blech_limit: 1nA, reference_temperature: 85C, activation_energy: 0.9eV, current_exponent: 2)",
    ),
    (
        "s.rel",
        "reliability(; required_lifetime: 1h, reference_lifetime: 1000h, reference_stress: 1800mV, stress_exponent: 2, reference_temperature: 85C, activation_energy: 0.7eV, max_abs_voltage: 10V, duty_cycle: 1)",
    ),
    ("s.hv", "hv_domain(; max_delta: 1V, isolation: none)"),
    (
        "s.esdl",
        "esd_latchup(met2, mk; min_guard_ring_width: 1nm, max_tap_distance: 1nm, clamps: [\"load\"])",
    ),
    ("s.esd", "esd_topological(met2; clamps: [\"load\"])"),
    ("s.gox", "gate_oxide(; models: [\"load\"], max: 1V)"),
    ("s.vds", "drain_source(; models: [\"load\"], max: 1V)"),
    ("s.wb", "well_bias(; pmos: [\"load\"], nmos: none)"),
    ("s.ls", "missing_level_shifter(; shifters: none)"),
    ("s.xing", "domain_crossing()"),
];

/// `rule <id> <row>` lines.
fn rule_lines(rows: &[(&str, &str)]) -> String {
    rows.iter()
        .map(|(id, row)| format!("rule {id} {row}\n"))
        .collect::<Vec<_>>()
        .concat()
}

/// Outcomes the grid and intent decide: every intent-gated kind records
/// Skipped with no intent file, and with an intent naming no net of the
/// layout, while the kinds that need none run; a budget that reaches no
/// device refuses the current rules but not `reliability` (no current is the
/// fail-closed stress); a conductor with no sheet resistance refuses every
/// kind that reads a resistance, and nothing else.
fn grid_outcomes() -> Vec<Fixture> {
    let mut out = Vec::new();
    let mut rules = rule_lines(&INTENT_ROWS);
    rules.push_str(
        "rule p2p p2p_resistance(; max: 1ohm)\nrule fg floating_gate(; labels_are_ports: false)",
    );
    let mut layout = Layout::default();
    rail(&mut layout, "VDD", 20_000, 0, 1000, &[18_000]);
    let catalog: &[&'static str] = &[
        "ERC-E8", "ERC-E1", "ERC-E4", "ERC-F5", "ERC-F10", "ERC-D2", "ERC-C1", "ERC-F2", "ERC-F3",
        "ERC-F12", "ERC-F6", "ERC-F9",
    ];
    for (name, intent_text) in [
        ("no_intent", None),
        (
            "intent_names_no_layout_net",
            Some(intent(
                &[("core", 1800.0)],
                &[("NOPE", "core", "power")],
                &[],
            )),
        ),
    ] {
        let mut f = Fixture::new(
            &format!("erc/skipped/{name}"),
            catalog,
            &rail_deck(&rules),
            ERC,
        )
        .layout(layout.clone())
        .expect(Expect::clean("p2p"))
        .expect(Expect::clean("fg"))
        .expect(Expect::Passes(false));
        for (id, _) in INTENT_ROWS {
            f = f.expect(Expect::outcome(id, Want::Skipped));
        }
        f.intent = intent_text;
        out.push(f);
    }
    // A budget on a rail with no device.
    let mut bare = Layout::default();
    rail(&mut bare, "VDD", 20_000, 0, 1000, &[]);
    let mut f = Fixture::new(
        "erc/refused/budget_reaches_no_device",
        &["ERC-E8", "ERC-E1", "ERC-E4", "ERC-F5"],
        &rail_deck(&rule_lines(&INTENT_ROWS[..4])),
        ERC,
    )
    .layout(bare)
    .expect(Expect::outcome("s.ir", Want::Refused))
    .expect(Expect::outcome("s.emcd", Want::Refused))
    .expect(Expect::outcome("s.em", Want::Refused))
    .expect(Expect::clean("s.rel"));
    f.intent = Some(vdd_intent(1000.0));
    out.push(f);
    // No sheet resistance for poly, a conductor the loads touch.
    let mut f = Fixture::new(
        "erc/refused/no_sheet_resistance",
        &["ERC-E8", "ERC-C6", "ERC-E1", "ERC-E4", "ERC-F5"],
        &format!(
            "{RAIL_PROCESS}{}rule p2p p2p_resistance(; max: 1ohm)\nrule fg floating_gate(; labels_are_ports: false)\n",
            rule_lines(&INTENT_ROWS[..4])
        ),
        ERC,
    )
    .layout(layout)
    .expect(Expect::outcome("s.ir", Want::Refused))
    .expect(Expect::outcome("s.emcd", Want::Refused))
    .expect(Expect::outcome("s.em", Want::Refused))
    .expect(Expect::outcome("s.rel", Want::Refused))
    .expect(Expect::outcome("p2p", Want::Refused))
    .expect(Expect::clean("fg"));
    f.intent = Some(vdd_intent(1000.0));
    out.push(f);
    out
}

// ----------------------------------------------------------------- topology

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
const TOPO_RULES: [(&str, &str, bool); 17] = [
    ("fg", "floating_gate(; labels_are_ports: false)", false),
    ("fgp", "floating_gate(; labels_are_ports: true)", false),
    ("md1", "multiple_drivers(; max: 1)", true),
    ("md2", "multiple_drivers(; max: 2)", true),
    ("thl", "tie_high_low()", true),
    ("up", "unconnected_pin(met1, met2)", false),
    ("ss", "supply_short(ntap, ptap)", false),
    ("ssw", "supply_short(ntap, ptap, nwpm)", false),
    ("soft", "soft_connection(well)", false),
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
const TOPO_CATALOG: &[&str] = &["ERC-G1", "ERC-G6", "ERC-E9"];
/// The rows a board with intent proves too: the kinds the rails orient,
/// propagation and the voltage kinds.
const VOLTAGE_CATALOG: &[&str] = &[
    "ERC-G3", "ERC-G7", "ERC-F1", "ERC-F2", "ERC-F3", "ERC-F6", "ERC-F9", "ERC-F10",
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
const TRACK_H: i64 = 400;
const PITCH: i64 = 4000;

fn track_y(net: usize) -> i64 {
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
enum Model {
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
struct Dev {
    model: Model,
    g: usize,
    s: usize,
    d: usize,
    b: Option<usize>,
}

fn dev(model: Model, g: usize, s: usize, d: usize) -> Dev {
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
        intent(&self.domains, &supplies, &[])
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
        let sweep = |free: &[bool]| -> Vec<Option<Reach>> {
            let mut r: Vec<Option<Reach>> = (0..NETS)
                .map(|net| {
                    self.supply(net).map(|s| Reach {
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
                        if self.supply(n).is_none() && widened != r[n] {
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
        if !self.with_intent {
            for (id, _, needs) in TOPO_RULES {
                if needs {
                    out.push(Expect::outcome(id, Want::Skipped));
                }
            }
            return out;
        }
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
        }
        let mut f =
            Fixture::new(name, &catalog, &topo_deck(self.limits), ERC).layout(self.layout());
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
    for a in sample(&canonical_assignments(9), depth, 300, 0x7_0001) {
        let mut board = three_rails(false);
        board.devs = a
            .chunks(3)
            .map(|t| dev(Model::Nfet, t[0], t[1], t[2]))
            .collect();
        out.push(board.fixture(&format!("erc/topology/no_intent/{}", assignment_name(&a))));
    }
    for a in sample(&all_assignments(6), depth, 300, 0x7_0002) {
        let mut board = three_rails(true);
        board.devs = vec![
            dev(Model::Nfet, a[0], a[1], a[2]),
            dev(Model::Pfet, a[3], a[4], a[5]),
        ];
        out.push(board.fixture(&format!("erc/topology/intent2/{}", assignment_name(&a))));
    }
    let mut rng = Rng::new(0x7_0003);
    let three = match depth {
        Depth::Merge => 150,
        Depth::Nightly => 2000,
    };
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
    // Gate-conditioned switches (ERC-F1): an nfet_c (on at 1 V or more) and a
    // pfet_c (on at 2.5 V or less), every 4^6 assignment against VDD, VSS and
    // VDDH, so each gate sits on 0, 1.8 or 3.3 V, on the signal, or on a
    // channel of its own; then with a plain nfet, sampled, against those
    // rails and against VDD and VSS alone, so a gate can be driven through
    // another switch or float behind one that never turns on.
    for a in sample(&all_assignments(6), depth, 300, 0x7_0006) {
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
    let bulk: Vec<(Model, Vec<usize>)> = [Model::NfetB, Model::PfetB]
        .into_iter()
        .flat_map(|m| all_assignments(4).into_iter().map(move |a| (m, a)))
        .collect();
    for (model, a) in sample(&bulk, depth, 64, 0x7_0004) {
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
    // Isolation around the marker with a hole over its middle (a keyhole
    // outline, as GDS carries a hole) does not cover the marker.
    let mut f = board.fixture("erc/topology/hv/isolation_with_hole");
    f.layout = std::mem::take(&mut f.layout).polygon(
        "iso",
        &[
            (900, -100),
            (1300, -100),
            (1300, 1100),
            (900, 1100),
            (900, 500),
            (1050, 500),
            (1050, 600),
            (1150, 600),
            (1150, 400),
            (1050, 400),
            (1050, 500),
            (900, 500),
        ],
    );
    out.push(f);
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

    // A layer listed twice is checked, and reported, twice.
    out.push(
        Fixture::new(
            "erc/topology/unconnected_listed_twice",
            &["ERC-G6"],
            "grid 1nm\nlayer met1 = gds(1, 0)\nconnect conductors [met1]\nrule up unconnected_pin(met1, met1)\n",
            ERC,
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
        ERC,
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
    for a in sample(&all_assignments(6), depth, 250, 0xe5d_0001) {
        let mut board = base(true);
        board.devs = vec![
            dev(Model::Clamp, a[0], a[1], a[2]),
            dev(Model::Clamp, a[3], a[4], a[5]),
        ];
        out.push(board.fixture(&format!("erc/esd/two_clamps/{}", assignment_name(&a))));
    }
    for a in sample(&all_assignments(6), depth, 100, 0xe5d_0002) {
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
        ERC,
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
        ERC,
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
        ERC,
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

/// `supply_short` (ERC-G4): three tap stubs, each an n- or p-tap on any of
/// four nets (8^3 boards): a net holding both is one finding. With `within`,
/// named cases where an `nwpm` polygon covers some n-taps.
fn supply_short(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    let all: Vec<Vec<(bool, usize)>> = (0..512)
        .map(|code: usize| {
            (0..3)
                .map(|k| {
                    let digit = (code >> (3 * k)) & 7;
                    (digit & 4 != 0, digit & 3)
                })
                .collect()
        })
        .collect();
    for taps in sample(&all, depth, 100, 0x55_0001) {
        let mut board = three_rails(false);
        let name = taps
            .iter()
            .map(|&(n, net)| format!("{}{net}", if n { 'n' } else { 'p' }))
            .collect::<Vec<_>>()
            .concat();
        board.taps = taps;
        out.push(board.fixture(&format!("erc/supply_short/{name}")));
    }
    for (name, nwpm) in [
        ("covered", vec![0]),
        ("uncovered", vec![2]),
        ("both", vec![0, 2]),
    ] {
        let mut board = three_rails(false);
        board.taps = vec![(true, 0), (false, 0), (true, 1), (false, 1)];
        board.nwpm = nwpm;
        out.push(board.fixture(&format!("erc/supply_short/within/{name}")));
    }
    out
}

/// `soft_connection` (ERC-G5): two met1 islands joined only through a well
/// (soft) by two contacts, one finding; with a met1 strap between them,
/// clean. A met2 strap contacted to one island only and passing over the
/// other joins nothing, so the islands are still held only by the well (F27:
/// any two touching shapes were once taken as joined).
fn soft_connection() -> Vec<Fixture> {
    let base = || {
        let mut l = Layout::default();
        rect(&mut l, "well", (0, 0, 6000, 1000));
        rect(&mut l, "cont", (200, 200, 400, 400));
        rect(&mut l, "cont", (5600, 200, 5800, 400));
        rect(&mut l, "met1", (0, 0, 1000, 1000));
        rect(&mut l, "met1", (5000, 0, 6000, 1000));
        l
    };
    let mut strapped = base();
    rect(&mut strapped, "met1", (1000, 400, 5000, 600));
    let mut over = base();
    rect(&mut over, "met2", (500, 0, 5500, 1000));
    rect(&mut over, "via1", (600, 400, 800, 600));
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        Fixture::new(
            &format!("erc/soft_connection/{name}"),
            &["ERC-G5"],
            &topo_deck(Limits::default()),
            ERC,
        )
        .layout(layout)
        .expect(Expect::rule("soft", findings))
    };
    vec![
        case("through_well", base(), vec![count(2)]),
        case("strapped", strapped, Vec::new()),
        case("f27/overlap_without_via", over, vec![count(2)]),
    ]
}

/// A well and tap deck: geometric containment and distance, no nets.
const GEO_PROCESS: &str = "grid 1nm
layer nwell = gds(1, 0)
layer ntap = gds(2, 0)
layer act = gds(3, 0)
layer tap = gds(4, 0)
";

/// `floating_well` (ERC-G2): wells as unions of 1 µm cells on a 3 × 2 grid
/// (every pattern), a 200 nm tap at a cell's centre or across the edge
/// between two side-by-side cells, or none. A well is an 8-connected group of
/// cells: cells meeting only at a corner are one well, the corner model of
/// the merge. A tap ties a well only when the well covers all of it. Named: a
/// tap in a well's hole, in a notch, across its outer edge.
fn floating_well(depth: Depth) -> Vec<Fixture> {
    let cell = |c: usize| ((c % 3) as i64 * 1000, (c / 3) as i64 * 1000);
    let adjacent = |a: usize, b: usize| {
        let ((ax, ay), (bx, by)) = (cell(a), cell(b));
        (ax - bx).abs() + (ay - by).abs() == 1000
    };
    let diagonal = |a: usize, b: usize| {
        let ((ax, ay), (bx, by)) = (cell(a), cell(b));
        (ax - bx).abs() == 1000 && (ay - by).abs() == 1000
    };
    // Tap positions: six centres, then the four horizontal cell edges.
    let taps: Vec<(Vec<usize>, Rect)> = (0..6)
        .map(|c| {
            let (x, y) = cell(c);
            (vec![c], (x + 400, y + 400, x + 600, y + 600))
        })
        .chain([(0, 1), (1, 2), (3, 4), (4, 5)].into_iter().map(|(a, b)| {
            let (x, y) = cell(b);
            (vec![a, b], (x - 100, y + 400, x + 100, y + 600))
        }))
        .collect();
    let mut cases = Vec::new();
    for pattern in 1u32..64 {
        let cells: Vec<usize> = (0..6).filter(|&c| pattern >> c & 1 == 1).collect();
        for tap in (0..=taps.len()).map(|t| taps.get(t).cloned()) {
            cases.push((cells.clone(), tap));
        }
    }
    let mut out = Vec::new();
    for (cells, tap) in sample(&cases, depth, 100, 0xf3_0001) {
        // Components by edge or corner adjacency.
        let mut group: Vec<usize> = (0..6).collect();
        for &a in &cells {
            for &b in &cells {
                if adjacent(a, b) || diagonal(a, b) {
                    let (ga, gb) = (group[a], group[b]);
                    for g in &mut group {
                        if *g == gb {
                            *g = ga;
                        }
                    }
                }
            }
        }
        let mut wells: Vec<usize> = cells.iter().map(|&c| group[c]).collect();
        wells.sort_unstable();
        wells.dedup();
        let tied = tap.as_ref().and_then(|(under, _)| {
            under
                .iter()
                .all(|c| cells.contains(c))
                .then(|| group[under[0]])
        });
        let findings = wells
            .iter()
            .filter(|&&w| Some(w) != tied)
            .map(|_| count(0))
            .collect();
        let mut layout = Layout::default();
        for &c in &cells {
            let (x, y) = cell(c);
            rect(&mut layout, "nwell", (x, y, x + 1000, y + 1000));
        }
        let mut name = cells.iter().map(ToString::to_string).collect::<String>();
        if let Some((under, r)) = &tap {
            rect(&mut layout, "ntap", *r);
            name = format!("{name}/tap_{}", assignment_name(under));
        }
        out.push(
            Fixture::new(
                &format!("erc/floating_well/{name}"),
                &["ERC-G2"],
                &format!("{GEO_PROCESS}rule fw floating_well(nwell, ntap)\n"),
                ERC,
            )
            .layout(layout)
            .expect(Expect::rule("fw", findings)),
        );
    }
    // A ring of four bars around a tap: the tap sits in the hole.
    let ring = Layout::default()
        .rect("nwell", 0, 0, 3000, 500)
        .rect("nwell", 0, 2500, 3000, 3000)
        .rect("nwell", 0, 500, 500, 2500)
        .rect("nwell", 2500, 500, 3000, 2500)
        .rect("ntap", 1400, 1400, 1600, 1600);
    // A U whose notch holds the tap.
    let notch = Layout::default()
        .polygon(
            "nwell",
            &[
                (0, 0),
                (3000, 0),
                (3000, 3000),
                (2000, 3000),
                (2000, 1000),
                (1000, 1000),
                (1000, 3000),
                (0, 3000),
            ],
        )
        .rect("ntap", 1400, 2000, 1600, 2200);
    let edge = Layout::default()
        .rect("nwell", 0, 0, 2000, 2000)
        .rect("ntap", 1900, 900, 2100, 1100);
    let inside = Layout::default()
        .rect("nwell", 0, 0, 2000, 2000)
        .rect("ntap", 1800, 900, 2000, 1100);
    for (name, layout, findings) in [
        ("hole", ring, vec![count(0)]),
        ("notch", notch, vec![count(0)]),
        ("across_edge", edge, vec![count(0)]),
        ("inside_touching_edge", inside, Vec::new()),
    ] {
        out.extend(every_placement(&[Fixture::new(
            &format!("erc/floating_well/named/{name}"),
            &["ERC-G2"],
            &format!("{GEO_PROCESS}rule fw floating_well(nwell, ntap)\n"),
            ERC,
        )
        .layout(layout)
        .expect(Expect::rule("fw", findings))]));
    }
    out
}

/// `missing_tie` (ERC-D1): the furthest point of each region polygon from
/// the nearest tap edge, exact.
///
/// - A 1 µm square region whose far corner (0, 0) is a 3-4-5 triangle from
///   the tap's corner: 5000 nm, swept a nanometre either side, every
///   placement.
/// - A 10 µm bar between two taps 1 µm off each end: the furthest point is
///   the bar's middle, 6000 nm from both, on no vertex (a vertex check reads
///   1000).
/// - A region inside a ring of four tap bars: the furthest point is its
///   centre, 1500 nm from every inner edge.
/// - No tap at all: the region is flagged at the coordinate domain's bound.
fn missing_tie() -> Vec<Fixture> {
    let deck = |limit: i64| {
        format!("{GEO_PROCESS}rule mt missing_tie(act, tap; max_distance: {limit}nm)\n")
    };
    let mut out = Vec::new();
    let corner = Layout::default()
        .rect("act", 0, 0, 1000, 1000)
        .rect("tap", 3000, 4000, 3500, 4500);
    let bar = Layout::default()
        .rect("act", 0, 0, 10_000, 100)
        .rect("tap", -2000, 0, -1000, 100)
        .rect("tap", 11_000, 0, 12_000, 100);
    let ring = Layout::default()
        .rect("act", 0, 0, 1000, 1000)
        .rect("tap", -1500, -1500, -1000, 2500)
        .rect("tap", 2000, -1500, 2500, 2500)
        .rect("tap", -1000, -1500, 2000, -1000)
        .rect("tap", -1000, 2000, 2000, 2500);
    for (name, layout, value, at) in [
        ("pythagorean", corner, 5000, Some((0, 0))),
        ("mid_edge", bar, 6000, None),
        ("inside_ring", ring, 1500, Some((500, 500))),
    ] {
        for limit in [value - 1, value, value + 1] {
            let finding = match at {
                Some((x, y)) => length(value).at(x, y),
                None => length(value),
            };
            let f = Fixture::new(
                &format!(
                    "erc/missing_tie/{name}/{}",
                    side(limit as f64, value as f64)
                ),
                &["ERC-D1"],
                &deck(limit),
                ERC,
            )
            .layout(layout.clone())
            .expect(Expect::rule(
                "mt",
                if limit < value {
                    vec![finding]
                } else {
                    Vec::new()
                },
            ));
            if limit < value && at.is_some() {
                out.extend(every_placement(&[f]));
            } else {
                out.push(f);
            }
        }
    }
    out.push(
        Fixture::new("erc/missing_tie/no_tap", &["ERC-D1"], &deck(1000), ERC)
            .layout(Layout::default().rect("act", 0, 0, 1000, 1000))
            .expect(Expect::rule("mt", vec![length(MAX_ABS_DBU)])),
    );
    out
}

/// The rows the catalog marks expressible as DRC kinds: IHP Ant.h (no
/// antenna diode in an n-well, `forbidden`, ERC-A10), an ESD device's poly
/// width under its marker (`width` on a derived layer, ERC-C11), and slotting
/// of a wide plate (`cheesing`, ERC-E12).
fn expressible() -> Vec<Fixture> {
    let mut out = Vec::new();
    let a10 = "grid 1nm\nlayer nwell = gds(1, 0)\nlayer dant = gds(2, 0)\nrule Ant.h forbidden(dant and nwell)\n";
    out.push(
        Fixture::new("erc/expressible/ant_h/in_well", &["ERC-A10"], a10, DRC)
            .layout(
                Layout::default()
                    .rect("nwell", -500, -500, 500, 1500)
                    .rect("dant", 0, 0, 1000, 1000),
            )
            .expect(Expect::rule("Ant.h", vec![Finding::area(500_000)])),
    );
    out.push(
        Fixture::new("erc/expressible/ant_h/outside", &["ERC-A10"], a10, DRC)
            .layout(
                Layout::default()
                    .rect("nwell", -2000, -500, -1000, 1500)
                    .rect("dant", 0, 0, 1000, 1000),
            )
            .expect(Expect::clean("Ant.h")),
    );
    let c11 = "grid 1nm\nlayer poly = gds(1, 0)\nlayer esd = gds(2, 0)\nlayer esd_poly = poly and esd\nrule LVESD.w width(esd_poly) >= 500nm\n";
    for w in [499, 500, 501] {
        out.push(
            Fixture::new(
                &format!("erc/expressible/esd_width/{w}"),
                &["ERC-C11"],
                c11,
                DRC,
            )
            .layout(
                Layout::default()
                    .rect("esd", -1000, -1000, 3000, 5000)
                    .rect("poly", 0, 0, w, 4000)
                    .rect("poly", 5000, 0, 5400, 4000),
            )
            .expect(Expect::rule(
                "LVESD.w",
                if w < 500 {
                    vec![Finding::length(w)]
                } else {
                    Vec::new()
                },
            )),
        );
    }
    let e12 = "grid 1nm\nlayer met1 = gds(1, 0)\nrule slot cheesing(met1) <= 10um2\n";
    let slotted = Layout::default()
        .rect("met1", 0, 0, 4000, 1000)
        .rect("met1", 0, 3000, 4000, 4000)
        .rect("met1", 0, 1000, 1000, 3000)
        .rect("met1", 3000, 1000, 4000, 3000);
    for (name, layout, findings) in [
        (
            "solid",
            Layout::default().rect("met1", 0, 0, 4000, 4000),
            vec![Finding::area(16_000_000)],
        ),
        ("slotted", slotted, Vec::new()),
        (
            "small",
            Layout::default().rect("met1", 0, 0, 3000, 3000),
            Vec::new(),
        ),
    ] {
        out.push(
            Fixture::new(
                &format!("erc/expressible/cheesing/{name}"),
                &["ERC-E12"],
                e12,
                DRC,
            )
            .layout(layout)
            .expect(Expect::rule("slot", findings)),
        );
    }
    out
}
