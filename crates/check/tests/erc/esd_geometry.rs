//! The ESD and latch-up kinds that measure geometry, each on a cell drawn by
//! hand with a closed-form or by-construction answer: `esd_path`'s forced
//! current, `esd_parasitic`, `tie_area`, `guard_ring` and `latchup_victim`.

use crate::common;

use common::{head, manufacturing_grid, microamps, millivolts, ohms, rule};
use gpurify_check::erc::facts::IntentMap;
use gpurify_check::erc::power::{extract_stress_into, Process, Stress, StressGrid};
use gpurify_check::erc::rules::esd::{
    check_esd_parasitic, check_esd_path, EsdParasiticTable, EsdPathTable,
};
use gpurify_check::erc::rules::latchup::{
    check_guard_ring, check_latchup_victim, check_tie_area, GuardRingTable, LatchupVictimTable,
    TieAreaTable,
};
use gpurify_check::erc::{Design, Scratch};
use gpurify_check::report::{Measurement, RuleRun, Violations};
use gpurify_check::topology::{DeviceTable, NetId, NetTable};
use gpurify_geom::{Dbu, GeometryStore, LayerId, PolyId, Qty};
use gpurify_ingest::deck::{
    Connectivity, DeviceKind, DeviceRecognition, DeviceValue, ProcessStack,
};
use gpurify_ingest::intent::{DomainId, SupplyRole};
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::{Handle, Ids};
use gpurify_testgen::LayoutBuilder;

const PAD: LayerId = LayerId(0);
const MET1: LayerId = LayerId(1);
const PADV: LayerId = LayerId(2);
const MKD: LayerId = LayerId(3);
const DIFF: LayerId = LayerId(4);
const DCUT: LayerId = LayerId(5);
const RING: LayerId = LayerId(6);
const WELL: LayerId = LayerId(7);
const CONT: LayerId = LayerId(8);
const GATE: LayerId = LayerId(9);
const LAYERS: usize = 10;

/// The diode clamp model, recognised under `mkd` with its anode on met1 and
/// its cathode on the pad.
fn dio() -> StrId {
    rule(500)
}

/// A drawn cell, extracted: `pad`, `met1` and `diff` and `ring` conduct and
/// join within a layer by touching; `padv` joins met1 to the pad and `dcut`
/// diffusion to the pad.
struct Cell {
    store: GeometryStore,
    ids: Ids,
    nets: NetTable,
    devices: DeviceTable,
    connectivity: Connectivity,
    stack: ProcessStack,
}

impl Cell {
    fn new(draw: impl FnOnce(&mut LayoutBuilder)) -> Self {
        let mut layout = LayoutBuilder::new(LAYERS);
        draw(&mut layout);
        let (store, ids) = layout.finish();
        let connectivity = Connectivity {
            conductors: vec![PAD, MET1, DIFF, RING],
            via_cut: vec![PADV, DCUT],
            via_connects: vec![(MET1, PAD), (DIFF, PAD)],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        gpurify_check::topology::extract_nets_into(&store, &connectivity, &mut nets);
        let recognition = DeviceRecognition {
            kind: vec![DeviceKind::Diode],
            marker: vec![MKD],
            terminal_start: vec![0, 2],
            terminal: vec![MET1, PAD],
            model: vec![dio()],
            value: vec![DeviceValue::default()],
        };
        let mut devices = DeviceTable::default();
        gpurify_check::topology::device::recognise_into(&store, &nets, &recognition, &mut devices);
        let mut stack = ProcessStack {
            sheet_res_ohm_sq: vec![1.0; LAYERS],
            height_nm: vec![0.0; LAYERS],
            ..ProcessStack::default()
        };
        stack.sheet_res_ohm_sq[PAD.idx()] = 0.0625;
        stack.sheet_res_ohm_sq[MET1.idx()] = 0.125;
        stack.sheet_res_ohm_sq[PADV.idx()] = 0.25;
        Self {
            store,
            ids,
            nets,
            devices,
            connectivity,
            stack,
        }
    }

    fn design(&self) -> Design<'_> {
        Design {
            store: &self.store,
            nets: &self.nets,
            devices: &self.devices,
        }
    }

    fn process(&self) -> Process<'_> {
        Process {
            grid: manufacturing_grid(),
            stack: &self.stack,
            connectivity: &self.connectivity,
        }
    }

    fn poly(&self, handle: Handle) -> PolyId {
        self.ids.of(handle)
    }

    fn net(&self, handle: Handle) -> NetId {
        self.nets.net_of(self.poly(handle))
    }

    /// Intent declaring the net of `ground` a ground of a 1.8 V domain.
    fn ground(&self, ground: Handle) -> IntentMap {
        IntentMap {
            declared: true,
            supply_net: vec![self.net(ground)],
            supply_role: vec![SupplyRole::Ground],
            supply_domain: vec![DomainId(0)],
            supply_voltage: vec![millivolts(1800.0)],
            limit_net: Vec::new(),
            limit: Vec::new(),
        }
    }
}

fn report() -> (Violations, Vec<RuleRun>) {
    (Violations::default(), Vec::new())
}

/// The pad strip, the VSS strip 3 µm below it, and a 200 nm diode marker
/// spanning the two at each x of `diodes`; returns (pad, vss).
fn strips(l: &mut LayoutBuilder, diodes: &[i64]) -> (Handle, Handle) {
    let pad = l.rect(PAD, 0, 0, 20_000, 1000);
    let vss = l.rect(MET1, 0, -3000, 20_000, -2000);
    for &x in diodes {
        l.rect(MKD, x - 100, -2100, x + 100, 100);
    }
    (pad, vss)
}

/// One `esd_path` row forcing 1.33 A, each clamp 1 Ω, holding clamps to
/// `it2` A/m.
fn path_table(it2: f64) -> EsdPathTable {
    EsdPathTable {
        head: head(rule(1)),
        pad: vec![PAD],
        source: vec![PAD],
        clamp_start: vec![0, 1],
        clamp: vec![dio()],
        current: vec![microamps(1.33e6)],
        clamp_resistance: vec![ohms(1.0)],
        max_resistance: vec![None],
        clamp_it2: vec![Some(Qty::new(it2))],
        max_density: vec![None],
        max_current_per_cut: vec![None],
        max_voltage: vec![None],
        min_width: vec![None],
        clamp_voltage: vec![None],
    }
}

fn currents(out: &Violations) -> Vec<f64> {
    out.measured
        .iter()
        .map(|m| match m {
            Measurement::Current(ua) => ua.raw(),
            other => panic!("a clamp's share is a current, not {other:?}"),
        })
        .collect()
}

/// Three diode clamps placed unevenly, at 2, 8 and 14 µm, share the forced
/// current; rated at 1 A/m all are over, each reporting its share.
/// Oracle: Kirchhoff's current law: the shares sum to the 1.33 A forced in,
/// and with the clamps at different distances from the entry the shares
/// differ. One pin pair is solved.
#[test]
fn parallel_clamps_share_the_forced_current() {
    let mut pad = None;
    let cell = Cell::new(|l| {
        let (p, vss) = strips(l, &[2000, 8000, 14_000]);
        pad = Some((p, vss));
    });
    let (_, vss) = pad.expect("drawn");
    assert_eq!(cell.devices.len(), 3, "three diode clamps");
    let (mut out, mut runs) = report();
    check_esd_path(
        cell.design(),
        &cell.ground(vss),
        cell.process(),
        &path_table(1.0),
        &mut Scratch::default(),
        &mut out,
        &mut runs,
    );
    let shares = currents(&out);
    assert_eq!(shares.len(), 3, "every clamp is over 1 A/m: {shares:?}");
    let total: f64 = shares.iter().sum();
    assert!(
        (total - 1.33e6).abs() <= 1e-6 * 1.33e6,
        "the shares {shares:?} sum to {total} µA, not the 1.33 A forced"
    );
    assert!(
        (shares[0] - shares[2]).abs() > 1.0,
        "uneven clamps share unequally"
    );
    assert_eq!(common::run_of(&runs, rule(1)).examined, 1, "one pin pair");
}

/// One down diode carries all 1.33 A; its marker is 200 nm by 2.2 µm, 4.8
/// µm round, so it is rated `it2` times 4.8 µm.
/// Oracle: closed form: rated just below 1.33 A / 4.8 µm it is flagged with
/// all 1.33 A; just above it is clean.
#[test]
fn a_clamp_is_rated_its_it2_times_its_perimeter() {
    let rated = 1.33 / 4.8e-6;
    for (it2, flagged) in [(rated * 0.999, true), (rated * 1.001, false)] {
        let mut drawn = None;
        let cell = Cell::new(|l| drawn = Some(strips(l, &[2000])));
        let (_, vss) = drawn.expect("drawn");
        let (mut out, mut runs) = report();
        check_esd_path(
            cell.design(),
            &cell.ground(vss),
            cell.process(),
            &path_table(it2),
            &mut Scratch::default(),
            &mut out,
            &mut runs,
        );
        let shares = currents(&out);
        if flagged {
            assert_eq!(shares.len(), 1, "rated {it2} A/m");
            assert!((shares[0] - 1.33e6).abs() <= 1e-6 * 1.33e6, "{shares:?}");
        } else {
            assert!(shares.is_empty(), "rated {it2} A/m: {shares:?}");
        }
    }
}

/// A supply with a small met1 stub drawn before its long strip, touching it:
/// the stress network holds the supply at its feed point, the centre of its
/// widest shape on the highest layer.
/// Oracle: the rule `extract_stress_into`'s rustdoc states: both shapes are
/// on met1, so the widest, the strip, carries the held node.
#[test]
fn a_supply_with_no_pin_is_held_at_its_widest_shape() {
    let mut drawn = None;
    let cell = Cell::new(|l| {
        let stub = l.rect(MET1, 19_000, -2000, 20_000, -1500);
        let (pad, vss) = strips(l, &[2000]);
        drawn = Some((stub, pad, vss));
    });
    let (stub, pad, vss) = drawn.expect("drawn");
    assert_eq!(cell.net(stub), cell.net(vss), "the stub touches the strip");
    let mut nets = vec![cell.net(pad), cell.net(vss)];
    nets.sort_unstable();
    let mut grid = StressGrid::default();
    extract_stress_into(
        &cell.store,
        &cell.nets,
        &cell.devices,
        cell.process(),
        Stress {
            nets: &nets,
            source: cell.poly(pad),
            source_net: None,
            current: microamps(1.33e6),
            sink: cell.net(vss),
            pins: &[],
            devices: &[],
            device_resistance: ohms(1.0),
        },
        &mut grid,
    )
    .expect("every conductor has a sheet resistance");
    assert_eq!(grid.grid.source_node.len(), 1);
    let held = grid.grid.node_poly[grid.grid.source_node[0] as usize];
    assert_eq!(held, cell.poly(vss));
}

/// A pad's diffusion `d1` with another net's diffusion `d0` 4999 nm to its
/// left, drawn first so it has the lower row, and a third diffusion
/// diagonally off its corner, 4 µm on each axis (5657 nm away).
/// Oracle: by construction against 5 µm: only the 4999 nm pair is closer.
#[test]
fn a_pad_junction_is_flagged_only_closer_than_the_spacing() {
    let mut drawn = None;
    let cell = Cell::new(|l| {
        let d0 = l.rect(DIFF, 0, 5000, 1000, 6000);
        let d1 = l.rect(DIFF, 5999, 5000, 6999, 6000);
        l.rect(PAD, 5999, 5000, 6999, 6000);
        l.rect(DCUT, 6400, 5400, 6600, 5600);
        l.rect(DIFF, 10_999, 10_000, 11_999, 11_000);
        drawn = Some((d0, d1));
    });
    let (d0, d1) = drawn.expect("drawn");
    assert!(cell.poly(d0) < cell.poly(d1));
    let (mut out, mut runs) = report();
    check_esd_parasitic(
        cell.design(),
        &EsdParasiticTable {
            head: head(rule(2)),
            pad: vec![PAD],
            diffusion: vec![DIFF],
            min_spacing: vec![Dbu::new_unchecked(5000)],
        },
        &mut out,
        &mut runs,
    );
    assert_eq!(
        out.measured,
        vec![Measurement::Length(Dbu::new_unchecked(4999))]
    );
    assert_eq!(out.shape_a, vec![cell.poly(d1)]);
}

/// A 10 µm well holding a 2 µm² gate and three 200 nm contacts: 6 % of tie.
/// Oracle: closed form: 0.12 µm² over 2 µm² is 6 %, above a 3 % floor, so
/// the one well examined is clean.
#[test]
fn a_well_with_enough_tie_is_clean() {
    let cell = Cell::new(|l| {
        l.rect(WELL, 0, 0, 10_000, 10_000);
        l.rect(GATE, 1000, 1000, 2000, 3000);
        for x in [5000, 6000, 7000] {
            l.rect(CONT, x, 5000, x + 200, 5200);
        }
    });
    let (mut out, mut runs) = report();
    check_tie_area(
        cell.design(),
        &TieAreaTable {
            head: head(rule(3)),
            region: vec![WELL],
            contact: vec![CONT],
            channel: vec![GATE],
            min_ratio: vec![0.03],
        },
        &mut Scratch::default(),
        &mut out,
        &mut runs,
    );
    assert!(out.measured.is_empty(), "{:?}", out.measured);
    assert_eq!(common::run_of(&runs, rule(3)).examined, 1);
}

/// Four bars around the box `(x0, y0, x1, y1)`, `band` wide, on the ring.
fn ring_round(l: &mut LayoutBuilder, (x0, y0, x1, y1): (i64, i64, i64, i64), band: i64) {
    l.rect(RING, x0 - band, y0 - band, x1 + band, y0);
    l.rect(RING, x0 - band, y1, x1 + band, y1 + band);
    l.rect(RING, x0 - band, y0, x0, y1);
    l.rect(RING, x1, y0, x1 + band, y1);
}

/// A ring whose hole is an L (a block of ring fills one corner of a square
/// hole), with a target inside the block: in the hole's box but not in the
/// hole. A second target sits in a square ring.
/// Oracle: by construction: the first target is surrounded by no hole, the
/// second is; both are examined.
#[test]
fn a_target_in_a_hole_s_box_but_not_its_hole_is_not_surrounded() {
    let mut drawn = None;
    let cell = Cell::new(|l| {
        ring_round(l, (1000, 1000, 9000, 9000), 1000);
        l.rect(RING, 5000, 5000, 9000, 9000);
        let blocked = l.rect(DIFF, 6000, 6000, 8000, 8000);
        ring_round(l, (20_000, 20_000, 24_000, 24_000), 1000);
        l.rect(DIFF, 21_000, 21_000, 23_000, 23_000);
        drawn = Some(blocked);
    });
    let blocked = drawn.expect("drawn");
    let (mut out, mut runs) = report();
    check_guard_ring(
        cell.design(),
        &GuardRingTable {
            head: head(rule(4)),
            target: vec![DIFF],
            ring: vec![RING],
            max_space: vec![None],
            min_width: vec![None],
            pad: vec![None],
            near: vec![None],
            clear: vec![None],
        },
        &mut Scratch::default(),
        &mut out,
        &mut runs,
    );
    assert_eq!(out.measured, vec![Measurement::Count(0)]);
    assert_eq!(out.shape_a, vec![cell.poly(blocked)]);
    assert_eq!(common::run_of(&runs, rule(4)).examined, 2);
}

/// A diffusion joined to a pad is an aggressor; a 10 µm region 2 µm from
/// it, tapped only at its far end, is its victim.
/// Oracle: by construction: the region's left edge is 10 µm from its tap,
/// above the 2 µm a victim may be.
#[test]
fn a_victim_of_a_pad_junction_is_held_to_its_tap_distance() {
    let cell = Cell::new(|l| {
        l.rect(DIFF, 0, 0, 1000, 1000);
        l.rect(PAD, 0, 0, 1000, 1000);
        l.rect(DCUT, 400, 400, 600, 600);
        l.rect(GATE, 3000, 0, 13_000, 1000);
        l.rect(CONT, 13_000, 0, 13_500, 1000);
    });
    let (mut out, mut runs) = report();
    check_latchup_victim(
        cell.design(),
        &LatchupVictimTable {
            head: head(rule(5)),
            aggressor: vec![DIFF],
            region: vec![GATE],
            tap: vec![CONT],
            within: vec![Dbu::new_unchecked(15_000)],
            max_distance: vec![Dbu::new_unchecked(2000)],
            pad: vec![Some(PAD)],
        },
        &mut Scratch::default(),
        &mut out,
        &mut runs,
    );
    assert_eq!(
        out.measured,
        vec![Measurement::Length(Dbu::new_unchecked(10_000))]
    );
}
