//! Antenna family: `gate_areas_into`, and the fail-closed behaviour of the two
//! rules built on it.
//!
//! # What is and is not reachable here
//!
//! `gate_areas_into` reads only the `DeviceTable`, whose columns are public, so
//! it is fully testable and is tested below against a device set whose per-net
//! totals were decided before the call.
//!
//! The two `check_*` transforms also need a `NetTable` in order to ask which
//! shapes are on a gate's net, and `NetTable` has private fields, no
//! constructor, and one producer that takes a `Connectivity` — see
//! `docs/NEED_TESTING.md`. So the ratio itself cannot be constructed from
//! outside this crate. What *can* be tested, and is, is the more important half:
//! a design with no recognised MOS devices has no denominator for the ratio, and
//! the rule says so rather than reporting clean. A deck whose device recognisers
//! never matched is the way an antenna check silently checks nothing.

mod common;

use common::{Env, Sink, A, B, RULE};
use gpurify_core::PolyId;
use gpurify_drc::rules::antenna::{
    check_antenna, check_antenna_car, gate_areas_into, AntennaCarTable, AntennaTable,
};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use gpurify_report::{Outcome, SkipReason};
use gpurify_testgen::shapes::{area, LayoutBuilder};
use gpurify_topology::device::{DeviceMeasure, DeviceParam};
use gpurify_topology::{DeviceTable, NetId, TerminalRole};
use gpurify_units::DbuArea;

/// A device table of MOS rows, one per `(marker polygon, gate net, gate area)`.
///
/// Every row carries the four terminals that make it a transistor rather than a
/// two-terminal device, so a reader looking for the one with
/// `TerminalRole::Gate` has three others to pick wrongly from. Both CSR offset
/// arrays end with a trailing bound, which is what closes the last row's range.
fn mos_devices(rows: &[(u32, u32, i128)]) -> DeviceTable {
    let mut devices = DeviceTable::default();
    for &(marker, gate_net, gate_area) in rows {
        devices
            .terminal_start
            .push(u32::try_from(devices.terminal_net.len()).expect("a handful of terminals"));
        devices
            .param_start
            .push(u32::try_from(devices.param.len()).expect("a handful of parameters"));

        devices.kind.push(DeviceKind::Mos);
        devices.marker.push(PolyId(marker));
        devices.model.push(StrId(0));
        devices
            .terminal_net
            .extend([NetId(gate_net), NetId(100), NetId(101), NetId(102)]);
        devices.terminal_role.extend([
            TerminalRole::Gate,
            TerminalRole::Source,
            TerminalRole::Drain,
            TerminalRole::Bulk,
        ]);
        devices
            .param
            .push((DeviceParam::Area, DeviceMeasure::Area(area(gate_area))));
    }
    devices
        .terminal_start
        .push(u32::try_from(devices.terminal_net.len()).expect("a handful of terminals"));
    devices
        .param_start
        .push(u32::try_from(devices.param.len()).expect("a handful of parameters"));
    devices
}

// ---------------------------------------------------------- gate_areas_into

/// Oracle: construct-from-answer. Three transistors, two of them on one net:
/// the answer is two rows, ascending by net, with the shared net carrying the
/// sum of its two gates. Both are decided here before the transform runs.
///
/// The ascending-and-deduplicated shape is the point of two columns rather than
/// a map. The old version keyed this in a `HashMap` and reported violations at
/// whichever gate the map's iteration reached first, which is why its
/// coordinates differed between runs of the same binary.
#[test]
fn gate_areas_sum_per_net_and_come_back_ascending_with_no_net_repeated() {
    let devices = mos_devices(&[(0, 7, 10_000), (1, 3, 4_000), (2, 7, 6_000)]);

    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 100, 100);
    let (store, _ids) = layout.finish();

    let env = Env {
        devices,
        ..Env::default()
    };

    // Pre-filled with junk, so the clearing the doc promises is checked rather
    // than assumed: a transform that appended would leave these rows in place.
    let mut net = vec![NetId(999)];
    let mut gate_area = vec![area(-1)];
    gate_areas_into(env.design(&store), &mut net, &mut gate_area);

    assert_eq!(net, vec![NetId(3), NetId(7)]);
    assert_eq!(gate_area, vec![area(4_000), area(16_000)]);
}

/// Oracle: law. The two columns are parallel by definition — `net[i]` has area
/// `area[i]` — so their lengths agree for every input, including the empty one.
/// A design with no devices produces two empty columns, not one empty and one
/// stale.
#[test]
fn the_two_gate_area_columns_stay_parallel_including_over_an_empty_device_set() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 100, 100);
    let (store, _ids) = layout.finish();
    let env = Env::default();

    let mut net = vec![NetId(4), NetId(5), NetId(6)];
    let mut gate_area: Vec<DbuArea> = vec![area(1)];
    gate_areas_into(env.design(&store), &mut net, &mut gate_area);

    assert_eq!(net.len(), gate_area.len());
    assert!(
        net.is_empty(),
        "a design with no recognised devices has no gates"
    );
}

// ------------------------------------------------------------------ antenna

fn antenna_table(ratio: f64) -> AntennaTable {
    let mut table = AntennaTable::default();
    table.rule.push(RULE);
    table.layer.push(B);
    table.ratio.push(ratio);
    table.diode.push(None);
    table
}

/// Oracle: construct-from-answer, fail closed. An antenna ratio is collector
/// area over gate area, so a design with no gates has no denominator and no
/// verdict. Reporting that as clean passes a deck whose device recognisers
/// never matched a single transistor — which is a deck that checked nothing and
/// looked fully checked, the failure this whole tree is built against.
#[test]
fn an_antenna_rule_over_a_design_with_no_gates_is_skipped_not_clean() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(B, 0, 0, 4_000, 4_000);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_antenna(
        env.design(&store),
        &antenna_table(50.0),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(
        sink.runs.len(),
        1,
        "one run row per rule row, whatever the outcome"
    );
    assert_eq!(sink.runs[0].rule, RULE);
    assert_eq!(
        sink.runs[0].outcome,
        Outcome::Skipped(SkipReason::EmptyLayer)
    );
    assert_eq!(sink.runs[0].violations, 0);
    assert!(sink.out.rule.is_empty());
}

// -------------------------------------------------------------- antenna_car

fn antenna_car_table(ratio: f64, stack: &[gpurify_core::LayerId]) -> AntennaCarTable {
    let mut table = AntennaCarTable::default();
    table.rule.push(RULE);
    table.stack_start.push(0);
    table
        .stack_len
        .push(u32::try_from(stack.len()).expect("a handful of metal layers"));
    table.stack.extend_from_slice(stack);
    table.ratio.push(ratio);
    table.diode.push(None);
    table
}

/// Oracle: construct-from-answer. The stack a row names is exactly the slice
/// its CSR range covers, in the order the deck listed it. Order *is* the rule
/// here — `stack[k]` is what is being etched at stage `k` and `stack[..=k]` is
/// what exists — so a reader that reversed or reordered the slice would give a
/// different and wrong answer on every cumulative check.
#[test]
fn a_cumulative_rule_reads_back_its_metal_stack_in_fabrication_order() {
    use gpurify_core::LayerId;
    let stack = [LayerId(4), LayerId(2), LayerId(9)];
    let table = antenna_car_table(50.0, &stack);
    assert_eq!(table.stack_of(0), &stack[..]);
}

/// Oracle: construct-from-answer, fail closed. Same claim as the single-layer
/// rule: with no gates there is nothing to refer the collected charge to, and
/// the cumulative check says so per rule row rather than falling back to a clean
/// result.
#[test]
fn a_cumulative_antenna_rule_over_a_design_with_no_gates_is_skipped_not_clean() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(B, 0, 0, 4_000, 4_000);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_antenna_car(
        env.design(&store),
        &antenna_car_table(50.0, &[B]),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(sink.runs[0].rule, RULE);
    assert_eq!(
        sink.runs[0].outcome,
        Outcome::Skipped(SkipReason::EmptyLayer)
    );
    assert!(sink.out.rule.is_empty());
}
