//! The rules that ask only what is connected to what.
//!
//! Oracle throughout: construct-from-answer. `gpurify_testgen::layout_from_netlist`
//! emits a layout from a netlist whose structure was decided before any polygon
//! was drawn, so the floating gate, the contended net, the unreached conductor
//! and the tied-off input are all placed deliberately — and each must be found
//! on the net it was placed on, at that net's own polygon.
//!
//! Every clean assertion here goes through `assert_clean`, which asserts the
//! rule ran and examined a nonzero number of nets before asserting it found
//! nothing. Forty-five of the previous suite's ninety-four DRC cases asserted
//! only the last of those three, so a rule that never executed passed all of
//! them.

use crate::common;

use common::{head, rule};
use gpurify_geom::PolyId;
use gpurify_geom::Evaluator;
use gpurify_check::erc::facts::{classify_nets_into, NetFacts};
use gpurify_check::erc::rules::topology::{
    check_floating_gate, check_multiple_drivers, check_unconnected_pin, FloatingGateTable,
    MultipleDriversTable, UnconnectedPinTable,
};
use gpurify_check::erc::{Design, Scratch};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrTable;
use gpurify_check::report::{Measurement, Severity, Violations};
use gpurify_testgen::{
    assert_clean, assert_rule_ran, layout_from_netlist, DeviceSpec, Floorplan, NetlistCase,
    NetlistSpec,
};
use gpurify_check::topology::{DeviceTable, NetTable, TerminalRole};

/// A layout emitted from a netlist, extracted and classified — everything the
/// four transforms in `rules::topology` read.
struct Extracted {
    case: NetlistCase,
    derived: Evaluator,
    nets: NetTable,
    devices: DeviceTable,
    facts: NetFacts,
}

fn extract(spec: &NetlistSpec) -> Extracted {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(spec, Floorplan::default(), &mut strings);
    let derived = Evaluator::default();
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    gpurify_check::topology::device::recognise_into(
        &case.store,
        &derived,
        &nets,
        &case.recognition,
        &mut devices,
    );
    let mut facts = NetFacts::default();
    classify_nets_into(&nets, &devices, &mut facts);
    Extracted {
        case,
        derived,
        nets,
        devices,
        facts,
    }
}

impl Extracted {
    fn design(&self) -> Design<'_> {
        Design {
            store: &self.case.store,
            derived: &self.derived,
            nets: &self.nets,
            devices: &self.devices,
        }
    }

    /// The lowest-numbered polygon of netlist net `n`. `NetTable::polys_of` is
    /// ascending, so this is the canonical shape a per-net rule reports at.
    fn lowest_poly(&self, n: usize) -> PolyId {
        self.case.expected_net_polys[n][0]
    }
}

fn mos(model: &str, terminals: Vec<(TerminalRole, u32)>) -> DeviceSpec {
    DeviceSpec {
        kind: DeviceKind::Mos,
        model: model.to_owned(),
        terminals,
    }
}

/// Assert one violation on the expected net, reported at that net's lowest
/// polygon and at a point on it.
fn assert_one_violation_on(
    extracted: &Extracted,
    violations: &Violations,
    id: gpurify_ingest::StrId,
    net: usize,
) {
    assert_eq!(
        violations.rule.len(),
        1,
        "the layout holds exactly one of these"
    );
    assert_eq!(violations.rule[0], id);
    assert_eq!(violations.severity[0], Severity::Error);
    assert_eq!(
        violations.shape_a[0],
        extracted.lowest_poly(net),
        "a per-net violation is reported at the net's lowest-numbered polygon"
    );
    assert_eq!(
        violations.layer[0],
        extracted.case.store.poly_layer(extracted.lowest_poly(net))
    );
    common::assert_at_is_on_a_named_shape(&extracted.case.store, violations, 0);
}

/// Oracle: construct-from-answer. Net zero carries the transistor's gate and
/// nothing else, so it has no path to a supply through anything: it charges to
/// whatever the process left on it and stays there. The other three nets each
/// carry a source, a drain or a bulk, so they are not gates-and-nothing-else
/// and the rule must leave them alone.
#[test]
fn a_net_carrying_only_a_gate_is_flagged_at_its_own_polygon() {
    let extracted = extract(&NetlistSpec {
        nets: 4,
        devices: vec![mos(
            "nch",
            vec![
                (TerminalRole::Gate, 0),
                (TerminalRole::Source, 1),
                (TerminalRole::Drain, 2),
                (TerminalRole::Bulk, 3),
            ],
        )],
    });
    let id = rule(40);
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_floating_gate(
        extracted.design(),
        &extracted.facts,
        &FloatingGateTable { head: head(id) },
        &mut violations,
        &mut runs,
    );

    assert_one_violation_on(&extracted, &violations, id, 0);
    let run = assert_rule_ran(&runs, id);
    assert_eq!(
        run.examined, 1,
        "one net carries a gate terminal, and that is the population this rule could flag"
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. The same gate net, now also carrying a second
/// transistor's drain, is driven and is not floating. The clean assertion
/// asserts the rule ran and examined that net — an empty violation table on its
/// own is equally consistent with a rule whose layer lookup returned nothing.
#[test]
fn a_gate_net_that_a_drain_also_reaches_is_clean() {
    let extracted = extract(&NetlistSpec {
        nets: 4,
        devices: vec![
            mos(
                "nch",
                vec![
                    (TerminalRole::Gate, 0),
                    (TerminalRole::Source, 1),
                    (TerminalRole::Drain, 2),
                    (TerminalRole::Bulk, 3),
                ],
            ),
            mos(
                "nch",
                vec![
                    (TerminalRole::Gate, 1),
                    (TerminalRole::Drain, 0),
                    (TerminalRole::Source, 2),
                    (TerminalRole::Bulk, 3),
                ],
            ),
        ],
    });
    let id = rule(41);
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_floating_gate(
        extracted.design(),
        &extracted.facts,
        &FloatingGateTable { head: head(id) },
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

/// Two transistors whose drains meet on net two, driven from `gate_a` and
/// `gate_b`. Passing the same net for both is the multi-finger case.
///
/// Terminals are listed in `topology::role_at`'s MOS order — `Gate, Source,
/// Drain, Bulk` — because `DeviceSpec::terminals` is documented as "the order
/// the recogniser will report them" and the role written beside each net only
/// picks the layer. Listing `Drain` second puts the shared net on the *source*,
/// which makes the test contradict itself: no implementation can both report
/// one drain-carrying net and flag net two.
fn contended_output(gate_a: u32, gate_b: u32) -> NetlistSpec {
    NetlistSpec {
        nets: 5,
        devices: vec![
            mos(
                "nch",
                vec![
                    (TerminalRole::Gate, gate_a),
                    (TerminalRole::Source, 3),
                    (TerminalRole::Drain, 2),
                    (TerminalRole::Bulk, 3),
                ],
            ),
            mos(
                "pch",
                vec![
                    (TerminalRole::Gate, gate_b),
                    (TerminalRole::Source, 4),
                    (TerminalRole::Drain, 2),
                    (TerminalRole::Bulk, 4),
                ],
            ),
        ],
    }
}

/// Oracle: construct-from-answer. Two drains on net two, belonging to devices
/// whose gates are on different nets, is contention: two things can drive the
/// net at once. The measurement is the number of distinct driving gate nets —
/// two — against the configured maximum of one.
#[test]
fn a_net_with_two_independently_gated_drains_is_flagged_with_its_driver_count() {
    let extracted = extract(&contended_output(0, 1));
    let id = rule(42);
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &MultipleDriversTable {
            head: head(id),
            max_drivers: vec![1],
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_one_violation_on(&extracted, &violations, id, 2);
    assert_eq!(
        violations.measured[0],
        Measurement::Count(2),
        "the measurement is how many distinct gate nets drive this one"
    );
    assert_eq!(violations.limit[0], Measurement::Count(1));

    let run = assert_rule_ran(&runs, id);
    assert_eq!(run.examined, 1, "one net carries a drain terminal");
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. The same two drains, now sharing one gate
/// net: this is one driver built wide, which is how every multi-finger output
/// in a standard cell library is drawn. Counting drains instead of distinct
/// gate nets would make all of them violations, which is the false positive
/// this rule's doc comment is written against.
#[test]
fn two_drains_sharing_one_gate_net_are_one_driver_and_are_clean() {
    let extracted = extract(&contended_output(0, 0));
    let id = rule(43);
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &MultipleDriversTable {
            head: head(id),
            max_drivers: vec![1],
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

/// Oracle: construct-from-answer. `layout_from_netlist` gives every net a rail,
/// including the nets nothing attaches to — so net two's rail is a conductor
/// that reaches no device terminal, and the rails of nets zero and one are not.
/// The rule examines all three rails and reports exactly the one.
#[test]
fn a_conductor_on_a_net_no_device_reaches_is_flagged() {
    let extracted = extract(&NetlistSpec {
        nets: 3,
        devices: vec![mos(
            "nch",
            vec![(TerminalRole::Gate, 0), (TerminalRole::Source, 1)],
        )],
    });
    let id = rule(44);
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_unconnected_pin(
        extracted.design(),
        &extracted.facts,
        &UnconnectedPinTable {
            head: head(id),
            layer_start: vec![0, 1],
            layer: vec![extracted.case.layers.rail],
        },
        &mut violations,
        &mut runs,
    );

    assert_one_violation_on(&extracted, &violations, id, 2);
    let run = assert_rule_ran(&runs, id);
    assert_eq!(
        run.examined, 3,
        "one rail per net lies on the listed layer, and all three were looked at"
    );
}

/// Oracle: construct-from-answer. Naming no layer is a different situation from
/// naming a layer with nothing on it, and neither is clean: with an empty layer
/// list the rule has nothing to examine, and its run row must say so rather
/// than report a design fully checked.
#[test]
fn an_unconnected_pin_rule_naming_no_layer_examines_nothing() {
    let extracted = extract(&NetlistSpec {
        nets: 2,
        devices: vec![mos(
            "nch",
            vec![(TerminalRole::Gate, 0), (TerminalRole::Source, 1)],
        )],
    });
    let id = rule(45);
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_unconnected_pin(
        extracted.design(),
        &extracted.facts,
        &UnconnectedPinTable {
            head: head(id),
            layer_start: vec![0, 0],
            layer: Vec::new(),
        },
        &mut violations,
        &mut runs,
    );

    let run = common::run_of(&runs, id);
    assert_eq!(run.examined, 0);
    assert_eq!(run.violations, 0);
    assert!(violations.rule.is_empty());
}

/// Oracle: determinism. The same layout run twice must produce the same rows in
/// the same order, including the reported coordinate. Net ids are canonical
/// because they derive from the minimum polygon index in the component, so
/// nothing about this result is allowed to depend on the order the work
/// happened in.
#[test]
fn running_the_topological_rules_twice_produces_identical_rows() {
    let extracted = extract(&contended_output(0, 1));
    let id = rule(46);
    let table = MultipleDriversTable {
        head: head(id),
        max_drivers: vec![1],
    };

    let mut scratch = Scratch::default();
    let mut first = Violations::default();
    let mut first_runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &table,
        &mut scratch,
        &mut first,
        &mut first_runs,
    );

    let mut second = Violations::default();
    let mut second_runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &table,
        &mut scratch,
        &mut second,
        &mut second_runs,
    );

    gpurify_testgen::assert_violations_eq(&first, &second);
    assert_eq!(first_runs, second_runs);
}
