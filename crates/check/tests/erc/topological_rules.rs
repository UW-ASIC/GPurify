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
use gpurify_check::erc::facts::{classify_nets_into, IntentMap, NetFacts};
use gpurify_check::erc::rules::topology::{
    check_floating_gate, check_multiple_drivers, check_unconnected_pin, FloatingGateTable,
    MultipleDriversTable, UnconnectedPinTable,
};
use gpurify_check::erc::{Design, Scratch};
use gpurify_check::report::{Measurement, RuleRun, Severity, Violations};
use gpurify_check::topology::{bind_ports_into, DeviceTable, NetTable, PortTable, TerminalRole};
use gpurify_geom::PolyId;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrTable;
use gpurify_testgen::{
    assert_clean, assert_rule_ran, layout_from_netlist, DeviceSpec, Floorplan, NetlistCase,
    NetlistSpec,
};

/// A layout emitted from a netlist, extracted and classified — everything the
/// four transforms in `rules::topology` read.
struct Extracted {
    case: NetlistCase,
    nets: NetTable,
    devices: DeviceTable,
    facts: NetFacts,
}

fn extract(spec: &NetlistSpec) -> Extracted {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(spec, Floorplan::default(), &mut strings);
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    gpurify_check::topology::device::recognise_into(
        &case.store,
        &nets,
        &case.recognition,
        &mut devices,
    );
    let mut facts = NetFacts::default();
    classify_nets_into(&nets, &devices, &mut facts);
    Extracted {
        case,
        nets,
        devices,
        facts,
    }
}

impl Extracted {
    fn design(&self) -> Design<'_> {
        Design {
            store: &self.case.store,
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
        &PortTable::default(),
        &FloatingGateTable {
            head: head(id),
            labels_are_ports: vec![false],
        },
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
        &PortTable::default(),
        &FloatingGateTable {
            head: head(id),
            labels_are_ports: vec![false],
        },
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

/// Oracle: construct-from-answer. The gate-only net of the first test, now
/// labelled. A label alone names a net, so it still floats; on a row that
/// treats labels as ports it is a block input driven from outside, so it is
/// clean.
#[test]
fn a_labelled_gate_only_net_is_clean_only_where_labels_are_ports() {
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
    let mut strings = StrTable::default();
    let mut labels = gpurify_ingest::Provenance::default();
    labels.label(extracted.lowest_poly(0), strings.intern("in"));
    let mut ports = PortTable::default();
    bind_ports_into(&extracted.nets, &labels, &mut ports).expect("one label, one net");

    let id = rule(42);
    let run = |labels_are_ports| {
        let mut violations = Violations::default();
        let mut runs = Vec::new();
        check_floating_gate(
            extracted.design(),
            &extracted.facts,
            &ports,
            &FloatingGateTable {
                head: head(id),
                labels_are_ports: vec![labels_are_ports],
            },
            &mut violations,
            &mut runs,
        );
        (violations, runs)
    };

    let (violations, _) = run(false);
    assert_one_violation_on(&extracted, &violations, id, 0);
    let (violations, runs) = run(true);
    assert_clean(&runs, &violations, id);
}

/// Two transistors whose channels meet on net two, gated from `gate_a` and
/// `gate_b`: an nch from rail three and a pch from rail four. Passing the same
/// net for both is the multi-finger case. With `output_first`, the nch's
/// output end is the one extraction calls its source.
///
/// Terminals are listed in `topology::role_at`'s MOS order — `Gate, Source,
/// Drain, Bulk` — because `DeviceSpec::terminals` is documented as "the order
/// the recogniser will report them" and the role written beside each net only
/// picks the layer.
fn contended_output(gate_a: u32, gate_b: u32, output_first: bool) -> NetlistSpec {
    let (source, drain) = if output_first { (2, 3) } else { (3, 2) };
    NetlistSpec {
        nets: 5,
        devices: vec![
            mos(
                "nch",
                vec![
                    (TerminalRole::Gate, gate_a),
                    (TerminalRole::Source, source),
                    (TerminalRole::Drain, drain),
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

/// Intent declaring netlist nets `power` and `ground` the supplies, keyed by
/// the nets extraction gave them.
fn rails(extracted: &Extracted, power: usize, ground: usize) -> IntentMap {
    let net = |n: usize| extracted.nets.net_of(extracted.lowest_poly(n));
    common::declared_supplies(net(power), net(ground), 1_800.0)
}

/// One `multiple_drivers` row at `max: 1` over `extracted`, rails four
/// (power) and three (ground).
fn drivers(extracted: &Extracted, id: gpurify_ingest::StrId) -> (Violations, Vec<RuleRun>) {
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &rails(extracted, 4, 3),
        &MultipleDriversTable {
            head: head(id),
            max_drivers: vec![1],
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    (violations, runs)
}

/// Oracle: construct-from-answer. Net two is pulled down to rail three by a
/// transistor gated from net zero and up to rail four by one gated from net
/// one: contention, two things can drive the net at once. The measurement is
/// the number of distinct drivers — two — against the configured maximum of
/// one. Which channel end extraction calls the source does not matter: with
/// the nch drawn output end first, its "drain" is on the rail, and a rule
/// orienting channels by that order saw one driver (F28).
#[test]
fn a_net_with_two_independently_gated_pull_networks_is_flagged_with_its_driver_count() {
    for output_first in [false, true] {
        let extracted = extract(&contended_output(0, 1, output_first));
        let id = rule(42);
        let (violations, runs) = drivers(&extracted, id);

        assert_one_violation_on(&extracted, &violations, id, 2);
        assert_eq!(
            violations.measured[0],
            Measurement::Count(2),
            "the measurement is how many distinct drivers pull this net"
        );
        assert_eq!(violations.limit[0], Measurement::Count(1));

        let run = assert_rule_ran(&runs, id);
        assert_eq!(
            run.examined, 1,
            "one net other than the rails carries a channel end"
        );
        assert_eq!(run.violations, 1);
    }
}

/// Oracle: construct-from-answer. The same two transistors, now sharing one
/// gate net: an inverter, one driver. Counting channels instead of pull
/// networks joined by their gates would make every inverter a violation,
/// which is the false positive this rule's doc comment is written against.
#[test]
fn two_pull_networks_sharing_one_gate_net_are_one_driver_and_are_clean() {
    let extracted = extract(&contended_output(0, 0, false));
    let id = rule(43);
    let (violations, runs) = drivers(&extracted, id);
    assert_clean(&runs, &violations, id);
}

/// Oracle: construct-from-answer. An inverter gated from net zero drives net
/// two; a pass transistor gated from net one joins net two to net five. With
/// nothing else on net five, the pass transistor reaches no rail and drives
/// nothing by itself: one driver. With a pull-down on net five gated from net
/// six, the pass transistor carries that pull-down onto net two: two drivers
/// on net two, and on net five the inverter (through the pass transistor)
/// and the pull-down, two again.
#[test]
fn a_pass_gate_drives_only_what_reaches_a_rail_through_it() {
    for pulled in [false, true] {
        let mut spec = contended_output(0, 0, false);
        spec.nets = 7;
        spec.devices.push(mos(
            "nch",
            vec![
                (TerminalRole::Gate, 1),
                (TerminalRole::Source, 5),
                (TerminalRole::Drain, 2),
                (TerminalRole::Bulk, 3),
            ],
        ));
        if pulled {
            spec.devices.push(mos(
                "nch",
                vec![
                    (TerminalRole::Gate, 6),
                    (TerminalRole::Source, 3),
                    (TerminalRole::Drain, 5),
                    (TerminalRole::Bulk, 3),
                ],
            ));
        }
        let extracted = extract(&spec);
        let id = rule(47);
        let (violations, runs) = drivers(&extracted, id);
        let run = assert_rule_ran(&runs, id);
        assert_eq!(run.examined, 2, "nets two and five carry channel ends");
        if !pulled {
            assert_clean(&runs, &violations, id);
            continue;
        }
        let mut flagged: Vec<PolyId> = violations.shape_a.clone();
        flagged.sort_unstable();
        let mut want = vec![extracted.lowest_poly(2), extracted.lowest_poly(5)];
        want.sort_unstable();
        assert_eq!(flagged, want);
        assert!(violations
            .measured
            .iter()
            .all(|&m| m == Measurement::Count(2)));
    }
}

/// Oracle: construct-from-answer. Without intent no net is known to be a
/// rail, so no pull network can be told from a pass gate: the rule skips
/// rather than report every net clean.
#[test]
fn multiple_drivers_skips_without_intent() {
    let extracted = extract(&contended_output(0, 1, false));
    let id = rule(48);
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &IntentMap::default(),
        &MultipleDriversTable {
            head: head(id),
            max_drivers: vec![1],
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    common::assert_skipped_for_intent(&runs, &violations, id);
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
    let extracted = extract(&contended_output(0, 1, false));
    let intent = rails(&extracted, 4, 3);
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
        &intent,
        &table,
        &mut scratch,
        &mut first,
        &mut first_runs,
    );

    let mut second = Violations::default();
    let mut second_runs = Vec::new();
    check_multiple_drivers(
        extracted.design(),
        &intent,
        &table,
        &mut scratch,
        &mut second,
        &mut second_runs,
    );

    gpurify_testgen::assert_violations_eq(&first, &second);
    assert_eq!(first_runs, second_runs);
}
