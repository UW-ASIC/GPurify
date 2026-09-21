//! Role masks, and the one pass that builds them.
//!
//! `NetFacts` is read by six rules and built once, so an error here is six
//! wrong verdicts with one cause. Two oracles apply. The mask algebra is
//! checked by law over its whole domain — eight bits is small enough to
//! enumerate every pair, so "for all masks" is literal rather than sampled. The
//! fold itself is checked construct-from-answer: a layout emitted from a
//! netlist must classify back to that netlist's terminals.

use gpurify_check::erc::facts::{classify_nets_into, NetFacts, RoleMask};
use gpurify_check::topology::{DeviceTable, NetId, NetTable, TerminalRole};
use gpurify_geom::Evaluator;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrTable;
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistCase, NetlistSpec};

/// The seven named roles, with the bit each is documented to carry.
const NAMED: [(TerminalRole, RoleMask); 7] = [
    (TerminalRole::Gate, RoleMask::GATE),
    (TerminalRole::Source, RoleMask::SOURCE),
    (TerminalRole::Drain, RoleMask::DRAIN),
    (TerminalRole::Bulk, RoleMask::BULK),
    (TerminalRole::Base, RoleMask::BASE),
    (TerminalRole::Emitter, RoleMask::EMITTER),
    (TerminalRole::Collector, RoleMask::COLLECTOR),
];

/// Every single-role mask, for exhaustive law checking.
fn every_mask() -> Vec<RoleMask> {
    let mut masks: Vec<RoleMask> = NAMED.iter().map(|&(_, mask)| mask).collect();
    masks.push(RoleMask::PIN);
    masks.push(RoleMask::NONE);
    masks.push(RoleMask::ANY);
    // A few combinations, so the laws are exercised on masks with more than one
    // bit set as well as on the atoms.
    masks.push(RoleMask::GATE.union(RoleMask::SOURCE));
    masks.push(RoleMask::DRAIN.union(RoleMask::PIN));
    masks.push(RoleMask::ANY.without(RoleMask::GATE));
    masks
}

/// Oracle: construct-from-answer. `RoleMask::of` is the single place the
/// role-to-bit mapping is written down, so the mapping is the thing to pin: the
/// seven named roles land on the seven named constants, on seven distinct
/// single bits, and every one of them is inside `ANY`.
///
/// The distinctness half is what makes this more than a restatement of the
/// constants — a mapping that sent two roles to one bit would make
/// `tie_high_low` and `floating_gate` answer each other's question.
#[test]
fn each_named_terminal_role_maps_to_its_own_single_bit() {
    for (role, expected) in NAMED {
        assert_eq!(
            RoleMask::of(role),
            expected,
            "{role:?} maps to the wrong bit"
        );
        assert_eq!(
            expected.0.count_ones(),
            1,
            "{role:?} must be one bit, not {expected:?}"
        );
        assert!(
            RoleMask::ANY.contains(expected),
            "ANY must contain {role:?}"
        );
    }

    // Distinctness is read back out of `of`, not out of the constants: a
    // mapping that sent two roles to one bit is a defect in the function, and
    // deduplicating the constants would only ever catch someone editing the
    // constants.
    let mut bits: Vec<u8> = NAMED
        .iter()
        .map(|&(role, _)| RoleMask::of(role).0)
        .collect();
    bits.push(RoleMask::of(TerminalRole::Pin(0)).0);
    bits.sort_unstable();
    bits.dedup();
    assert_eq!(
        bits.len(),
        8,
        "the eight roles must map to eight distinct bits"
    );
    assert_eq!(
        bits.iter().fold(0u8, |all, &bit| all | bit),
        RoleMask::ANY.0,
        "the eight role bits together must be ANY, or a mask carries a bit no role sets"
    );
}

/// Oracle: construct-from-answer. The pin index of a symmetric two-terminal
/// device carries no electrical meaning, so every index collapses to one bit —
/// stated in `RoleMask`'s own doc comment. An implementation shifting by the
/// index instead would put `Pin(3)` on the drain bit and make a resistor look
/// like a driver.
#[test]
fn every_pin_index_collapses_to_the_one_pin_bit() {
    for index in [0u8, 1, 2, 7, 255] {
        assert_eq!(
            RoleMask::of(TerminalRole::Pin(index)),
            RoleMask::PIN,
            "Pin({index}) must carry no more meaning than Pin(0)"
        );
    }
}

/// Oracle: law, over the whole domain. Union is a set union: commutative,
/// idempotent, and a superset of both operands. Eight bits means these hold for
/// every pair rather than for the pairs a fixture happened to pick.
#[test]
fn union_is_commutative_idempotent_and_contains_both_operands() {
    for a in every_mask() {
        assert_eq!(a.union(a), a, "{a:?} union itself is itself");
        assert_eq!(a.union(RoleMask::NONE), a, "NONE is the identity of union");
        assert_eq!(a.union(RoleMask::ANY), RoleMask::ANY);
        for b in every_mask() {
            let joined = a.union(b);
            assert_eq!(
                joined,
                b.union(a),
                "union of {a:?} and {b:?} is not commutative"
            );
            assert!(joined.contains(a) && joined.contains(b));
        }
    }
}

/// Oracle: law, over the whole domain. `without` removes exactly the bits it
/// names and nothing else: the result stays inside the original, shares no bit
/// with what was removed, and putting the removed bits back recovers the
/// original.
#[test]
fn without_removes_exactly_the_bits_it_names() {
    for a in every_mask() {
        assert_eq!(a.without(RoleMask::NONE), a);
        assert_eq!(a.without(RoleMask::ANY), RoleMask::NONE);
        for b in every_mask() {
            let stripped = a.without(b);
            assert!(a.contains(stripped), "{stripped:?} left {a:?}");
            assert!(
                !stripped.intersects(b),
                "{stripped:?} still shares a bit with {b:?}"
            );
            assert!(
                stripped.union(b).contains(a),
                "removing {b:?} from {a:?} lost a bit that was not {b:?}"
            );
        }
    }
}

/// Oracle: law, over the whole domain. `intersects` and `without` are two views
/// of the same fact, so they must agree everywhere: two masks share a bit
/// exactly when removing one changes the other. Cross-checking the pair is what
/// catches an implementation that got one of them backwards, which neither
/// function's own test would notice.
#[test]
fn intersects_agrees_with_whether_removal_changes_anything() {
    for a in every_mask() {
        for b in every_mask() {
            assert_eq!(
                a.intersects(b),
                a.without(b) != a,
                "{a:?} and {b:?} disagree between intersects and without"
            );
            assert_eq!(a.intersects(b), b.intersects(a), "intersects is symmetric");
        }
    }
}

/// Oracle: law. `NONE` is the empty mask and `ANY` is the full one, and
/// `is_empty` must agree with both. `is_device_connected` is written as
/// `mask != NONE` across five rules, so a mask that reported itself empty while
/// holding a bit would report a connected net as floating.
#[test]
fn none_is_the_only_empty_mask_and_any_contains_everything() {
    assert!(RoleMask::NONE.is_empty());
    assert!(!RoleMask::ANY.is_empty());
    assert_eq!(RoleMask::default(), RoleMask::NONE);
    for mask in every_mask() {
        assert_eq!(mask.is_empty(), mask == RoleMask::NONE, "{mask:?}");
        assert!(RoleMask::ANY.contains(mask));
        assert!(mask.contains(mask), "contains is reflexive");
        assert!(mask.contains(RoleMask::NONE), "everything contains NONE");
    }
}

/// A layout emitted from `spec`, extracted, and classified.
struct Classified {
    case: NetlistCase,
    nets: NetTable,
    facts: NetFacts,
}

fn classify(spec: &NetlistSpec) -> Classified {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(spec, Floorplan::default(), &mut strings);
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    gpurify_check::topology::device::recognise_into(
        &case.store,
        &Evaluator::default(),
        &nets,
        &case.recognition,
        &mut devices,
    );
    let mut facts = NetFacts::default();
    classify_nets_into(&nets, &devices, &mut facts);
    Classified { case, nets, facts }
}

impl Classified {
    fn net(&self, n: usize) -> NetId {
        self.nets.net_of(self.case.expected_net_polys[n][0])
    }
}

/// A MOS and a resistor sharing two nets, plus a net nothing attaches to.
fn mixed_netlist() -> NetlistSpec {
    NetlistSpec {
        nets: 5,
        devices: vec![
            DeviceSpec {
                kind: DeviceKind::Mos,
                model: "nch".to_owned(),
                terminals: vec![
                    (TerminalRole::Gate, 0),
                    (TerminalRole::Source, 1),
                    (TerminalRole::Drain, 2),
                    (TerminalRole::Bulk, 3),
                ],
            },
            DeviceSpec {
                kind: DeviceKind::Resistor,
                model: "res".to_owned(),
                terminals: vec![(TerminalRole::Pin(0), 2), (TerminalRole::Pin(1), 3)],
            },
        ],
    }
}

/// Oracle: construct-from-answer. The netlist decided which role sits on which
/// net before a single polygon was drawn, so the classification must give it
/// back exactly — including the resistor's two pins landing on the same bit and
/// the fifth net, which nothing touches, coming back empty.
#[test]
fn role_masks_reproduce_the_netlist_the_layout_was_built_from() {
    let classified = classify(&mixed_netlist());
    let expected = [
        RoleMask::GATE,
        RoleMask::SOURCE,
        RoleMask::DRAIN.union(RoleMask::PIN),
        RoleMask::BULK.union(RoleMask::PIN),
        RoleMask::NONE,
    ];

    for (index, want) in expected.into_iter().enumerate() {
        let net = classified.net(index);
        assert_eq!(
            classified.facts.role_of(net),
            want,
            "net {index} ({net:?}) carries the wrong roles"
        );
    }
}

/// Oracle: construct-from-answer. Terminals are counted, not devices, so the
/// column must reproduce the per-net terminal count the spec states: one on the
/// gate and source nets, two on each of the nets the resistor shares with the
/// transistor, none on the fifth.
#[test]
fn terminal_counts_reproduce_the_netlists_own_per_net_totals() {
    let classified = classify(&mixed_netlist());
    for (index, want) in [1u32, 1, 2, 2, 0].into_iter().enumerate() {
        let net = classified.net(index);
        assert_eq!(
            classified.facts.terminals[net.0 as usize], want,
            "net {index} ({net:?}) has the wrong terminal count"
        );
    }
}

/// Oracle: law. Every terminal lands on exactly one net, so summing the per-net
/// counts must give the netlist's total. Conservation, so it holds for any
/// spec — and it is what catches a fold that skipped a device family, which is
/// the failure the mask's own doc comment records the old tree having.
#[test]
fn terminal_counts_sum_to_the_number_of_terminals_in_the_netlist() {
    let spec = mixed_netlist();
    let classified = classify(&spec);

    let declared: u32 = spec
        .devices
        .iter()
        .map(|device| u32::try_from(device.terminals.len()).expect("a hand-written spec is small"))
        .sum();
    let counted: u32 = classified.facts.terminals.iter().sum();
    assert_eq!(counted, declared, "a terminal was lost or double-counted");
    assert_eq!(
        classified.facts.len(),
        classified.nets.net_count(),
        "there is one row of facts per extracted net"
    );
    assert!(!classified.facts.is_empty());
}

/// Oracle: construct-from-answer, on the regression the mask's doc comment
/// names. A block holding only passives has no MOS device at all, and the old
/// implementation answered "is anything attached" by scanning the MOS list —
/// so it reported every net in such a block as unconnected, a whole-block false
/// positive. Both of this resistor's nets are device-connected.
#[test]
fn a_net_reached_only_by_a_passive_device_is_still_device_connected() {
    let spec = NetlistSpec {
        nets: 3,
        devices: vec![DeviceSpec {
            kind: DeviceKind::Resistor,
            model: "res".to_owned(),
            terminals: vec![(TerminalRole::Pin(0), 0), (TerminalRole::Pin(1), 1)],
        }],
    };
    let classified = classify(&spec);

    assert!(classified.facts.is_device_connected(classified.net(0)));
    assert!(classified.facts.is_device_connected(classified.net(1)));
    assert!(
        !classified.facts.is_device_connected(classified.net(2)),
        "the third net has no terminal on it at all"
    );
}
