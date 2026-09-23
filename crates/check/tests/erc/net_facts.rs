//! Role masks, and the one pass that builds them.
//!
//! `NetFacts` is read by six rules and built once, so an error here is six
//! wrong verdicts with one cause. The fold is checked construct-from-answer: a
//! layout emitted from a netlist must classify back to that netlist's
//! terminals.

use gpurify_check::erc::facts::{classify_nets_into, NetFacts, RoleMask};
use gpurify_check::topology::{DeviceTable, NetId, NetTable, TerminalRole};
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

/// Oracle: construct-from-answer. `RoleMask::of` is the single place the
/// role-to-bit mapping is written down, so the mapping is the thing to pin: the
/// seven named roles land on the seven named constants, on seven distinct
/// single bits.
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
        0xFF,
        "the eight role bits together must be all eight bits"
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
            classified.facts.role[net.idx()],
            want,
            "net {index} ({net:?}) carries the wrong roles"
        );
    }
}

/// Oracle: construct-from-answer. One row of facts per extracted net.
#[test]
fn there_is_one_row_of_facts_per_extracted_net() {
    let classified = classify(&mixed_netlist());
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
