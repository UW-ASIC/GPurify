use super::*;
use crate::compare::compare;

/// A SPEF as an extractor writes one: picofarads and kilohms, a name map,
/// a driver pin, triplets, and the coupling listed in both nets' sections.
const SPEF: &str = r#"*SPEF "IEEE 1481-2009"
*DESIGN "top"
*DIVIDER /
*DELIMITER :
*BUS_DELIMITER [ ]
*T_UNIT 1 NS
*C_UNIT 1 PF
*R_UNIT 1 KOHM
*L_UNIT 1 HENRY

*NAME_MAP
*1 a\[0\]
*2 b
*3 u1

*PORTS
*1 I

*D_NET *1 0.0030
*CONN
*I *3:Y O *L 0.001 *D INV
*P *1 I
*N *1:2 *C 1.0 2.0
*CAP
1 *1:2 0.0010:0.0012:0.0014
2 *3:Y 0.0005
3 *1:2 *2:1 0.0008
*RES
1 *3:Y *1:2 0.050
2 *1:2 *1 0.025
*END

*D_NET *2 0.0011
*CONN
*P *2 O
*CAP
1 *2:1 0.0003
2 *2:1 *1:2 0.0008
*RES
1 *2 *2:1 0.010
*END
"#;

fn element(read: &Read, kind: fn(Parasitic) -> Option<f64>) -> Vec<f64> {
    read.network.value.iter().filter_map(|&v| kind(v)).collect()
}

/// Oracle: hand-derived from IEEE 1481's units and forms: 1 PF is 1000 fF
/// and 1 KOHM 1000 Ω; `*1` reads as the mapped name with its escapes
/// removed; a triplet reads as its middle value; the coupling listed in both
/// nets is one 0.8 fF capacitor, so `a[0]` totals 1.2 + 0.5 + 0.8 = 2.5 fF
/// and `b` 0.3 + 0.8 = 1.1 fF; the driver is the output pin `u1:Y`.
#[test]
fn a_spef_reads_in_ff_and_ohms_with_its_names_mapped() {
    let read = read_spef(SPEF).expect("reads");
    assert_eq!(read.names, ["a[0]", "b"]);
    let totals = read.network.capacitance_per_net();
    assert!(
        (totals[0] - 2.5).abs() < 1e-9 && (totals[1] - 1.1).abs() < 1e-9,
        "{totals:?}"
    );
    let coupling = element(&read, |v| match v {
        Parasitic::CouplingCap(q) => Some(q.raw()),
        _ => None,
    });
    assert_eq!(coupling.len(), 1);
    let ohms = element(&read, |v| match v {
        Parasitic::Resistance(q) => Some(q.raw()),
        _ => None,
    });
    assert_eq!(ohms.len(), 3);
    assert!(ohms.iter().any(|&r| (r - 50.0).abs() < 1e-9));
    // The driver, u1:Y, is a[0]'s first node: its resistance to the port is
    // 50 + 25 = 75 Ω, and the farthest node from it.
    let both = compare(&read.network, &read.network);
    assert!((both.resistance.reference[0] - 75.0).abs() < 1e-9);
}

/// Oracle: the module's refusal list: a reduced net is not read, a node
/// no net owns is refused at its line, and so is a section before any
/// `*D_NET` (the fuzz crasher `fuzz/regressions/spef/conn_before_any_net`).
#[test]
fn a_reduced_net_and_an_orphan_node_are_refused() {
    let headless = SPEF.replacen("*D_NET *1", "*D_NOT *1", 1);
    let e = read_spef(&headless).unwrap_err();
    assert!(e.message.contains("before any *D_NET"), "{e}");
    assert!(e.line > 0);
    let reduced = SPEF.replace("*D_NET *2", "*R_NET *2");
    assert!(read_spef(&reduced).unwrap_err().message.contains("*R_NET"));
    let orphan = SPEF.replace("2 *2:1 *1:2 0.0008", "2 *2:1 zz:9 0.0008");
    let e = read_spef(&orphan).unwrap_err();
    assert!(e.message.contains("zz:9"), "{e}");
    assert!(e.line > 0);
}

/// Oracle: hand-derived: a DSPF's SPICE cards with scale suffixes (`f`,
/// `k`, `p`) and a `+` continuation; a coupling card between two nets'
/// nodes; ground named by `*|GROUND_NET`.
#[test]
fn a_dspf_reads_its_cards_with_their_suffixes() {
    let text = "*|DSPF 1.5\n*|DELIMITER :\n*|GROUND_NET VSS\n.SUBCKT top a b\n\
                *|NET a 0.3PF\n*|P (a I 0.0 0 0)\n*|S (a:1 1 2)\n\
                *|NET b 0.1PF\n*|I (u2:A u2 A I 0.0 0 0)\n\
                R1 a a:1 1.5k\nC1 a:1 VSS 200f\nC2 a:1\n+ u2:A 0.1p\nL1 a a:1 3p\nK1 L1 L2 0.5\n\
                Xu2 a b INV\n.ENDS\n";
    let read = read_dspf(text).expect("reads");
    assert_eq!(read.names, ["a", "b"]);
    let totals = read.network.capacitance_per_net();
    assert!(
        (totals[0] - 300.0).abs() < 1e-9 && (totals[1] - 100.0).abs() < 1e-9,
        "{totals:?}"
    );
    assert!(read
        .network
        .value
        .iter()
        .any(|v| matches!(v, Parasitic::Resistance(q) if (q.raw() - 1500.0).abs() < 1e-9)));
    assert!(read
        .network
        .value
        .iter()
        .any(|v| matches!(v, Parasitic::Inductance(q) if (q.raw() - 3.0).abs() < 1e-9)));
}

/// Oracle: construct-from-answer: two files over overlapping nets, put on
/// the union of their names, share one net id per name, in order.
#[test]
fn two_files_meet_on_the_union_of_their_names() {
    let one = read_spef(SPEF).expect("reads");
    let union: Vec<String> = ["a[0]", "b", "c"].map(String::from).to_vec();
    let on = one.on_names(&union);
    assert_eq!(on.node_net.first(), Some(&NetId(0)));
    assert_eq!(on.node_net.last(), Some(&NetId(1)));
}
