//! The reference netlist: its top-cell rule, a card-for-card read, and the two
//! readers' refusal to guess. CSR offset columns carry one terminator entry.

use gpurify_geom::StrTable;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::netlist::{spectre, spice, Netlist, NetlistError, RefNetId, SubcktId};

/// Two subcircuits, three devices, and terminal and parameter runs of three
/// different lengths — including an empty one, which is the case a CSR column
/// gets wrong.
fn two_subcircuits(strings: &mut StrTable) -> Netlist {
    let nets: Vec<RefNetId> = (0..6).map(RefNetId).collect();
    Netlist {
        subckt_name: vec![strings.intern("inv"), strings.intern("term")],
        subckt_port_start: vec![0, 2, 4],
        port_net: vec![nets[0], nets[1], nets[0], nets[4]],
        subckt_device_start: vec![0, 2, 3],

        device_name: vec![
            strings.intern("M1"),
            strings.intern("M2"),
            strings.intern("R1"),
        ],
        device_model: vec![
            strings.intern("nfet"),
            strings.intern("pfet"),
            strings.intern("rpoly"),
        ],
        device_kind: vec![DeviceKind::Mos, DeviceKind::Mos, DeviceKind::Resistor],
        device_terminal_start: vec![0, 4, 8, 10],
        terminal_net: vec![
            nets[1], nets[0], nets[2], nets[2], // M1
            nets[1], nets[0], nets[3], nets[3], // M2
            nets[4], nets[5], // R1
        ],
        device_param_start: vec![0, 2, 3, 3],
        param: vec![
            (strings.intern("w"), 1.0),
            (strings.intern("l"), 0.15),
            (strings.intern("w"), 2.0),
        ],

        net_name: (0..6).map(|i| strings.intern(&format!("n{i}"))).collect(),
        net_subckt: vec![
            SubcktId(0),
            SubcktId(0),
            SubcktId(0),
            SubcktId(0),
            SubcktId(1),
            SubcktId(1),
        ],

        // Nothing here instantiates anything: `inv` and `term` are both leaves.
        // The empty instance table is what a flat netlist looks like, and is
        // the case `Netlist::top` has to answer with the first subcircuit.
        ..Netlist::default()
    }
}

/// Device `row`'s terminal nets, in card order.
fn terminals_of(netlist: &Netlist, row: usize) -> &[RefNetId] {
    &netlist.terminal_net[netlist.device_terminal_start[row] as usize
        ..netlist.device_terminal_start[row + 1] as usize]
}

/// Oracle: construct-from-answer. `top` is "the one nothing else instantiates",
/// and the three answers are decided by the netlist rather than by the search:
/// one subcircuit is the top, none is no top, and two uninstantiated ones are
/// an ambiguity `lvs` must refuse rather than resolve by taking the first or
/// the last.
#[test]
fn the_top_subcircuit_is_the_uninstantiated_one_and_ambiguity_is_refused() {
    let mut strings = StrTable::default();

    let empty = Netlist::default();
    assert!(
        empty.top().is_none(),
        "a netlist with no subcircuits named one as its top"
    );

    let single = Netlist {
        subckt_name: vec![strings.intern("only")],
        subckt_port_start: vec![0, 0],
        subckt_device_start: vec![0, 0],
        ..Netlist::default()
    };
    assert_eq!(
        single.top(),
        Some(SubcktId(0)),
        "the one subcircuit in the file is the top"
    );

    let ambiguous = two_subcircuits(&mut strings);
    assert!(
        ambiguous.top().is_none(),
        "two subcircuits, neither instantiating the other, have no unique top; \
         picking one is a guess `lvs` is not allowed to make"
    );
}

/// Oracle: construct-from-answer. The SPICE card grammar is an external
/// specification, so a deck written to it has an answer decided before the
/// reader runs: `.subckt <name> <ports…>` names its ports in order, and
/// `M<name> <d> <g> <s> <b> <model> <k>=<v>…` is a four-terminal device in that
/// terminal order. Every identifier is lower case and every parameter value is
/// a bare number, so neither case folding nor SPICE's suffix multipliers — both
/// of which the frozen signatures leave unstated — can change what the correct
/// answer is.
///
/// This is the assertion the rest of this file was missing: the three parser
/// tests below it all take an error path, so a `read` that returned
/// `Netlist::default()` for every well-formed deck passed all of them. Names
/// are compared through `StrTable::resolve` and nets through id equality,
/// because which `RefNetId` a net receives is an ordering the interface never
/// commits to, while two occurrences of one name being *one* net is the whole
/// point of the table.
#[test]
fn a_subcircuit_of_two_transistors_reads_back_card_for_card() {
    let source = "\
* an inverter, ports in declaration order
.subckt inv a y vdd vss
mn y a vss vss nfet w=2 l=1
mp y a vdd vdd pfet w=4
.ends
";
    let mut strings = StrTable::default();
    let netlist = spice::read(source, &mut strings).expect("a deck inside the declared subset");

    assert_eq!(netlist.subckt_count(), 1);
    assert_eq!(
        netlist.top(),
        Some(SubcktId(0)),
        "the only subcircuit in the file is its top"
    );
    assert_eq!(strings.resolve(netlist.subckt_name[0]), "inv");

    let ports = &netlist.port_net
        [netlist.subckt_port_start[0] as usize..netlist.subckt_port_start[1] as usize];
    let port_names: Vec<&str> = ports
        .iter()
        .map(|n| strings.resolve(netlist.net_name[n.0 as usize]))
        .collect();
    assert_eq!(
        port_names,
        ["a", "y", "vdd", "vss"],
        "the port list is not the one the .subckt card declares, in its order"
    );

    assert_eq!(netlist.devices_of(SubcktId(0)), 0..2);
    for (device, name, model) in [(0u32, "mn", "nfet"), (1, "mp", "pfet")] {
        let row = device as usize;
        assert_eq!(strings.resolve(netlist.device_name[row]), name);
        assert_eq!(
            strings.resolve(netlist.device_model[row]),
            model,
            "{name} was given the wrong model, which is an LVS mismatch that \
             looks like a layout bug"
        );
        assert_eq!(netlist.device_kind[row], DeviceKind::Mos);
        assert_eq!(
            terminals_of(&netlist, device as usize).len(),
            4,
            "{name} is a four-terminal card"
        );
    }

    // Drain, gate, source, bulk — the order the card states them in.
    let mn = terminals_of(&netlist, 0);
    assert_eq!(
        mn,
        &[ports[1], ports[0], ports[3], ports[3]],
        "mn's terminals are not y a vss vss, or a repeated net name became two \
         nets"
    );
    let mp = terminals_of(&netlist, 1);
    assert_eq!(mp, &[ports[1], ports[0], ports[2], ports[2]]);

    for (device, expected) in [
        (0usize, [("w", 2.0), ("l", 1.0)].as_slice()),
        (1, [("w", 4.0)].as_slice()),
    ] {
        let params = &netlist.param[netlist.device_param_start[device] as usize
            ..netlist.device_param_start[device + 1] as usize];
        assert_eq!(
            params.len(),
            expected.len(),
            "device {device} read a parameter run belonging to another device"
        );
        for (&(name, value), &(want_name, want_value)) in params.iter().zip(expected) {
            assert_eq!(strings.resolve(name), want_name);
            assert!(
                (value - want_value).abs() <= 1e-12,
                "device {device}'s {want_name} came back as {value}, not {want_value}"
            );
        }
    }

    assert_eq!(
        netlist.net_subckt,
        vec![SubcktId(0); netlist.net_name.len()],
        "a net in a one-subcircuit file was attributed to another subcircuit"
    );
}

/// Oracle: construct-from-answer. A subcircuit defined twice is one of the
/// error variants the reader declares, and the input here contains exactly one
/// such definition at a line the test chose. Asserting the line as well as the
/// variant is what stops a reader that reports the right kind of error against
/// the wrong card from passing. Lines are counted from one, as a compiler
/// diagnostic is.
#[test]
fn a_subcircuit_defined_twice_is_refused_at_the_line_that_redefines_it() {
    let source = "\
* a comment card
.subckt inv a y
M1 y a 0 0 nfet w=1u l=0.15u
.ends
.subckt inv a y
.ends
";
    let mut strings = StrTable::default();
    match spice::read(source, &mut strings) {
        Err(NetlistError::Redefined(span, name)) => {
            assert_eq!(
                span.line, 5,
                "the redefinition is on line 5 of the source; the reader blamed \
                 line {}",
                span.line
            );
            assert_eq!(name, "inv", "the wrong name was blamed");
        }
        other => panic!("a duplicate .subckt produced {other:?} rather than Redefined"),
    }
}

/// Oracle: construct-from-answer. A call to a subcircuit that is never defined
/// is unresolvable, and the reader is documented as saying so rather than
/// producing a netlist with a hole in it. A silently misparsed reference
/// netlist is an LVS mismatch that looks like a layout bug.
#[test]
fn a_call_to_an_undefined_subcircuit_is_refused_rather_than_left_dangling() {
    let source = "\
.subckt top a y
X1 a y missing_cell
.ends
";
    let mut strings = StrTable::default();
    match spice::read(source, &mut strings) {
        Err(NetlistError::UndefinedSubckt(span, name)) => {
            assert_eq!(span.line, 2, "the call is on line 2");
            assert_eq!(name, "missing_cell");
        }
        other => panic!("a call to an undefined subcircuit produced {other:?}"),
    }
}

/// Oracle: construct-from-answer. The Spectre reader states its subset in its
/// own doc comment — no `inline subckt`, no `alter`, no sweeps — and anything
/// outside it is `Unsupported` with the line. A reader that skipped what it did
/// not recognise would produce a netlist missing whatever the statement said.
#[test]
fn a_spectre_statement_outside_the_declared_subset_is_refused_with_its_line() {
    let source = "\
subckt inv a y
ends inv
alter corner_tt dev=nfet param=vth value=0.4
";
    let mut strings = StrTable::default();
    match spectre::read(source, &mut strings) {
        Err(NetlistError::Unsupported(span, _)) => {
            assert_eq!(
                span.line, 3,
                "the unsupported statement is on line 3; the reader blamed line {}",
                span.line
            );
        }
        other => panic!("an `alter` statement produced {other:?} rather than Unsupported"),
    }
}
