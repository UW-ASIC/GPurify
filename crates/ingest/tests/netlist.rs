//! The reference netlist: its top-cell rule, a card-for-card read, and the two
//! readers' refusal to guess. CSR offset columns carry one terminator entry.

use gpurify_geom::StrTable;
use gpurify_ingest::deck::{DeviceKind, DeviceRecognition};
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
    let netlist = spice::read(source, &mut strings, &DeviceRecognition::default())
        .expect("a deck inside the declared subset");

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
    match spice::read(source, &mut strings, &DeviceRecognition::default()) {
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
    match spice::read(source, &mut strings, &DeviceRecognition::default()) {
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

/// Oracle: the M-card form. A sky130 primitive called as a subcircuit, the
/// way PDK netlists write it (`X` card, bare W/L in µm, upper-case names),
/// reads as the same device as `M` with `u`-suffixed lower-case parameters.
/// The model is one the deck's recognisers name, not one the file defines.
#[test]
fn an_x_card_calling_a_deck_model_is_the_same_device_as_the_m_card() {
    let mut strings = StrTable::default();
    let model = strings.intern("sky130_fd_pr__nfet_01v8");
    let devices = DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        model: vec![model],
        ..DeviceRecognition::default()
    };
    let x = ".subckt c d g s b\nXM1 d g s b sky130_fd_pr__nfet_01v8 W=0.42 L=0.15 nf=1\n.ends\n";
    let m = ".subckt c d g s b\nM1 d g s b sky130_fd_pr__nfet_01v8 w=0.42u l=0.15u nf=1\n.ends\n";
    let x = spice::read(x, &mut strings, &devices).expect("an X card calling a deck model");
    let m = spice::read(m, &mut strings, &devices).expect("the M-card form");

    assert!(
        x.instance_of.is_empty(),
        "the X card became a subcircuit call"
    );
    assert_eq!(x.device_kind, [DeviceKind::Mos]);
    assert_eq!(x.device_model, m.device_model);
    assert_eq!(x.terminal_net, m.terminal_net);
    assert_eq!(x.param.len(), m.param.len());
    for (&(xn, xv), &(mn, mv)) in x.param.iter().zip(&m.param) {
        assert_eq!(strings.resolve(xn), strings.resolve(mn));
        assert!(
            (xv - mv).abs() <= 1e-12 * mv.abs(),
            "{}: {xv} vs {mv}",
            strings.resolve(xn)
        );
    }

    // Without the deck naming the model it is still an undefined subcircuit.
    let none = spice::read(
        ".subckt c d g s b\nXM1 d g s b sky130_fd_pr__nfet_01v8 W=0.42 L=0.15\n.ends\n",
        &mut strings,
        &DeviceRecognition::default(),
    );
    assert!(
        matches!(
            none,
            Err(NetlistError::Unsupported(..) | NetlistError::UndefinedSubckt(..))
        ),
        "{none:?}"
    );
}

/// Flattening places every leaf device under the top, wired through the
/// instance's port nets, with internal nets named by path.
#[test]
fn flattening_wires_instances_through_their_ports() {
    let mut strings = StrTable::default();
    let source = "\
.subckt INV A Y VDD VSS
M0 Y A mid VSS nfet
M1 mid A VDD VDD pfet
.ends
.subckt BUF IN OUT VDD VSS
X1 IN n1 VDD VSS INV
X2 n1 OUT VDD VSS INV
.ends
";
    let netlist = spice::read(source, &mut strings, &DeviceRecognition::default())
        .expect("a two-level netlist reads");
    let top = netlist.top().expect("BUF is the one top");
    let flat = netlist.flatten_top(top, &mut strings).expect("no cycle");

    assert_eq!(flat.subckt_count(), 1);
    assert_eq!(strings.resolve(flat.subckt_name[0]), "BUF");
    assert_eq!(flat.device_model.len(), 4, "two inverters of two devices");
    let net = |id: gpurify_ingest::netlist::RefNetId| {
        strings.resolve(flat.net_name[id.0 as usize]).to_owned()
    };
    let ports: Vec<String> = flat.port_net.iter().map(|&n| net(n)).collect();
    assert_eq!(ports, ["IN", "OUT", "VDD", "VSS"]);
    // Device 0 is X1's nfet: drain Y = n1, gate A = IN, source = X1.mid.
    let terminals = |device: usize| -> Vec<String> {
        let range = flat.device_terminal_start[device] as usize
            ..flat.device_terminal_start[device + 1] as usize;
        flat.terminal_net[range].iter().map(|&n| net(n)).collect()
    };
    assert_eq!(terminals(0), ["n1", "IN", "X1.mid", "VSS"]);
    assert_eq!(terminals(2), ["OUT", "n1", "X2.mid", "VSS"]);
}

/// A subcircuit that places itself is refused, not expanded forever.
#[test]
fn flattening_refuses_a_cycle() {
    let mut strings = StrTable::default();
    let source = "\
.subckt A x
X1 x B
.ends
.subckt B x
X1 x A
.ends
.subckt TOP x
X1 x A
.ends
";
    let netlist = spice::read(source, &mut strings, &DeviceRecognition::default())
        .expect("reads: a cycle is a property of the hierarchy, not of a card");
    let top = netlist.top().expect("TOP is the one top");
    assert!(matches!(
        netlist.flatten_top(top, &mut strings),
        Err(gpurify_ingest::netlist::NetlistError::CyclicHierarchy(_))
    ));
}

/// Oracle: SPICE's own card syntax (ngspice manual, "Resistors" and
/// "Capacitors": `RXXXXXXX n+ n- <value> <mname>`). A value written between
/// a card's nets and its model is the device's `r` or `c`, so the positional
/// card reads back as the card that names it: `1k` is 1000 ohms and `1p` is
/// 1e-12 farads. A value with no model is refused, since LVS pairs a device
/// by its model, and so is a value stated both ways.
#[test]
fn an_r_or_c_cards_positional_value_is_its_r_or_c() {
    let mut strings = StrTable::default();
    let none = DeviceRecognition::default();
    let read = |cards: &str, strings: &mut StrTable| {
        spice::read(
            &format!(".subckt top a b\n{cards}\n.ends\n"),
            strings,
            &none,
        )
    };
    let positional =
        read("R1 a b 1k rpoly w=1u\nC1 a b 1p cmim", &mut strings).expect("the positional form");
    let named =
        read("R1 a b rpoly r=1k w=1u\nC1 a b cmim c=1p", &mut strings).expect("the named form");
    let (r, w, c) = (
        strings.intern("r"),
        strings.intern("w"),
        strings.intern("c"),
    );
    assert_eq!(positional.param, [(r, 1000.0), (w, 1e-6), (c, 1e-12)]);
    assert_eq!(positional.param, named.param);
    assert_eq!(positional.device_param_start, named.device_param_start);
    assert_eq!(positional.device_model, named.device_model);
    assert_eq!(
        positional.device_kind,
        [DeviceKind::Resistor, DeviceKind::Capacitor]
    );

    for card in ["R1 a b 1k", "C1 a b 1p"] {
        match read(card, &mut strings) {
            Err(NetlistError::Unsupported(span, _)) => assert_eq!(span.line, 2, "{card}"),
            other => panic!("{card}: a value with no model read as {other:?}"),
        }
    }
    match read("R1 a b 1k rpoly r=2k", &mut strings) {
        Err(NetlistError::Unexpected(span, token)) => {
            assert_eq!((span.line, token.as_str()), (2, "r=2k"));
        }
        other => panic!("a value stated twice read as {other:?}"),
    }
}
