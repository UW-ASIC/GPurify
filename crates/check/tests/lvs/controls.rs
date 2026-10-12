//! The deck's `lvs` statements, applied by `compare_with` to graphs built by
//! hand: each changes the verdict exactly where its definition says.

use crate::common;

use common::{GraphBuilder, LENGTH, NCH, PCH, WIDTH};
use gpurify_check::lvs::graph::Graph;
use gpurify_check::lvs::verdict::Verdict;
use gpurify_check::lvs::{compare_with, join_must_connect, CompareOptions, ParamNames};
use gpurify_check::topology::TerminalRole::{Bulk, Drain, Gate, Source};
use gpurify_ingest::deck::{DeviceKind, LvsControls, LvsTolerance};
use gpurify_ingest::StrId;

/// One `NCH` transistor on four nets, stating `params`.
fn one_mos(params: &[(StrId, f64)]) -> Graph {
    let mut builder = GraphBuilder::new(4);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        params,
    );
    builder.finish()
}

fn verdict(layout: &Graph, reference: &Graph, controls: &LvsControls) -> Verdict {
    compare_with(layout, reference, CompareOptions::default(), controls).0
}

/// One `lvs tolerance` row.
fn tolerance(model: StrId, param: StrId, relative: f64, absolute: f64) -> LvsControls {
    LvsControls {
        tolerance: vec![LvsTolerance {
            model,
            param,
            relative,
            absolute,
            stated: 0.0,
        }],
        ..LvsControls::default()
    }
}

/// Oracle: the definition, `|a - b| <= absolute + relative * max(|a|, |b|)`
/// (`KLayout`'s `tolerance`: "absolute and relative tolerances add"),
/// evaluated by hand. A drawn width of 1.00 um against a written 1.05 um
/// differs by 0.05 um, 4.76 % of the larger: past the default 2 %; within a
/// 5 % row (0.0525 um) and not a 4 % one (0.042 um); within an absolute
/// 0.06 um and not 0.04 um; and within 3 % plus 0.03 um (0.0615 um) though
/// each part alone (0.0315 um, 0.03 um) is not. A row for another model or
/// another parameter leaves the default in force. Breaks if a row is
/// ignored, if its parts do not add, or if it applies beyond its model and
/// parameter.
#[test]
fn a_tolerance_row_bounds_its_parameter_of_its_model_only() {
    let layout = one_mos(&[(WIDTH, 1.00e-6)]);
    let reference = one_mos(&[(WIDTH, 1.05e-6)]);
    let none = LvsControls::default();
    assert_ne!(verdict(&layout, &reference, &none), Verdict::Match);
    for (relative, absolute, matched) in [
        (0.05, 0.0, true),
        (0.04, 0.0, false),
        (0.0, 0.06e-6, true),
        (0.0, 0.04e-6, false),
        (0.03, 0.03e-6, true),
        (0.03, 0.0, false),
        (0.0, 0.03e-6, false),
    ] {
        let controls = tolerance(NCH, WIDTH, relative, absolute);
        assert_eq!(
            verdict(&layout, &reference, &controls) == Verdict::Match,
            matched,
            "relative {relative}, absolute {absolute}"
        );
    }
    for (model, param) in [(PCH, WIDTH), (NCH, LENGTH)] {
        let controls = tolerance(model, param, 0.05, 0.0);
        assert_ne!(
            verdict(&layout, &reference, &controls),
            Verdict::Match,
            "a row for another model or parameter applied"
        );
    }
}

/// Oracle: the definition. A row replaces the default for its parameter, so
/// a row tighter than 2 % turns a 1.5 % difference, a match by default, into
/// a mismatch: 1.000 um against 1.015 um is within 2 % (0.0203 um) and not
/// within 1 % (0.01015 um). Breaks if a row only ever widens the bound.
#[test]
fn a_tolerance_row_can_be_tighter_than_the_default() {
    let layout = one_mos(&[(WIDTH, 1.000e-6)]);
    let reference = one_mos(&[(WIDTH, 1.015e-6)]);
    assert_eq!(
        verdict(&layout, &reference, &LvsControls::default()),
        Verdict::Match
    );
    let tight = tolerance(NCH, WIDTH, 0.01, 0.0);
    assert_ne!(verdict(&layout, &reference, &tight), Verdict::Match);
}

/// `NCH` transistors on the same four nets, one per parameter list.
fn parallel_mos(each: &[&[(StrId, f64)]]) -> Graph {
    let mut builder = GraphBuilder::new(4);
    for params in each {
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
            params,
        );
    }
    builder.finish()
}

/// Oracle: the definition (`KLayout`'s `ignore_parameter`, Netgen's
/// `property ... remove`): an ignored parameter is not compared and does not
/// stop a merge. A width of 1.0 um against 1.5 um mismatches, and matches
/// once `w` is ignored on `NCH`, not on `PCH`. Two transistors in parallel
/// of `l` 1.0 and 1.2 um do not merge, so they are not one card of twice the
/// width; with `l` ignored they merge, and are. Breaks if an ignored
/// parameter is still compared, or still read by a parallel merge.
#[test]
fn an_ignored_parameter_is_neither_compared_nor_merged_on() {
    let ignore = |model, param| LvsControls {
        ignore_parameter: vec![(model, param)],
        ..LvsControls::default()
    };
    let layout = one_mos(&[(WIDTH, 1.0e-6)]);
    let reference = one_mos(&[(WIDTH, 1.5e-6)]);
    assert_ne!(
        verdict(&layout, &reference, &LvsControls::default()),
        Verdict::Match
    );
    assert_eq!(
        verdict(&layout, &reference, &ignore(NCH, WIDTH)),
        Verdict::Match
    );
    assert_ne!(
        verdict(&layout, &reference, &ignore(PCH, WIDTH)),
        Verdict::Match
    );

    let options = CompareOptions {
        params: ParamNames {
            width: Some(WIDTH),
            ..ParamNames::default()
        },
        ..CompareOptions::default()
    };
    let two = parallel_mos(&[
        &[(WIDTH, 1.0e-6), (LENGTH, 1.0e-6)],
        &[(WIDTH, 1.0e-6), (LENGTH, 1.2e-6)],
    ]);
    let wide = parallel_mos(&[&[(WIDTH, 2.0e-6), (LENGTH, 1.1e-6)]]);
    let run = |controls: &LvsControls| compare_with(&two, &wide, options, controls).0;
    assert_ne!(run(&LvsControls::default()), Verdict::Match);
    assert_eq!(run(&ignore(NCH, LENGTH)), Verdict::Match);
}

/// An `NCH` transistor on gate 0, source `source`, drain `drain`, bulk 3,
/// beside a `PCH` gated by net 1 whose channel and bulk sit on net 3: the
/// gate tells net 1 from net 2, so exchanging them is no relabelling.
fn anchored_mos(source: u32, drain: u32) -> Graph {
    let mut builder = GraphBuilder::new(4);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 3)],
    );
    builder.device(
        DeviceKind::Mos,
        PCH,
        &[(Gate, 1), (Source, 3), (Drain, 3), (Bulk, 3)],
    );
    builder.finish()
}

/// Oracle: the definition (`KLayout`'s DMOS: "source and drain are not
/// swappable"). A transistor written with source and drain exchanged is
/// the same circuit, and another one once its model is asymmetric; a
/// second model's row changes nothing. Two in parallel merge into one of
/// twice the width when aligned, and, asymmetric, not when opposed. Breaks
/// if the control is ignored, leaks to another model, or a parallel merge
/// still exchanges the ends.
#[test]
fn an_asymmetric_transistor_keeps_its_source_and_drain_apart() {
    let asymmetric = |model| LvsControls {
        asymmetric: vec![model],
        ..LvsControls::default()
    };
    let (drawn, written) = (anchored_mos(1, 2), anchored_mos(2, 1));
    let none = LvsControls::default();
    assert_eq!(verdict(&drawn, &written, &none), Verdict::Match);
    assert_ne!(verdict(&drawn, &written, &asymmetric(NCH)), Verdict::Match);
    assert_eq!(verdict(&drawn, &drawn, &asymmetric(NCH)), Verdict::Match);
    assert_eq!(verdict(&drawn, &written, &asymmetric(PCH)), Verdict::Match);

    let options = CompareOptions {
        params: ParamNames {
            width: Some(WIDTH),
            ..ParamNames::default()
        },
        ..CompareOptions::default()
    };
    let pair = |second: (u32, u32)| {
        let mut builder = GraphBuilder::new(4);
        for (source, drain) in [(1, 2), second] {
            builder.device_with_params(
                DeviceKind::Mos,
                NCH,
                &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 3)],
                &[(WIDTH, 1.0e-6)],
            );
        }
        builder.finish()
    };
    let wide = parallel_mos(&[&[(WIDTH, 2.0e-6)]]);
    let run =
        |layout: &Graph, controls: &LvsControls| compare_with(layout, &wide, options, controls).0;
    assert_eq!(run(&pair((2, 1)), &none), Verdict::Match);
    assert_ne!(run(&pair((2, 1)), &asymmetric(NCH)), Verdict::Match);
    assert_eq!(run(&pair((1, 2)), &asymmetric(NCH)), Verdict::Match);
}

/// A capacitor model and a multiplier name of this file's own.
const CAP: StrId = StrId(40);
const MULT: StrId = StrId(41);

/// A device of `kind` and `model` with these `(role, net)` terminals, beside
/// an `NCH` gated by net 0 whose other terminals sit on net 3: the gate
/// tells net 0 from net 1.
fn anchored(
    kind: DeviceKind,
    model: StrId,
    terminals: &[(gpurify_check::topology::TerminalRole, u32)],
) -> Graph {
    let mut builder = GraphBuilder::new(4);
    builder.device(kind, model, terminals);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 3), (Drain, 3), (Bulk, 3)],
    );
    builder.finish()
}

fn permute(model: StrId, a: u8, b: u8) -> LvsControls {
    LvsControls {
        permute: vec![(model, a, b)],
        ..LvsControls::default()
    }
}

/// Oracle: the definition (Netgen's `permute`, `KLayout`'s
/// `equivalent_pins`). A capacitor written with its plates reversed, and a
/// bipolar with its emitter and collector exchanged, are other circuits by
/// default (testing-plan F15) and the same once the deck permutes those
/// pins; a permutation on another model changes nothing. Two capacitors on
/// the same nets in opposite directions merge into one of `m = 2` only when
/// their plates permute. Breaks if a permutation is ignored, leaks to
/// another model, or does not reach the parallel merge.
#[test]
fn permuted_pins_are_interchangeable() {
    use gpurify_check::topology::TerminalRole::{Base, Collector, Emitter, Pin};
    let none = LvsControls::default();
    let cap = |a, b| anchored(DeviceKind::Capacitor, CAP, &[(Pin(0), a), (Pin(1), b)]);
    let (drawn, reversed) = (cap(0, 1), cap(1, 0));
    assert_ne!(verdict(&drawn, &reversed, &none), Verdict::Match);
    assert_eq!(
        verdict(&drawn, &reversed, &permute(CAP, 0, 1)),
        Verdict::Match
    );
    assert_ne!(
        verdict(&drawn, &reversed, &permute(PCH, 0, 1)),
        Verdict::Match
    );

    let bjt = |emitter, collector| {
        anchored(
            DeviceKind::Bjt,
            common::NPN,
            &[(Base, 2), (Emitter, emitter), (Collector, collector)],
        )
    };
    let (drawn, flipped) = (bjt(0, 1), bjt(1, 0));
    assert_ne!(verdict(&drawn, &flipped, &none), Verdict::Match);
    assert_eq!(
        verdict(&drawn, &flipped, &permute(common::NPN, 1, 2)),
        Verdict::Match
    );
    assert_ne!(
        verdict(&drawn, &flipped, &permute(common::NPN, 0, 1)),
        Verdict::Match,
        "base with emitter is not emitter with collector"
    );

    let options = CompareOptions {
        params: ParamNames {
            multiplier: Some(MULT),
            ..ParamNames::default()
        },
        ..CompareOptions::default()
    };
    let mut opposed = GraphBuilder::new(2);
    for (a, b) in [(0, 1), (1, 0)] {
        opposed.device(DeviceKind::Capacitor, CAP, &[(Pin(0), a), (Pin(1), b)]);
    }
    let opposed = opposed.finish();
    let mut counted = GraphBuilder::new(2);
    counted.device_with_params(
        DeviceKind::Capacitor,
        CAP,
        &[(Pin(0), 0), (Pin(1), 1)],
        &[(MULT, 2.0)],
    );
    let counted = counted.finish();
    let run = |controls: &LvsControls| compare_with(&opposed, &counted, options, controls).0;
    assert_ne!(run(&none), Verdict::Match);
    assert_eq!(run(&permute(CAP, 0, 1)), Verdict::Match);
}

/// Oracle: the definition (Netgen's `ignore class`, `KLayout`'s
/// `same_device_classes(nil, ...)`): an ignored model's devices are not
/// compared on either side, and a net only they reached is no node unless
/// it is a port. A transistor beside a capacitor on its gate and an
/// internal net 4 matches the transistor alone once the capacitor's model
/// is ignored, and not before; ignoring the transistor's model instead
/// leaves the capacitor unpaired. With net 4 a reference port, the port
/// must still pair, and does not. A parallel merge on the layout lists the
/// rows the layout was given, past the dropped capacitor. Breaks if the
/// model's devices are compared, an orphaned internal net is still
/// required, a port is not, or merge rows are those of the filtered graph.
#[test]
fn an_ignored_model_s_devices_and_their_private_nets_are_left_out() {
    use gpurify_check::topology::TerminalRole::Pin;
    let ignore = |model| LvsControls {
        ignore: vec![model],
        ..LvsControls::default()
    };
    let with_cap = |port: bool| {
        let mut builder = GraphBuilder::new(5);
        builder.device(DeviceKind::Capacitor, CAP, &[(Pin(0), 0), (Pin(1), 4)]);
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        );
        for net in 0..4 {
            builder.port(net);
        }
        builder.name_net(4, StrId(42));
        if port {
            builder.port(4);
        }
        builder.finish()
    };
    let alone = {
        let mut builder = GraphBuilder::new(4);
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        );
        for net in 0..4 {
            builder.port(net);
        }
        builder.finish()
    };
    let none = LvsControls::default();
    assert_ne!(verdict(&alone, &with_cap(false), &none), Verdict::Match);
    assert_eq!(
        verdict(&alone, &with_cap(false), &ignore(CAP)),
        Verdict::Match
    );
    assert_eq!(
        verdict(&with_cap(false), &alone, &ignore(CAP)),
        Verdict::Match
    );
    assert_ne!(
        verdict(&alone, &with_cap(false), &ignore(NCH)),
        Verdict::Match
    );
    assert_ne!(
        verdict(&alone, &with_cap(true), &ignore(CAP)),
        Verdict::Match,
        "a reference port must pair even when its devices are ignored"
    );

    let options = CompareOptions {
        params: ParamNames {
            multiplier: Some(MULT),
            ..ParamNames::default()
        },
        ..CompareOptions::default()
    };
    let mut drawn = GraphBuilder::new(4);
    drawn.device(DeviceKind::Capacitor, CAP, &[(Pin(0), 0), (Pin(1), 3)]);
    for _ in 0..2 {
        drawn.device(
            DeviceKind::Resistor,
            common::RES,
            &[(Pin(0), 1), (Pin(0), 2)],
        );
    }
    let drawn = drawn.finish();
    let (_, merges) = compare_with(&drawn, &drawn, options, &ignore(CAP));
    let layout_rows: Vec<&[u32]> = merges
        .iter()
        .filter(|(side, _)| *side == gpurify_check::lvs::verdict::Side::Layout)
        .map(|(_, merge)| merge.devices.as_slice())
        .collect();
    assert_eq!(layout_rows, [&[1u32, 2][..]]);
}

/// Oracle: the definition (Netgen's `ignore shorted`: "instances ... which
/// have all pins shorted"). A dummy transistor with every terminal on net 3
/// beside a real one is left out on either side once its model ignores
/// shorted devices, and not before; one with its gate on net 0 is no dummy
/// and stays. Breaks if a partly shorted device is dropped, or a shorted one
/// is compared.
#[test]
fn an_ignored_dummy_is_one_with_every_terminal_on_one_net() {
    let shorted = LvsControls {
        ignore_shorted: vec![NCH],
        ..LvsControls::default()
    };
    let with = |gate: u32| {
        let mut builder = GraphBuilder::new(4);
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        );
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, gate), (Source, 3), (Drain, 3), (Bulk, 3)],
        );
        builder.finish()
    };
    let alone = one_mos(&[]);
    let none = LvsControls::default();
    assert_ne!(verdict(&with(3), &alone, &none), Verdict::Match);
    assert_eq!(verdict(&with(3), &alone, &shorted), Verdict::Match);
    assert_eq!(verdict(&alone, &with(3), &shorted), Verdict::Match);
    assert_ne!(verdict(&with(0), &alone, &shorted), Verdict::Match);
}

/// Oracle: the definition (`KLayout`'s `flag_missing_ports`: ports "not
/// labelled correspondingly in the layout" are errors, which "prevents
/// swapping of port labels or pads"), by hand. Two transistors, each with
/// its own gate and drain port, the reference wiring gate `in1` to drain
/// `out2`: the same circuit up to renaming, so a match by structure, and a
/// mismatch once ports go by name. Labels on the nets the reference names
/// match either way, and a reference port no layout net is labelled with
/// is unpaired. Breaks if names are not held to their ports, or are when
/// the deck does not ask.
#[test]
fn ports_by_name_hold_each_port_to_its_label() {
    let [in1, in2, out1, out2, vss] = [StrId(70), StrId(71), StrId(72), StrId(73), StrId(74)];
    // Transistor `k` gated by `gates[k]` and draining into `drains[k]`,
    // its source and bulk on `vss`; every named net is a port.
    let pair = |gates: [StrId; 2], drains: [StrId; 2], labelled: bool| {
        let mut builder = GraphBuilder::new(5);
        for (net, name) in (0u32..).zip([gates[0], gates[1], drains[0], drains[1], vss]) {
            if labelled {
                builder.name_net(net, name);
                builder.port(net);
            }
        }
        for k in 0..2u32 {
            builder.device(
                DeviceKind::Mos,
                NCH,
                &[(Gate, k), (Source, 4), (Drain, 2 + k), (Bulk, 4)],
            );
        }
        builder.finish()
    };
    let by_name = LvsControls {
        ports_by_name: true,
        ..LvsControls::default()
    };
    let none = LvsControls::default();
    let layout = pair([in1, in2], [out1, out2], true);
    let crossed = pair([in1, in2], [out2, out1], true);
    assert_eq!(verdict(&layout, &crossed, &none), Verdict::Match);
    assert_ne!(verdict(&layout, &crossed, &by_name), Verdict::Match);
    assert_eq!(verdict(&layout, &layout, &by_name), Verdict::Match);
    let unlabelled = pair([in1, in2], [out1, out2], false);
    assert_eq!(verdict(&unlabelled, &layout, &none), Verdict::Match);
    assert_ne!(verdict(&unlabelled, &layout, &by_name), Verdict::Match);
}

/// Oracle: closed form, Kirchhoff's laws for parallel elements, which the
/// relaxed policy follows (Netgen's `property topology relaxed`: networks
/// "numerically the same after series and parallel combinations"). Two
/// capacitors of 1 fF on the same nets are one of 2 fF and two resistors of
/// 100 ohm one of 50 ohm, with no count left; a capacitor of 1 fF and
/// `m = 2` is one of 2 fF; capacitors stating no value keep a count of two.
/// Under the strict policy two capacitors of 1 fF stay 1 fF with `m = 2`.
/// Breaks if a value adds where it should combine harmonically, the count
/// is kept beside a combined value, or `m` is not folded in.
#[test]
fn relaxed_parallel_passives_combine_their_value_by_its_law() {
    use gpurify_check::lvs::reduce::reduce_with;
    use gpurify_check::topology::TerminalRole::Pin;
    let (r, c) = (StrId(42), StrId(43));
    let names = |relaxed| ParamNames {
        multiplier: Some(MULT),
        values: [Some(r), Some(c), None, None, None, None],
        relaxed,
        ..ParamNames::default()
    };
    let parallel = |kind: DeviceKind, model: StrId, params: &[&[(StrId, f64)]]| {
        let mut builder = GraphBuilder::new(2);
        for &stated in params {
            let ends = if kind == DeviceKind::Resistor {
                [(Pin(0), 0), (Pin(0), 1)]
            } else {
                [(Pin(0), 0), (Pin(1), 1)]
            };
            builder.device_with_params(kind, model, &ends, stated);
        }
        builder.finish()
    };
    let one = |graph: &Graph, names| {
        let (out, _) = reduce_with(graph, names);
        assert_eq!(out.device_count(), 1, "the parallel devices merged");
        out.params_of(0).to_vec()
    };
    let caps = parallel(DeviceKind::Capacitor, CAP, &[&[(c, 1e-15)], &[(c, 1e-15)]]);
    assert_eq!(one(&caps, names(true)), [(c, 2e-15)]);
    assert_eq!(one(&caps, names(false)), [(c, 1e-15), (MULT, 2.0)]);
    let res = parallel(
        DeviceKind::Resistor,
        common::RES,
        &[&[(r, 100.0)], &[(r, 100.0)]],
    );
    assert_eq!(one(&res, names(true)), [(r, 50.0)]);
    let counted = parallel(DeviceKind::Capacitor, CAP, &[&[(c, 1e-15), (MULT, 2.0)]]);
    assert_eq!(one(&counted, names(true)), [(c, 2e-15)]);
    let bare = parallel(DeviceKind::Capacitor, CAP, &[&[], &[]]);
    assert_eq!(one(&bare, names(true)), [(MULT, 2.0)]);
}

/// Oracle: `KLayout`'s `connect_implicit` ("for nets matching the net name
/// pattern and for which there is more than one subnet, the subnets are
/// connected") and `connect_explicit`, by hand. Two transistors' sources on
/// two nets both labelled `VDD` are two nets, so they do not match a
/// reference that ties both sources to one `VDD`; once `VDD*` is
/// must-connect, or `VDD` and `VCC` are joined explicitly with the second
/// labelled `VCC`, they do. A pattern that matches nothing changes nothing.
/// Breaks if the join misses a matching label, joins a non-matching one, or
/// leaves a terminal on the dropped row.
#[test]
fn must_connect_nets_are_one_net_to_compare() {
    use gpurify_ingest::StrTable;
    let mut strings = StrTable::default();
    let [vdd, vcc, out1, out2, gate] =
        ["VDD", "VCC", "OUT1", "OUT2", "G"].map(|n| strings.intern(n));
    // Gate net 0; sources on nets 1 and 2, named `first` and `second`;
    // drains on 3 and 4; bulk on 5.
    let split = |first, second| {
        let mut builder = GraphBuilder::new(6);
        for (net, name) in [(0, gate), (1, first), (2, second), (3, out1), (4, out2)] {
            builder.name_net(net, name);
            builder.port(net);
        }
        for (source, drain) in [(1, 3), (2, 4)] {
            builder.device(
                DeviceKind::Mos,
                NCH,
                &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 5)],
            );
        }
        builder.finish()
    };
    let tied = {
        let mut builder = GraphBuilder::new(5);
        for (net, name) in [(0, gate), (1, vdd), (2, out1), (3, out2)] {
            builder.name_net(net, name);
            builder.port(net);
        }
        for drain in [2, 3] {
            builder.device(
                DeviceKind::Mos,
                NCH,
                &[(Gate, 0), (Source, 1), (Drain, drain), (Bulk, 4)],
            );
        }
        builder.finish()
    };
    let none = LvsControls::default();
    let implicit = |pattern: &str| LvsControls {
        connect_implicit: vec![pattern.to_owned()],
        ..LvsControls::default()
    };
    let joined = |layout: &Graph, controls: &LvsControls| {
        verdict(&join_must_connect(layout, controls, &strings), &tied, &none)
    };
    let same = split(vdd, vdd);
    assert_ne!(joined(&same, &none), Verdict::Match);
    assert_eq!(joined(&same, &implicit("VDD*")), Verdict::Match);
    assert_ne!(joined(&same, &implicit("GND*")), Verdict::Match);
    let renamed = split(vdd, vcc);
    assert_ne!(joined(&renamed, &implicit("VDD*")), Verdict::Match);
    let explicit = LvsControls {
        connect_explicit: vec![vec![vdd, vcc]],
        ..LvsControls::default()
    };
    assert_eq!(joined(&renamed, &explicit), Verdict::Match);
}

/// Oracle: `KLayout`'s `max_res` and `min_caps` ("the netlist compare will
/// ignore resistor devices with a resistance value above the given
/// threshold", "capacitance devices with a capacitance value below"), by
/// hand. A layout of one transistor between nets 0 and 1 with a resistor
/// of 10 Mohm and a capacitor of 5 aF across them, against a reference of
/// the transistor alone, mismatches; it matches once `max_res` is 1 Mohm
/// and `min_caps` 10 aF, and not with only one of them, nor with
/// thresholds past the values (`max_res` 20 Mohm, `min_caps` 1 aF). A
/// resistor stating no value is never above the threshold. Breaks if a
/// threshold is read the wrong way round, in the wrong unit, or applied to
/// another kind.
#[test]
fn value_thresholds_leave_out_parasitic_passives_as_opens() {
    use gpurify_check::topology::TerminalRole::Pin;
    let (r, c) = (StrId(42), StrId(43));
    let options = CompareOptions {
        params: ParamNames {
            values: [Some(r), Some(c), None, None, None, None],
            ..ParamNames::default()
        },
        ..CompareOptions::default()
    };
    let circuit = |passives: &[(DeviceKind, StrId, f64)]| {
        let mut builder = GraphBuilder::new(4);
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 2), (Source, 0), (Drain, 1), (Bulk, 3)],
        );
        for &(kind, name, value) in passives {
            let model = if kind == DeviceKind::Resistor {
                common::RES
            } else {
                CAP
            };
            let params: Vec<(StrId, f64)> =
                (value > 0.0).then_some((name, value)).into_iter().collect();
            builder.device_with_params(kind, model, &[(Pin(0), 0), (Pin(1), 1)], &params);
        }
        builder.finish()
    };
    let layout = circuit(&[
        (DeviceKind::Resistor, r, 10e6),
        (DeviceKind::Capacitor, c, 5e-18),
    ]);
    let reference = circuit(&[]);
    let run = |max_res, min_caps| {
        let controls = LvsControls {
            max_res,
            min_caps,
            ..LvsControls::default()
        };
        compare_with(&layout, &reference, options, &controls).0 == Verdict::Match
    };
    assert!(!run(None, None));
    assert!(run(Some(1e6), Some(10.0)));
    assert!(!run(Some(1e6), None));
    assert!(!run(None, Some(10.0)));
    assert!(!run(Some(20e6), Some(10.0)));
    assert!(!run(Some(1e6), Some(1.0)));
    let unvalued = circuit(&[(DeviceKind::Resistor, r, 0.0)]);
    let controls = LvsControls {
        max_res: Some(1.0),
        ..LvsControls::default()
    };
    assert_ne!(
        compare_with(&unvalued, &reference, options, &controls).0,
        Verdict::Match
    );
}

/// Oracle: `KLayout`'s `same_nets!` ("if the specified nets do not match,
/// an error is reported"), by hand. Two transistors gated by nets `A` and
/// `B` and draining into `X` and `Y` are symmetric: a reference whose
/// labels cross them (`A` gates the transistor draining into `Y`) matches
/// by structure. Pairing layout `A` with reference `A` and layout `X` with
/// reference `X` breaks the symmetry the wrong way, so the comparison
/// mismatches; pairing layout `A` with reference `A` and layout `X` with
/// reference `Y`, as the crossed reference wires them, matches. A row naming a net neither side
/// has changes nothing. Breaks if a row does not hold its two nets
/// together, or holds others.
#[test]
fn same_nets_hold_two_named_nets_together() {
    let [a, b, x, y, vss, nowhere] = [70, 71, 72, 73, 74, 75].map(StrId);
    let pair = |drains: [StrId; 2]| {
        let mut builder = GraphBuilder::new(5);
        for (net, name) in (0u32..).zip([a, b, drains[0], drains[1], vss]) {
            builder.name_net(net, name);
            builder.port(net);
        }
        for k in 0..2u32 {
            builder.device(
                DeviceKind::Mos,
                NCH,
                &[(Gate, k), (Source, 4), (Drain, 2 + k), (Bulk, 4)],
            );
        }
        builder.finish()
    };
    let layout = pair([x, y]);
    let crossed = pair([y, x]);
    let same = |rows: &[(StrId, StrId)]| LvsControls {
        same_nets: rows.to_vec(),
        ..LvsControls::default()
    };
    assert_eq!(
        verdict(&layout, &crossed, &LvsControls::default()),
        Verdict::Match
    );
    assert_ne!(
        verdict(&layout, &crossed, &same(&[(a, a), (x, x)])),
        Verdict::Match
    );
    assert_eq!(
        verdict(&layout, &crossed, &same(&[(a, a), (x, y)])),
        Verdict::Match
    );
    assert_eq!(
        verdict(&layout, &crossed, &same(&[(nowhere, nowhere)])),
        Verdict::Match
    );
}

/// One device as built by hand: its `(role, net)` ends and its parameters.
type Card<'a> = (
    &'a [(gpurify_check::topology::TerminalRole, u32)],
    &'a [(StrId, f64)],
);

/// Oracle: closed form, Kirchhoff's laws for elements in series, as
/// `KLayout`'s `ResistorDeviceCombiner::serial` and
/// `CapacitorDeviceCombiner::serial` state them (R = R1 + R2, L = L1 + L2;
/// C = C1 C2 / (C1 + C2); area and perimeter adding), and Netgen's
/// relaxed topology. Under the relaxed policy three resistors of 100 ohm
/// chained through two internal nets are one of 300 ohm with `l` 3 um and
/// `area` 3 um²; two capacitors of 2 fF chained plate to plate are one of
/// 1 fF whose ends keep their plates. None merges under the strict policy,
/// through a port, with `w` differing, in a ring, tail to tail for ordered
/// plates (it does once the plates compare under one role, as `lvs
/// permute` makes them), or without a value. Breaks if a value combines by
/// the wrong law, an internal net survives, or a merge is made where its
/// definition does not hold.
#[test]
fn relaxed_series_passives_combine_their_value_by_its_law() {
    use gpurify_check::lvs::reduce::reduce_with;
    use gpurify_check::topology::TerminalRole::{self, Pin};
    let (r, c, area) = (StrId(42), StrId(43), StrId(44));
    let names = |relaxed| ParamNames {
        length: Some(LENGTH),
        width: Some(WIDTH),
        multiplier: Some(MULT),
        values: [Some(r), Some(c), Some(area), None, None, None],
        relaxed,
        ..ParamNames::default()
    };
    // Devices of `kind` on `(role, net)` pairs, over `nets` nets of which
    // `ports` are ports.
    let build = |kind, model, nets: u32, ports: &[u32], devices: &[Card]| {
        let mut builder = GraphBuilder::new(nets);
        for &port in ports {
            builder.port(port);
        }
        for &(ends, params) in devices {
            builder.device_with_params(kind, model, ends, params);
        }
        builder.finish()
    };
    let reduced = |graph: &Graph, relaxed| reduce_with(graph, names(relaxed)).0;
    let resistor: &[(StrId, f64)] = &[(r, 100.0), (LENGTH, 1e-6), (WIDTH, 2e-7), (area, 1e-12)];
    let chain = build(
        DeviceKind::Resistor,
        common::RES,
        4,
        &[0, 3],
        &[
            (&[(Pin(0), 0), (Pin(0), 1)], resistor),
            (&[(Pin(0), 1), (Pin(0), 2)], resistor),
            (&[(Pin(0), 2), (Pin(0), 3)], resistor),
        ],
    );
    let out = reduced(&chain, true);
    assert_eq!(out.device_count(), 1, "the chain is one resistor");
    assert_eq!(out.net_count(), 2, "both internal nets are consumed");
    let mut params = out.params_of(0).to_vec();
    params.sort_by_key(|p| p.0);
    let close = |a: f64, b: f64| (a - b).abs() <= 1e-9 * b.abs();
    let want = [(r, 300.0), (LENGTH, 3e-6), (WIDTH, 2e-7), (area, 3e-12)];
    for (name, value) in want {
        let got = params.iter().find(|p| p.0 == name).expect("stated").1;
        assert!(close(got, value), "{name:?}: {got} against {value}");
    }
    assert_eq!(
        reduced(&chain, false).device_count(),
        3,
        "strict keeps them"
    );
    let through_port = build(
        DeviceKind::Resistor,
        common::RES,
        4,
        &[0, 1, 3],
        &[
            (&[(Pin(0), 0), (Pin(0), 1)], resistor),
            (&[(Pin(0), 1), (Pin(0), 2)], resistor),
            (&[(Pin(0), 2), (Pin(0), 3)], resistor),
        ],
    );
    assert_eq!(
        reduced(&through_port, true).device_count(),
        2,
        "a port stops it"
    );
    let narrow: &[(StrId, f64)] = &[(r, 100.0), (LENGTH, 1e-6), (WIDTH, 1e-7), (area, 1e-12)];
    let mixed = build(
        DeviceKind::Resistor,
        common::RES,
        3,
        &[0, 2],
        &[
            (&[(Pin(0), 0), (Pin(0), 1)], resistor),
            (&[(Pin(0), 1), (Pin(0), 2)], narrow),
        ],
    );
    assert_eq!(reduced(&mixed, true).device_count(), 2, "w must agree");
    let ring = build(
        DeviceKind::Resistor,
        common::RES,
        3,
        &[],
        &[
            (&[(Pin(0), 0), (Pin(0), 1)], resistor),
            (&[(Pin(0), 1), (Pin(0), 2)], resistor),
            (&[(Pin(0), 2), (Pin(0), 0)], resistor),
        ],
    );
    assert_eq!(
        reduced(&ring, true).device_count(),
        3,
        "a ring is no device"
    );
    let bare = build(
        DeviceKind::Resistor,
        common::RES,
        3,
        &[0, 2],
        &[
            (&[(Pin(0), 0), (Pin(0), 1)], &[]),
            (&[(Pin(0), 1), (Pin(0), 2)], &[]),
        ],
    );
    assert_eq!(reduced(&bare, true).device_count(), 2, "no value, no law");

    let cap: &[(StrId, f64)] = &[(c, 2e-15)];
    let caps = |second: TerminalRole, first: TerminalRole| {
        build(
            DeviceKind::Capacitor,
            CAP,
            3,
            &[0, 2],
            &[
                (&[(first, 0), (second, 1)], cap),
                (&[(first, 1), (second, 2)], cap),
            ],
        )
    };
    let out = reduced(&caps(Pin(1), Pin(0)), true);
    assert_eq!(out.device_count(), 1, "plate to plate merges");
    assert!(
        close(out.params_of(0)[0].1, 1e-15),
        "{:?}",
        out.params_of(0)
    );
    assert_eq!(out.terminals_of(0), (&[0, 1][..], &[Pin(0), Pin(1)][..]));
    let tail_to_tail = build(
        DeviceKind::Capacitor,
        CAP,
        3,
        &[0, 2],
        &[
            (&[(Pin(0), 0), (Pin(1), 1)], cap),
            (&[(Pin(0), 2), (Pin(1), 1)], cap),
        ],
    );
    assert_eq!(
        reduced(&tail_to_tail, true).device_count(),
        2,
        "ordered plates"
    );
    let permuted = build(
        DeviceKind::Capacitor,
        CAP,
        3,
        &[0, 2],
        &[
            (&[(Pin(8), 0), (Pin(8), 1)], cap),
            (&[(Pin(8), 2), (Pin(8), 1)], cap),
        ],
    );
    assert_eq!(
        reduced(&permuted, true).device_count(),
        1,
        "permuted plates"
    );
}
