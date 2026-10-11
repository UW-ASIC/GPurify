//! The deck's `lvs` statements, applied by `compare_with` to graphs built by
//! hand: each changes the verdict exactly where its definition says.

use crate::common;

use common::{GraphBuilder, LENGTH, NCH, PCH, WIDTH};
use gpurify_check::lvs::graph::Graph;
use gpurify_check::lvs::verdict::Verdict;
use gpurify_check::lvs::{compare_with, CompareOptions, ParamNames};
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
