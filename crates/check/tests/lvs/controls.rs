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
