//! Via family: `redundant_via` and `via_array_spacing`.
//!
//! Both rules count cuts rather than measuring one, and both are policies
//! rather than physical limits (`docs/NEED_TESTING.md`), so what is definitive
//! about them is the arithmetic: which cuts are in a neighbourhood, and which
//! pairs are inside a cluster large enough to be an array. Both hinge on the
//! same inclusive-at-the-limit boundary, and both are tested one unit either
//! side of it.
//!
//! Distance is between nearest points, not centres. A centre-based test
//! over-counts neighbours for large cuts and can call an isolated via
//! redundant, which is fail-open and is what the old tree did — so the cut side
//! is 100 here and the pitches are stated so the two readings differ.

use crate::common;

use common::{Sink, A, RULE};
use gpurify_check::drc::Rule;
use gpurify_check::report::{Measurement, Severity, Violation};
use gpurify_geom::PolyId;
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{
    assert_clean, assert_has_violation, assert_only_violation, assert_rule_ran, dbu,
    layout_with_violation, point, Amount, ShapeKind, ViolationShape,
};

/// `count` cuts of side 100 in a row, the first centred on the origin.
fn cut_row(count: i64, pitch: i64) -> (gpurify_geom::GeometryStore, Vec<PolyId>) {
    let mut layout = LayoutBuilder::new(1);
    let handles: Vec<_> = (0..count)
        .map(|i| {
            let cx = i * pitch;
            layout.rect(A, cx - 50, -50, cx + 50, 50)
        })
        .collect();
    let (store, ids) = layout.finish();
    let cuts = handles.iter().map(|&h| ids.of(h)).collect();
    (store, cuts)
}

// ------------------------------------------------------------ redundant_via

fn redundant_via_table(min_count: u16, within: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::RedundantVia {
            layer: A,
            min_count: min_count,
            within: dbu(within),
        },
    )]
}

/// Oracle: construct-from-answer. A single cut has a neighbourhood population
/// of one — itself — against a requirement of two, so it is a single point of
/// failure and is reported at the cut with the count it had.
#[test]
fn a_lone_cut_is_reported_at_the_cut_with_the_count_it_had() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::ViaArray {
                cut: A,
                size: 100,
                pitch: 400,
            },
        },
        (0, 0),
        Amount::Count(1),
        Amount::Count(2),
    );

    let mut sink = Sink::default();
    sink.run(&case.store, &redundant_via_table(2, 500));

    assert_only_violation(&sink.out, &case.expected);
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, 1, "examined counts cuts");
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. Two cuts at a pitch of 400 have 300 units of
/// clear space between their nearest edges, so a neighbourhood radius of exactly
/// 300 reaches and one of 299 does not. That single unit flips both cuts from
/// doubled to isolated, and it is measured between nearest points: a
/// centre-based reading would call the gap 400 and get both answers wrong.
#[test]
fn a_neighbourhood_radius_reaches_exactly_as_far_as_it_says_and_no_further() {
    let (store, cuts) = cut_row(2, 400);

    let mut reaching = Sink::default();
    reaching.run(&store, &redundant_via_table(2, 300));
    assert_clean(&reaching.runs, &reaching.out, RULE);
    assert_eq!(assert_rule_ran(&reaching.runs, RULE).examined, 2);

    let mut short = Sink::default();
    short.run(&store, &redundant_via_table(2, 299));
    assert_eq!(
        short.out.rule.len(),
        2,
        "one unit short of reach, neither cut has a neighbour"
    );
    for (index, &cut) in cuts.iter().enumerate() {
        let _ = assert_has_violation(
            &short.out,
            &Violation {
                rule: RULE,
                layer: A,
                severity: Severity::Error,
                at: point(i64::try_from(index).expect("two cuts") * 400, 0),
                measured: Measurement::Count(1),
                limit: Measurement::Count(2),
                shapes: (cut, None),
            },
        );
    }
    assert_eq!(assert_rule_ran(&short.runs, RULE).examined, 2);
}

/// Oracle: construct-from-answer. A triple-via requirement is the same
/// arithmetic one higher: three cuts in reach of each other satisfy a
/// requirement of three, and the outer two of a row of three do not once the
/// radius only reaches their immediate neighbour.
#[test]
fn a_triple_via_requirement_counts_the_cut_itself_among_the_three() {
    let (store, cuts) = cut_row(3, 400);

    let mut wide = Sink::default();
    wide.run(&store, &redundant_via_table(3, 700));
    assert_clean(&wide.runs, &wide.out, RULE);
    assert_eq!(assert_rule_ran(&wide.runs, RULE).examined, 3);

    let mut narrow = Sink::default();
    narrow.run(&store, &redundant_via_table(3, 300));
    assert_eq!(
        narrow.out.rule.len(),
        2,
        "the middle cut sees both neighbours; the two ends see one each"
    );
    for (index, at) in [(0usize, point(0, 0)), (2usize, point(800, 0))] {
        let _ = assert_has_violation(
            &narrow.out,
            &Violation {
                rule: RULE,
                layer: A,
                severity: Severity::Error,
                at,
                measured: Measurement::Count(2),
                limit: Measurement::Count(3),
                shapes: (cuts[index], None),
            },
        );
    }
}

// -------------------------------------------------------- via_array_spacing

fn via_array_table(array_threshold: u16, limit: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::ViaArraySpacing {
            layer: A,
            array_threshold: array_threshold,
            limit: dbu(limit),
        },
    )]
}

/// Oracle: construct-from-answer. Four cuts at a pitch of 200 leave gaps of 100
/// between neighbours, so with a limit of 100 they form one cluster of four —
/// larger than a threshold of three, and therefore an array — and no pair inside
/// it is *below* the limit. Clean, over a nonzero population: `examined` counts
/// the three adjacent pairs the rule actually judged.
#[test]
fn pairs_inside_an_array_exactly_at_the_limit_are_clean() {
    let (store, _cuts) = cut_row(4, 200);
    let mut sink = Sink::default();

    sink.run(&store, &via_array_table(3, 100));

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        3,
        "examined counts candidate pairs inside a qualifying cluster"
    );
}

/// Oracle: construct-from-answer. One unit more limit and every adjacent pair in
/// the same array is short by one. Three violations rather than one per cluster:
/// a six-by-six array with one bad column has a specific place to fix, and
/// reporting the cluster loses it.
#[test]
fn every_short_pair_inside_an_array_is_its_own_violation_at_its_own_gap() {
    let (store, cuts) = cut_row(4, 200);
    let mut sink = Sink::default();

    sink.run(&store, &via_array_table(3, 101));

    assert_eq!(sink.out.rule.len(), 3);
    for index in 0..3usize {
        let _ = assert_has_violation(
            &sink.out,
            &Violation {
                rule: RULE,
                layer: A,
                severity: Severity::Error,
                at: point(i64::try_from(index).expect("three gaps") * 200 + 100, 0),
                measured: Measurement::Length(dbu(100)),
                limit: Measurement::Length(dbu(101)),
                shapes: (cuts[index], Some(cuts[index + 1])),
            },
        );
    }
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, 3);
    assert_eq!(run.violations, 3);
}

/// Oracle: construct-from-answer. A cluster of four is not *larger* than a
/// threshold of four, so it is not an array and its pairs keep the layer's
/// ordinary spacing — being in a big group is a trigger, not a defect. The
/// `examined` count falling to zero is what distinguishes that from a pass.
#[test]
fn a_cluster_exactly_at_the_array_threshold_is_not_yet_an_array() {
    let (store, _cuts) = cut_row(4, 200);
    let mut sink = Sink::default();

    sink.run(&store, &via_array_table(4, 101));

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(sink.runs[0].examined, 0);
    assert_eq!(sink.runs[0].violations, 0);
    assert!(sink.out.rule.is_empty());
}
