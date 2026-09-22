//! Grid family: `off_grid` and `angle`. Angles are exact: an edge lies on an
//! allowed line (0/45/90/135 degrees) or it does not; there is no tolerance band.

use crate::common;

use common::{Sink, A, RULE};
use gpurify_check::drc::Rule;
use gpurify_check::report::{Measurement, Severity, Violation};
use gpurify_geom::PolyId;
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{
    assert_clean, assert_has_violation, assert_rule_ran, dbu, layout_with_violation, point, Amount,
    ShapeKind, ViolationShape,
};

// ----------------------------------------------------------------- off_grid

fn off_grid_table(pitch: i64) -> Vec<(StrId, Rule)> {
    vec![(RULE, Rule::OffGrid { pitch: dbu(pitch) })]
}

/// A square of side `size` with its lower-left corner at `(x, y)`.
fn square(x: i64, y: i64, size: i64) -> (gpurify_geom::GeometryStore, PolyId) {
    let mut layout = LayoutBuilder::new(1);
    let handle = layout.rect(A, x, y, x + size, y + size);
    let (store, ids) = layout.finish();
    (store, ids.of(handle))
}

/// Oracle: construct-from-answer. A square whose x coordinates are 7 and 57 sits
/// seven units off a pitch of fifty at every one of its four vertices, so the
/// rule reports four violations — one per coordinate a mask-prep tool has to
/// edit — each measured at seven and each at its own vertex.
///
/// `examined` counts vertices rather than polygons. It is the only rule in the
/// crate where those differ by two orders of magnitude, and it is what shows the
/// sweep really covered the design.
#[test]
fn every_vertex_off_the_pitch_is_reported_at_that_vertex_with_its_offset() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::OffGrid {
                layer: A,
                size: 50,
                grid: 50,
            },
        },
        (7, 0),
        Amount::Length(7),
        Amount::Length(0),
    );

    let mut sink = Sink::default();
    sink.run(&case.store, &off_grid_table(50));

    assert_eq!(
        sink.out.rule.len(),
        4,
        "all four vertices are off the pitch"
    );
    for corner in [point(7, 0), point(57, 0), point(57, 50), point(7, 50)] {
        let _ = assert_has_violation(
            &sink.out,
            &Violation {
                at: corner,
                ..case.expected
            },
        );
    }

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, 4, "examined counts vertices");
    assert_eq!(run.violations, 4);
}

/// Oracle: construct-from-answer. One database unit is the whole rule here: a
/// square on the lattice is clean and the same square translated by one is four
/// violations of one unit each. Nothing about the shape changed.
#[test]
fn a_shape_on_the_lattice_is_clean_and_the_same_shape_one_unit_off_is_not() {
    let (aligned, _id) = square(0, 0, 50);
    let mut clean = Sink::default();
    clean.run(&aligned, &off_grid_table(50));
    assert_clean(&clean.runs, &clean.out, RULE);
    assert_eq!(assert_rule_ran(&clean.runs, RULE).examined, 4);

    let (nudged, shape) = square(1, 0, 50);
    let mut off = Sink::default();
    off.run(&nudged, &off_grid_table(50));
    assert_eq!(off.out.rule.len(), 4);
    let _ = assert_has_violation(
        &off.out,
        &Violation {
            rule: RULE,
            layer: A,
            severity: Severity::Error,
            at: point(1, 0),
            measured: Measurement::Length(dbu(1)),
            limit: Measurement::Length(dbu(0)),
            shapes: (shape, None),
        },
    );
    assert_eq!(assert_rule_ran(&off.runs, RULE).examined, 4);
}

// -------------------------------------------------------------------- angle

/// 0 and 90 degrees.
const RECTILINEAR: u8 = 0b0101;

fn angle_table(allowed: u8) -> Vec<(StrId, Rule)> {
    vec![(RULE, Rule::Angle { allowed })]
}

/// Oracle: construct-from-answer. The triangle's hypotenuse rises 100 over 100,
/// which is parallel to neither of the two rectilinear directions, so exactly
/// one of its three edges is illegal. The measurement is the number of allowed
/// directions that edge matched — zero, against a requirement of one — because
/// "45 degrees" is not something this crate can produce exactly and reporting an
/// inexact angle would be the tolerance band wearing a different hat.
#[test]
fn an_edge_parallel_to_no_allowed_direction_is_reported_at_the_vertex_it_leaves() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Angle {
                layer: A,
                run: (100, 100),
            },
        },
        (0, 0),
        Amount::Ratio(45.0),
        Amount::Count(1),
    );

    let mut sink = Sink::default();
    sink.run(&case.store, &angle_table(RECTILINEAR));

    assert_eq!(sink.out.rule.len(), 1, "one edge of the three is diagonal");
    let _ = assert_has_violation(
        &sink.out,
        &Violation {
            measured: Measurement::Count(0),
            limit: Measurement::Count(1),
            ..case.expected
        },
    );

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined, 3,
        "examined counts edges, and a triangle has three"
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. The same triangle under a rule that also
/// allows the two diagonals is clean, and the rectangle is clean under the
/// rectilinear rule. Both halves are needed: a rule that accepted everything
/// would pass the first and a rule that never ran would pass the second, and the
/// `RuleRun` is what separates the second from a rule that ran.
#[test]
fn an_edge_parallel_to_an_allowed_direction_is_clean() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Angle {
                layer: A,
                run: (100, 100),
            },
        },
        (0, 0),
        Amount::Ratio(45.0),
        Amount::Count(1),
    );
    let diagonal_allowed = RECTILINEAR | 0b0010;
    let mut permissive = Sink::default();
    permissive.run(&case.store, &angle_table(diagonal_allowed));
    assert_clean(&permissive.runs, &permissive.out, RULE);
    assert_eq!(assert_rule_ran(&permissive.runs, RULE).examined, 3);

    let (rectangle, _id) = square(0, 0, 200);
    let mut strict = Sink::default();
    strict.run(&rectangle, &angle_table(RECTILINEAR));
    assert_clean(&strict.runs, &strict.out, RULE);
    assert_eq!(assert_rule_ran(&strict.runs, RULE).examined, 4);
}
