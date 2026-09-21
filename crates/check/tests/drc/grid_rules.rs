//! Grid family: `off_grid`, `angle`, and the exact-integer `Direction` the
//! second one is built on.
//!
//! The old tree took `atan2` in `f64` and accepted anything within half a
//! degree. That band is fail-open by construction — an edge four tenths of a
//! degree off a legal direction is not on it, and a checker that says otherwise
//! has silently widened the process. So the tests here are written against the
//! absence of a band: an angle either is expressible as an integer vector or is
//! rejected at load, and an edge either is parallel to one or is not.

use crate::common;

use common::{Env, Sink, A, RULE};
use gpurify_check::drc::rules::grid::{
    check_angle, check_off_grid, AngleTable, Direction, OffGridTable,
};
use gpurify_check::report::{Measurement, Severity, Violation};
use gpurify_geom::PolyId;
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{
    assert_clean, assert_has_violation, assert_rule_ran, dbu, layout_with_violation, point, Amount,
    ShapeKind, ViolationShape,
};

// ----------------------------------------------------------------- off_grid

fn off_grid_table(pitch: i64) -> OffGridTable {
    let mut table = OffGridTable::default();
    table.rule.push(RULE);
    table.pitch.push(dbu(pitch));
    table
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

    let env = Env::default();
    let mut sink = Sink::default();
    check_off_grid(
        env.design(&case.store),
        &off_grid_table(50),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

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
    let env = Env::default();

    let (aligned, _id) = square(0, 0, 50);
    let mut clean = Sink::default();
    check_off_grid(
        env.design(&aligned),
        &off_grid_table(50),
        &mut clean.scratch,
        &mut clean.out,
        &mut clean.runs,
    );
    assert_clean(&clean.runs, &clean.out, RULE);
    assert_eq!(assert_rule_ran(&clean.runs, RULE).examined, 4);

    let (nudged, shape) = square(1, 0, 50);
    let mut off = Sink::default();
    check_off_grid(
        env.design(&nudged),
        &off_grid_table(50),
        &mut off.scratch,
        &mut off.out,
        &mut off.runs,
    );
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

const RECTILINEAR: [Direction; 2] = [Direction { dx: 1, dy: 0 }, Direction { dx: 0, dy: 1 }];

fn angle_table(allowed: &[Direction]) -> AngleTable {
    let mut table = AngleTable::default();
    table.rule.push(RULE);
    table.allowed_start.push(0);
    table
        .allowed_len
        .push(u32::try_from(allowed.len()).expect("a handful of directions"));
    table.allowed.extend_from_slice(allowed);
    table
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

    let env = Env::default();
    let mut sink = Sink::default();
    check_angle(
        env.design(&case.store),
        &angle_table(&RECTILINEAR),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

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
    let env = Env::default();

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
    let diagonal_allowed = [
        Direction { dx: 1, dy: 0 },
        Direction { dx: 0, dy: 1 },
        Direction { dx: 1, dy: 1 },
    ];
    let mut permissive = Sink::default();
    check_angle(
        env.design(&case.store),
        &angle_table(&diagonal_allowed),
        &mut permissive.scratch,
        &mut permissive.out,
        &mut permissive.runs,
    );
    assert_clean(&permissive.runs, &permissive.out, RULE);
    assert_eq!(assert_rule_ran(&permissive.runs, RULE).examined, 3);

    let (rectangle, _id) = square(0, 0, 200);
    let mut strict = Sink::default();
    check_angle(
        env.design(&rectangle),
        &angle_table(&RECTILINEAR),
        &mut strict.scratch,
        &mut strict.out,
        &mut strict.runs,
    );
    assert_clean(&strict.runs, &strict.out, RULE);
    assert_eq!(assert_rule_ran(&strict.runs, RULE).examined, 4);
}

// ---------------------------------------------------------------- Direction

/// Oracle: closed form. Only the four directions at multiples of 45 degrees are
/// integer vectors, and each is the vector whose components are the sign of the
/// cosine and the sine of that angle. Everything else is rejected — which is not
/// a tolerance decision but an arithmetic fact, so the loop below covers every
/// whole degree of two full turns rather than a handful of samples.
#[test]
fn only_multiples_of_forty_five_degrees_are_representable_as_an_integer_vector() {
    assert_eq!(Direction::from_degrees(0), Some(Direction { dx: 1, dy: 0 }));
    assert_eq!(
        Direction::from_degrees(45),
        Some(Direction { dx: 1, dy: 1 })
    );
    assert_eq!(
        Direction::from_degrees(90),
        Some(Direction { dx: 0, dy: 1 })
    );
    assert_eq!(
        Direction::from_degrees(135),
        Some(Direction { dx: -1, dy: 1 })
    );

    for degrees in -360..=360 {
        assert_eq!(
            Direction::from_degrees(degrees).is_some(),
            degrees.rem_euclid(45) == 0,
            "{degrees} degrees was answered the wrong way"
        );
    }
}

/// Oracle: closed form. Parallelism is a cross product that is zero or is not,
/// so an edge and its exact reverse both match and an edge one unit off over a
/// run of a million does not. That last case is the whole argument against the
/// old half-degree band: it is two ten-thousandths of a degree from the
/// diagonal, well inside any tolerance anyone would write, and it is not on the
/// diagonal.
#[test]
fn parallelism_is_exact_and_admits_no_near_miss_however_long_the_edge() {
    let horizontal = Direction { dx: 1, dy: 0 };
    assert!(horizontal.parallel_to(dbu(100), dbu(0)));
    assert!(horizontal.parallel_to(dbu(-100), dbu(0)));
    assert!(!horizontal.parallel_to(dbu(100), dbu(1)));

    let diagonal = Direction { dx: 1, dy: 1 };
    assert!(diagonal.parallel_to(dbu(5), dbu(5)));
    assert!(diagonal.parallel_to(dbu(-5), dbu(-5)));
    assert!(!diagonal.parallel_to(dbu(5), dbu(4)));
    assert!(
        !diagonal.parallel_to(dbu(1_000_000), dbu(999_999)),
        "an edge one unit off the diagonal over a million is not on the diagonal"
    );

    let anti_diagonal = Direction { dx: -1, dy: 1 };
    assert!(anti_diagonal.parallel_to(dbu(-7), dbu(7)));
    assert!(anti_diagonal.parallel_to(dbu(7), dbu(-7)));
    assert!(!anti_diagonal.parallel_to(dbu(7), dbu(7)));
}

/// Oracle: law. Scaling an edge vector by any nonzero factor cannot change
/// which line it lies on, for every direction and every factor. A cross product
/// has that property and a normalised-then-compared implementation does not, so
/// this is the law that pins the implementation to the arithmetic.
#[test]
fn parallelism_is_invariant_under_scaling_the_edge() {
    let directions = [
        Direction { dx: 1, dy: 0 },
        Direction { dx: 0, dy: 1 },
        Direction { dx: 1, dy: 1 },
        Direction { dx: -1, dy: 1 },
    ];
    for direction in directions {
        for scale in [1i64, 2, 17, 1_000_000, -1, -3] {
            let (dx, dy) = (
                dbu(i64::from(direction.dx) * scale),
                dbu(i64::from(direction.dy) * scale),
            );
            assert!(
                direction.parallel_to(dx, dy),
                "{direction:?} scaled by {scale} left its own line"
            );
        }
    }
}
