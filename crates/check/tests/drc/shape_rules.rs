//! Per-shape kinds of `drc::rules::grid` read from deck text:
//! `min_interior_angle`, `polygon_validity` and `origin`. The cases are the
//! root suite's exhaustive fixtures (`tests/exhaustive/drc_dimension.rs`,
//! `drc_overlay.rs`) at the crate level, with the same oracles.

use crate::common::deck::{
    apply, by_rule, check_everywhere, new_deck, run, Finding, Layout, SYMMETRIES,
};
use gpurify_check::report::{Measurement, Outcome};
use gpurify_testgen::dbu;

const ANGLE: &str = "rule r interior_angle(met1) >= 90deg\nrule ihp interior_angle() >= 87deg";

/// Oracle: angles fixed by construction. A rectangle (90 at a limit of 90:
/// legal), an L (its inner corner 270), a ring (its hole, a clockwise row,
/// has corners of 270 on the shape's side; one reading the hole's own inside
/// would see 90, legal too, but one taking the smaller angle of a corner
/// flags the L), an octagon (135): nothing under either rule.
#[test]
fn right_and_reflex_corners_are_legal() {
    let deck = new_deck(&["met1", "met2"], ANGLE);
    let cases: [(&str, Layout); 4] = [
        ("rectangle", Layout::default().rect("met1", 0, 0, 1000, 500)),
        (
            "l_shape",
            Layout::default()
                .rect("met1", 0, 0, 1000, 100)
                .rect("met1", 0, 100, 100, 1000),
        ),
        (
            "ring",
            Layout::default()
                .rect("met1", 0, 0, 1000, 1000)
                .polygon("met1", &[(300, 300), (300, 700), (700, 700), (700, 300)]),
        ),
        (
            "octagon",
            Layout::default().polygon(
                "met1",
                &[
                    (100, 0),
                    (900, 0),
                    (1000, 100),
                    (1000, 900),
                    (900, 1000),
                    (100, 1000),
                    (0, 900),
                    (0, 100),
                ],
            ),
        ),
    ];
    for (name, shapes) in cases {
        check_everywhere(name, &deck, &shapes, &by_rule(&["r", "ihp"], &[]));
    }
}

/// Oracle: angles fixed by construction. A right isosceles triangle has two
/// 45-degree corners (exactly 45 once rounded), under both limits, each at
/// its vertex; a 30-60-90 triangle's two acute corners (30 and 60) are
/// under both too. On `met2` the triangle is read only by the every-layer
/// rule.
#[test]
fn acute_corners_are_reported_at_their_vertices() {
    let deck = new_deck(&["met1", "met2"], ANGLE);
    let triangle = [(0, 0), (1000, 0), (0, 1000)];
    let acute = |rule| {
        [
            (rule, Finding::ratio(45.0).at(1000, 0)),
            (rule, Finding::ratio(45.0).at(0, 1000)),
        ]
    };
    let both: Vec<(&str, Finding)> = acute("r").into_iter().chain(acute("ihp")).collect();
    check_everywhere(
        "right_triangle",
        &deck,
        &Layout::default().polygon("met1", &triangle),
        &by_rule(&["r", "ihp"], &both),
    );
    let thirty: Vec<(&str, Finding)> = ["r", "ihp"]
        .into_iter()
        .flat_map(|rule| {
            [
                (rule, Finding::any().at(1732, 0)),
                (rule, Finding::any().at(0, 1000)),
            ]
        })
        .collect();
    check_everywhere(
        "thirty_sixty",
        &deck,
        &Layout::default().polygon("met1", &[(0, 0), (1732, 0), (0, 1000)]),
        &by_rule(&["r", "ihp"], &thirty),
    );
    check_everywhere(
        "other_layer",
        &deck,
        &Layout::default().polygon("met2", &triangle),
        &by_rule(&["r", "ihp"], &acute("ihp")),
    );
}

/// Oracle: an angle just under and at the limit. A triangle with a corner of
/// exactly 90 at (0, 0) and the other two at 45 is reported only at the two
/// 45s under `>= 46deg`; under `>= 45deg` nothing (45 is at the limit).
#[test]
fn an_angle_at_the_limit_is_legal() {
    let deck = new_deck(
        &["met1", "met2"],
        "rule a interior_angle(met1) >= 45deg\nrule b interior_angle(met1) >= 46deg",
    );
    let triangle = [(0, 0), (1000, 0), (0, 1000)];
    let want = [
        ("b", Finding::ratio(45.0).at(1000, 0)),
        ("b", Finding::ratio(45.0).at(0, 1000)),
    ];
    check_everywhere(
        "limit",
        &deck,
        &Layout::default().polygon("met1", &triangle),
        &by_rule(&["a", "b"], &want),
    );
}

/// Oracle: polygons drawn with the defect by construction: a ring crossing
/// itself and a ring doubling back on itself (zero area) are one finding
/// each (measured 0 against 1); a rectangle and a 45-degree triangle are
/// valid. `valid(met1)` reads met1 only, `valid()` every drawn layer.
#[test]
fn polygon_validity_reports_crossing_and_degenerate_rings() {
    let deck = new_deck(&["met1", "met2"], "rule v valid(met1)\nrule all valid()");
    let crossing = [
        (0, 0),
        (2000, 0),
        (2000, 2000),
        (1000, 2000),
        (1000, -1000),
        (0, -1000),
    ];
    let both = |n: usize| -> Vec<(&str, Finding)> {
        (0..n)
            .flat_map(|_| [("v", Finding::count(0)), ("all", Finding::count(0))])
            .collect()
    };
    let cases: [(&str, Layout, Vec<(&str, Finding)>); 4] = [
        (
            "self_crossing",
            Layout::default().polygon("met1", &crossing),
            both(1),
        ),
        (
            "zero_area",
            Layout::default().polygon("met1", &[(0, 0), (1000, 0), (500, 0)]),
            both(1),
        ),
        (
            "valid_shapes",
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .polygon("met1", &[(2000, 0), (3000, 0), (2000, 1000)]),
            vec![],
        ),
        (
            "other_layer",
            Layout::default().polygon("met2", &crossing),
            vec![("all", Finding::count(0))],
        ),
    ];
    for (name, shapes, want) in cases {
        let shapes = shapes.rect("met1", 5000, 5000, 6000, 6000);
        check_everywhere(name, &deck, &shapes, &by_rule(&["v", "all"], &want));
    }
}

/// Oracle: the image of the seal ring's box under each symmetry about the
/// origin: its lower-left corner and that corner's distance from the origin
/// (3, 4 is 5; 1, 0 is 1), one finding there unless it is `(0, 0)`. The
/// rule is anchored on the origin, so each placement's expectation is
/// computed, not mapped: only the unturned ring drawn from the origin
/// passes, and a rule reading any corner other than the box's lower left
/// breaks a turned case. `examined` counts the ring's four rows.
#[test]
fn origin_measures_the_lower_left_corner_s_distance_from_the_origin() {
    let deck = new_deck(&["seal", "met1"], "rule x.19 origin(seal)");
    let root = |d2: i64| (0..=d2).take_while(|r| r * r <= d2).last().unwrap_or(0);
    for (dx, dy) in [(0, 0), (1, 0), (0, -1), (3, 4)] {
        let drawn = Layout::default()
            .rect("met1", dx + 500, dy + 500, dx + 600, dy + 600)
            .rect("seal", dx, dy, dx + 4000, dy + 100)
            .rect("seal", dx, dy + 3900, dx + 4000, dy + 4000)
            .rect("seal", dx, dy + 100, dx + 100, dy + 3900)
            .rect("seal", dx + 3900, dy + 100, dx + 4000, dy + 3900);
        for s in SYMMETRIES {
            let corners = [
                (dx, dy),
                (dx + 4000, dy),
                (dx, dy + 4000),
                (dx + 4000, dy + 4000),
            ]
            .map(|p| apply(s, p));
            let x = corners.iter().map(|c| c.0).min().expect("four corners");
            let y = corners.iter().map(|c| c.1).min().expect("four corners");
            let rows = run(&deck, &drawn.transformed(s, 0, 0));
            let want: Vec<(Measurement, (i64, i64))> = if (x, y) == (0, 0) {
                vec![]
            } else {
                vec![(Measurement::Length(dbu(root(x * x + y * y))), (x, y))]
            };
            let [row] = &rows[..] else {
                panic!("one row: {rows:?}")
            };
            let found: Vec<_> = row.findings.iter().map(|f| (f.0, f.2)).collect();
            assert_eq!(found, want, "({dx}, {dy}) under {s:?}");
            assert_eq!(
                (row.id.as_str(), row.outcome, row.examined),
                ("x.19", Outcome::Ran, 4)
            );
        }
    }
    // An empty seal layer is skipped, not passed.
    let rows = run(&deck, &Layout::default().rect("met1", 0, 0, 10, 10));
    assert!(matches!(rows[0].outcome, Outcome::Skipped(_)), "{rows:?}");
}

/// Oracle: `Rule::Forbidden`'s definition (shapes as the store holds them,
/// not merged; area with holes excluded), areas by hand: two overlapping
/// 100 squares are two findings of 10000, and so are two abutting ones; a
/// 1000 square with a 200 square hole (a clockwise row) is one of 1000000 -
/// 40000 = 960000; a shape on another layer is none.
#[test]
fn forbidden_reports_each_drawn_shape_with_its_area() {
    let deck = new_deck(&["met1", "met2"], "rule f forbidden(met2)");
    let ten = || [("f", Finding::area(10_000)), ("f", Finding::area(10_000))];
    let cases: [(&str, Layout, Vec<(&str, Finding)>); 4] = [
        (
            "overlapping_drawn",
            Layout::default()
                .rect("met2", 0, 0, 100, 100)
                .rect("met2", 50, 0, 150, 100),
            ten().to_vec(),
        ),
        (
            "abutting_drawn",
            Layout::default()
                .rect("met2", 0, 0, 100, 100)
                .rect("met2", 100, 0, 200, 100),
            ten().to_vec(),
        ),
        (
            "holed",
            Layout::default()
                .rect("met2", 0, 0, 1000, 1000)
                .polygon("met2", &[(400, 400), (400, 600), (600, 600), (600, 400)]),
            vec![("f", Finding::area(960_000))],
        ),
        (
            "other_layer_only",
            Layout::default().rect("met1", 0, 0, 100, 100),
            vec![],
        ),
    ];
    for (name, shapes, want) in cases {
        check_everywhere(name, &deck, &shapes, &by_rule(&["f"], &want));
    }
}
