//! The corner model, rule by rule: shapes that meet only at a corner are one
//! figure, the corner a neck of width 0, and a ring closed only at a corner
//! encloses a hole (`Rule`'s "merged", `geom::boolean::union_into`).
//!
//! Oracle: that definition, applied by hand. Before it every rule but the
//! spacing kinds read the shapes as separate figures, so testing-plan F38 and
//! F51's gap was neither a notch nor a space.

use crate::common;

use common::{Sink, A, RULE};
use gpurify_check::drc::Rule;
use gpurify_check::report::Measurement;
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::{area, LayoutBuilder};
use gpurify_testgen::{assert_clean, assert_rule_ran, dbu, point};

fn rule(rule: Rule) -> Vec<(StrId, Rule)> {
    vec![(RULE, rule)]
}

/// F38's squares (0, 0)-(10, 10), (10, 10)-(20, 20) and (20, 0)-(30, 10)
/// are one figure joined at two corners. The 10-wide gap between the outer
/// two faces itself across empty space with a full overlap: a notch of 10 at
/// its middle, (15, 5), and no space at any limit.
///
/// Oracle: the corner model `union_into` states (touching at a corner is one
/// figure), applied by hand: the 10 gap is a notch of 10 at (15, 5), flagged
/// under 11 and not under 10, and never a space.
#[test]
fn a_gap_between_parts_joined_at_corners_is_a_notch_and_not_a_space() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 10, 10);
    layout.rect(A, 10, 10, 20, 20);
    layout.rect(A, 20, 0, 30, 10);
    let (store, _) = layout.finish();
    let mut sink = Sink::default();

    sink.run(
        &store,
        &rule(Rule::Notch {
            layer: A,
            limit: dbu(11),
        }),
    );
    assert_eq!(sink.out.len(), 1, "the gap is one figure's notch");
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(10)));
    assert_eq!(sink.out.at[0], point(15, 5));

    sink.run(
        &store,
        &rule(Rule::Notch {
            layer: A,
            limit: dbu(10),
        }),
    );
    assert_clean(&sink.runs, &sink.out, RULE);

    sink.run(
        &store,
        &rule(Rule::MinSpacing {
            layer: A,
            limit: dbu(1_000),
        }),
    );
    assert_clean(&sink.runs, &sink.out, RULE);
}

/// Two 100-squares meeting at (100, 100) are one figure whose two concave
/// corners there coincide, voids opposite: a width of 0, reported there.
///
/// Oracle: the corner model `union_into` states, applied by hand: two squares
/// meeting at (100, 100) are one figure with a neck of 0 there.
#[test]
fn a_corner_contact_is_a_width_of_zero() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(A, 100, 100, 200, 200);
    let (store, _) = layout.finish();
    let mut sink = Sink::default();

    sink.run(
        &store,
        &rule(Rule::MinWidth {
            layer: A,
            limit: dbu(1),
        }),
    );
    assert_eq!(sink.out.len(), 1, "one figure, one finding");
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(0)));
    assert_eq!(sink.out.at[0], point(100, 100));
}

/// The same two squares are one figure of 20 000: clean against 20 000,
/// reported once at 20 000 against 20 001, never as two of 10 000.
///
/// Oracle: the corner model `union_into` states, applied by hand: the two
/// squares are one figure of 20 000, clean at 20 000 and reported once against
/// 20 001.
#[test]
fn min_area_sums_a_figure_joined_at_a_corner() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(A, 100, 100, 200, 200);
    let (store, _) = layout.finish();
    let mut sink = Sink::default();
    let min_area = |limit| {
        rule(Rule::MinArea {
            layer: A,
            limit: area(limit),
        })
    };

    sink.run(&store, &min_area(20_000));
    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1, "one figure");

    sink.run(&store, &min_area(20_001));
    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Area(area(20_000)));
}

/// `#####|#...#|#.#.#|##..#|#####` on 100-cells: the centre cell meets the
/// frame only at its lower left corner, so it is part of the frame, and the
/// seven empty cells round it are one hole of 70 000 whose box, (100, 100) to
/// (400, 400), centres on (250, 250). Read as an island, the hole would be
/// eight cells and the island a figure of its own.
///
/// Oracle: the corner model `union_into` states, applied by hand to the
/// picture: one hole of seven cells, 70 000, centred on (250, 250), and one
/// figure of 18 cells, 180 000.
#[test]
fn a_hole_round_an_island_joined_at_a_corner_excludes_the_island() {
    let picture = ["#####", "#...#", "#.#.#", "##..#", "#####"];
    let mut layout = LayoutBuilder::new(1);
    for (y, row) in (0..5).rev().zip(picture) {
        for (x, cell) in (0..).zip(row.bytes()) {
            if cell == b'#' {
                layout.rect(A, x * 100, y * 100, x * 100 + 100, y * 100 + 100);
            }
        }
    }
    let (store, _) = layout.finish();
    let mut sink = Sink::default();

    sink.run(
        &store,
        &rule(Rule::MinEnclosedArea {
            layer: A,
            limit: area(80_000),
        }),
    );
    assert_eq!(sink.out.len(), 1, "one hole");
    assert_eq!(sink.out.measured[0], Measurement::Area(area(70_000)));
    assert_eq!(sink.out.at[0], point(250, 250));

    sink.run(
        &store,
        &rule(Rule::MinArea {
            layer: A,
            limit: area(180_001),
        }),
    );
    assert_eq!(sink.out.len(), 1, "island and frame are one figure");
    assert_eq!(sink.out.measured[0], Measurement::Area(area(180_000)));
}
