//! Design rules on one layer's dimensions and spacing, and the integrity
//! checks: one generator per rule kind, each the full matrix of
//! `docs/testing-plan.md` §6.
//!
//! The pattern, shown on `min_width`: a deck with the one rule, a family of
//! layouts whose measurement is known by construction, the limit swept one grid
//! step either side, and each layout under all eight symmetries of the square
//! at two translations. The expectation comes from the rule's definition
//! (`drc::Rule::MinWidth`'s rustdoc and `docs/deck.md`), never from a run.

use crate::harness::{Depth, Expect, Finding, Fixture, Layout, NONE};
use gpurify::engine::run::Checks;

/// DRC alone.
pub const DRC: Checks = Checks { drc: true, ..NONE };

/// The translations every case is repeated at: the origin, and far off it in
/// the negative quadrant, so nothing depends on coordinates being small or
/// positive.
pub const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// A one-layer deck with `rules` appended, on a 1 nm manufacturing grid.
pub fn one_layer_deck(rules: &str) -> String {
    format!("grid 1nm\nlayer met1 = gds(68, 20)\n{rules}\n")
}

/// Every fixture this module generates at `depth`.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    let mut out = Vec::new();
    out.extend(min_width(depth));
    out
}

/// Repeats each fixture under every symmetry at every offset.
pub fn every_placement(fixtures: Vec<Fixture>) -> Vec<Fixture> {
    fixtures
        .iter()
        .flat_map(|fixture| {
            OFFSETS
                .iter()
                .flat_map(move |&(dx, dy)| fixture.every_symmetry(dx, dy))
        })
        .collect()
}

/// `width(met1) >= 100nm` (`min_width`, DRC-010): one finding per merged
/// figure narrower than the limit, measuring its narrowest width.
///
/// Swept at 99, 100 and 101 nm: at the limit is legal (`>=`). Shapes:
/// - a plain bar;
/// - an L whose one arm carries the width under test and whose other arm is
///   wide, so a check that measures the bounding box, or only the first arm
///   it meets, is caught;
/// - the bar drawn as two abutting halves, each narrower than the limit, which
///   merge into one legal or illegal figure: a check that does not merge
///   flags halves that are fine together.
fn min_width(_depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = one_layer_deck("rule w width(met1) >= 100nm");
    let mut cases = Vec::new();
    for width in [LIMIT - 1, LIMIT, LIMIT + 1] {
        let side = match width.cmp(&LIMIT) {
            std::cmp::Ordering::Less => "below",
            std::cmp::Ordering::Equal => "at",
            std::cmp::Ordering::Greater => "above",
        };
        let findings = if width < LIMIT {
            vec![Finding::length(width)]
        } else {
            Vec::new()
        };
        let case = |shape: &str, layout: Layout| {
            Fixture::new(
                &format!("min_width/{shape}/{side}"),
                &["DRC-010"],
                &deck,
                DRC,
            )
            .layout(layout)
            .expect(Expect::rule("w", findings.clone()))
        };
        cases.push(case(
            "bar",
            Layout::default().rect("met1", 0, 0, width, 2000),
        ));
        cases.push(case(
            "l_shape",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 600),
                    (width, 600),
                    (width, 2000),
                    (0, 2000),
                ],
            ),
        ));
        cases.push(case(
            "abutting_halves",
            Layout::default().rect("met1", 0, 0, width / 2, 2000).rect(
                "met1",
                width / 2,
                0,
                width,
                2000,
            ),
        ));
    }
    every_placement(cases)
}
