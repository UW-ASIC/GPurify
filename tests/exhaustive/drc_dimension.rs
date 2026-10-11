//! Design rules on one layer's dimensions and spacing, and the integrity
//! checks: one generator per rule kind, each the full matrix of
//! `docs/testing-plan.md` §6.
//!
//! The pattern, shown on `min_width`: a deck with the one rule, a family of
//! layouts whose measurement is known by construction, the limit swept one grid
//! step either side, and each layout under all eight symmetries of the square
//! at two translations. The expectation comes from the rule's definition
//! (`drc::Rule`'s rustdoc and `docs/deck.md`), never from a run.
//!
//! Conventions every generator keeps:
//! - A minimum passes at its limit and a maximum passes at its limit; only a
//!   strict excess is a finding.
//! - A marker is pinned only where the rustdoc names the point exactly (a
//!   midpoint, a vertex, a box centre) and that point is a lattice point, so
//!   every symmetry maps it exactly ([`pin`]). Elsewhere only `measured` is.
//! - The vacuous case is the rule on an empty layer. No variant in scope says
//!   it records `Skipped`, and the rustdoc says each one that can does, so the
//!   definition's outcome is `Ran` with nothing found.
//! - A fixture that disagrees with a carefully derived expectation carries the
//!   finding it is waiting on (`F<n>`).
//!
//! None are carried today: the fixtures F18, F42, F48 and F49 marked hold
//! since B14 and B15.

pub use crate::harness::DRC;
use crate::harness::{Depth, Expect, Finding, Fixture, Layout, Symmetry, Want};
use gpurify::check::report::Measurement;

/// The translations every case is repeated at: the origin, and far off it in
/// the negative quadrant, so nothing depends on coordinates being small or
/// positive.
pub const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// How far either side of a limit the nightly sweep reaches, in grid steps.
const NIGHTLY_REACH: i64 = 24;

/// A one-layer deck with `rules` appended, on a 1 nm manufacturing grid.
pub fn one_layer_deck(rules: &str) -> String {
    format!("grid 1nm\nlayer met1 = gds(68, 20)\n{rules}\n")
}

/// A deck with `met1`, `met2` and a `region` layer, `rules` appended.
fn three_layer_deck(rules: &str) -> String {
    format!(
        "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
         layer region = gds(81, 1)\n{rules}\n"
    )
}

/// Every fixture this module generates at `depth`.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    [
        min_width(depth),
        min_width_neck(depth),
        max_width(depth),
        cut_size(depth),
        cut_class(depth),
        allowed_width(depth),
        min_edge_length(depth),
        min_step(depth),
        edge_length_of_edges(depth),
        notch(depth),
        min_spacing(depth),
        min_spacing_diff(depth),
        eol_spacing(depth),
        eol_within_spacing(depth),
        eol_keep_out(depth),
        prl_spacing(depth),
        corner_to_corner(depth),
        convex_corner_spacing(depth),
        wide_spacing(depth),
        attached_wide_spacing(depth),
        net_spacing(depth),
        spacing_table(depth),
        two_width_spacing_table(depth),
        tip_spacing_table(depth),
        forbidden_spacing(depth),
        span_length(depth),
        exact_pitch(depth),
        min_area(depth),
        min_enclosed_area(depth),
        off_grid(depth),
        angle(depth),
        interior_angle(depth),
        polygon_validity(depth),
        forbidden(depth),
        max_area(depth),
        aspect_ratio(depth),
        channel(depth),
        directional(depth),
        validity(depth),
        pins(depth),
    ]
    .concat()
}

/// Repeats each fixture under every symmetry at every offset.
pub fn every_placement(fixtures: Vec<Fixture>) -> Vec<Fixture> {
    every_placement_at(fixtures, &OFFSETS)
}

/// Repeats each fixture under the four symmetries of the square that keep
/// the axes (no quarter turn) at every offset, for a rule tied to an axis:
/// a quarter turn makes a vertical pitch a horizontal one.
fn every_axis_placement(fixtures: &[Fixture]) -> Vec<Fixture> {
    let mut out = Vec::new();
    for fixture in fixtures {
        for &(dx, dy) in &OFFSETS {
            for &symmetry in Symmetry::ALL.iter().filter(|s| s.turns % 2 == 0) {
                out.push(fixture.transformed(symmetry, dx, dy));
            }
        }
    }
    out
}

/// Repeats each fixture under every symmetry at each of `offsets`.
fn every_placement_at(fixtures: Vec<Fixture>, offsets: &[(i64, i64)]) -> Vec<Fixture> {
    fixtures
        .into_iter()
        .flat_map(|fixture| {
            offsets
                .iter()
                .flat_map(move |&(dx, dy)| fixture.every_symmetry(dx, dy))
        })
        .collect()
}

// ------------------------------------------------------------------ helpers

/// The values a limit is swept over: one grid step either side at merge
/// depth, [`NIGHTLY_REACH`] steps at nightly.
fn sweep(depth: Depth, limit: i64) -> Vec<i64> {
    match depth {
        Depth::Merge => vec![limit - 1, limit, limit + 1],
        Depth::Nightly => (limit - NIGHTLY_REACH..=limit + NIGHTLY_REACH).collect(),
    }
}

/// `below99`, `at100`, `above101`: where `value` sits against `limit`.
fn side(value: i64, limit: i64) -> String {
    let word = match value.cmp(&limit) {
        std::cmp::Ordering::Less => "below",
        std::cmp::Ordering::Equal => "at",
        std::cmp::Ordering::Greater => "above",
    };
    format!("{word}{value}")
}

/// Pins `finding` at `(x2 / 2, y2 / 2)`, the doubled coordinates of a
/// midpoint, when both halves are whole. A midpoint off the lattice is
/// floored, and a floor does not commute with a mirror, so it stays unpinned.
fn pin(finding: Finding, x2: i64, y2: i64) -> Finding {
    if x2 % 2 == 0 && y2 % 2 == 0 {
        finding.at(x2 / 2, y2 / 2)
    } else {
        finding
    }
}

/// A finding whose measured value is a count.
fn count(n: u32) -> Finding {
    Finding {
        measured: Some(Measurement::Count(n)),
        at: None,
    }
}

/// The largest `r` with `r * r <= n`: a Euclidean gap as the report floors it.
fn floor_sqrt(n: i64) -> i64 {
    (0..=n).take_while(|r| r * r <= n).last().unwrap_or(0)
}

/// A rectangle with a rectangular hole, as GDSII writes one: a single ring
/// that runs in to the hole along a slit and back out along it.
fn holed(outer: [i64; 4], hole: [i64; 4]) -> Vec<(i64, i64)> {
    let [xa, ya, xb, yb] = outer;
    let [xl, yl, xh, yh] = hole;
    vec![
        (xl, ya),
        (xb, ya),
        (xb, yb),
        (xa, yb),
        (xa, ya),
        (xl, ya),
        (xl, yl),
        (xl, yh),
        (xh, yh),
        (xh, yl),
        (xl, yl),
    ]
}

/// Adds axis-aligned rectangles `[xlo, ylo, xhi, yhi]` on `layer`.
fn rects(mut layout: Layout, layer: &str, boxes: &[[i64; 4]]) -> Layout {
    for &[xlo, ylo, xhi, yhi] in boxes {
        layout = layout.rect(layer, xlo, ylo, xhi, yhi);
    }
    layout
}

/// `met1` rectangles.
fn met1(boxes: &[[i64; 4]]) -> Layout {
    rects(Layout::default(), "met1", boxes)
}

/// A fixture expecting each `(rule, findings)` row to run and find exactly
/// those findings.
fn fixture(
    name: &str,
    catalog: &[&'static str],
    deck: &str,
    layout: Layout,
    rows: Vec<(&str, Vec<Finding>)>,
) -> Fixture {
    rows.into_iter().fold(
        Fixture::new(name, catalog, deck, DRC).layout(layout),
        |fixture, (id, findings)| fixture.expect(Expect::rule(id, findings)),
    )
}

/// A fixture expecting rule `id` to run, find exactly `findings`, and examine
/// every shape of `layout`: for the kinds whose `examined` counts drawn
/// polygons (`drc::Rule::MinWidth`, `drc::Rule::MaxWidth`), when every shape
/// is one polygon on the measured layer. A rule that skips the layer, or
/// counts merged figures, fails it.
fn counted(
    name: &str,
    catalog: &[&'static str],
    deck: &str,
    layout: Layout,
    id: &str,
    findings: Vec<Finding>,
) -> Fixture {
    let drawn = layout.shapes.len() as u64;
    Fixture::new(name, catalog, deck, DRC)
        .layout(layout)
        .expect(Expect::rule(id, findings).examined(drawn))
}

/// `rules` on an empty `met1`, with a `met2` shape so the layout is not
/// empty: each rule runs and finds nothing.
fn vacuous(kind: &str, catalog: &[&'static str], rules: &str, ids: &[&str]) -> Fixture {
    let deck = format!("grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n{rules}\n");
    let layout = Layout::default().rect("met2", 0, 0, 1000, 1000);
    let rows = ids.iter().map(|id| (*id, Vec::new())).collect();
    fixture(&format!("{kind}/vacuous"), catalog, &deck, layout, rows)
}

// ------------------------------------------------------------------ min_width

/// `width(met1) >= 100nm` (`min_width`, DRC-010): one finding per merged
/// figure narrower than the limit, measuring its narrowest width, at the
/// middle of that gap.
///
/// Swept at the limit and one step either side: at the limit is legal (`>=`).
/// Shapes:
/// - a plain bar;
/// - an L whose one arm carries the width under test and whose other arm is
///   wide, so a check that measures the bounding box, or only the first arm
///   it meets, is caught;
/// - the bar drawn as two abutting halves, each narrower than the limit, which
///   merge into one legal or illegal figure: a check that does not merge
///   flags halves that are fine together; the same with overlapping halves,
///   and a narrow rectangle drawn inside the bar (it adds no width);
/// - a plus and a U, each with two narrow arms but one figure, so one finding
///   (a check reporting per arm or per drawn rectangle reports more);
/// - a narrow tab on a wide plate (a bounding-box width passes it);
/// - a ring, drawn as one holed polygon and as four abutting bands, whose band
///   is the width (a check blind to holes sees only the outer square);
/// - three separate bars, two of them too narrow: one finding each.
fn min_width(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = one_layer_deck("rule w width(met1) >= 100nm");
    let mut cases = Vec::new();
    for w in sweep(depth, LIMIT) {
        let narrow = w < LIMIT;
        // One finding at the doubled midpoint when the width is short.
        let one = |x2, y2| {
            if narrow {
                vec![pin(Finding::length(w), x2, y2)]
            } else {
                Vec::new()
            }
        };
        let unpinned = || {
            if narrow {
                vec![Finding::length(w)]
            } else {
                Vec::new()
            }
        };
        let mut case = |shape: &str, layout: Layout, findings: Vec<Finding>| {
            cases.push(counted(
                &format!("min_width/{shape}/{}", side(w, LIMIT)),
                &["DRC-010"],
                &deck,
                layout,
                "w",
                findings,
            ));
        };
        case("bar", met1(&[[0, 0, w, 2000]]), one(w, 2000));
        case(
            "l_shape",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 600),
                    (w, 600),
                    (w, 2000),
                    (0, 2000),
                ],
            ),
            one(w, 2600),
        );
        case(
            "abutting_halves",
            met1(&[[0, 0, w / 2, 2000], [w / 2, 0, w, 2000]]),
            one(w, 2000),
        );
        case(
            "overlapping_halves",
            met1(&[[0, 0, 60, 2000], [40, 0, w, 2000]]),
            one(w, 2000),
        );
        // A narrow rectangle drawn inside a wide one adds no width of its own.
        case(
            "narrow_inside_wide",
            met1(&[[0, 0, w, 2000], [20, 0, 50, 2000]]),
            one(w, 2000),
        );
        // Four arms of width w meet in a w-square: four tied gaps.
        let (lo, hi) = (1000, 1000 + w);
        case(
            "plus",
            Layout::default().polygon(
                "met1",
                &[
                    (lo, 0),
                    (hi, 0),
                    (hi, lo),
                    (2100, lo),
                    (2100, hi),
                    (hi, hi),
                    (hi, 2100),
                    (lo, 2100),
                    (lo, hi),
                    (0, hi),
                    (0, lo),
                    (lo, lo),
                ],
            ),
            unpinned(),
        );
        case(
            "plus_overlapping",
            met1(&[[0, lo, 2100, hi], [lo, 0, hi, 2100]]),
            unpinned(),
        );
        // Two arms of width w on a 500-high base: two tied gaps, one figure.
        case(
            "u_shape",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (1000, 0),
                    (1000, 2000),
                    (1000 - w, 2000),
                    (1000 - w, 500),
                    (w, 500),
                    (w, 2000),
                    (0, 2000),
                ],
            ),
            unpinned(),
        );
        case(
            "u_three_rects",
            met1(&[
                [0, 0, 1000, 500],
                [0, 500, w, 2000],
                [1000 - w, 500, 1000, 2000],
            ]),
            unpinned(),
        );
        case(
            "tab_on_plate",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 2000),
                    (900 + w, 2000),
                    (900 + w, 3000),
                    (900, 3000),
                    (900, 2000),
                    (0, 2000),
                ],
            ),
            one(1800 + w, 5000),
        );
        case(
            "tab_touching_plate",
            met1(&[[0, 0, 2000, 2000], [900, 2000, 900 + w, 3000]]),
            one(1800 + w, 5000),
        );
        case(
            "ring",
            Layout::default().polygon(
                "met1",
                &holed([0, 0, 1000, 1000], [w, w, 1000 - w, 1000 - w]),
            ),
            unpinned(),
        );
        case(
            "ring_of_bands",
            met1(&[
                [0, 0, 1000, w],
                [0, 1000 - w, 1000, 1000],
                [0, w, w, 1000 - w],
                [1000 - w, w, 1000, 1000 - w],
            ]),
            unpinned(),
        );
        // Bars of widths w, 60 and 140, 2000 apart: one finding per narrow bar.
        let widths = [w, 60, 140];
        let mut layout = Layout::default();
        let mut findings = Vec::new();
        for (x, width) in (0..).step_by(2000).zip(widths) {
            layout = layout.rect("met1", x, 0, x + width, 2000);
            if width < LIMIT {
                findings.push(pin(Finding::length(width), 2 * x + width, 2000));
            }
        }
        case("three_bars", layout, findings);
    }
    let mut out = every_placement(cases);
    out.push(vacuous(
        "min_width",
        &["DRC-010"],
        "rule w width(met1) >= 100nm",
        &["w"],
    ));
    out
}

/// `min_width`'s Euclidean neck (DRC-010): two squares overlapping at a corner
/// by `d` leave a neck between two concave corners `d·√2` apart, which no
/// facing pair of edges sees. The rustdoc measures it Euclidean, floors the
/// reported value, and compares exactly; the marker is the corners' midpoint.
///
/// Swept two ways: `d` at a fixed limit, and the limit around a fixed `d = 70`
/// (neck √9800 ≈ 98.99), so a limit of 99 fails and reports 98. A Chebyshev or
/// Manhattan neck, or a neck rounded up, reads differently.
fn min_width_neck(depth: Depth) -> Vec<Fixture> {
    let overlaps = match depth {
        Depth::Merge => vec![70, 71, 72],
        Depth::Nightly => (2..=100).collect(),
    };
    let limits = match depth {
        Depth::Merge => vec![98, 99, 100],
        Depth::Nightly => (90..=110).collect(),
    };
    let mut cases = Vec::new();
    let mut add = |d: i64, limit: i64| {
        let deck = one_layer_deck(&format!("rule w width(met1) >= {limit}nm"));
        let gap2 = 2 * d * d;
        let findings = if gap2 < limit * limit {
            vec![pin(Finding::length(floor_sqrt(gap2)), 2000 - d, 2000 - d)]
        } else {
            Vec::new()
        };
        let far = 2000 - d;
        let drawings = [
            (
                "overlapping",
                met1(&[[0, 0, 1000, 1000], [1000 - d, 1000 - d, far, far]]),
            ),
            (
                "polygon",
                Layout::default().polygon(
                    "met1",
                    &[
                        (0, 0),
                        (1000, 0),
                        (1000, 1000 - d),
                        (far, 1000 - d),
                        (far, far),
                        (1000 - d, far),
                        (1000 - d, 1000),
                        (0, 1000),
                    ],
                ),
            ),
        ];
        for (drawn, layout) in drawings {
            cases.push(counted(
                &format!("min_width/neck_{drawn}/d{d}/limit{limit}"),
                &["DRC-010"],
                &deck,
                layout,
                "w",
                findings.clone(),
            ));
        }
    };
    for &d in &overlaps {
        add(d, 100);
    }
    for &limit in limits.iter().filter(|&&limit| limit != 100) {
        add(70, limit);
    }
    every_placement(cases)
}

// ------------------------------------------------------------------ max_width

/// `width(met1) <= 1001nm` (`max_width`, DRC-012): one finding per connected
/// region where a 1002 square fits, measuring the region's narrowest gap, at
/// its middle. At the limit is legal (`<=`).
///
/// Shapes: a bar (wide in one axis only below the limit); the bar as abutting
/// or overlapping halves (merged first); a plate with a thin tab and an L with
/// one wide arm (the region is the wide part, not the bounding box); a ring
/// whose band carries the width (wide all round only when the band is); a
/// dumbbell, two regions joined by a thin bar (two findings, not one per
/// figure), and joined by a wide bar (one region, its narrowest gap the bar).
fn max_width(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 1001;
    let deck = one_layer_deck("rule mx width(met1) <= 1001nm");
    let mut cases = Vec::new();
    for w in sweep(depth, LIMIT) {
        let wide = w > LIMIT;
        let one = |x2, y2| {
            if wide {
                vec![pin(Finding::length(w), x2, y2)]
            } else {
                Vec::new()
            }
        };
        let mut case = |shape: &str, layout: Layout, findings: Vec<Finding>| {
            cases.push(counted(
                &format!("max_width/{shape}/{}", side(w, LIMIT)),
                &["DRC-012"],
                &deck,
                layout,
                "mx",
                findings,
            ));
        };
        case("bar", met1(&[[0, 0, w, 5000]]), one(w, 5000));
        case(
            "abutting_halves",
            met1(&[[0, 0, w / 2, 5000], [w / 2, 0, w, 5000]]),
            one(w, 5000),
        );
        case(
            "overlapping_halves",
            met1(&[[0, 0, 600, 5000], [400, 0, w, 5000]]),
            one(w, 5000),
        );
        case(
            "plate_with_tab",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (w, 0),
                    (w, 3000),
                    (100, 3000),
                    (100, 5000),
                    (0, 5000),
                ],
            ),
            one(w, 3000),
        );
        case(
            "plate_and_touching_tab",
            met1(&[[0, 0, w, 3000], [0, 3000, 100, 5000]]),
            one(w, 3000),
        );
        case(
            "l_one_wide_arm",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (5000, 0),
                    (5000, w),
                    (500, w),
                    (500, 5000),
                    (0, 5000),
                ],
            ),
            one(5000, w),
        );
        // Four tied bands: the marker is not pinned.
        let ring = holed(
            [0, 0, 2 * w + 2000, 2 * w + 2000],
            [w, w, w + 2000, w + 2000],
        );
        case(
            "ring",
            Layout::default().polygon("met1", &ring),
            if wide {
                vec![Finding::length(w)]
            } else {
                Vec::new()
            },
        );
    }
    cases.push(counted(
        "max_width/dumbbell",
        &["DRC-012"],
        &deck,
        met1(&[
            [0, 0, 2000, 2000],
            [3000, 0, 5000, 2000],
            [2000, 900, 3000, 1000],
        ]),
        "mx",
        vec![
            Finding::length(2000).at(1000, 1000),
            Finding::length(2000).at(4000, 1000),
        ],
    ));
    // The bar is wide too, so the plates and the bar are one region, and its
    // narrowest gap is the bar's height.
    cases.push(counted(
        "max_width/dumbbell_wide_bar",
        &["DRC-012"],
        &deck,
        met1(&[
            [0, 0, 2000, 2000],
            [3000, 0, 5000, 2000],
            [2000, 500, 3000, 1502],
        ]),
        "mx",
        vec![Finding::length(1002).at(2500, 1001)],
    ));
    cases.push(counted(
        "max_width/two_plates",
        &["DRC-012"],
        &deck,
        met1(&[[0, 0, 1500, 1500], [3000, 0, 4600, 1600]]),
        "mx",
        vec![
            Finding::length(1500).at(750, 750),
            Finding::length(1600).at(3800, 800),
        ],
    ));
    let mut out = every_placement(cases);
    out.push(vacuous(
        "max_width",
        &["DRC-012"],
        "rule mx width(met1) <= 1001nm",
        &["mx"],
    ));
    out
}

// ------------------------------------------------------------------ cut_size

/// `size(via) == 100nm x 150nm` (`cut_size`, DRC-013): every merged figure is
/// exactly that rectangle, either way round. A wrong short side reports it,
/// else a wrong long side, else (a non-rectangle with the right box) the area;
/// at the centre of the figure's bounding box.
///
/// Each side swept one step either side; a square cut; two 100 x 75 halves
/// that merge into a legal cut, and two legal cuts that merge into an illegal
/// slot; a corner bite and a hole (the right box, the wrong shape); a cut
/// drawn twice. Two rules of one size each flag each other's cuts: several
/// legal sizes are `cut_class`'s (DRC-014).
fn cut_size(depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer via = gds(68, 44)\nrule cs size(via) == 100nm x 150nm\n";
    let via = |boxes: &[[i64; 4]]| rects(Layout::default(), "via", boxes);
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("cut_size/{shape}"),
            &["DRC-013"],
            deck,
            layout,
            vec![("cs", findings)],
        ));
    };
    for s in sweep(depth, 100) {
        let findings = if s == 100 {
            Vec::new()
        } else {
            vec![pin(Finding::length(s), s, 150)]
        };
        case(
            format!("short_side/{}", side(s, 100)),
            via(&[[0, 0, s, 150]]),
            findings,
        );
    }
    for l in sweep(depth, 150) {
        let findings = if l == 150 {
            Vec::new()
        } else {
            vec![pin(Finding::length(l), 100, l)]
        };
        case(
            format!("long_side/{}", side(l, 150)),
            via(&[[0, 0, 100, l]]),
            findings,
        );
    }
    case(
        "square".into(),
        via(&[[0, 0, 100, 100]]),
        vec![Finding::length(100).at(50, 50)],
    );
    case(
        "both_sides_off".into(),
        via(&[[0, 0, 99, 149]]),
        vec![Finding::any()],
    );
    case(
        "halves_make_a_cut".into(),
        via(&[[0, 0, 100, 75], [0, 75, 100, 150]]),
        Vec::new(),
    );
    case(
        "two_cuts_make_a_slot".into(),
        via(&[[0, 0, 100, 150], [100, 0, 200, 150]]),
        vec![Finding::length(150).at(100, 75)],
    );
    case(
        "corner_bite".into(),
        Layout::default().polygon(
            "via",
            &[(0, 0), (100, 0), (100, 140), (90, 140), (90, 150), (0, 150)],
        ),
        vec![Finding::area(14_900).at(50, 75)],
    );
    case(
        "holed".into(),
        Layout::default().polygon("via", &holed([0, 0, 100, 150], [40, 40, 60, 110])),
        vec![Finding::area(13_600).at(50, 75)],
    );
    case(
        "drawn_twice".into(),
        via(&[[0, 0, 100, 150], [0, 0, 100, 150]]),
        Vec::new(),
    );
    case(
        "drawn_twice_offset".into(),
        via(&[[0, 0, 100, 150], [0, 10, 100, 160]]),
        vec![Finding::length(160).at(50, 80)],
    );
    case(
        "array_with_one_wrong".into(),
        via(&[
            [0, 0, 100, 150],
            [300, 0, 400, 150],
            [600, 0, 700, 150],
            [900, 0, 1020, 150],
        ]),
        vec![Finding::length(120).at(960, 75)],
    );
    // Two exact-size rules on one layer flag each other's cuts by the long
    // side; two legal classes are one `cut_class` rule (DRC-014).
    cases.push(fixture(
        "cut_size/two_classes",
        &["DRC-013", "DRC-014"],
        "grid 1nm\nlayer via = gds(68, 44)\nrule c1 size(via) == 100nm x 100nm\n\
         rule c2 size(via) == 100nm x 200nm\n",
        via(&[[0, 0, 100, 100], [1000, 0, 1100, 200]]),
        vec![
            ("c1", vec![Finding::length(200).at(1050, 100)]),
            ("c2", vec![Finding::length(100).at(50, 50)]),
        ],
    ));
    let mut out = every_placement(cases);
    out.push(fixture(
        "cut_size/vacuous",
        &["DRC-013"],
        "grid 1nm\nlayer via = gds(68, 44)\nlayer met1 = gds(68, 20)\n\
         rule cs size(via) == 100nm x 150nm\n",
        met1(&[[0, 0, 1000, 1000]]),
        vec![("cs", Vec::new())],
    ));
    out
}

/// `size(via; allowed: [100nm x 100nm, 100nm x 200nm])` (`cut_class`,
/// DRC-014: sky130 via.1b's three square via sizes, LEF58 `CUTCLASS`): every
/// merged figure is a rectangle of one listed size, either way round; one
/// finding per figure that is none, at its bounding box's centre, measuring
/// `Count(0)`.
///
/// Oracle: sizes fixed by construction. Each class exactly (clean), and each
/// side of each class one step either side (a finding); a 200 square, whose
/// side is only a slot's long side (a check comparing sides one at a time
/// passes it); two abutting squares that merge into the legal slot, and two
/// abutting slots that merge into an illegal 200 x 200 square (a check
/// reading drawn rows sees two legal cuts each time); a slot with a corner
/// bite and one with a hole (the right box, no rectangle); one wrong cut in
/// an array. The second rule writes the list in another order with a repeat,
/// and finds the same.
fn cut_class(depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer via = gds(68, 44)\n\
                rule cc size(via; allowed: [100nm x 100nm, 100nm x 200nm])\n\
                rule cr size(via; allowed: [200nm x 100nm, 100nm x 100nm, 100nm x 100nm])\n";
    let via = |boxes: &[[i64; 4]]| rects(Layout::default(), "via", boxes);
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("cut_class/{shape}"),
            &["DRC-014"],
            deck,
            layout,
            vec![("cc", findings.clone()), ("cr", findings)],
        ));
    };
    for (w, h) in [(100, 100), (100, 200)] {
        for dw in sweep(depth, w) {
            let findings = if dw == w {
                Vec::new()
            } else {
                vec![pin(count(0), dw, h)]
            };
            case(
                format!("{w}x{h}/width/{}", side(dw, w)),
                via(&[[0, 0, dw, h]]),
                findings,
            );
        }
        for dh in sweep(depth, h) {
            let findings = if dh == h {
                Vec::new()
            } else {
                vec![pin(count(0), w, dh)]
            };
            case(
                format!("{w}x{h}/height/{}", side(dh, h)),
                via(&[[0, 0, w, dh]]),
                findings,
            );
        }
    }
    case(
        "square_of_a_long_side".into(),
        via(&[[0, 0, 200, 200]]),
        vec![count(0).at(100, 100)],
    );
    case(
        "two_squares_make_a_slot".into(),
        via(&[[0, 0, 100, 100], [100, 0, 200, 100]]),
        Vec::new(),
    );
    case(
        "two_slots_make_a_square".into(),
        via(&[[0, 0, 100, 200], [100, 0, 200, 200]]),
        vec![count(0).at(100, 100)],
    );
    case(
        "corner_bite".into(),
        Layout::default().polygon(
            "via",
            &[(0, 0), (100, 0), (100, 190), (90, 190), (90, 200), (0, 200)],
        ),
        vec![count(0).at(50, 100)],
    );
    case(
        "holed".into(),
        Layout::default().polygon("via", &holed([0, 0, 100, 200], [40, 40, 60, 160])),
        vec![count(0).at(50, 100)],
    );
    case(
        "array_with_one_wrong".into(),
        via(&[
            [0, 0, 100, 100],
            [300, 0, 400, 200],
            [600, 0, 700, 100],
            [900, 0, 1000, 150],
        ]),
        vec![count(0).at(950, 75)],
    );
    let mut out = every_placement(cases);
    out.push(fixture(
        "cut_class/vacuous",
        &["DRC-014"],
        "grid 1nm\nlayer via = gds(68, 44)\nlayer met1 = gds(68, 20)\n\
         rule cc size(via; allowed: [100nm x 100nm])\n",
        met1(&[[0, 0, 1000, 1000]]),
        vec![("cc", Vec::new())],
    ));
    out
}

/// `width(met1; allowed: [100nm, 200nm])` (`allowed_width`, DRC-015 and
/// DRC-090: sky130 rpm.1b-1f, a precision resistor's five legal widths): one
/// finding per merged figure whose narrowest width is not listed, at the
/// centre of its first rectangle, measuring that width.
///
/// Oracle: widths fixed by construction: bars at each listed width and one
/// step either side; a 150 square, between the two; a 100 bar drawn as two
/// abutting 50 halves (each 50 unmerged); an L of a 100 and a 200 arm,
/// judged by its narrower; two plates overlapping 100 x 100 at a corner, a
/// neck of √20000 (141 floored), which no facing pair sees.
fn allowed_width(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck("rule aw width(met1; allowed: [100nm, 200nm])");
    let mut cases = Vec::new();
    let mut case = |name: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("allowed_width/{name}"),
            &["DRC-015", "DRC-090"],
            &deck,
            layout,
            vec![("aw", findings)],
        ));
    };
    for listed in [100, 200] {
        for w in sweep(depth, listed) {
            let findings = if w == listed {
                Vec::new()
            } else {
                vec![pin(Finding::length(w), w, 1000)]
            };
            case(
                format!("bar_{listed}/{}", side(w, listed)),
                met1(&[[0, 0, w, 1000]]),
                findings,
            );
        }
    }
    case(
        "between".into(),
        met1(&[[0, 0, 150, 150]]),
        vec![Finding::length(150).at(75, 75)],
    );
    case(
        "halves".into(),
        met1(&[[0, 0, 50, 1000], [50, 0, 100, 1000]]),
        Vec::new(),
    );
    case(
        "l_of_two_widths".into(),
        met1(&[[0, 0, 1000, 100], [0, 100, 200, 1000]]),
        Vec::new(),
    );
    case(
        "corner_neck".into(),
        met1(&[[0, 0, 1000, 1000], [900, 900, 1900, 1900]]),
        vec![Finding::length(141)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "allowed_width",
        &["DRC-015"],
        "rule aw width(met1; allowed: [100nm])",
        &["aw"],
    ));
    out
}

// ------------------------------------------------------------ min_edge_length

/// The step, short-rectangle and hole shapes both edge-length checks share,
/// with the findings an edge-length limit of 101 gives them: each short edge
/// at its midpoint. `s` is the short edge.
fn short_edge_shapes(s: i64) -> Vec<(&'static str, Layout, Vec<Finding>)> {
    const LIMIT: i64 = 101;
    let short = s < LIMIT;
    let at = |points: &[(i64, i64)]| -> Vec<Finding> {
        if short {
            points
                .iter()
                .map(|&(x2, y2)| pin(Finding::length(s), x2, y2))
                .collect()
        } else {
            Vec::new()
        }
    };
    vec![
        (
            "step",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 1000),
                    (1000, 1000),
                    (1000, 1000 + s),
                    (0, 1000 + s),
                ],
            ),
            at(&[(2000, 2000 + s)]),
        ),
        (
            "thin_rect",
            met1(&[[0, 0, s, 2000]]),
            at(&[(s, 0), (s, 4000)]),
        ),
        (
            "hole",
            Layout::default().polygon(
                "met1",
                &holed([0, 0, 2000, 2000], [900, 900, 900 + s, 900 + s]),
            ),
            at(&[
                (1800 + s, 1800),
                (1800 + 2 * s, 1800 + s),
                (1800 + s, 1800 + 2 * s),
                (1800, 1800 + s),
            ]),
        ),
    ]
}

/// The merged shapes both edge-length checks share: a square drawn as a strip
/// of height `s` on a block (its edges are the square's), and two rectangles
/// overlapping so their union has two jogs of length `s`.
fn merged_edge_shapes(s: i64) -> Vec<(&'static str, Layout, Vec<Finding>)> {
    let jogs = if s < 101 {
        vec![
            pin(Finding::length(s), 2000 + s, 800),
            pin(Finding::length(s), s, 1000),
        ]
    } else {
        Vec::new()
    };
    vec![
        (
            "strip_on_block",
            met1(&[[0, 0, 2000, s], [0, s, 2000, 2000]]),
            Vec::new(),
        ),
        (
            "overlap_jog",
            met1(&[[0, 0, 1000, 500], [s, 400, 1000 + s, 900]]),
            jogs,
        ),
    ]
}

/// `edge_length(met1) >= 101nm` (`min_edge_length`, DRC-020): one finding per
/// edge shorter than the limit, at its midpoint, measuring its length. At the
/// limit is legal.
///
/// The layer is merged first, so the edges are the merged figure's: a square
/// drawn as a thin strip on a block has none of the strip's short ends, and
/// an overlap whose union has two short jogs has both (F18).
fn min_edge_length(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = one_layer_deck("rule el edge_length(met1) >= 101nm");
    let mut cases = Vec::new();
    for s in sweep(depth, LIMIT) {
        for (shape, layout, findings) in short_edge_shapes(s) {
            cases.push(fixture(
                &format!("min_edge_length/{shape}/{}", side(s, LIMIT)),
                &["DRC-020"],
                &deck,
                layout,
                vec![("el", findings)],
            ));
        }
        for (shape, layout, findings) in merged_edge_shapes(s) {
            cases.push(fixture(
                &format!("min_edge_length/{shape}/{}", side(s, LIMIT)),
                &["DRC-020"],
                &deck,
                layout,
                vec![("el", findings)],
            ));
        }
    }
    let mut out = every_placement(cases);
    out.push(vacuous(
        "min_edge_length",
        &["DRC-020"],
        "rule el edge_length(met1) >= 101nm",
        &["el"],
    ));
    out
}

/// LEF `MINSTEP` variants (`min_step`, DRC-020) at a minStepLength of 50 nm:
/// `corner: outside` with and without `length_sum: 80nm`, `corner: inside`,
/// `corner: step`, `max_edges: 1` and `max_edges: 2`. One finding per run of
/// edges shorter than 50 that its row rejects, at the centre of the run's
/// vertices, measuring the run's edge count (or its length, with
/// `length_sum`).
///
/// Oracle: LEF 5.8's own examples. Its Figure 1-14 a (two 40 nm edges at an
/// outside corner, 80 in all) and d (four, 160): "MINSTEP 0.05" rejects both,
/// and "MINSTEP 0.05 LENGTHSUM 0.08" passes a and rejects d (Example 1-16).
/// Figure 1-15's MAXEDGES: more short edges in a row than allowed is a
/// violation, as many is not. Beside them, by construction: two short edges
/// at an inside corner (`inside` only), one short jog between two edges
/// running the same way (`step` only), a 40 nm wide line whose short ends are
/// no corner and no step, and the outside staircase swept at 49, 50 and 51.
fn min_step(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(
        "rule out min_step(met1; corner: outside, length_sum: none) >= 50nm\n\
         rule sum min_step(met1; corner: outside, length_sum: 80nm) >= 50nm\n\
         rule in min_step(met1; corner: inside, length_sum: none) >= 50nm\n\
         rule st min_step(met1; corner: step, length_sum: none) >= 50nm\n\
         rule e1 min_step(met1; max_edges: 1) >= 50nm\n\
         rule e2 min_step(met1; max_edges: 2) >= 50nm",
    );
    let ids = ["out", "sum", "in", "st", "e1", "e2"];
    let mut cases = Vec::new();
    let mut case = |name: String, points: &[(i64, i64)], rows: [Vec<Finding>; 6]| {
        let mut fixture = Fixture::new(&format!("min_step/{name}"), &["DRC-020"], &deck, DRC)
            .layout(Layout::default().polygon("met1", points));
        for (id, findings) in ids.iter().zip(rows) {
            fixture = fixture.expect(Expect::rule(id, findings));
        }
        cases.push(fixture);
    };
    // A 1000 square whose top right corner is a staircase of two edges `s`.
    let outside_two = |s: i64| {
        vec![
            (0, 0),
            (1000, 0),
            (1000, 1000 - s),
            (1000 - s, 1000 - s),
            (1000 - s, 1000),
            (0, 1000),
        ]
    };
    for s in sweep(depth, 50).into_iter().filter(|&s| s > 0 && s < 500) {
        let rows = if s < 50 {
            let at = |f: Finding| pin(f, 2000 - s, 2000 - s);
            let sum = if 2 * s > 80 {
                vec![at(Finding::length(2 * s))]
            } else {
                vec![]
            };
            [
                vec![at(count(2))],
                sum,
                vec![],
                vec![],
                vec![at(count(2))],
                vec![],
            ]
        } else {
            Default::default()
        };
        case(
            format!("outside_two/{}", side(s, 50)),
            &outside_two(s),
            rows,
        );
    }
    case(
        "lef_figure_a".into(),
        &outside_two(40),
        [
            vec![count(2).at(980, 980)],
            vec![],
            vec![],
            vec![],
            vec![count(2).at(980, 980)],
            vec![],
        ],
    );
    case(
        "lef_figure_d".into(),
        &[
            (0, 0),
            (1000, 0),
            (1000, 920),
            (960, 920),
            (960, 960),
            (920, 960),
            (920, 1000),
            (0, 1000),
        ],
        [
            vec![count(4).at(960, 960)],
            vec![Finding::length(160).at(960, 960)],
            vec![],
            vec![],
            vec![count(4).at(960, 960)],
            vec![count(4).at(960, 960)],
        ],
    );
    case(
        "inside_two".into(),
        &[
            (0, 0),
            (1000, 0),
            (1000, 500),
            (540, 500),
            (540, 540),
            (500, 540),
            (500, 1000),
            (0, 1000),
        ],
        [
            vec![],
            vec![],
            vec![count(2).at(520, 520)],
            vec![],
            vec![count(2).at(520, 520)],
            vec![],
        ],
    );
    case(
        "step".into(),
        &[
            (0, 0),
            (1000, 0),
            (1000, 500),
            (500, 500),
            (500, 540),
            (0, 540),
        ],
        [
            vec![],
            vec![],
            vec![],
            vec![count(1).at(500, 520)],
            vec![],
            vec![],
        ],
    );
    case(
        "line_end".into(),
        &[(0, 0), (1000, 0), (1000, 40), (0, 40)],
        Default::default(),
    );
    every_placement(cases)
}

/// `length(met1.edges()) >= 101nm` (`edge_min_length`) and
/// `forbidden(met1.edges().with_length(< 101nm))` (DRC-021): edge length on an
/// edge layer. `.edges()` is the boundary of the merged layer, so both see
/// what `min_edge_length` should: the jogs of an overlap, and none of the
/// strip's ends. Each short edge is one finding at its midpoint, measuring its
/// length, for both rules.
fn edge_length_of_edges(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = one_layer_deck(
        "rule le length(met1.edges()) >= 101nm\n\
         rule fe forbidden(met1.edges().with_length(< 101nm))",
    );
    let mut cases = Vec::new();
    for s in sweep(depth, LIMIT) {
        for (shape, layout, findings) in short_edge_shapes(s)
            .into_iter()
            .chain(merged_edge_shapes(s))
        {
            cases.push(fixture(
                &format!("edge_min_length/{shape}/{}", side(s, LIMIT)),
                &["DRC-021"],
                &deck,
                layout,
                vec![("le", findings.clone()), ("fe", findings)],
            ));
        }
    }
    let mut out = every_placement(cases);
    out.push(vacuous(
        "edge_min_length",
        &["DRC-021"],
        "rule le length(met1.edges()) >= 101nm\n\
         rule fe forbidden(met1.edges().with_length(< 101nm))",
        &["le", "fe"],
    ));
    out
}

// ------------------------------------------------------------------ notch

/// `notch(met1) >= 101nm` (`notch`, DRC-024): one finding per merged figure,
/// at the middle of its narrowest notch, the gap between two parallel edges
/// of one figure facing each other across empty space. At the limit is legal.
///
/// A U drawn as one polygon and as three touching rectangles (merged first);
/// the same gap between two separate bars, which is spacing and not a notch;
/// a slot hole (a narrow hole is a notch); a comb with two notches (one
/// finding, the narrower); a figure whose only narrow gap is corner to corner
/// (not measured).
fn notch(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = one_layer_deck("rule n notch(met1) >= 101nm");
    let mut cases = Vec::new();
    for g in sweep(depth, LIMIT) {
        let one = |x2, y2| {
            if g < LIMIT {
                vec![pin(Finding::length(g), x2, y2)]
            } else {
                Vec::new()
            }
        };
        let mut case = |shape: &str, layout: Layout, findings: Vec<Finding>| {
            cases.push(fixture(
                &format!("notch/{shape}/{}", side(g, LIMIT)),
                &["DRC-024"],
                &deck,
                layout,
                vec![("n", findings)],
            ));
        };
        case(
            "u_shape",
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (1000 + g, 0),
                    (1000 + g, 2000),
                    (500 + g, 2000),
                    (500 + g, 500),
                    (500, 500),
                    (500, 2000),
                    (0, 2000),
                ],
            ),
            one(1000 + g, 2500),
        );
        case(
            "u_three_rects",
            met1(&[
                [0, 0, 1000 + g, 500],
                [0, 500, 500, 2000],
                [500 + g, 500, 1000 + g, 2000],
            ]),
            one(1000 + g, 2500),
        );
        case(
            "separate_bars",
            met1(&[[0, 0, 500, 2000], [500 + g, 0, 1000 + g, 2000]]),
            Vec::new(),
        );
        case(
            "slot_hole",
            Layout::default().polygon(
                "met1",
                &holed([0, 0, 2000, 2000], [900, 500, 900 + g, 1500]),
            ),
            one(1800 + g, 2000),
        );
        // Teeth g apart, then 50 apart: one finding, the 50.
        case(
            "comb",
            met1(&[
                [0, 0, 500, 2500],
                [500, 0, 2000, 500],
                [500, 500 + g, 2000, 1000 + g],
                [500, 1050 + g, 2000, 1550 + g],
            ]),
            vec![pin(Finding::length(50), 2500, 2050 + 2 * g)],
        );
    }
    // Two squares 50 apart corner to corner, joined round the far side; every
    // facing gap is at least 450.
    cases.push(fixture(
        "notch/corner_gap",
        &["DRC-024"],
        &deck,
        met1(&[
            [0, 0, 1000, 1000],
            [1050, 1050, 2050, 2050],
            [0, 1000, 500, 3000],
            [0, 2500, 2050, 3000],
            [1550, 2050, 2050, 2500],
        ]),
        vec![("n", Vec::new())],
    ));
    // An island 50 inside a 1000 hole: the gap is spacing between two
    // figures, and the hole itself is 1000 wide.
    cases.push(fixture(
        "notch/island_in_hole",
        &["DRC-024"],
        &deck,
        Layout::default()
            .polygon("met1", &holed([0, 0, 3000, 3000], [1000, 1000, 2000, 2000]))
            .rect("met1", 1050, 1050, 1950, 1950),
        vec![("n", Vec::new())],
    ));
    let mut out = every_placement(cases);
    out.push(vacuous(
        "notch",
        &["DRC-024"],
        "rule n notch(met1) >= 101nm",
        &["n"],
    ));
    out
}

// ---------------------------------------------------------------- min_spacing

/// The diagonal offsets swept for Euclidean corner gaps: `d` on both axes, so
/// the gap is `d·√2`, around a limit of 101 (70 gives 98.99, 71 gives
/// 100.41, 72 gives 101.82).
fn diagonals(depth: Depth) -> Vec<i64> {
    match depth {
        Depth::Merge => vec![70, 71, 72],
        Depth::Nightly => (1..=90).collect(),
    }
}

/// Two 1000 squares `d` apart on both axes, and what a Euclidean minimum of
/// 101 finds: the floored gap, midway between the facing corners.
fn diagonal_pair(layers: (&str, &str), d: i64) -> (Layout, Vec<Finding>) {
    let layout = Layout::default().rect(layers.0, 0, 0, 1000, 1000).rect(
        layers.1,
        1000 + d,
        1000 + d,
        2000 + d,
        2000 + d,
    );
    let gap2 = 2 * d * d;
    let findings = if gap2 < 101 * 101 {
        vec![pin(Finding::length(floor_sqrt(gap2)), 2000 + d, 2000 + d)]
    } else {
        Vec::new()
    };
    (layout, findings)
}

/// The square `[0, 1000]²` and a hook beside it: the hook's left side,
/// x = 1050, runs down from y = 500 to -500, facing the square's right edge
/// 50 away over y = 0..500; its inner corner (1060, 1060) faces the square's
/// corner (1000, 1000) diagonally, √7200 = 84.9 away. The hook's box spans
/// y = -500..1500, so the boxes' gap is centred at (1025, 500), on neither.
fn hook_beside_a_square() -> Layout {
    Layout::default().rect("met1", 0, 0, 1000, 1000).polygon(
        "met1",
        &[
            (1050, -500),
            (1600, -500),
            (1600, 1500),
            (1060, 1500),
            (1060, 1060),
            (1500, 1060),
            (1500, 500),
            (1050, 500),
        ],
    )
}

/// The finding for a square `[100 + g, 1000]²` tucked into the L of arms
/// `[0, 1000] x [0, 100]` and `[0, 100] x [0, 1000]`, g apart: two nearest
/// stretches of one length, 900 - g, tie. The L's y = 100 faces the square's
/// y = 100 + g over x = 100 + g..1000, midpoint ((1100 + g) / 2, (200 + g) /
/// 2), and the L's x = 100 faces x = 100 + g, its mirror across y = x. The
/// marker is the middle of the box bounding the two: ((650 + g) / 2, (650 +
/// g) / 2), on the diagonal the pair is symmetric across, pinned where whole
/// (F82). Either midpoint alone would follow drawing order, and a transposed
/// layout would report the other.
fn tucked_marker(g: i64) -> Finding {
    pin(Finding::length(g), 650 + g, 650 + g)
}

/// `space(met1) >= 101nm` (`min_spacing`, DRC-023): one finding per pair of
/// rows in different merged figures closer than the limit, Euclidean, at the
/// midpoint of the nearest points (the middle of the stretch where the two
/// run alongside at that distance). At the limit is legal.
///
/// Side by side and corner to corner (Euclidean: a Chebyshev or Manhattan gap
/// reads differently); touching, overlapping, corner-touching and nested
/// shapes (one figure, no gap); a notch and a narrow own hole (inside one
/// figure, not spacing); an island in a hole (keeps its gap to the hole's
/// edge), and in a hole closed by four bands (one finding per band); a square
/// tucked into an L's corner (the boxes overlap, the shapes do not); a figure
/// drawn as two halves near a bar (one finding per row pair); three bars with
/// two short gaps; a hook beside a square, marked on the 50 gap it measures,
/// not on its box (F66); a side drawn as two collinear edges, marked at the
/// middle of the whole side (F92).
fn min_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = one_layer_deck("rule s space(met1) >= 101nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("min_spacing/{shape}"),
            &["DRC-023"],
            &deck,
            layout,
            vec![("s", findings)],
        ));
    };
    for g in sweep(depth, LIMIT) {
        let near = g < LIMIT;
        let when = |findings: Vec<Finding>| if near { findings } else { Vec::new() };
        let tag = side(g, LIMIT);
        case(
            format!("side_by_side/{tag}"),
            met1(&[[0, 0, 500, 2000], [500 + g, 0, 1000 + g, 2000]]),
            when(vec![pin(Finding::length(g), 1000 + g, 2000)]),
        );
        case(
            format!("island_in_hole/{tag}"),
            Layout::default()
                .polygon("met1", &holed([0, 0, 3000, 3000], [1000, 1000, 2000, 2000]))
                .rect("met1", 1000 + g, 1000 + g, 2000 - g, 2000 - g),
            when(vec![Finding::length(g)]),
        );
        // The same hole closed by four bands: one finding per band.
        case(
            format!("island_in_bands/{tag}"),
            met1(&[
                [0, 0, 3000, 1000],
                [0, 2000, 3000, 3000],
                [0, 1000, 1000, 2000],
                [2000, 1000, 3000, 2000],
                [1000 + g, 1000 + g, 2000 - g, 2000 - g],
            ]),
            when(vec![
                pin(Finding::length(g), 3000, 2000 + g),
                pin(Finding::length(g), 3000, 4000 - g),
                pin(Finding::length(g), 2000 + g, 3000),
                pin(Finding::length(g), 4000 - g, 3000),
            ]),
        );
        // A square tucked into an L's corner: the boxes overlap, the shapes
        // are g apart, marked at [`tucked_marker`].
        case(
            format!("tucked_into_l/{tag}"),
            Layout::default()
                .polygon(
                    "met1",
                    &[
                        (0, 0),
                        (1000, 0),
                        (1000, 100),
                        (100, 100),
                        (100, 1000),
                        (0, 1000),
                    ],
                )
                .rect("met1", 100 + g, 100 + g, 1000, 1000),
            when(vec![tucked_marker(g)]),
        );
        case(
            format!("halves_near_a_bar/{tag}"),
            met1(&[
                [0, 0, 500, 1000],
                [0, 1000, 500, 2000],
                [500 + g, 0, 1000 + g, 2000],
            ]),
            when(vec![
                pin(Finding::length(g), 1000 + g, 1000),
                pin(Finding::length(g), 1000 + g, 3000),
            ]),
        );
        let mut three = vec![Finding::length(50).at(525, 1000)];
        if near {
            three.push(pin(Finding::length(g), 2100 + g, 2000));
        }
        case(
            format!("three_bars/{tag}"),
            met1(&[
                [0, 0, 500, 2000],
                [550, 0, 1050, 2000],
                [1050 + g, 0, 1550 + g, 2000],
            ]),
            three,
        );
    }
    for d in diagonals(depth) {
        let (layout, findings) = diagonal_pair(("met1", "met1"), d);
        case(format!("diagonal/d{d}"), layout, findings);
    }
    // The nearest points are x = 1000 and x = 1050 over y = 0..500: marked
    // at the middle of that stretch (the corners' 84.9 is no nearer).
    case(
        "hook_beside_a_square".into(),
        hook_beside_a_square(),
        vec![pin(Finding::length(50), 1000 + 1050, 500)],
    );
    // A square whose side x = 1000 is drawn as two edges, split by a
    // collinear vertex at y = 300, faces a bar 50 off over y = 0..1000: one
    // stretch, marked at its middle (1025, 500), not at the longer piece's
    // (1025, 650) (F92).
    case(
        "side_split_by_a_vertex".into(),
        Layout::default()
            .polygon(
                "met1",
                &[(0, 0), (1000, 0), (1000, 300), (1000, 1000), (0, 1000)],
            )
            .rect("met1", 1050, 0, 2000, 1000),
        vec![pin(Finding::length(50), 1000 + 1050, 1000)],
    );
    for (shape, layout) in [
        ("touching", met1(&[[0, 0, 500, 2000], [500, 0, 1000, 2000]])),
        (
            "overlapping",
            met1(&[[0, 0, 500, 2000], [400, 0, 900, 2000]]),
        ),
        (
            "corner_touching",
            met1(&[[0, 0, 1000, 1000], [1000, 1000, 2000, 2000]]),
        ),
        ("nested", met1(&[[0, 0, 1000, 1000], [400, 400, 600, 600]])),
        (
            "notch",
            met1(&[
                [0, 0, 1050, 500],
                [0, 500, 500, 2000],
                [550, 500, 1050, 2000],
            ]),
        ),
        (
            "narrow_own_hole",
            Layout::default().polygon("met1", &holed([0, 0, 1000, 1000], [100, 100, 150, 900])),
        ),
    ] {
        case(shape.into(), layout, Vec::new());
    }
    let mut out = every_placement(cases);
    out.push(vacuous(
        "min_spacing",
        &["DRC-023"],
        "rule s space(met1) >= 101nm",
        &["s"],
    ));
    out
}

// ----------------------------------------------------------- min_spacing_diff

/// `space(poly, diff) >= 101nm` and the same rule with the layers swapped
/// (`min_spacing_diff`, DRC-047): one finding per pair of a poly and a diff
/// shape closer than the limit, Euclidean, at the midpoint of the nearest
/// points. Nothing is exempt: touching, overlapping, nested and
/// corner-touching pairs measure 0. Shapes are not merged, so a diff drawn as
/// two halves is two pairs. Two poly shapes near each other are not measured.
/// The distance is symmetric, so both rules find the same.
fn min_spacing_diff(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = "grid 1nm\nlayer poly = gds(66, 20)\nlayer diff = gds(65, 20)\n\
                rule sd space(poly, diff) >= 101nm\nrule ds space(diff, poly) >= 101nm\n";
    let two = |poly: &[[i64; 4]], diff: &[[i64; 4]]| {
        rects(rects(Layout::default(), "poly", poly), "diff", diff)
    };
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("min_spacing_diff/{shape}"),
            &["DRC-047"],
            deck,
            layout,
            vec![("sd", findings.clone()), ("ds", findings)],
        ));
    };
    for g in sweep(depth, LIMIT) {
        let when = |findings: Vec<Finding>| if g < LIMIT { findings } else { Vec::new() };
        let tag = side(g, LIMIT);
        case(
            format!("side_by_side/{tag}"),
            two(&[[0, 0, 500, 2000]], &[[500 + g, 0, 1000 + g, 2000]]),
            when(vec![pin(Finding::length(g), 1000 + g, 2000)]),
        );
        case(
            format!("island_in_hole/{tag}"),
            Layout::default()
                .polygon("poly", &holed([0, 0, 3000, 3000], [1000, 1000, 2000, 2000]))
                .rect("diff", 1000 + g, 1000 + g, 2000 - g, 2000 - g),
            when(vec![Finding::length(g)]),
        );
        case(
            format!("tucked_into_l/{tag}"),
            Layout::default()
                .polygon(
                    "poly",
                    &[
                        (0, 0),
                        (1000, 0),
                        (1000, 100),
                        (100, 100),
                        (100, 1000),
                        (0, 1000),
                    ],
                )
                .rect("diff", 100 + g, 100 + g, 1000, 1000),
            when(vec![tucked_marker(g)]),
        );
        case(
            format!("halves/{tag}"),
            two(
                &[[0, 0, 500, 2000]],
                &[
                    [500 + g, 0, 1000 + g, 1000],
                    [500 + g, 1000, 1000 + g, 2000],
                ],
            ),
            when(vec![
                pin(Finding::length(g), 1000 + g, 1000),
                pin(Finding::length(g), 1000 + g, 3000),
            ]),
        );
    }
    for d in diagonals(depth) {
        let (layout, findings) = diagonal_pair(("poly", "diff"), d);
        case(format!("diagonal/d{d}"), layout, findings);
    }
    case(
        "touching".into(),
        two(&[[0, 0, 500, 2000]], &[[500, 0, 1000, 2000]]),
        vec![Finding::length(0).at(500, 1000)],
    );
    case(
        "overlapping".into(),
        two(&[[0, 0, 500, 2000]], &[[400, 0, 900, 2000]]),
        vec![Finding::length(0)],
    );
    case(
        "nested".into(),
        two(&[[0, 0, 1000, 1000]], &[[400, 400, 600, 600]]),
        vec![Finding::length(0)],
    );
    case(
        "corner_touching".into(),
        two(&[[0, 0, 1000, 1000]], &[[1000, 1000, 2000, 2000]]),
        vec![Finding::length(0).at(1000, 1000)],
    );
    case(
        "same_layer_only".into(),
        two(&[[0, 0, 500, 2000], [550, 0, 1050, 2000]], &[]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(fixture(
        "min_spacing_diff/vacuous",
        &["DRC-047"],
        deck,
        two(&[[0, 0, 500, 2000]], &[]),
        vec![("sd", Vec::new()), ("ds", Vec::new())],
    ));
    out
}

// ---------------------------------------------------------------- eol_spacing

/// `eol_space(met1; eol_width: 200nm) >= 101nm` (`eol_spacing`, DRC-029,
/// DRC-031): an edge strictly shorter than 200 is an end of line; its
/// keep-out is its own span pushed 101 straight out. One finding per pair of
/// separate figures with an edge in a keep-out, measuring the nearest
/// approach, at its midpoint.
///
/// Tip to tip and tip to side (not told apart), the gap swept; the line width
/// swept around `eol_width` at a gap of 50 (a 200-wide end is not an end of
/// line); two lines side by side (no end faces the other); a wide shape just
/// beside the keep-out (no sideways reach, though Euclidean 51 away); a line
/// end facing its own figure (one figure, not a pair). Ends are the merged
/// layer's edges: a wide end drawn as strips is no end, nor is an edge two
/// shapes share, whose keep-out would run through its own figure; a hole's
/// short edge keeps out into the hole, not through the band beyond it.
fn eol_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = one_layer_deck("rule eol eol_space(met1; eol_width: 200nm) >= 101nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, catalog: &[&'static str], layout: Layout, findings| {
        cases.push(fixture(
            &format!("eol_spacing/{shape}"),
            catalog,
            &deck,
            layout,
            vec![("eol", findings)],
        ));
    };
    for g in sweep(depth, LIMIT) {
        let findings = if g < LIMIT {
            vec![pin(Finding::length(g), 100, 4000 + g)]
        } else {
            Vec::new()
        };
        let tag = side(g, LIMIT);
        case(
            format!("tip_to_tip/{tag}"),
            &["DRC-029", "DRC-031"],
            met1(&[[0, 0, 100, 2000], [0, 2000 + g, 100, 4000 + g]]),
            findings.clone(),
        );
        case(
            format!("tip_to_side/{tag}"),
            &["DRC-029", "DRC-031"],
            met1(&[[0, 0, 100, 2000], [-1000, 2000 + g, 1100, 2200 + g]]),
            findings,
        );
    }
    for w in sweep(depth, 200) {
        let findings = if w < 200 {
            vec![pin(Finding::length(50), w, 4050)]
        } else {
            Vec::new()
        };
        case(
            format!("line_width/{}", side(w, 200)),
            &["DRC-029"],
            met1(&[[0, 0, w, 2000], [0, 2050, w, 4050]]),
            findings,
        );
    }
    for (shape, layout) in [
        (
            "side_by_side",
            met1(&[[0, 0, 100, 2000], [150, 0, 250, 2000]]),
        ),
        (
            "beside_the_keep_out",
            met1(&[[0, 0, 100, 2000], [110, 2050, 2000, 4000]]),
        ),
        (
            "facing_its_own_figure",
            met1(&[
                [0, 0, 100, 1000],
                [0, -500, 1000, 0],
                [900, -500, 1000, 1550],
                [0, 1050, 1000, 1550],
            ]),
        ),
    ] {
        case(shape.into(), &["DRC-029"], layout, Vec::new());
    }
    // A 300-wide line drawn as three 100-wide strips: its end is 300 wide, not
    // an end of line, so the line end 50 past it is legal.
    cases.push(fixture(
        "eol_spacing/wide_end_drawn_as_strips",
        &["DRC-029"],
        &deck,
        met1(&[
            [0, 0, 100, 2000],
            [100, 0, 200, 2000],
            [200, 0, 300, 2000],
            [0, 2050, 300, 4050],
        ]),
        vec![("eol", Vec::new())],
    ));
    // A 100-wide line under a 50-thick bar 1100 wide, and a 500-wide shape 30
    // above the bar. The line's top edge is the bar's to share, not an end of
    // line; read as one, its keep-out runs up through the bar to the shape, 80
    // from the line. The bar's 50-long sides are ends, keeping out sideways.
    cases.push(fixture(
        "eol_spacing/shared_edge_is_no_end",
        &["DRC-029"],
        &deck,
        met1(&[
            [0, 0, 100, 1000],
            [-500, 1000, 600, 1050],
            [-200, 1080, 300, 1500],
        ]),
        vec![("eol", Vec::new())],
    ));
    // A square hole with a 100-wide, 50-deep slot in its top. The slot's top
    // edge is an end of line whose keep-out is pushed out of the material,
    // down into the hole, where an 800-wide island's top edge sits 90 below it:
    // marked between the two, at (500, 1005), not in the island (F66).
    cases.push(fixture(
        "eol_spacing/hole_end_of_line",
        &["DRC-029"],
        &deck,
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, -500),
                    (1500, -500),
                    (1500, 1600),
                    (-500, 1600),
                    (-500, -500),
                    (0, -500),
                    (0, 0),
                    (0, 1000),
                    (450, 1000),
                    (450, 1050),
                    (550, 1050),
                    (550, 1000),
                    (1000, 1000),
                    (1000, 0),
                    (0, 0),
                ],
            )
            .rect("met1", 100, 100, 900, 960),
        vec![("eol", vec![pin(Finding::length(90), 450 + 550, 1050 + 960)])],
    ));
    // The other way: a 100-wide slot hole in a ring whose band past the
    // slot's end is 50 thick, and a wide shape 30 beyond the band. The slot's
    // end keeps out down the slot, so nothing is near it; pushed the wrong way
    // it would reach through the band to the shape, 80 away.
    cases.push(fixture(
        "eol_spacing/hole_end_keeps_out_of_the_band",
        &["DRC-029"],
        &deck,
        Layout::default()
            .polygon("met1", &holed([0, 0, 200, 1000], [50, 50, 150, 950]))
            .rect("met1", -500, 1030, 700, 1500),
        vec![("eol", Vec::new())],
    ));
    let mut out = every_placement(cases);
    out.push(vacuous(
        "eol_spacing",
        &["DRC-029"],
        "rule eol eol_space(met1; eol_width: 200nm) >= 101nm",
        &["eol"],
    ));
    out
}

// --------------------------------------------------------- eol_within_spacing

/// LEF/DEF 5.8 Example 1-18 in nanometres, `SPACING 1.2 ENDOFLINE 1.3 WITHIN
/// 0.6`, with `parallel` and `end_to_end` as the deck writes them.
fn lef_eol(parallel: &str, end_to_end: &str) -> String {
    one_layer_deck(&format!(
        "rule e eol_space(met1; eol_width: 1300nm, within: 600nm, parallel: {parallel}, \
         end_to_end: {end_to_end}) >= 1200nm"
    ))
}

/// A 1000 wide line ending at y = 0: its top is an end of line (shorter
/// than 1300, both corners convex) facing up, its keep-out x in
/// (-600, 1600), y from 0 up to 1200.
const LINE: [i64; 4] = [0, -5000, 1000, 0];

/// `eol_space(met1; eol_width: 1300nm, within: 600nm, parallel: ..,
/// end_to_end: ..) >= 1200nm` (`eol_within_spacing`, DRC-029), LEF's
/// `SPACING ENDOFLINE`: a facing edge of another figure in an end's keep-out
/// (the end widened by `within` each side, out to the limit) fails by its
/// depth; one finding per pair of figures, at the middle of the stretch
/// where the facing edge overlaps the widened end.
///
/// Without `parallel`: a 5000 wide bar's depth swept around 1200 (LEF
/// Figure 1-23 a, b); a 2000 square 300 above, its side swept around 600
/// past the end (Figure 1-23 c, d: within is "less than"); a 1000 long edge
/// whose one corner is concave (no end, clean); an end facing its own figure.
/// With `PARALLELEDGE 1.1 WITHIN 0.5` (Figure 1-24), a bar 1000 above fails
/// only with a neighbour beside the line: its distance swept around 1100,
/// its top swept around 500 behind the end's line; none at all, clean. With
/// `TWOEDGES`, one side is not enough and two are. With `end_to_end:
/// 1400nm`, two ends facing each other need 1400 (swept), and an end facing
/// a side still 1200.
fn eol_within_spacing(depth: Depth) -> Vec<Fixture> {
    let mut cases = Vec::new();
    let mut case = |shape: String, deck: &str, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("eol_within_spacing/{shape}"),
            &["DRC-029"],
            deck,
            layout,
            vec![("e", findings)],
        ));
    };
    let plain = lef_eol("none", "none");
    let parallel = lef_eol("(space: 1100nm, within: 500nm, two_edges: false)", "none");
    let two_edges = lef_eol("(space: 1100nm, within: 500nm, two_edges: true)", "none");
    let ends = lef_eol("none", "1400nm");
    // A 7000 wide bar 1000 above the line: inside the keep-out, its bottom
    // overlapping the widened end over x = -600..1600.
    let bar_above = [-3000, 1000, 4000, 2000];
    let at_1000 = || vec![pin(Finding::length(1000), 1000, 1000)];
    for g in sweep(depth, 1200) {
        let findings = if g < 1200 {
            vec![pin(Finding::length(g), 1000, g)]
        } else {
            Vec::new()
        };
        case(
            format!("depth/{}", side(g, 1200)),
            &plain,
            met1(&[LINE, [-2000, g, 3000, g + 1000]]),
            findings,
        );
    }
    for d in sweep(depth, 600) {
        let findings = if d < 600 {
            vec![pin(Finding::length(300), 2600 + d, 300)]
        } else {
            Vec::new()
        };
        case(
            format!("within/{}", side(d, 600)),
            &plain,
            met1(&[LINE, [1000 + d, 300, 3000 + d, 2300]]),
            findings,
        );
    }
    // A tab on a base: its left side is 1000 long but its lower corner is
    // concave, so it is no end, and the wide shape 500 to its left is clean.
    case(
        "concave_corner_is_no_end".into(),
        &plain,
        met1(&[
            [-3000, -5000, 4000, -1000],
            [0, -1000, 1000, 0],
            [-3000, -900, -500, 3000],
        ]),
        Vec::new(),
    );
    // The line's end faces a bar 1000 above that a frame joins to the line.
    case(
        "facing_its_own_figure".into(),
        &plain,
        met1(&[
            LINE,
            [0, -6000, 3000, -5000],
            [2000, -6000, 3000, 1000],
            [-2000, 1000, 3000, 2000],
        ]),
        Vec::new(),
    );
    for p in sweep(depth, 1100) {
        let findings = if p < 1100 { at_1000() } else { Vec::new() };
        case(
            format!("parallel_space/{}", side(p, 1100)),
            &parallel,
            met1(&[LINE, bar_above, [-p - 2000, -5000, -p, 0]]),
            findings,
        );
    }
    for t in sweep(depth, -500) {
        let findings = if t > -500 { at_1000() } else { Vec::new() };
        case(
            format!("parallel_within/{}", side(t, -500)),
            &parallel,
            met1(&[LINE, bar_above, [-2500, -5000, -500, t]]),
            findings,
        );
    }
    case(
        "no_parallel_edge".into(),
        &parallel,
        met1(&[LINE, bar_above]),
        Vec::new(),
    );
    case(
        "two_edges/one_side".into(),
        &two_edges,
        met1(&[LINE, bar_above, [-2500, -5000, -500, 0]]),
        Vec::new(),
    );
    case(
        "two_edges/both_sides".into(),
        &two_edges,
        met1(&[
            LINE,
            bar_above,
            [-2500, -5000, -500, 0],
            [1500, -5000, 3500, 0],
        ]),
        at_1000(),
    );
    for g in sweep(depth, 1400) {
        let findings = if g < 1400 {
            vec![pin(Finding::length(g), 1000, g)]
        } else {
            Vec::new()
        };
        case(
            format!("end_to_end/{}", side(g, 1400)),
            &ends,
            met1(&[LINE, [0, g, 1000, g + 5000]]),
            findings,
        );
    }
    case(
        "end_to_side_keeps_the_limit".into(),
        &ends,
        met1(&[LINE, [-2000, 1300, 3000, 2300]]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "eol_within_spacing",
        &["DRC-029"],
        "rule e eol_space(met1; eol_width: 1300nm, within: 600nm, parallel: none, \
         end_to_end: none) >= 1200nm",
        &["e"],
    ));
    out
}

// --------------------------------------------------------------- eol_keep_out

/// `eol_keep_out(met1; eol_width: 1300nm, backward: 200nm, side: 300nm,
/// forward: 1000nm)` (`eol_keep_out`, DRC-030), `LEF58_EOLKEEPOUT 1.3
/// EXTENSION 0.2 0.3 1.0`: the line's end (1000 wide, both corners convex)
/// keeps out x = -300..1300, y = -200..1000; each other figure overlapping
/// that box with a positive area is one finding, measuring the area inside,
/// at the centre of its box.
///
/// The box's far side swept with a bar's bottom around y = 1000, its side
/// with a block's left side around x = 1300, its back with a block beside
/// the line whose top is swept around y = -200 (touching is outside). Two
/// figures inside are two findings; a bar drawn as two rectangles is one
/// figure, one finding with the summed area; the line's own figure turning
/// back into the box is not an intruder.
fn eol_keep_out(depth: Depth) -> Vec<Fixture> {
    const RULE: &str =
        "rule k eol_keep_out(met1; eol_width: 1300nm, backward: 200nm, side: 300nm, forward: 1000nm)";
    let deck = one_layer_deck(RULE);
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("eol_keep_out/{shape}"),
            &["DRC-030"],
            &deck,
            layout,
            vec![("k", findings)],
        ));
    };
    for g in sweep(depth, 1000) {
        let findings = if g < 1000 {
            vec![pin(
                Finding::area(i128::from(1600 * (1000 - g))),
                1000,
                g + 1000,
            )]
        } else {
            Vec::new()
        };
        case(
            format!("forward/{}", side(g, 1000)),
            met1(&[LINE, [-2000, g, 3000, g + 500]]),
            findings,
        );
    }
    for d in sweep(depth, 300) {
        let findings = if d < 300 {
            vec![pin(
                Finding::area(i128::from((300 - d) * 500)),
                2300 + d,
                1500,
            )]
        } else {
            Vec::new()
        };
        case(
            format!("side/{}", side(d, 300)),
            met1(&[LINE, [1000 + d, 500, 3000 + d, 2500]]),
            findings,
        );
    }
    for b in sweep(depth, -200) {
        let findings = if b > -200 {
            vec![pin(
                Finding::area(i128::from(200 * (b + 200))),
                2400,
                b - 200,
            )]
        } else {
            Vec::new()
        };
        case(
            format!("backward/{}", side(b, -200)),
            met1(&[LINE, [1100, b - 2000, 3100, b]]),
            findings,
        );
    }
    case(
        "two_figures".into(),
        met1(&[LINE, [-2000, 300, 200, 1800], [700, 300, 2500, 1800]]),
        vec![
            pin(Finding::area(350_000), -100, 1300),
            pin(Finding::area(420_000), 2000, 1300),
        ],
    );
    case(
        "one_figure_drawn_twice".into(),
        met1(&[LINE, [-2000, 500, 500, 1500], [500, 500, 3000, 1500]]),
        vec![pin(Finding::area(800_000), 1000, 1500)],
    );
    case(
        "own_figure_in_the_box".into(),
        met1(&[
            LINE,
            [0, -6000, 3000, -5000],
            [2000, -6000, 3000, 1100],
            [-500, 600, 3000, 1100],
        ]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous("eol_keep_out", &["DRC-030"], RULE, &["k"]));
    out
}

// ---------------------------------------------------------------- prl_spacing

/// `prl_space(met1; prl: 500nm) >= 101nm` (`prl_spacing`, DRC-026): pairs in
/// different figures whose run (the longest length over which edges of their
/// merged figures facing each other at most 101 apart project onto each other)
/// is at least 500 are held to 101. One finding per pair, at the midpoint of
/// the nearest points.
///
/// The run swept around 500 at a gap of 100 (at 500 the limit applies); the
/// gap swept at a long run; an L whose box would overstate the run against a
/// short bar (its facing edges run 100: clean, F49); a diagonal pair (no
/// run); touching shapes (one figure); a wire drawn as segments, each shorter
/// than the threshold, which runs its whole length beside the other wire.
fn prl_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 101;
    let deck = one_layer_deck("rule prl prl_space(met1; prl: 500nm) >= 101nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings| {
        cases.push(fixture(
            &format!("prl_spacing/{shape}"),
            &["DRC-026"],
            &deck,
            layout,
            vec![("prl", findings)],
        ));
    };
    for r in sweep(depth, 500) {
        let findings = if r >= 500 {
            vec![pin(Finding::length(100), 300, 4000 - r)]
        } else {
            Vec::new()
        };
        case(
            format!("run/{}", side(r, 500)),
            met1(&[[0, 0, 100, 2000], [200, 2000 - r, 300, 4000 - r]]),
            findings,
        );
    }
    for g in sweep(depth, LIMIT) {
        let findings = if g < LIMIT {
            vec![pin(Finding::length(g), 200 + g, 2000)]
        } else {
            Vec::new()
        };
        case(
            format!("gap/{}", side(g, LIMIT)),
            met1(&[[0, 0, 100, 2000], [100 + g, 0, 200 + g, 2000]]),
            findings,
        );
    }
    // The L's arm faces the bar's end, x = 100 against x = 200, over
    // y = 1900..2000: a run of 100. Its long arm's top, y = 100, faces the
    // bar's underside 1800 away, past the limit. The boxes would overlap by
    // 1300 on x.
    case(
        "l_box_overstates_run".into(),
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 100),
                    (100, 100),
                    (100, 2000),
                    (0, 2000),
                ],
            )
            .rect("met1", 200, 1900, 1500, 2000),
        Vec::new(),
    );
    case(
        "diagonal".into(),
        met1(&[[0, 0, 1000, 1000], [1050, 1050, 2050, 2050]]),
        Vec::new(),
    );
    case(
        "touching".into(),
        met1(&[[0, 0, 100, 2000], [100, 0, 200, 2000]]),
        Vec::new(),
    );
    // A line 100 from another that runs 2000 beside it, drawn as four
    // 500-long segments: the figures run 2000 alongside, past a 600
    // threshold, so each segment's pair is held to the limit; read off each
    // segment's box, the run would be 500 and the wire would escape it.
    cases.push(fixture(
        "prl_spacing/segmented_run",
        &["DRC-026"],
        &one_layer_deck("rule prl prl_space(met1; prl: 600nm) >= 101nm"),
        met1(&[
            [0, 0, 100, 2000],
            [200, 0, 300, 500],
            [200, 500, 300, 1000],
            [200, 1000, 300, 1500],
            [200, 1500, 300, 2000],
        ]),
        vec![(
            "prl",
            vec![
                Finding::length(100).at(150, 250),
                Finding::length(100).at(150, 750),
                Finding::length(100).at(150, 1250),
                Finding::length(100).at(150, 1750),
            ],
        )],
    ));
    let mut out = every_placement(cases);
    out.push(vacuous(
        "prl_spacing",
        &["DRC-026"],
        "rule prl prl_space(met1; prl: 500nm) >= 101nm",
        &["prl"],
    ));
    out
}

// ----------------------------------------------------------- corner_to_corner

/// `corner_space(met1) >= 101nm` (`corner_to_corner`, DRC-032): pairs in
/// different figures with convex corners of the merged layer facing each other
/// (each beyond the other on both axes), measured between the nearest such
/// corners, Euclidean, midway between those corners.
///
/// The diagonal swept; a pair 50 apart on x and 1 on y (apart on both: 50.01,
/// reported 50); the same with no gap on y (facing across an edge:
/// `min_spacing`'s); side by side; two squares 50 apart corner to corner but
/// one figure. An L whose arm's corner faces a square diagonally though its
/// box overlaps the square on y; a hook facing a square across an edge and,
/// further on, corner to corner (the corners are held); a square's corner
/// that a shape on top of it turns into a stretch of the figure's edge (not a
/// corner).
fn corner_to_corner(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck("rule cc corner_space(met1) >= 101nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings| {
        cases.push(fixture(
            &format!("corner_to_corner/{shape}"),
            &["DRC-032"],
            &deck,
            layout,
            vec![("cc", findings)],
        ));
    };
    for d in diagonals(depth) {
        let (layout, findings) = diagonal_pair(("met1", "met1"), d);
        case(format!("diagonal/d{d}"), layout, findings);
    }
    case(
        "skew".into(),
        met1(&[[0, 0, 1000, 1000], [1050, 1001, 2050, 2001]]),
        vec![Finding::length(50)],
    );
    case(
        "no_gap_on_one_axis".into(),
        met1(&[[0, 0, 1000, 1000], [1050, 1000, 2050, 2000]]),
        Vec::new(),
    );
    case(
        "side_by_side".into(),
        met1(&[[0, 0, 1000, 1000], [1050, 0, 2050, 1000]]),
        Vec::new(),
    );
    case(
        "one_figure".into(),
        met1(&[
            [0, 0, 1000, 1000],
            [1050, 1050, 2050, 2050],
            [-500, 0, 0, 3500],
            [-500, 3000, 2050, 3500],
            [1050, 2050, 2050, 3000],
        ]),
        Vec::new(),
    );
    // An L with a 100-thick arm along the bottom to x = 1000, and a square
    // whose corner (1050, 150) is 50 past the arm's corner (1000, 100) on both
    // axes: √5000, 70, marked midway between the corners (F66). The L's box
    // reaches y = 1000, past the square's.
    case(
        "l_corner_inside_its_box".into(),
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (1000, 0),
                    (1000, 100),
                    (100, 100),
                    (100, 1000),
                    (0, 1000),
                ],
            )
            .rect("met1", 1050, 150, 1150, 250),
        vec![pin(Finding::length(70), 1000 + 1050, 100 + 150)],
    );
    // A hook whose left side faces the square's right edge 50 away, below
    // y = 500, and whose inner corner (1060, 1060) faces the square's corner
    // (1000, 1000): √7200, 84, marked midway between the corners, not on the
    // edge gap (F66). The edge gap is `min_spacing`'s; the corners are this
    // rule's.
    case(
        "corner_beside_an_edge_gap".into(),
        hook_beside_a_square(),
        vec![pin(Finding::length(84), 1000 + 1060, 1000 + 1060)],
    );
    // A square with a 10-thick bar on top, flush with its right side: the
    // square's corner (1000, 1000) is a stretch of the figure's right edge,
    // which runs to y = 1010 and faces a shape from y = 1005 across 50. No
    // corner faces it.
    case(
        "row_corner_inside_a_figure_edge".into(),
        met1(&[
            [0, 0, 1000, 1000],
            [0, 1000, 1000, 1010],
            [1050, 1005, 2050, 2005],
        ]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "corner_to_corner",
        &["DRC-032"],
        "rule cc corner_space(met1) >= 101nm",
        &["cc"],
    ));
    out
}

// ------------------------------------------------------ convex_corner_spacing

/// `corner_space(met1; corner_to_corner: .., except_eol: ..) >= 101nm`.
fn corner_deck(corner_to_corner: bool, except_eol: &str) -> String {
    one_layer_deck(&format!(
        "rule c corner_space(met1; corner_to_corner: {corner_to_corner}, except_eol: {except_eol}) \
         >= 101nm"
    ))
}

/// `corner_space(met1; corner_to_corner: .., except_eol: ..) >= 101nm`
/// (`convex_corner_spacing`, DRC-032), `LEF58_CORNERSPACING CONVEXCORNER`:
/// facing convex corners of different figures measured by the larger axis
/// gap (`TritonRoute`'s `maxXY`), or Euclidean with `corner_to_corner`; one
/// finding per pair of figures, midway between the nearest corners.
///
/// Diagonal pairs `d` apart on both axes: the larger gap is `d`, the
/// Euclidean one `d·√2` (the same pairs as `corner_to_corner`). A pair 50
/// apart on y with the x gap swept around 101: the larger gap is the x gap,
/// and Euclidean it is clean at 100 (111.8). Side by side, no facing
/// corners; touching at a corner, one figure. With `except_eol: 200nm`, a
/// 100 wide line end's corners are exempt on either shape, and two wide
/// squares' are not.
fn convex_corner_spacing(depth: Depth) -> Vec<Fixture> {
    let square = corner_deck(false, "none");
    let euclid = corner_deck(true, "none");
    let eol = corner_deck(false, "200nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, deck: &str, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("convex_corner_spacing/{shape}"),
            &["DRC-032"],
            deck,
            layout,
            vec![("c", findings)],
        ));
    };
    for d in diagonals(depth) {
        let (layout, euclidean) = diagonal_pair(("met1", "met1"), d);
        let larger = if d < 101 {
            vec![pin(Finding::length(d), 2000 + d, 2000 + d)]
        } else {
            Vec::new()
        };
        case(
            format!("diagonal/square/d{d}"),
            &square,
            layout.clone(),
            larger,
        );
        case(
            format!("diagonal/euclidean/d{d}"),
            &euclid,
            layout,
            euclidean,
        );
    }
    for d in sweep(depth, 101) {
        let findings = if d < 101 {
            vec![pin(Finding::length(d), 2000 + d, 2050)]
        } else {
            Vec::new()
        };
        case(
            format!("skewed/{}", side(d, 101)),
            &square,
            met1(&[[0, 0, 1000, 1000], [1000 + d, 1050, 2000 + d, 2050]]),
            findings,
        );
    }
    case(
        "skewed_euclidean".into(),
        &euclid,
        met1(&[[0, 0, 1000, 1000], [1100, 1050, 2100, 2050]]),
        Vec::new(),
    );
    case(
        "side_by_side".into(),
        &square,
        met1(&[[0, 0, 1000, 1000], [1050, 0, 2050, 1000]]),
        Vec::new(),
    );
    case(
        "one_figure".into(),
        &square,
        met1(&[[0, 0, 1000, 1000], [1000, 1000, 2000, 2000]]),
        Vec::new(),
    );
    case(
        "except_eol/line_end".into(),
        &eol,
        met1(&[[0, 0, 100, 1000], [150, 1050, 1150, 2050]]),
        Vec::new(),
    );
    case(
        "except_eol/other_line_end".into(),
        &eol,
        met1(&[[0, 0, 1000, 1000], [1050, 1050, 1150, 2050]]),
        Vec::new(),
    );
    case(
        "except_eol/wide_corners".into(),
        &eol,
        met1(&[[0, 0, 1000, 1000], [1050, 1050, 2050, 2050]]),
        vec![pin(Finding::length(50), 2050, 2050)],
    );
    case(
        "line_end_without_except".into(),
        &square,
        met1(&[[0, 0, 100, 1000], [150, 1050, 1150, 2050]]),
        vec![pin(Finding::length(50), 250, 2050)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "convex_corner_spacing",
        &["DRC-032"],
        "rule c corner_space(met1; corner_to_corner: false, except_eol: none) >= 101nm",
        &["c"],
    ));
    out
}

// ------------------------------------------------------ wide_dependent_spacing

/// `wide_space(met1; width: 1000nm) >= 301nm` (`wide_dependent_spacing`,
/// DRC-025): the wide part is where a 1000 square fits (exactly 1000 wide
/// counts); pairs in different figures where either has one, measured from
/// that part, at the midpoint of the nearest points.
///
/// The plate width swept around the threshold beside a line 200 off; the gap
/// swept at a wide plate; a thin tab of a wide plate 200 from a line that is
/// 500 from the plate (not held); a 1200 x 1000 plate drawn as two 1200 x 500
/// halves, neither wide alone (two row pairs, both held); two thin lines; a
/// thin line between the plate and another line (the far pair has no wide
/// part); a thin staircase 100 from the plate over y = 1500..2000 whose box
/// reaches far below, marked on the gap it measures (F66); a plate whose
/// facing side the wide part's rectangles cut in three, marked at the middle
/// of the whole side (F92).
fn wide_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 301;
    let deck = one_layer_deck("rule wd wide_space(met1; width: 1000nm) >= 301nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings| {
        cases.push(fixture(
            &format!("wide_dependent_spacing/{shape}"),
            &["DRC-025"],
            &deck,
            layout,
            vec![("wd", findings)],
        ));
    };
    for w in sweep(depth, 1000) {
        let findings = if w >= 1000 {
            vec![pin(Finding::length(200), 2 * w + 200, 3000)]
        } else {
            Vec::new()
        };
        case(
            format!("plate_width/{}", side(w, 1000)),
            met1(&[[0, 0, w, 3000], [w + 200, 0, w + 300, 3000]]),
            findings,
        );
    }
    for g in sweep(depth, LIMIT) {
        let findings = if g < LIMIT {
            vec![pin(Finding::length(g), 4000 + g, 3000)]
        } else {
            Vec::new()
        };
        case(
            format!("gap/{}", side(g, LIMIT)),
            met1(&[[0, 0, 2000, 3000], [2000 + g, 0, 2100 + g, 3000]]),
            findings,
        );
    }
    case(
        "thin_tab_not_held".into(),
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 2000),
                    (1000, 2000),
                    (1000, 3000),
                    (900, 3000),
                    (900, 2000),
                    (0, 2000),
                ],
            )
            .rect("met1", 1200, 2500, 1300, 3000),
        Vec::new(),
    );
    case(
        "thin_tab_touching_not_held".into(),
        met1(&[
            [0, 0, 2000, 2000],
            [900, 2000, 1000, 3000],
            [1200, 2500, 1300, 3000],
        ]),
        Vec::new(),
    );
    case(
        "wide_only_merged".into(),
        met1(&[
            [0, 0, 1200, 500],
            [0, 500, 1200, 1000],
            [1400, 0, 1500, 1000],
        ]),
        vec![
            Finding::length(200).at(1300, 250),
            Finding::length(200).at(1300, 750),
        ],
    );
    case(
        "two_thin_lines".into(),
        met1(&[[0, 0, 100, 3000], [300, 0, 400, 3000]]),
        Vec::new(),
    );
    case(
        "line_between".into(),
        met1(&[
            [0, 0, 2000, 2000],
            [2100, 0, 2200, 2000],
            [2400, 0, 2500, 2000],
        ]),
        vec![Finding::length(100).at(2050, 1000)],
    );
    // A 100-wide staircase: up from y = 1500 at x = 2100..2200, and an arm
    // x = 2200..2300 down to y = -1000. The plate's side x = 2000 faces it
    // nearest, 100, over y = 1500..2000 (the arm is 200 off): marked at
    // (2050, 1750). The boxes' gap is centred at (2050, 1000).
    case(
        "staircase_beside_the_plate".into(),
        Layout::default().rect("met1", 0, 0, 2000, 2000).polygon(
            "met1",
            &[
                (2100, 1500),
                (2200, 1500),
                (2200, -1000),
                (2300, -1000),
                (2300, 1600),
                (2200, 1600),
                (2200, 4000),
                (2100, 4000),
            ],
        ),
        vec![pin(Finding::length(100), 2000 + 2100, 1500 + 2000)],
    );
    // A 3000 x 2000 plate with a 1000-wide arm below x = 500..1500, all of
    // it wide, and a line 200 above its top y = 2000. Cut into vertical
    // slabs, the wide part's top is three sides, x = 0..500, 500..1500 and
    // 1500..3000, in the orientations where it lies along x: one stretch,
    // marked at (1500, 2100), not at the longest piece's (2250, 2100) (F92).
    case(
        "wide_side_cut_into_slabs".into(),
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (500, 0),
                    (500, -1000),
                    (1500, -1000),
                    (1500, 0),
                    (3000, 0),
                    (3000, 2000),
                    (0, 2000),
                ],
            )
            .rect("met1", 0, 2200, 3000, 2300),
        vec![pin(Finding::length(200), 3000, 2000 + 2200)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "wide_dependent_spacing",
        &["DRC-025"],
        "rule wd wide_space(met1; width: 1000nm) >= 301nm",
        &["wd"],
    ));
    out
}

/// `wide_space(met1; width: 1000nm, attached: 300nm) >= 301nm`
/// (`attached_wide_spacing`, DRC-028) beside the same rule without
/// `attached`: the wide part grown by 300 and clipped to its own figure also
/// holds what is attached to it.
///
/// A 2000 plate with a 100-wide finger up its middle, and a line 200 beside
/// the finger starting `a` above the plate: the attached stub reaches 300 up
/// the finger, so the line is `min(a, √(200² + (a − 300)²))` from the grown
/// part and `a` from the plate. A thin line inside the grown square but in
/// another figure is not attached, so the line beyond it is not held.
fn attached_wide_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 301;
    let deck = one_layer_deck(
        "rule wd wide_space(met1; width: 1000nm) >= 301nm\n\
         rule aw wide_space(met1; width: 1000nm, attached: 300nm) >= 301nm",
    );
    let starts = match depth {
        Depth::Merge => vec![100, 400, 600],
        Depth::Nightly => (100..=700).step_by(10).collect(),
    };
    let mut cases = Vec::new();
    for a in starts {
        let held = |gap2: i64| {
            if gap2 < LIMIT * LIMIT {
                vec![Finding::length(floor_sqrt(gap2))]
            } else {
                Vec::new()
            }
        };
        let stub2 = if a <= 300 {
            200 * 200
        } else {
            200 * 200 + (a - 300) * (a - 300)
        };
        cases.push(fixture(
            &format!("attached_wide_spacing/finger/a{a}"),
            &["DRC-025", "DRC-028"],
            &deck,
            Layout::default()
                .polygon(
                    "met1",
                    &[
                        (0, 0),
                        (2000, 0),
                        (2000, 2000),
                        (1000, 2000),
                        (1000, 3000),
                        (900, 3000),
                        (900, 2000),
                        (0, 2000),
                    ],
                )
                .rect("met1", 1200, 2000 + a, 1300, 3000),
            vec![("wd", held(a * a)), ("aw", held(stub2.min(a * a)))],
        ));
    }
    cases.push(fixture(
        "attached_wide_spacing/line_between",
        &["DRC-025", "DRC-028"],
        &deck,
        met1(&[
            [0, 0, 2000, 2000],
            [2100, 0, 2200, 2000],
            [2400, 0, 2500, 2000],
        ]),
        vec![
            ("wd", vec![Finding::length(100).at(2050, 1000)]),
            ("aw", vec![Finding::length(100).at(2050, 1000)]),
        ],
    ));
    let mut out = every_placement(cases);
    out.push(vacuous(
        "attached_wide_spacing",
        &["DRC-028"],
        "rule aw wide_space(met1; width: 1000nm, attached: 300nm) >= 301nm",
        &["aw"],
    ));
    out
}

// ---------------------------------------------------------------- net_spacing

/// The net-spacing deck: two metals joined through `via1`, labels on `met1`.
const NET_DECK: &str = "grid 1nm
layer met1 = gds(68, 20)
layer via1 = gds(68, 44)
layer met2 = gds(69, 20)
layer met1_label = gds(68, 5)
connect conductors [met1, met2]
connect touch_within_layer
connect via via1 [met1, met2]
connect label met1_label names met1
rule sn space(met1; nets: same) >= 301nm
rule dn space(met1; nets: different) >= 301nm
";

/// `space(met1; nets: same) >= 301nm` and `nets: different` (`net_spacing`,
/// DRC-080): pairs in different figures, by extracted net, at the midpoint of
/// the nearest points.
///
/// Two bars `g` apart, strapped through vias and `met2` (one net: only the
/// same-net rule holds them) or not (two nets); labels with different names
/// and with one name (a name does not join nets: they stay two); touching
/// bars (one figure, no pair). A deck naming a non-conductor is refused.
fn net_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 301;
    let mut cases = Vec::new();
    for g in sweep(depth, LIMIT) {
        let near = if g < LIMIT {
            vec![pin(Finding::length(g), 1000 + g, 2000)]
        } else {
            Vec::new()
        };
        let bars = met1(&[[0, 0, 500, 2000], [500 + g, 0, 1000 + g, 2000]]);
        let strapped = rects(
            rects(
                bars.clone(),
                "via1",
                &[[200, 200, 300, 300], [700 + g, 200, 800 + g, 300]],
            ),
            "met2",
            &[[100, 100, 900 + g, 400]],
        );
        let tag = side(g, LIMIT);
        for (shape, layout, same) in [
            ("strapped", strapped, true),
            ("apart", bars.clone(), false),
            (
                "labelled_apart",
                bars.clone().label("met1_label", 250, 1000, "A").label(
                    "met1_label",
                    750 + g,
                    1000,
                    "B",
                ),
                false,
            ),
            (
                "one_name_apart",
                bars.label("met1_label", 250, 1000, "A")
                    .label("met1_label", 750 + g, 1000, "A"),
                false,
            ),
        ] {
            let (sn, dn) = if same {
                (near.clone(), Vec::new())
            } else {
                (Vec::new(), near.clone())
            };
            cases.push(fixture(
                &format!("net_spacing/{shape}/{tag}"),
                &["DRC-080"],
                NET_DECK,
                layout,
                vec![("sn", sn), ("dn", dn)],
            ));
        }
    }
    cases.push(fixture(
        "net_spacing/touching",
        &["DRC-080"],
        NET_DECK,
        met1(&[[0, 0, 500, 2000], [500, 0, 1000, 2000]]),
        vec![("sn", Vec::new()), ("dn", Vec::new())],
    ));
    let mut out = every_placement(cases);
    out.push(fixture(
        "net_spacing/vacuous",
        &["DRC-080"],
        NET_DECK,
        rects(Layout::default(), "met2", &[[0, 0, 1000, 1000]]),
        vec![("sn", Vec::new()), ("dn", Vec::new())],
    ));
    out.push(
        Fixture::new(
            "net_spacing/not_a_conductor",
            &["DRC-080"],
            &one_layer_deck("rule dn space(met1; nets: different) >= 301nm"),
            DRC,
        )
        .layout(met1(&[[0, 0, 500, 2000]]))
        .expect(Expect::Passes(false)),
    );
    out
}

// -------------------------------------------------------------- spacing_table

/// The table every `spacing_table` fixture uses: 180 everywhere, 220 for a
/// pair whose wider shape is wider than 300 running alongside for more than
/// 1000.
const TABLE: &str = "rule t space_table(met1;
    prl:   [0nm, 1000nm],
    width: [0nm, 300nm],
    space: [[180nm, 180nm],
            [180nm, 220nm]])";

/// `space_table` (`spacing_table`, DRC-025, DRC-026, DRC-027): the column of
/// the last `prl` strictly exceeded by the run of the merged figures' edges
/// facing each other at most that column's cell apart, the row of the last
/// `width` the wider shape strictly exceeds (measured on its part that wide),
/// the first row always applied to whole shapes. One finding per pair,
/// measuring its distance, at the midpoint of the points it measured.
///
/// A `wa`-wide line beside a 100-wide one, `g` apart with a run `r`: the width
/// swept around 300 (exactly 300 is the first row), the run around 1000
/// (exactly 1000 is the first column), the gap around 220 and, for two thin
/// lines, around 180. A thin tab of a wide plate is held to the first row
/// only; a ring's own hole is never a pair; touching lines are one figure.
/// A wire drawn as short segments takes the column of its whole run. An L
/// whose box would overstate the run, and a pair whose long run lies past
/// the cell it would select, keep the first column (F49).
fn spacing_table(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(TABLE);
    let mut cases = Vec::new();
    // A `wa`-wide line and a 100-wide one, `g` apart, overlapping by `r`.
    let mut pair = |name: String, catalog: &[&'static str], wa: i64, g: i64, r: i64| {
        let column = usize::from(r > 1000);
        let row_need = if wa > 300 { [180, 220][column] } else { 180 };
        let findings = if g < row_need.max(180) {
            vec![pin(Finding::length(g), 2 * wa + g, 4000 - r)]
        } else {
            Vec::new()
        };
        cases.push(fixture(
            &format!("spacing_table/{name}"),
            catalog,
            &deck,
            met1(&[[0, 0, wa, 2000], [wa + g, 2000 - r, wa + g + 100, 4000 - r]]),
            vec![("t", findings)],
        ));
    };
    for wa in sweep(depth, 300) {
        pair(
            format!("width/{}", side(wa, 300)),
            &["DRC-025", "DRC-027"],
            wa,
            200,
            2000,
        );
    }
    for r in sweep(depth, 1000) {
        pair(format!("run/{}", side(r, 1000)), &["DRC-026"], 400, 200, r);
    }
    for g in sweep(depth, 220) {
        pair(
            format!("gap_wide/{}", side(g, 220)),
            &["DRC-025", "DRC-026"],
            400,
            g,
            2000,
        );
    }
    for g in sweep(depth, 180) {
        pair(
            format!("gap_thin/{}", side(g, 180)),
            &["DRC-026"],
            100,
            g,
            2000,
        );
    }
    for (shape, layout) in [
        (
            "thin_tab_first_row",
            Layout::default()
                .polygon(
                    "met1",
                    &[
                        (0, 0),
                        (2000, 0),
                        (2000, 2000),
                        (1000, 2000),
                        (1000, 4000),
                        (900, 4000),
                        (900, 2000),
                        (0, 2000),
                    ],
                )
                .rect("met1", 1200, 2500, 1300, 4000),
        ),
        (
            "own_hole",
            Layout::default().polygon("met1", &holed([0, 0, 2000, 2000], [100, 100, 1900, 1900])),
        ),
        ("touching", met1(&[[0, 0, 400, 2000], [400, 0, 500, 2000]])),
    ] {
        cases.push(fixture(
            &format!("spacing_table/{shape}"),
            &["DRC-025"],
            &deck,
            layout,
            vec![("t", Vec::new())],
        ));
    }
    // A 400-wide line and an L, 200 apart only where the L's top arm reaches
    // in, over y = 1900..2000 (run 100); its long arm faces the line 1100
    // away, past every cell. The run is 100, column 0: 180, and 200 is
    // clean. The boxes would overlap by 2000 on y (column 1: 220, F49).
    cases.push(fixture(
        "spacing_table/l_box_overstates_run",
        &["DRC-026"],
        &deck,
        Layout::default().rect("met1", 0, 0, 400, 2000).polygon(
            "met1",
            &[
                (1500, 0),
                (1600, 0),
                (1600, 2000),
                (600, 2000),
                (600, 1900),
                (1500, 1900),
            ],
        ),
        vec![("t", Vec::new())],
    ));
    // Each cell takes the run of the edges facing closer than itself. Two
    // thin lines (row 0: 180, then 200 past a 1000 run): a bar 230 off
    // running 3000, and a stub on it reaching to 190 for 50. Within 200 the
    // run is the stub's 50, so column 0 holds: 190 is clean. The bar's run
    // counts only for a cell wider than 230.
    cases.push(fixture(
        "spacing_table/run_within_the_cell",
        &["DRC-026"],
        &one_layer_deck(
            "rule t space_table(met1;
    prl:   [0nm, 1000nm],
    width: [0nm, 300nm],
    space: [[180nm, 200nm],
            [180nm, 260nm]])",
        ),
        met1(&[
            [0, 0, 100, 3000],
            [330, 0, 430, 3000],
            [290, 1000, 330, 1050],
        ]),
        vec![("t", Vec::new())],
    ));
    // A 400-wide line and a 100-wide one 200 apart, running 2000 alongside,
    // the thin one drawn as four 500-long segments: the figures' run passes
    // 1000, so each segment's pair is held to 220; read off each segment's
    // box (run 500: 180), the wire would escape the second column.
    cases.push(fixture(
        "spacing_table/segmented_run",
        &["DRC-026"],
        &deck,
        met1(&[
            [0, 0, 400, 2000],
            [600, 0, 700, 500],
            [600, 500, 700, 1000],
            [600, 1000, 700, 1500],
            [600, 1500, 700, 2000],
        ]),
        vec![(
            "t",
            vec![
                Finding::length(200).at(500, 250),
                Finding::length(200).at(500, 750),
                Finding::length(200).at(500, 1250),
                Finding::length(200).at(500, 1750),
            ],
        )],
    ));
    let mut out = every_placement(cases);
    out.push(vacuous("spacing_table", &["DRC-025"], TABLE, &["t"]));
    out
}

// ---------------------------------------------------- two_width_spacing_table

/// LEF/DEF 5.8's two-width table ("Two-Width Spacing Tables"), in
/// nanometres: widths 0, 0.25, 1.5 and 3.0 µm with runs none, 0, 1.5 and
/// 3.0 µm, and the manual's cells.
const TWO_WIDTHS: &str = "rule t two_width_table(met1;
    width: [0nm, 250nm, 1500nm, 3000nm],
    prl:   [none, 0nm, 1500nm, 3000nm],
    space: [[150nm, 200nm, 500nm, 1000nm],
            [200nm, 250nm, 500nm, 1000nm],
            [500nm, 500nm, 600nm, 1000nm],
            [1000nm, 1000nm, 1000nm, 1200nm]])";

/// `two_width_table` (`two_width_spacing_table`, DRC-027): a pair needs the
/// cell at the last width that applies to each shape, a width applying to a
/// shape wider than it whose figures run alongside for more than its run.
///
/// LEF's own worked example (SE), each case's gap swept one step around its
/// space: widths 250 and 250 with no run, 150; 250 and 260 with no run, 150;
/// 250 and 260 with a run of 100, 200; 260 and 260 with a run of 100, 250.
/// The 1500 run swept around 1500 between two 1600 wide plates 550 apart
/// (600 only past it). A 260 wide line 220 from the thin tab of a 2 µm plate
/// is clean: the plate is wide, the tab is not (holding the whole shape to
/// its widest part would ask 250). A ring's own hole, and touching shapes,
/// are no pair.
fn two_width_spacing_table(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(TWO_WIDTHS);
    let mut cases = Vec::new();
    let mut case = |shape: String, catalog: &[&'static str], layout: Layout, findings| {
        cases.push(fixture(
            &format!("two_width_spacing_table/{shape}"),
            catalog,
            &deck,
            layout,
            vec![("t", findings)],
        ));
    };
    // Lines `wa` and `wb` wide, `g` apart, overlapping by `r` along y.
    for (example, wa, wb, r, need) in [
        ("w250_w250_run0", 250, 250, 0, 150),
        ("w250_w260_run0", 250, 260, 0, 150),
        ("w250_w260_run100", 250, 260, 100, 200),
        ("w260_w260_run100", 260, 260, 100, 250),
    ] {
        for g in sweep(depth, need) {
            let findings = if g < need {
                vec![pin(Finding::length(g), 2 * wa + g, 4000 - r)]
            } else {
                Vec::new()
            };
            case(
                format!("lef_example/{example}/{}", side(g, need)),
                &["DRC-027"],
                met1(&[[0, 0, wa, 2000], [wa + g, 2000 - r, wa + g + wb, 4000 - r]]),
                findings,
            );
        }
    }
    for r in sweep(depth, 1500) {
        let findings = if r > 1500 {
            vec![pin(Finding::length(550), 3750, 6000 - r)]
        } else {
            Vec::new()
        };
        case(
            format!("run_1500/{}", side(r, 1500)),
            &["DRC-027"],
            met1(&[[0, 0, 1600, 3000], [2150, 3000 - r, 3750, 6000 - r]]),
            findings,
        );
    }
    case(
        "thin_tab_is_thin".into(),
        &["DRC-027"],
        met1(&[
            [0, 0, 2000, 2000],
            [900, 2000, 1000, 3000],
            [1220, 2500, 1480, 4000],
        ]),
        Vec::new(),
    );
    case(
        "own_hole".into(),
        &["DRC-027"],
        Layout::default().polygon("met1", &holed([0, 0, 2000, 2000], [100, 100, 1900, 1900])),
        Vec::new(),
    );
    case(
        "touching".into(),
        &["DRC-027"],
        met1(&[[0, 0, 400, 2000], [400, 0, 500, 2000]]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "two_width_spacing_table",
        &["DRC-027"],
        TWO_WIDTHS,
        &["t"],
    ));
    out
}

// ---------------------------------------------------------- tip_spacing_table

/// The ASAP7 M1 tip table (DRM r1p7, Table 3.12.1): edges below 24 nm, from
/// 24 to 36 nm, and above 36 nm; M1.S.1 side to side 18, M1.S.2 tip to side
/// 25, M1.S.3 tip to tip 27 (both 24 to 36), M1.S.4 31 (both below 24),
/// M1.S.5 31 (one of each).
const TIPS: &str = "rule t tip_space_table(met1;
    length: [0nm, 24nm, 37nm],
    space: [[31nm, 31nm, 25nm],
            [31nm, 27nm, 25nm],
            [25nm, 25nm, 18nm]])";

/// `tip_space_table` (`tip_spacing_table`, DRC-031): whole edges of the
/// merged layer in different figures that face each other over a positive
/// run need the cell of their two length classes; one finding per pair of
/// figures, its smallest offending gap, at the middle of the stretch the
/// two edges face each other over.
///
/// Each ASAP7 rule's gap swept around its value (FR; positive gaps only, as
/// shapes that touch merge): side to side, tip to
/// side from a 20 and from a 30 wide line, tip to tip at both widths and
/// mixed. Each class boundary swept at a gap between its two cells: tips 23,
/// 24 and 25 wide 28 apart (31 below 24, 27 from it), and 36, 37 and 38 wide
/// 20 apart (27 to 36, 18 above). Clean: a diagonal pair (no run), a notch
/// inside one figure, and a 30 wide tip drawn as two 15 wide strips 28 from
/// another (one 30 wide end, 27; a check classing drawn edges would ask
/// 31). Three bars, two findings; a figure facing a bar 15 and 10 away
/// along two steps, one finding at the nearer.
fn tip_spacing_table(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(TIPS);
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("tip_spacing_table/{shape}"),
            &["DRC-031"],
            &deck,
            layout,
            vec![("t", findings)],
        ));
    };
    // Two lines `wa` and `wb` wide, tip to tip `g` apart, both starting at
    // x = 0: they face each other over the narrower width.
    let tips = |wa: i64, wb: i64, g: i64| met1(&[[0, 0, wa, 1000], [0, 1000 + g, wb, 2000 + g]]);
    let found = |g: i64, need: i64, x2: i64, y2: i64| {
        if g < need {
            vec![pin(Finding::length(g), x2, y2)]
        } else {
            Vec::new()
        }
    };
    for g in sweep(depth, 18).into_iter().filter(|&g| g > 0) {
        case(
            format!("side_to_side/{}", side(g, 18)),
            met1(&[[0, 0, 100, 1000], [100 + g, 0, 200 + g, 1000]]),
            found(g, 18, 200 + g, 1000),
        );
    }
    for w in [20, 30] {
        for g in sweep(depth, 25).into_iter().filter(|&g| g > 0) {
            case(
                format!("tip_to_side/w{w}/{}", side(g, 25)),
                met1(&[[0, 0, w, 1000], [-500, 1000 + g, 500, 1100 + g]]),
                found(g, 25, w, 2000 + g),
            );
        }
    }
    for (rule, wa, wb, need) in [("s3", 30, 30, 27), ("s4", 20, 20, 31), ("s5", 30, 20, 31)] {
        for g in sweep(depth, need).into_iter().filter(|&g| g > 0) {
            case(
                format!("tip_to_tip/{rule}/{}", side(g, need)),
                tips(wa, wb, g),
                found(g, need, wa.min(wb), 2000 + g),
            );
        }
    }
    for w in sweep(depth, 24).into_iter().filter(|&w| w > 0) {
        let need = if w < 24 {
            31
        } else if w < 37 {
            27
        } else {
            18
        };
        case(
            format!("class_24/{}", side(w, 24)),
            tips(w, w, 28),
            found(28, need, w, 2028),
        );
    }
    for w in sweep(depth, 37) {
        let need = if w < 24 {
            31
        } else if w < 37 {
            27
        } else {
            18
        };
        case(
            format!("class_37/{}", side(w, 37)),
            tips(w, w, 20),
            found(20, need, w, 2020),
        );
    }
    case(
        "diagonal".into(),
        met1(&[[0, 0, 30, 1000], [40, 1010, 70, 2000]]),
        Vec::new(),
    );
    case(
        "notch_in_one_figure".into(),
        met1(&[[0, 0, 20, 500], [30, 0, 50, 500], [0, -20, 50, 0]]),
        Vec::new(),
    );
    case(
        "tip_drawn_as_strips".into(),
        met1(&[[0, 0, 15, 1000], [15, 0, 30, 1000], [0, 1028, 30, 2028]]),
        Vec::new(),
    );
    case(
        "three_bars".into(),
        met1(&[[0, 0, 100, 1000], [110, 0, 210, 1000], [220, 0, 320, 1000]]),
        vec![
            Finding::length(10).at(105, 500),
            Finding::length(10).at(215, 500),
        ],
    );
    // A bar's 1000-long side x = 100 faces a figure stepped 15 away below
    // y = 400 and 10 away above it: both 400 and 600 long, 18 apart needed;
    // the nearer step is the finding, over y = 400..1000.
    case(
        "nearest_of_two_steps".into(),
        met1(&[[0, 0, 100, 1000], [115, 0, 215, 400], [110, 400, 210, 1000]]),
        vec![Finding::length(10).at(105, 700)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous("tip_spacing_table", &["DRC-031"], TIPS, &["t"]));
    out
}

// ---------------------------------------------------------- forbidden_spacing

/// `forbidden_space(met1; min: 100nm, max: 150nm, prl: 200nm)`
/// (`forbidden_spacing`, DRC-033): facing edges of different figures that
/// run alongside for more than 200 at a gap from 100 to 150, both included,
/// are forbidden; one finding per pair of figures, its smallest forbidden
/// gap, at the middle of the stretch the two edges face each other over.
///
/// The gap swept around both ends of the range (both are forbidden: 99 and
/// 151 are legal), the run swept around 200 at a gap of 120 (200 is not
/// more than 200). Clean: a diagonal pair, a U whose arms are 120 apart
/// (one figure). Three bars 120 apart, two findings. A figure facing a bar
/// 90 away along one step and 130 along another: the narrower gap is below
/// the range and legal, and the finding is the 130.
fn forbidden_spacing(depth: Depth) -> Vec<Fixture> {
    const RULE: &str = "rule f forbidden_space(met1; min: 100nm, max: 150nm, prl: 200nm)";
    let deck = one_layer_deck(RULE);
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("forbidden_spacing/{shape}"),
            &["DRC-033"],
            &deck,
            layout,
            vec![("f", findings)],
        ));
    };
    let bars = |g: i64| met1(&[[0, 0, 100, 1000], [100 + g, 0, 200 + g, 1000]]);
    for (end, limit) in [("min", 100), ("max", 150)] {
        for g in sweep(depth, limit) {
            let findings = if (100..=150).contains(&g) {
                vec![pin(Finding::length(g), 200 + g, 1000)]
            } else {
                Vec::new()
            };
            case(format!("gap_{end}/{}", side(g, limit)), bars(g), findings);
        }
    }
    for r in sweep(depth, 200) {
        let findings = if r > 200 {
            vec![pin(Finding::length(120), 320, 2000 - r)]
        } else {
            Vec::new()
        };
        case(
            format!("run/{}", side(r, 200)),
            met1(&[[0, 0, 100, 1000], [220, 1000 - r, 320, 2000 - r]]),
            findings,
        );
    }
    case(
        "diagonal".into(),
        met1(&[[0, 0, 100, 1000], [220, 1100, 320, 2000]]),
        Vec::new(),
    );
    case(
        "one_figure".into(),
        met1(&[[0, 0, 100, 1000], [220, 0, 320, 1000], [0, -100, 320, 0]]),
        Vec::new(),
    );
    case(
        "three_bars".into(),
        met1(&[[0, 0, 100, 1000], [220, 0, 320, 1000], [440, 0, 540, 1000]]),
        vec![
            Finding::length(120).at(160, 500),
            Finding::length(120).at(380, 500),
        ],
    );
    // The bar's side x = 100 faces the figure's step x = 190 over
    // y = 0..400 (90: below the range, legal) and x = 230 over y = 400..1000
    // (130, run 600: forbidden), marked at (165, 700).
    case(
        "narrower_step_is_legal".into(),
        met1(&[[0, 0, 100, 1000], [190, 0, 290, 400], [230, 400, 330, 1000]]),
        vec![Finding::length(130).at(165, 700)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous("forbidden_spacing", &["DRC-033"], RULE, &["f"]));
    out
}

// ---------------------------------------------------------------- exact_pitch

/// `pitch(met1, vertical) == 27nm` and `pitch(met1, horizontal) == 54nm`
/// (`exact_pitch`, DRC-035), ASAP7 FIN.S.1 (7 nm fins, 27 nm pitch) and
/// GATE.S.1 (20 nm gates, 54 nm pitch): each rectangle's nearest neighbours
/// past it that overlap it across must have their centre lines exactly the
/// pitch apart; one finding per pair off it, in the middle of their gap.
///
/// Three fins and three gates with the pitch swept one step either side
/// (FR): both neighbouring pairs off the pitch, and none at it. A missing
/// fin is a pitch of 54. Fins that do not overlap across are no neighbours.
/// A bent shape refuses the rule. Placed under the symmetries that keep the
/// axes: a quarter turn swaps a vertical pitch for a horizontal one.
fn exact_pitch(depth: Depth) -> Vec<Fixture> {
    let fins = one_layer_deck("rule p pitch(met1, vertical) == 27nm");
    let gates = one_layer_deck("rule p pitch(met1, horizontal) == 54nm");
    let mut cases = Vec::new();
    let mut case = |shape: String, deck: &str, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("exact_pitch/{shape}"),
            &["DRC-035"],
            deck,
            layout,
            vec![("p", findings)],
        ));
    };
    for p in sweep(depth, 27).into_iter().filter(|&p| p > 7) {
        let findings = if p == 27 {
            Vec::new()
        } else {
            vec![
                pin(Finding::length(p), 1000, p + 7),
                pin(Finding::length(p), 1000, 3 * p + 7),
            ]
        };
        case(
            format!("fins/{}", side(p, 27)),
            &fins,
            met1(&[
                [0, 0, 1000, 7],
                [0, p, 1000, p + 7],
                [0, 2 * p, 1000, 2 * p + 7],
            ]),
            findings,
        );
    }
    for p in sweep(depth, 54).into_iter().filter(|&p| p > 20) {
        let findings = if p == 54 {
            Vec::new()
        } else {
            vec![
                pin(Finding::length(p), p + 20, 1000),
                pin(Finding::length(p), 3 * p + 20, 1000),
            ]
        };
        case(
            format!("gates/{}", side(p, 54)),
            &gates,
            met1(&[
                [0, 0, 20, 1000],
                [p, 0, p + 20, 1000],
                [2 * p, 0, 2 * p + 20, 1000],
            ]),
            findings,
        );
    }
    case(
        "missing_fin".into(),
        &fins,
        met1(&[[0, 0, 1000, 7], [0, 27, 1000, 34], [0, 81, 1000, 88]]),
        vec![pin(Finding::length(54), 1000, 115)],
    );
    case(
        "no_overlap_across".into(),
        &fins,
        met1(&[[0, 0, 1000, 7], [2000, 30, 3000, 37]]),
        Vec::new(),
    );
    let mut out = every_axis_placement(&cases);
    out.push(
        Fixture::new("exact_pitch/bent_is_refused", &["DRC-035"], &fins, DRC)
            .layout(Layout::default().polygon(
                "met1",
                &[(0, 0), (1000, 0), (1000, 7), (7, 7), (7, 500), (0, 500)],
            ))
            .expect(Expect::outcome("p", Want::Refused)),
    );
    out.push(vacuous(
        "exact_pitch",
        &["DRC-035"],
        "rule p pitch(met1, vertical) == 27nm",
        &["p"],
    ));
    out
}

// ---------------------------------------------------------------- span_length

/// LEF/DEF 5.8's span tables for its vertical METAL2 (`SPANLENGTHTABLE 0.06
/// 0.08 0.12 0.16 0.20 ;` and `SPANLENGTHTABLE 0.12 0.16 0.20 WRONGDIRECTION
/// ;`): horizontal spans, a vertical wire's width, on the first; vertical
/// spans, parallel to the layer's direction, on the wrong-direction one.
const SPANS: &str =
    "rule s span_length(met1; x: [60nm, 80nm, 120nm, 160nm, 200nm], y: [120nm, 160nm, 200nm])";

/// `span_length` (`span_length`, DRC-036): every chord a horizontal or
/// vertical line cuts from a merged figure is one of its axis's lengths, or
/// at least the last; one finding per maximal region of an unchanged illegal
/// chord, at its centre, measuring the chord.
///
/// LEF's own lists, each value and one step either side (SE): a vertical
/// wire's width on `x`, a horizontal piece's height on `y` (the longer
/// chords, 1000, are legal). A U with a stepped arm: the left arm's 100 is
/// one region however many vertices the right arm adds beside it, and the
/// base's 100 one region across the step. A ring's band, four regions. A
/// 200 long piece drawn as two 100 long halves is one legal span.
fn span_length(_depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(SPANS);
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("span_length/{shape}"),
            &["DRC-036"],
            &deck,
            layout,
            vec![("s", findings)],
        ));
    };
    let around =
        |values: &[i64]| -> Vec<i64> { values.iter().flat_map(|&v| [v - 1, v, v + 1]).collect() };
    for w in around(&[60, 80, 120, 160, 200]) {
        let legal = [60, 80, 120, 160].contains(&w) || w >= 200;
        let findings = if legal {
            Vec::new()
        } else {
            vec![pin(Finding::length(w), w, 1000)]
        };
        case(format!("x/w{w}"), met1(&[[0, 0, w, 1000]]), findings);
    }
    for h in around(&[120, 160, 200]) {
        let legal = [120, 160].contains(&h) || h >= 200;
        let findings = if legal {
            Vec::new()
        } else {
            vec![pin(Finding::length(h), 1000, h)]
        };
        case(format!("y/h{h}"), met1(&[[0, 0, 1000, h]]), findings);
    }
    case(
        "stepped_u".into(),
        met1(&[
            [0, 0, 1000, 100],
            [0, 0, 100, 1000],
            [900, 0, 1000, 500],
            [850, 500, 1000, 1000],
        ]),
        vec![
            pin(Finding::length(100), 100, 1100),
            pin(Finding::length(100), 1900, 600),
            pin(Finding::length(150), 1850, 1500),
            pin(Finding::length(100), 1000, 100),
        ],
    );
    case(
        "ring".into(),
        Layout::default().polygon("met1", &holed([0, 0, 1000, 1000], [100, 100, 900, 900])),
        vec![
            pin(Finding::length(100), 100, 1000),
            pin(Finding::length(100), 1900, 1000),
            pin(Finding::length(100), 1000, 100),
            pin(Finding::length(100), 1000, 1900),
        ],
    );
    case(
        "drawn_in_halves".into(),
        met1(&[[0, 0, 100, 120], [100, 0, 200, 120]]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous("span_length", &["DRC-036"], SPANS, &["s"]));
    out
}

// ------------------------------------------------------- min_area, hole_area

/// `area(met1) >= 10000nm2` (`min_area`, DRC-017): one finding per merged
/// figure smaller than the limit, measuring its area without its holes. At the
/// limit is legal; the marker is "one of its rectangles", so not pinned.
///
/// A 100-wide rectangle whose height is swept around 100; the same drawn as
/// two 50-wide halves (merged first); a square with a 1 nm bite (9999) or
/// bump (10001); a holed square whose filled area would pass.
fn min_area(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck("rule a area(met1) >= 10000nm2");
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings| {
        cases.push(fixture(
            &format!("min_area/{shape}"),
            &["DRC-017"],
            &deck,
            layout,
            vec![("a", findings)],
        ));
    };
    for h in sweep(depth, 100) {
        let findings = if h < 100 {
            vec![Finding::area(i128::from(100 * h))]
        } else {
            Vec::new()
        };
        let tag = side(h, 100);
        case(
            format!("rect/{tag}"),
            met1(&[[0, 0, 100, h]]),
            findings.clone(),
        );
        case(
            format!("halves/{tag}"),
            met1(&[[0, 0, 50, h], [50, 0, 100, h]]),
            findings,
        );
    }
    case(
        "bite".into(),
        Layout::default().polygon(
            "met1",
            &[(0, 0), (100, 0), (100, 99), (99, 99), (99, 100), (0, 100)],
        ),
        vec![Finding::area(9999)],
    );
    case(
        "bump".into(),
        Layout::default().polygon(
            "met1",
            &[(0, 0), (100, 0), (100, 100), (1, 100), (1, 101), (0, 101)],
        ),
        Vec::new(),
    );
    case(
        "holed".into(),
        Layout::default().polygon("met1", &holed([0, 0, 120, 120], [20, 20, 100, 100])),
        vec![Finding::area(8000)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "min_area",
        &["DRC-017"],
        "rule a area(met1) >= 10000nm2",
        &["a"],
    ));
    out
}

/// `hole_area(met1) >= 10000nm2` (`min_enclosed_area`, DRC-019): one finding
/// per hole of the merged layer smaller than the limit, measuring its area, at
/// the centre of its box. At the limit is legal.
///
/// A plate with a 100-high hole whose width is swept around 100, drawn as one
/// holed polygon and as four touching bands (a hole only the union has); two
/// holes in one figure; the gap between two bars (not a hole).
fn min_enclosed_area(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck("rule h hole_area(met1) >= 10000nm2");
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings| {
        cases.push(fixture(
            &format!("min_enclosed_area/{shape}"),
            &["DRC-019"],
            &deck,
            layout,
            vec![("h", findings)],
        ));
    };
    for hx in sweep(depth, 100) {
        let findings = if hx < 100 {
            vec![pin(Finding::area(i128::from(100 * hx)), 800 + hx, 900)]
        } else {
            Vec::new()
        };
        let tag = side(hx, 100);
        case(
            format!("holed/{tag}"),
            Layout::default().polygon(
                "met1",
                &holed([0, 0, 1000, 1000], [400, 400, 400 + hx, 500]),
            ),
            findings.clone(),
        );
        case(
            format!("bands/{tag}"),
            met1(&[
                [0, 0, 1000, 400],
                [0, 500, 1000, 1000],
                [0, 400, 400, 500],
                [400 + hx, 400, 1000, 500],
            ]),
            findings,
        );
    }
    case(
        "two_holes".into(),
        met1(&[
            [0, 0, 2000, 400],
            [0, 500, 2000, 1000],
            [0, 400, 400, 500],
            [480, 400, 1200, 500],
            [1290, 400, 2000, 500],
        ]),
        vec![
            Finding::area(8000).at(440, 450),
            Finding::area(9000).at(1245, 450),
        ],
    );
    case(
        "gap_between_bars".into(),
        met1(&[[0, 0, 500, 2000], [599, 0, 1100, 2000]]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "min_enclosed_area",
        &["DRC-019"],
        "rule h hole_area(met1) >= 10000nm2",
        &["h"],
    ));
    out
}

// ------------------------------------------------------------------ off_grid

/// `off_grid(; pitch: 10nm)` (`off_grid`, DRC-001): one finding per vertex of
/// any row on any drawn layer off the 10 nm lattice, at the vertex, measuring
/// its Chebyshev distance to the nearest lattice point.
///
/// The lattice is fixed to the origin, so the translations here are whole
/// multiples of the pitch; every symmetry of the square maps it to itself. A
/// rectangle shifted by `k` on x (every vertex off by `min(k, 10 − k)`); one
/// off on both axes (the larger offset); one off at two vertices only; a hole
/// with two vertices off; a shape on another layer; an empty layout. And a
/// deck deriving `met1.sized(5nm)` and a copy `met1 not met2` (F50): derived
/// layers are not checked, so on-grid met1 is clean though its halo is 5 off,
/// and off-grid met1 is reported once, not again on the copy.
fn off_grid(depth: Depth) -> Vec<Fixture> {
    const OFFSETS_ON_GRID: [(i64, i64); 2] = [(0, 0), (-1_234_560, 987_650)];
    let deck = "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
                rule g off_grid(; pitch: 10nm)\n";
    let shifts: Vec<i64> = match depth {
        Depth::Merge => vec![0, 1, 4, 5, 6, 9],
        Depth::Nightly => (0..=10).collect(),
    };
    let vertices = |[xlo, ylo, xhi, yhi]: [i64; 4], off: i64| -> Vec<Finding> {
        [(xlo, ylo), (xhi, ylo), (xhi, yhi), (xlo, yhi)]
            .into_iter()
            .map(|(x, y)| Finding::length(off).at(x, y))
            .collect()
    };
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, findings| {
        cases.push(fixture(
            &format!("off_grid/{shape}"),
            &["DRC-001"],
            deck,
            layout,
            vec![("g", findings)],
        ));
    };
    for k in shifts {
        let off = k.min(10 - k);
        let rect = [k, 0, 100 + k, 100];
        let findings = if off == 0 {
            Vec::new()
        } else {
            vertices(rect, off)
        };
        case(format!("shifted/k{k}"), met1(&[rect]), findings);
    }
    case(
        "both_axes".into(),
        met1(&[[2, 6, 102, 206]]),
        vertices([2, 6, 102, 206], 4),
    );
    case(
        "two_vertices".into(),
        met1(&[[0, 0, 105, 100]]),
        vec![
            Finding::length(5).at(105, 0),
            Finding::length(5).at(105, 100),
        ],
    );
    case(
        "hole".into(),
        Layout::default().polygon("met1", &holed([0, 0, 1000, 1000], [500, 503, 700, 700])),
        vec![
            Finding::length(3).at(500, 503),
            Finding::length(3).at(700, 503),
        ],
    );
    case(
        "other_layer".into(),
        rects(Layout::default(), "met2", &[[3, 0, 103, 100]]),
        vertices([3, 0, 103, 100], 3),
    );
    let derived_deck = "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
                        layer halo = met1.sized(5nm)\nlayer copy = met1 not met2\n\
                        rule g off_grid(; pitch: 10nm)\n";
    for (shape, rect, findings) in [
        ("on_grid", [0, 0, 100, 100], Vec::new()),
        ("off_grid", [3, 0, 103, 100], vertices([3, 0, 103, 100], 3)),
    ] {
        cases.push(fixture(
            &format!("off_grid/derived/{shape}"),
            &["DRC-001"],
            derived_deck,
            met1(&[rect]),
            vec![("g", findings)],
        ));
    }
    let mut out = every_placement_at(cases, &OFFSETS_ON_GRID);
    out.push(fixture(
        "off_grid/empty_layout",
        &["DRC-001"],
        deck,
        Layout::default(),
        vec![("g", Vec::new())],
    ));
    out
}

// ------------------------------------------------------------------ angle

/// `angle` (DRC-002, DRC-003, DRC-037): one finding per edge not along an
/// allowed line, at its first vertex, measuring `Count(0)`.
///
/// Three rules whose allowed sets every symmetry of the square maps to
/// themselves, so the transforms keep the expectation: `[0, 90]` on `met1`,
/// all four lines on every layer, and `[45, 135]` on every layer. A rectangle
/// (every vertex starts one flagged edge under `[45, 135]`, so the markers
/// are its vertices in any order), the same on `met2`, and a right triangle
/// whose hypotenuse is at 45 or 135 degrees. The rustdoc's Limits say a
/// non-rectilinear layout is refused at load; its body says the rule checks
/// the lines, and with no rule validating the layer nothing refuses it. A
/// deck deriving `met1.sized(5nm)` and a copy `met1 not met2` (F63): with no
/// layer only drawn layers are checked, so the rectangle's corners are
/// reported once, not again on the copy and the halo.
fn angle(_depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
                rule a angle(met1; allowed: [0deg, 90deg])\n\
                rule all angle(; allowed: [0deg, 45deg, 90deg, 135deg])\n\
                rule d angle(; allowed: [45deg, 135deg])\n";
    let corners = || {
        vec![
            count(0).at(0, 0),
            count(0).at(1000, 0),
            count(0).at(1000, 500),
            count(0).at(0, 500),
        ]
    };
    let cases = vec![
        fixture(
            "angle/rect",
            &["DRC-002"],
            deck,
            met1(&[[0, 0, 1000, 500]]),
            vec![("a", Vec::new()), ("all", Vec::new()), ("d", corners())],
        ),
        fixture(
            "angle/rect_other_layer",
            &["DRC-002"],
            deck,
            rects(Layout::default(), "met2", &[[0, 0, 1000, 500]]),
            vec![("a", Vec::new()), ("all", Vec::new()), ("d", corners())],
        ),
        fixture(
            "angle/triangle",
            &["DRC-002", "DRC-003", "DRC-037"],
            deck,
            Layout::default().polygon("met1", &[(0, 0), (1000, 0), (0, 1000)]),
            vec![
                ("a", vec![count(0)]),
                ("all", Vec::new()),
                ("d", vec![count(0), count(0)]),
            ],
        ),
        fixture(
            "angle/derived",
            &["DRC-002"],
            "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
             layer halo = met1.sized(5nm)\nlayer copy = met1 not met2\n\
             rule d angle(; allowed: [45deg, 135deg])\n",
            met1(&[[0, 0, 1000, 500]]),
            vec![("d", corners())],
        ),
    ];
    let mut out = every_placement(cases);
    out.push(fixture(
        "angle/empty_layout",
        &["DRC-002"],
        deck,
        Layout::default(),
        vec![("a", Vec::new()), ("all", Vec::new()), ("d", Vec::new())],
    ));
    out
}

/// `interior_angle` (`min_interior_angle`, DRC-003: IHP 3.1 "shapes with
/// acute angles <87 degree are not allowed on any layer", GF180 SH.2 "angles
/// <90 deg"): one finding per drawn corner whose angle inside its shape is
/// under the limit, at the vertex, measuring the angle.
///
/// Oracle: angles fixed by construction. A rectangle (90 at a limit of 90:
/// legal), an L (its inner corner 270), a ring (its hole's corners 270 on the
/// shape's side, 90 inside the hole: a check that reads a hole's own inside
/// flags nothing either way, but one that takes the smaller angle of a
/// corner flags an L's inner corner), an octagon (135); a right isosceles
/// triangle (two 45-degree corners, exactly 45 once rounded) under both
/// limits; a 30-60-90 triangle whose two acute corners are under both; and
/// the triangle on another layer, which only the every-layer rule reads.
fn interior_angle(_depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
                rule r interior_angle(met1) >= 90deg\n\
                rule ihp interior_angle() >= 87deg\n";
    let triangle = [(0, 0), (1000, 0), (0, 1000)];
    let acute = || vec![ratio(45.0).at(1000, 0), ratio(45.0).at(0, 1000)];
    let both = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("interior_angle/{name}"),
            &["DRC-003"],
            deck,
            layout,
            vec![("r", findings.clone()), ("ihp", findings)],
        )
    };
    let cases = vec![
        both("rectangle", met1(&[[0, 0, 1000, 500]]), Vec::new()),
        both(
            "l_shape",
            met1(&[[0, 0, 1000, 100], [0, 100, 100, 1000]]),
            Vec::new(),
        ),
        both(
            "ring",
            Layout::default().polygon("met1", &holed([0, 0, 1000, 1000], [300, 300, 700, 700])),
            Vec::new(),
        ),
        both(
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
            Vec::new(),
        ),
        both(
            "right_triangle",
            Layout::default().polygon("met1", &triangle),
            acute(),
        ),
        both(
            "thirty_sixty",
            Layout::default().polygon("met1", &[(0, 0), (1732, 0), (0, 1000)]),
            vec![Finding::any().at(1732, 0), Finding::any().at(0, 1000)],
        ),
        fixture(
            "interior_angle/other_layer",
            &["DRC-003"],
            deck,
            Layout::default().polygon("met2", &triangle),
            vec![("r", Vec::new()), ("ihp", acute())],
        ),
    ];
    every_placement(cases)
}

/// `valid` (`polygon_validity`, DRC-004: IHP 3.1 "self-intersecting polygons
/// must be avoided"): one finding per drawn polygon that crosses itself or
/// encloses no area, where every other rule reading its layer records
/// `Refused`.
///
/// Oracle: polygons drawn with the defect by construction: a ring crossing
/// itself, a ring doubling back on itself (zero area), and beside them a
/// rectangle and a 45-degree triangle, both valid (a check that also refuses
/// diagonal edges flags the triangle). `valid(met1)` reads met1 only, and
/// `valid()` every drawn layer, so a crossing ring on met2 is the second's.
fn polygon_validity(_depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
                rule v valid(met1)\nrule all valid()\n";
    let crossing = [
        (0, 0),
        (2000, 0),
        (2000, 2000),
        (1000, 2000),
        (1000, -1000),
        (0, -1000),
    ];
    let case = |name: &str, layout: Layout, v: Vec<Finding>, all: Vec<Finding>| {
        fixture(
            &format!("polygon_validity/{name}"),
            &["DRC-004"],
            deck,
            layout.rect("met1", 5000, 5000, 6000, 6000),
            vec![("v", v), ("all", all)],
        )
    };
    every_placement(vec![
        case(
            "self_crossing",
            Layout::default().polygon("met1", &crossing),
            vec![count(0)],
            vec![count(0)],
        ),
        case(
            "zero_area",
            Layout::default().polygon("met1", &[(0, 0), (1000, 0), (500, 0)]),
            vec![count(0)],
            vec![count(0)],
        ),
        case(
            "valid_shapes",
            Layout::default()
                .rect("met1", 0, 0, 1000, 500)
                .polygon("met1", &[(2000, 0), (3000, 0), (2000, 1000)]),
            Vec::new(),
            Vec::new(),
        ),
        case(
            "other_layer",
            Layout::default().polygon("met2", &crossing),
            Vec::new(),
            vec![count(0)],
        ),
    ])
}

// ------------------------------------------------------------ forbidden

/// `forbidden` (DRC-006): every shape of the layer, as stored and not merged,
/// one finding each measuring its area without holes, at a vertex of its outer
/// ring (which one is not stated, so not pinned).
///
/// `forbidden(met2)`: two overlapping and two abutting rectangles (two each),
/// a holed square, nothing on `met2`. `forbidden(met1 and met2)`: an overlap,
/// shapes that only touch or meet at a corner (no shape), two overlapping
/// `met1` rectangles whose union meets `met2` (the derived layer is merged:
/// one shape). `forbidden(met1 not region)`: a shape straddling the region,
/// and shapes inside it or filling it exactly.
fn forbidden(_depth: Depth) -> Vec<Fixture> {
    let mut cases = Vec::new();
    let mut case = |name: &str, rule: &str, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("forbidden/{name}"),
            &["DRC-006"],
            &three_layer_deck(&format!("rule f forbidden({rule})")),
            layout,
            vec![("f", findings)],
        ));
    };
    let on = |layer: &str, boxes: &[[i64; 4]]| rects(Layout::default(), layer, boxes);
    let both = |a: &[[i64; 4]], b: &[[i64; 4]]| rects(on("met1", a), "met2", b);
    case(
        "overlapping_drawn",
        "met2",
        on("met2", &[[0, 0, 100, 100], [50, 0, 150, 100]]),
        vec![Finding::area(10_000), Finding::area(10_000)],
    );
    case(
        "abutting_drawn",
        "met2",
        on("met2", &[[0, 0, 100, 100], [100, 0, 200, 100]]),
        vec![Finding::area(10_000), Finding::area(10_000)],
    );
    case(
        "holed",
        "met2",
        Layout::default().polygon("met2", &holed([0, 0, 1000, 1000], [400, 400, 600, 600])),
        vec![Finding::area(960_000)],
    );
    case(
        "other_layer_only",
        "met2",
        on("met1", &[[0, 0, 100, 100]]),
        Vec::new(),
    );
    case(
        "and_overlap",
        "met1 and met2",
        both(&[[0, 0, 1000, 1000]], &[[500, 0, 1500, 1000]]),
        vec![Finding::area(500_000)],
    );
    case(
        "and_touching",
        "met1 and met2",
        both(&[[0, 0, 1000, 1000]], &[[1000, 0, 2000, 1000]]),
        Vec::new(),
    );
    case(
        "and_corner",
        "met1 and met2",
        both(&[[0, 0, 1000, 1000]], &[[1000, 1000, 2000, 2000]]),
        Vec::new(),
    );
    case(
        "and_merged_operand",
        "met1 and met2",
        both(
            &[[0, 0, 1000, 1000], [0, 500, 1000, 1500]],
            &[[500, 0, 1500, 1500]],
        ),
        vec![Finding::area(750_000)],
    );
    let region = |boxes: &[[i64; 4]]| rects(on("region", &[[0, 0, 1000, 1000]]), "met1", boxes);
    case(
        "outside_region",
        "met1 not region",
        region(&[[500, 0, 1500, 1000]]),
        vec![Finding::area(500_000)],
    );
    case(
        "inside_region",
        "met1 not region",
        region(&[[200, 200, 800, 800]]),
        Vec::new(),
    );
    case(
        "fills_region",
        "met1 not region",
        region(&[[0, 0, 1000, 1000]]),
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "forbidden",
        &["DRC-006"],
        "rule f forbidden(met1)",
        &["f"],
    ));
    out
}

/// A maximum area, `forbidden(met1.with_area(> 10000nm2))` (DRC-018), beside
/// one at 35000: `with_area` reads merged shapes without their holes, and
/// `forbidden` reports each with its area. At the limit is legal (`>`).
///
/// A 100-wide rectangle whose height is swept around 100; a square with a
/// 1 nm bite or bump; two halves that merge into 10100; a holed square of
/// 30000 whose filled area (40000) would break the 35000 rule.
fn max_area(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(
        "rule ma forbidden(met1.with_area(> 10000nm2))\n\
         rule mb forbidden(met1.with_area(> 35000nm2))",
    );
    let mut cases = Vec::new();
    let mut case = |shape: String, layout: Layout, ma: Vec<Finding>| {
        cases.push(fixture(
            &format!("max_area/{shape}"),
            &["DRC-018"],
            &deck,
            layout,
            vec![("ma", ma), ("mb", Vec::new())],
        ));
    };
    for h in sweep(depth, 100) {
        let findings = if h > 100 {
            vec![Finding::area(i128::from(100 * h))]
        } else {
            Vec::new()
        };
        case(
            format!("rect/{}", side(h, 100)),
            met1(&[[0, 0, 100, h]]),
            findings,
        );
    }
    case(
        "bite".into(),
        Layout::default().polygon(
            "met1",
            &[(0, 0), (100, 0), (100, 99), (99, 99), (99, 100), (0, 100)],
        ),
        Vec::new(),
    );
    case(
        "bump".into(),
        Layout::default().polygon(
            "met1",
            &[(0, 0), (100, 0), (100, 100), (1, 100), (1, 101), (0, 101)],
        ),
        vec![Finding::area(10_001)],
    );
    case(
        "halves".into(),
        met1(&[[0, 0, 50, 101], [50, 0, 100, 101]]),
        vec![Finding::area(10_100)],
    );
    case(
        "holed".into(),
        Layout::default().polygon("met1", &holed([0, 0, 200, 200], [50, 50, 150, 150])),
        vec![Finding::area(30_000)],
    );
    let mut out = every_placement(cases);
    out.push(vacuous(
        "max_area",
        &["DRC-018"],
        "rule ma forbidden(met1.with_area(> 10000nm2))",
        &["ma"],
    ));
    out
}

// ------------------------------------------------------------ aspect_ratio

/// A finding whose measured value is a ratio.
fn ratio(r: f64) -> Finding {
    Finding {
        measured: Some(Measurement::Ratio(r)),
        at: None,
    }
}

/// `aspect_ratio(met1) <= 3` (`aspect_ratio`, DRC-022: sky130 capm.6 "maximum
/// aspect ratio (length/width)", li.2 "max ratio of length to width"): one
/// finding per merged figure whose bounding box's longer side over its
/// shorter is above the limit, measuring that ratio, at the centre of the
/// figure's first rectangle.
///
/// Oracle: ratios fixed by construction, the limit swept one grid step either
/// side (a 100-wide bar 299, 300 and 301 long; and 249, 250, 251 under a
/// limit of 2.5, a ratio the deck writes as a decimal): at the limit is
/// legal. The 301 bar drawn as two abutting halves (each 1.5 alone: a check
/// that does not merge passes it); an L of two 400 x 100 arms (its box is
/// square: a check per drawn row or per rectangle flags each arm at 4); a
/// square joined at a corner to a 400 x 100 bar (one figure of box 500 x 200
/// under the corner model, 2.5; the bar alone would read 4); a 1000 x 200
/// ring (5, its hole changes nothing); an empty layer.
fn aspect_ratio(depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck("rule ar aspect_ratio(met1) <= 3");
    let mut cases = Vec::new();
    let mut case = |name: String, layout: Layout, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("aspect_ratio/{name}"),
            &["DRC-022"],
            &deck,
            layout,
            vec![("ar", findings)],
        ));
    };
    for l in sweep(depth, 300) {
        #[allow(clippy::cast_precision_loss, reason = "small integers")]
        let findings = if l > 300 {
            vec![pin(ratio(l as f64 / 100.0), 100, l)]
        } else {
            Vec::new()
        };
        case(
            format!("bar/{}", side(l, 300)),
            met1(&[[0, 0, 100, l]]),
            findings,
        );
    }
    case(
        "halves".into(),
        met1(&[[0, 0, 100, 150], [0, 150, 100, 301]]),
        vec![ratio(3.01)],
    );
    case(
        "l_of_two_long_arms".into(),
        met1(&[[0, 0, 400, 100], [0, 100, 100, 400]]),
        Vec::new(),
    );
    case(
        "bar_joined_at_a_corner".into(),
        met1(&[[0, 0, 100, 100], [100, 100, 500, 200]]),
        Vec::new(),
    );
    case(
        "ring".into(),
        Layout::default().polygon("met1", &holed([0, 0, 1000, 200], [100, 50, 900, 150])),
        vec![ratio(5.0)],
    );
    let decimal = one_layer_deck("rule ar aspect_ratio(met1) <= 2.5");
    for l in sweep(depth, 250) {
        #[allow(clippy::cast_precision_loss, reason = "small integers")]
        let findings = if l > 250 {
            vec![pin(ratio(l as f64 / 100.0), 100, l)]
        } else {
            Vec::new()
        };
        cases.push(fixture(
            &format!("aspect_ratio/decimal/{}", side(l, 250)),
            &["DRC-022"],
            &decimal,
            met1(&[[0, 0, 100, l]]),
            vec![("ar", findings)],
        ));
    }
    let mut out = every_placement(cases);
    out.push(vacuous(
        "aspect_ratio",
        &["DRC-022"],
        "rule ar aspect_ratio(met1) <= 3",
        &["ar"],
    ));
    out
}

// ------------------------------------------------------- edge width, facing

/// A transistor's channel length and width (`edge_width`, DRC-011: sky130
/// poly.1b "min channel length (poly width)", difftap.2 "minimum channel width
/// (diff and poly)", IHP Gat.a1 to a4, GF180 PL.2): `width(gate.edges() not
/// diff.edges()) >= 150nm` measures the gap between the gate's sides inside
/// the diffusion, `width(gate.edges() and diff.edges()) >= 420nm` the gap
/// between its sides on the diffusion's edge; one finding per pair, at the
/// middle of the gap, measuring it.
///
/// Oracle: channels drawn to a length and a width, each swept one step either
/// side of its limit with the other legal. A gate 300 long and 200 wide: its
/// length passes and its width fails, where a plain `width(gate)` would read
/// 200 for both. Two fingers on one diffusion: the sides facing across the
/// shared source are face to face and not a width, and the outer sides, 450
/// apart, are no finding at 150; at a length of 149 each finger is one
/// finding. An empty layout.
fn channel(depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm\nlayer diff = gds(65, 20)\nlayer poly = gds(66, 20)\n\
                layer gate = poly and diff\n\
                layer lsides = gate.edges() not diff.edges()\n\
                layer wsides = gate.edges() and diff.edges()\n\
                rule l width(lsides) >= 150nm\nrule w width(wsides) >= 420nm\n";
    let fet = |w: i64, polys: &[[i64; 4]]| {
        rects(
            rects(Layout::default(), "diff", &[[0, 0, 1000, w]]),
            "poly",
            polys,
        )
    };
    let mut cases = Vec::new();
    let mut case = |name: String, layout: Layout, l: Vec<Finding>, w: Vec<Finding>| {
        cases.push(fixture(
            &format!("channel/{name}"),
            &["DRC-011"],
            deck,
            layout,
            vec![("l", l), ("w", w)],
        ));
    };
    for l in sweep(depth, 150) {
        let findings = if l < 150 {
            vec![pin(Finding::length(l), 900 + l, 1000)]
        } else {
            Vec::new()
        };
        case(
            format!("length/{}", side(l, 150)),
            fet(1000, &[[450, -200, 450 + l, 1200]]),
            findings,
            Vec::new(),
        );
    }
    for w in sweep(depth, 420) {
        let findings = if w < 420 {
            vec![pin(Finding::length(w), 1050, w)]
        } else {
            Vec::new()
        };
        case(
            format!("width/{}", side(w, 420)),
            fet(w, &[[450, -200, 600, w + 200]]),
            Vec::new(),
            findings,
        );
    }
    case(
        "long_and_narrow".into(),
        fet(200, &[[450, -200, 750, 400]]),
        Vec::new(),
        vec![Finding::length(200).at(600, 100)],
    );
    case(
        "two_fingers".into(),
        fet(1000, &[[300, -200, 450, 1200], [600, -200, 750, 1200]]),
        Vec::new(),
        Vec::new(),
    );
    case(
        "two_short_fingers".into(),
        fet(1000, &[[300, -200, 449, 1200], [600, -200, 749, 1200]]),
        vec![Finding::length(149), Finding::length(149)],
        Vec::new(),
    );
    let mut out = every_placement(cases);
    out.push(fixture(
        "channel/empty",
        &["DRC-011"],
        deck,
        rects(Layout::default(), "diff", &[[0, 0, 1000, 1000]]),
        vec![("l", Vec::new()), ("w", Vec::new())],
    ));
    out
}

/// Width and spacing in one direction (DRC-016: ASAP7 M4.W.1 "minimum
/// vertical width of M4" 24, M4.W.5 "minimum horizontal width" 44, M4.S.1
/// "minimum vertical spacing" 24, M4.S.2 "minimum horizontal spacing" 40):
/// `width` (`edge_width`) and `facing_space` (`edge_facing_space`) on
/// `met4.edges().horizontal()` (a vertical measure) and `.vertical()`.
///
/// Oracle: wires drawn to a width or gap, each swept one step either side of
/// its limit: a horizontal wire's thickness is a vertical width, two
/// horizontal wires' gap a vertical spacing, and the same transposed. One gap
/// of 30 between two horizontal wires passes (24) where the same gap between
/// two vertical wires fails (40): a direction-blind spacing reads both alike.
/// A U whose arms are 30 apart is a horizontal notch, which `facing_space`
/// measures as `KLayout`'s `space` does, while each arm's 50 is a width and
/// not a spacing. A quarter turn swaps the axes, so the turned placements
/// swap `horizontal()` and `vertical()` in the deck and keep the expectation.
fn directional(depth: Depth) -> Vec<Fixture> {
    let deck = |turned: bool| {
        let (h, v) = if turned {
            ("vertical", "horizontal")
        } else {
            ("horizontal", "vertical")
        };
        format!(
            "grid 1nm\nlayer met4 = gds(71, 20)\nlayer h = met4.edges().{h}()\n\
             layer v = met4.edges().{v}()\nrule w1 width(h) >= 24nm\n\
             rule w5 width(v) >= 44nm\nrule s1 facing_space(h) >= 24nm\n\
             rule s2 facing_space(v) >= 40nm\n"
        )
    };
    let flat = deck(false);
    let met4 = |boxes: &[[i64; 4]]| rects(Layout::default(), "met4", boxes);
    let mut cases = Vec::new();
    let mut case = |name: String, layout: Layout, rows: [Vec<Finding>; 4]| {
        let [w1, w5, s1, s2] = rows;
        cases.push(fixture(
            &format!("directional/{name}"),
            &["DRC-016"],
            &flat,
            layout,
            vec![("w1", w1), ("w5", w5), ("s1", s1), ("s2", s2)],
        ));
    };
    let below = |v: i64, limit: i64, x2: i64, y2: i64| {
        if v < limit {
            vec![pin(Finding::length(v), x2, y2)]
        } else {
            Vec::new()
        }
    };
    for t in sweep(depth, 24).into_iter().filter(|&v| v > 0) {
        case(
            format!("vertical_width/{}", side(t, 24)),
            met4(&[[0, 0, 1000, t]]),
            [below(t, 24, 1000, t), vec![], vec![], vec![]],
        );
    }
    for t in sweep(depth, 44).into_iter().filter(|&v| v > 0) {
        case(
            format!("horizontal_width/{}", side(t, 44)),
            met4(&[[0, 0, t, 1000]]),
            [vec![], below(t, 44, t, 1000), vec![], vec![]],
        );
    }
    for g in sweep(depth, 24).into_iter().filter(|&v| v > 0) {
        case(
            format!("vertical_space/{}", side(g, 24)),
            met4(&[[0, 0, 1000, 50], [0, 50 + g, 1000, 100 + g]]),
            [vec![], vec![], below(g, 24, 1000, 100 + g), vec![]],
        );
    }
    for g in sweep(depth, 40).into_iter().filter(|&v| v > 0) {
        case(
            format!("horizontal_space/{}", side(g, 40)),
            met4(&[[0, 0, 50, 1000], [50 + g, 0, 100 + g, 1000]]),
            [vec![], vec![], vec![], below(g, 40, 100 + g, 1000)],
        );
    }
    case(
        "same_gap_two_directions".into(),
        met4(&[
            [0, 0, 1000, 50],
            [0, 80, 1000, 130],
            [2000, 0, 2050, 1000],
            [2080, 0, 2130, 1000],
        ]),
        [
            vec![],
            vec![],
            vec![],
            vec![Finding::length(30).at(2065, 500)],
        ],
    );
    case(
        "notch".into(),
        Layout::default().polygon(
            "met4",
            &[
                (0, 0),
                (130, 0),
                (130, 500),
                (80, 500),
                (80, 50),
                (50, 50),
                (50, 500),
                (0, 500),
            ],
        ),
        [
            vec![],
            vec![],
            vec![],
            vec![Finding::length(30).at(65, 275)],
        ],
    );
    let turned = deck(true);
    cases
        .iter()
        .flat_map(|fixture| {
            OFFSETS.iter().flat_map(move |&(dx, dy)| {
                Symmetry::ALL
                    .iter()
                    .map(move |&symmetry| (fixture, symmetry, dx, dy))
            })
        })
        .map(|(fixture, symmetry, dx, dy)| {
            let mut placed = fixture.transformed(symmetry, dx, dy);
            if symmetry.turns % 2 == 1 {
                placed.deck.clone_from(&turned);
            }
            placed
        })
        .collect()
}

// ------------------------------------------------------------ integrity

/// Layer validity (DRC-004, DRC-002): a rule that reads a layer holding a
/// self-crossing, zero-area or non-rectilinear ring records `Refused`, and
/// the run does not pass. `off_grid` and `angle` read raw rows and never
/// refuse: they run, and `angle` flags the diagonal.
fn validity(_depth: Depth) -> Vec<Fixture> {
    let deck = one_layer_deck(
        "rule w width(met1) >= 100nm\nrule f forbidden(met1)\n\
         rule g off_grid(; pitch: 1nm)\nrule an angle(met1; allowed: [0deg, 90deg])",
    );
    let refused = |name: &str, catalog: &[&'static str], points: &[(i64, i64)], angles| {
        Fixture::new(&format!("validity/{name}"), catalog, &deck, DRC)
            .layout(
                Layout::default()
                    .rect("met1", 5000, 5000, 6000, 6000)
                    .polygon("met1", points),
            )
            .expect(Expect::outcome("w", Want::Refused))
            .expect(Expect::outcome("f", Want::Refused))
            .expect(Expect::clean("g"))
            .expect(Expect::rule("an", angles))
            .expect(Expect::Passes(false))
    };
    every_placement(vec![
        refused(
            "self_crossing",
            &["DRC-004"],
            &[
                (0, 0),
                (2000, 0),
                (2000, 2000),
                (1000, 2000),
                (1000, -1000),
                (0, -1000),
            ],
            Vec::new(),
        ),
        refused(
            "zero_area",
            &["DRC-004"],
            &[(0, 0), (1000, 0), (500, 0)],
            Vec::new(),
        ),
        refused(
            "diagonal",
            &["DRC-002", "DRC-004"],
            &[(0, 0), (1000, 0), (0, 1000)],
            vec![count(0)],
        ),
    ])
}

/// Pins and labels (DRC-007): `inside(met1_pin, met1)` reports the area of a
/// pin left outside its metal (touching the edge from inside is inside), and a
/// label over no net aborts extraction, so the run does not pass.
fn pins(_depth: Depth) -> Vec<Fixture> {
    let deck = "grid 1nm
layer met1 = gds(68, 20)
layer met1_pin = gds(68, 16)
layer met1_label = gds(68, 5)
connect conductors [met1]
connect touch_within_layer
connect label met1_label names met1
rule pin inside(met1_pin, met1)
";
    let drawn = |pin: [i64; 4]| rects(met1(&[[0, 0, 1000, 1000]]), "met1_pin", &[pin]);
    let mut out = every_placement(vec![
        fixture(
            "pins/inside",
            &["DRC-007"],
            deck,
            drawn([400, 400, 600, 600]).label("met1_label", 500, 500, "A"),
            vec![("pin", Vec::new())],
        ),
        fixture(
            "pins/touching_from_inside",
            &["DRC-007"],
            deck,
            drawn([800, 400, 1000, 600]),
            vec![("pin", Vec::new())],
        ),
        fixture(
            "pins/straddling",
            &["DRC-007"],
            deck,
            drawn([900, 400, 1100, 600]),
            vec![("pin", vec![Finding::area(20_000)])],
        ),
    ]);
    out.push(
        Fixture::new("pins/label_on_no_net", &["DRC-007"], deck, DRC)
            .layout(drawn([400, 400, 600, 600]).label("met1_label", 5000, 5000, "A"))
            .expect(Expect::Passes(false)),
    );
    out
}
