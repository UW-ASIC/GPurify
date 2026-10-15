//! `patterning` (plain and anchored) and `pattern` from deck text, under the
//! eight symmetries of the square. The cases are the root suite's exhaustive
//! fixtures (`tests/exhaustive/drc_overlay.rs`) at the crate level, with the
//! same oracles.

use crate::common::deck::{by_rule, check_everywhere, new_deck, ring, run, Finding, Layout};
use gpurify_check::report::Outcome;

/// A cycle of `n >= 4` bars around a 4000 square frame, each `gap` from the
/// next and far from every other: the bottom side split into `(n - 1) / 2`
/// bars, the top into the rest, and one bar up each side.
fn bar_cycle(n: i64, gap: i64) -> Layout {
    const S: i64 = 4000;
    const T: i64 = 100;
    let bottom = (n - 1) / 2;
    let top = n - 2 - bottom;
    let pieces = |to: i64, k: i64| -> Vec<(i64, i64)> {
        let len = (to - (k - 1) * gap) / k;
        (0..k)
            .map(|i| {
                let lo = i * (len + gap);
                (lo, if i == k - 1 { to } else { lo + len })
            })
            .collect()
    };
    let mut out = Layout::default().rect("met1", S - T, T + gap, S, S).rect(
        "met1",
        0,
        T + gap,
        T,
        S - T - gap,
    );
    for (lo, hi) in pieces(S, bottom) {
        out = out.rect("met1", lo, 0, hi, T);
    }
    for (lo, hi) in pieces(S - T - gap, top) {
        out = out.rect("met1", lo, S - T, hi, S);
    }
    out
}

const MP: &str = "rule mp1 patterning(met1; colors: 1) >= 100nm\n\
                  rule mp2 patterning(met1; colors: 2) >= 100nm\n\
                  rule mp3 patterning(met1; colors: 3) >= 100nm";

/// `chromatic` masks needed: each row of k masks finds one count of k + 1
/// when more are needed.
fn needs(name: &str, layout: &Layout, chromatic: u32) {
    let want: Vec<(&str, Finding)> = [("mp1", 1), ("mp2", 2), ("mp3", 3)]
        .into_iter()
        .filter(|&(_, k)| chromatic > k)
        .map(|(id, k)| (id, Finding::count(k + 1)))
        .collect();
    check_everywhere(
        name,
        &new_deck(&["met1", "other"], MP),
        layout,
        &by_rule(&["mp1", "mp2", "mp3"], &want),
    );
}

/// Oracle: each layout's chromatic number by construction, figures closer
/// than 100 conflicting, swept one unit either side of the limit: a
/// triangle of mutual gaps 99/100/101 needs 3 masks, or 1 when no gap
/// conflicts; a pair 2 or 1; a U whose arms are 99/100/101 apart, and a
/// ring whose slot hole is, conflict with themselves below 100 (Calibre's
/// self-conflict: no palette colours them) and need 1 at 100 and above.
#[test]
fn multi_patterning_counts_masks_either_side_of_the_colour_spacing() {
    for g in [99, 100, 101] {
        let conflicts = g < 100;
        needs(
            &format!("triangle/{g}"),
            &Layout::default()
                .rect("met1", 0, 0, 500, 500)
                .rect("met1", 500 + g, 0, 1000 + g, 500)
                .rect("met1", 0, 500 + g, 1000 + g, 1000 + g),
            if conflicts { 3 } else { 1 },
        );
        let notched = if conflicts { u32::MAX } else { 1 };
        needs(
            &format!("u_notch/{g}"),
            &Layout::default().polygon(
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
            notched,
        );
        needs(
            &format!("slot_hole/{g}"),
            &ring(
                Layout::default(),
                "met1",
                [0, 0, 2000, 2000],
                [900, 500, 900 + g, 1500],
            ),
            notched,
        );
        needs(
            &format!("pair/{g}"),
            &Layout::default()
                .rect("met1", 0, 0, 500, 500)
                .rect("met1", 500 + g, 0, 1000 + g, 500),
            if conflicts { 2 } else { 1 },
        );
    }
}

/// Oracle: chromatic numbers by construction: cycles of 4 to 7 bars need 2
/// masks when even and 3 when odd; a 2 x 2 block at 50 whose diagonals are
/// 70.7 apart is K4 (4); a triangle whose two lower shapes abut is two
/// figures (2); two squares touching only at a corner are one figure (1);
/// one shape (1); an island 50 inside a ring's hole is a real gap (2); a
/// shape drawn inside another 50 from its boundary is one figure (1), and
/// that pair beside a third 50 away needs 2. An empty layer is skipped.
#[test]
fn multi_patterning_counts_masks_of_known_graphs() {
    for n in 4..=7 {
        needs(
            &format!("cycle/{n}"),
            &bar_cycle(n, 50),
            if n % 2 == 0 { 2 } else { 3 },
        );
    }
    needs(
        "k4",
        &Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 550, 0, 1050, 500)
            .rect("met1", 0, 550, 500, 1050)
            .rect("met1", 550, 550, 1050, 1050),
        4,
    );
    needs(
        "merged_triangle",
        &Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 500, 0, 1000, 500)
            .rect("met1", 0, 550, 1000, 1050),
        2,
    );
    needs("single", &Layout::default().rect("met1", 0, 0, 500, 500), 1);
    let island = ring(
        Layout::default(),
        "met1",
        [0, 0, 2000, 2000],
        [500, 500, 1500, 1500],
    )
    .rect("met1", 550, 550, 1450, 1450);
    needs("island_in_hole", &island, 2);
    let inside = Layout::default()
        .rect("met1", 0, 0, 2000, 2000)
        .rect("met1", 50, 50, 1950, 1950);
    needs("drawn_inside", &inside, 1);
    needs(
        "corner_touch",
        &Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 500, 500, 1000, 1000),
        1,
    );
    let beside = inside.clone().rect("met1", 2050, 0, 2550, 2000);
    needs("drawn_inside_beside_one", &beside, 2);

    let rows = run(
        &new_deck(&["met1", "other"], MP),
        &Layout::default().rect("other", 0, 0, 100, 100),
    );
    for row in &rows {
        assert!(row.findings.is_empty(), "{row:?}");
        assert!(matches!(row.outcome, Outcome::Skipped(_)), "{row:?}");
    }
}

const AP: &str = "rule odd patterning(met1; colors: 2) >= 100nm\n\
                  rule ap patterning(met1, c1, c2; colors: 2) >= 100nm\n\
                  rule ap3 patterning(met1, c1, c2, c3; colors: 3) >= 100nm";

/// `n` bars 100 x 500, 150 apart in x (a 50 gap, a conflict), in a chain.
fn chain(n: i64) -> Layout {
    (0..n).fold(Layout::default(), |layout, i| {
        layout.rect("met1", 150 * i, 0, 150 * i + 100, 500)
    })
}

/// `layout` with `more`'s shapes added.
fn with(mut layout: Layout, more: Layout) -> Layout {
    layout.shapes.extend(more.shapes);
    layout
}

fn anchored(name: &str, layout: &Layout, want: &[(&str, Finding)]) {
    check_everywhere(
        name,
        &new_deck(&["met1", "c1", "c2", "c3"], AP),
        layout,
        &by_rule(&["odd", "ap", "ap3"], want),
    );
}

/// Oracle: US8473873B2's FIG. 1, 5 and 6 and the parity of a chain: four
/// bars (three conflicts, odd) anchored alike at both ends is an anchor
/// path, one finding of 3 masks against 2 at the middle of the gap between
/// the lowest anchored bar and the first of the wrong parity, (275, 250);
/// anchored apart it is honoured. Five bars (four conflicts, even) alike are
/// honoured, apart a path at (350, 250). Four unanchored bars, nothing. Any
/// overlap anchors (a 50 square on the end bar); an anchor that only
/// touches its bar does not.
#[test]
fn anchored_patterning_finds_anchor_paths_by_parity() {
    anchored(
        "chain4/alike",
        &chain(4)
            .rect("c1", 0, 0, 100, 500)
            .rect("c1", 450, 0, 550, 500),
        &[("ap", Finding::count(3).at(275, 250))],
    );
    anchored(
        "chain4/apart",
        &chain(4)
            .rect("c1", 0, 0, 100, 500)
            .rect("c2", 450, 0, 550, 500),
        &[],
    );
    anchored(
        "chain5/alike",
        &chain(5)
            .rect("c1", 0, 0, 100, 500)
            .rect("c1", 600, 0, 700, 500),
        &[],
    );
    anchored(
        "chain5/apart",
        &chain(5)
            .rect("c1", 0, 0, 100, 500)
            .rect("c2", 600, 0, 700, 500),
        &[("ap", Finding::count(3).at(350, 250))],
    );
    anchored("chain4/unanchored", &chain(4), &[]);
    anchored(
        "chain4/partial_anchor",
        &chain(4)
            .rect("c1", 0, 0, 50, 50)
            .rect("c1", 450, 0, 550, 500),
        &[("ap", Finding::count(3).at(275, 250))],
    );
    anchored(
        "chain4/touching_anchor",
        &chain(4)
            .rect("c1", -100, 0, 0, 500)
            .rect("c1", 450, 0, 550, 500),
        &[],
    );
}

/// Oracle: the same definition. One bar under both anchor layers conflicts
/// with its own anchors: 3 masks against 2 and 4 against 3, at its centre
/// (50, 250). A triangle has no 2-mask split (the plain row's 3); with two
/// corners anchored to mask 1 the 3-mask row finds the lowest anchored
/// figure's conflict, 4 against 3 at (250, 250); one anchor per mask is
/// honoured. An empty layer is skipped.
#[test]
fn anchored_patterning_self_conflicts_and_three_masks() {
    let triangle = || {
        Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 550, 0, 1050, 500)
            .rect("met1", 0, 550, 1050, 1050)
    };
    anchored(
        "self_conflict",
        &chain(1)
            .rect("c1", 0, 0, 100, 500)
            .rect("c2", 0, 0, 100, 500),
        &[
            ("ap", Finding::count(3).at(50, 250)),
            ("ap3", Finding::count(4).at(50, 250)),
        ],
    );
    anchored(
        "odd_cycle",
        &triangle().rect("c1", 0, 0, 500, 500),
        &[("odd", Finding::count(3))],
    );
    anchored(
        "triangle/alike",
        &triangle()
            .rect("c1", 0, 0, 500, 500)
            .rect("c1", 550, 0, 1050, 500),
        &[
            ("odd", Finding::count(3)),
            ("ap3", Finding::count(4).at(250, 250)),
        ],
    );
    anchored(
        "triangle/each",
        &triangle()
            .rect("c1", 0, 0, 500, 500)
            .rect("c2", 550, 0, 1050, 500)
            .rect("c3", 0, 550, 1050, 1050),
        &[("odd", Finding::count(3))],
    );
    let rows = run(
        &new_deck(&["met1", "c1", "c2", "c3"], AP),
        &Layout::default().rect("c1", 0, 0, 100, 100),
    );
    for row in &rows {
        assert!(row.findings.is_empty(), "{row:?}");
    }
    for row in rows.iter().filter(|r| r.id != "odd") {
        assert!(matches!(row.outcome, Outcome::Skipped(_)), "{row:?}");
    }
}

/// An L whose horizontal arm is `arm` tall and both arms `run` long, from
/// x = `x`.
fn ell(x: i64, arm: i64, run: i64) -> Layout {
    Layout::default()
        .rect("m", x, 0, x + run, arm)
        .rect("m", x, arm, x + 100, run)
}

/// Oracle: the pattern's definition, by construction. The pattern is an L
/// of two 100-wide arms in a 300 window (area 300 * 100 + 100 * 200 =
/// 50000), with and without a don't-care box over the window's upper right
/// quarter. An L with its arm 99, 100 or 101 tall matches only at 100; arms
/// 600 long still match inside the window (one placement); a small square
/// in the don't-care quarter matches only the row with the don't-care box;
/// one by the L's corner, outside it, matches neither; two Ls are two; a
/// solid square matches nothing. Each finding measures the pattern's area.
#[test]
fn pattern_matches_the_shapes_exactly_outside_the_dont_care_boxes() {
    const L: &str = "shapes: [0nm x 0nm, 300nm x 100nm, 0nm x 100nm, 100nm x 300nm]";
    let deck = new_deck(
        &["m"],
        &format!(
            "rule p pattern(m; window: 300nm x 300nm, {L}, ignore: none)\n\
             rule pd pattern(m; window: 300nm x 300nm, {L}, ignore: [150nm x 150nm, 300nm x 300nm])"
        ),
    );
    let case = |name: &str, layout: &Layout, (p, pd): (usize, usize)| {
        let want: Vec<(&str, Finding)> = std::iter::repeat_n(("p", Finding::area(50_000)), p)
            .chain(std::iter::repeat_n(("pd", Finding::area(50_000)), pd))
            .collect();
        check_everywhere(name, &deck, layout, &by_rule(&["p", "pd"], &want));
    };
    for arm in [99, 100, 101] {
        let n = usize::from(arm == 100);
        case(&format!("arm/{arm}"), &ell(0, arm, 300), (n, n));
    }
    case("long_arms", &ell(0, 100, 600), (1, 1));
    case(
        "square_in_the_dont_care",
        &ell(0, 100, 300).rect("m", 200, 200, 250, 250),
        (0, 1),
    );
    case(
        "square_by_the_corner",
        &ell(0, 100, 300).rect("m", 120, 120, 140, 140),
        (0, 0),
    );
    case("two", &with(ell(0, 100, 300), ell(2000, 100, 300)), (2, 2));
    case(
        "solid",
        &Layout::default().rect("m", 0, 0, 300, 300),
        (0, 0),
    );
}
