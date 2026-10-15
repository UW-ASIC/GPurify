//! The scored and matched kinds through deck text: `dfm_score` (the
//! design's score over a check's findings) and `pattern` (a window of
//! shapes matched in any orientation). Each case is the root
//! `tests/exhaustive/drc_overlay.rs` fixture of the same name, its oracle
//! restated on the test.

use crate::deck_fixture::{check_everywhere, new_deck, row, run, Finding, Layout};
use gpurify_check::report::Measurement;

/// DFM scoring (`dfm_score`, DRC-111, arXiv:1805.10016 with deck-supplied
/// values): required 100 nm, recommended 200 nm, failure rate 0.5,
/// sign-off 0.9, over `space(m)`, `width(m)` and `enclosure(v, m)`.
///
/// Oracle: the score by hand: a finding at `g` scores `(g - 100) / 100`
/// clamped to `[0, 1]`, the design `Π 1 - 0.5 (1 - score)`: gaps of 179,
/// 180, 181 (0.895 found; 0.9 and 0.905 pass), 200 (no finding of the
/// check), two gaps of 150 (0.75², 0.5625, though each alone passes 0.75),
/// a gap of 50 (below the required value: 0.5); a bar 150 wide (0.75); a via
/// enclosed by 150 (0.75). Every layout also holds a plate with a via 300
/// inside it far off, which each check reads and finds clean.
#[test]
fn dfm_score_multiplies_each_findings_survival() {
    let deck = new_deck(
        &["m", "v"],
        "rule ds dfm_score(m; check: space, required: 100nm, recommended: 200nm, rate: 0.5) >= 0.9\n\
         rule dw dfm_score(m; check: width, required: 100nm, recommended: 200nm, rate: 0.5) >= 0.9\n\
         rule de dfm_score(v, m; check: enclosure, required: 100nm, recommended: 200nm, rate: 0.5) >= 0.9\n",
    );
    let score = |gaps: &[i32]| -> Vec<Finding> {
        let design: f64 = gaps
            .iter()
            .map(|&g| 1.0 - 0.5 * (1.0 - (f64::from(g - 100) / 100.0).clamp(0.0, 1.0)))
            .product();
        if gaps.is_empty() || design >= 0.9 {
            vec![]
        } else {
            vec![Finding::ratio(design)]
        }
    };
    let case = |name: &str, layout: Layout, [ds, dw, de]: [Vec<Finding>; 3]| {
        check_everywhere(
            name,
            &deck,
            &layout
                .rect("m", 9000, 0, 10_000, 1000)
                .rect("v", 9300, 300, 9400, 400),
            &[("ds", ds), ("dw", dw), ("de", de)],
        );
    };
    let bars = |gaps: &[i32]| {
        let mut x = 0;
        let mut layout = Layout::default().rect("m", 0, 0, 1000, 1000);
        for &g in gaps {
            x += 1000 + i64::from(g);
            layout = layout.rect("m", x, 0, x + 1000, 1000);
        }
        layout
    };
    for gaps in [&[179][..], &[180], &[181], &[200], &[150, 150], &[50]] {
        case("space", bars(gaps), [score(gaps), vec![], vec![]]);
    }
    case(
        "width",
        Layout::default().rect("m", 0, 0, 150, 1000),
        [vec![], score(&[150]), vec![]],
    );
    case(
        "enclosure",
        Layout::default()
            .rect("m", 0, 0, 400, 400)
            .rect("v", 150, 150, 250, 250),
        [vec![], vec![], score(&[150])],
    );
}

/// Where a DFM score is reported and what it is held to.
///
/// Oracle: `Rule::DfmScore`'s rustdoc: one finding at the lowest-scoring
/// finding's marker, measuring the design's score against the sign-off.
/// Bars 150 apart then 120 apart: scores 0.5 and 0.2, survivals 0.75 and
/// 0.6, design 0.45, at the 120 gap's middle, (2180, 500), held to 0.9.
#[test]
fn dfm_score_reports_at_the_worst_finding() {
    let deck = new_deck(
        &["m"],
        "rule ds dfm_score(m; check: space, required: 100nm, recommended: 200nm, rate: 0.5) >= 0.9\n",
    );
    let rows = run(
        &deck,
        &Layout::default()
            .rect("m", 0, 0, 1000, 1000)
            .rect("m", 1150, 0, 2120, 1000)
            .rect("m", 2240, 0, 3240, 1000),
    );
    let found = &row(&rows, "ds").findings;
    assert_eq!(found.len(), 1, "{found:?}");
    let (measured, limit, at) = found[0];
    let Measurement::Ratio(design) = measured else {
        panic!("a ratio, not {measured:?}");
    };
    assert!((design - 0.75 * 0.6).abs() < 1e-12, "{design}");
    assert_eq!(limit, Measurement::Ratio(0.9));
    assert_eq!(at, (2180, 500));
}

/// Pattern matching (`pattern`, DRC-114): a 300 nm window holding an L of
/// 100-wide arms, `p` exact and `pd` with the window's upper-right `[150,
/// 300]²` don't-care; one finding per matching window, measuring the L's
/// 50000 nm².
///
/// Oracle: matches by construction from the definition (the layout inside
/// the window equals the pattern in any of the eight orientations,
/// don't-care regions matching anything): the L drawn exactly (both), with
/// arms running past the window (both), its arm 99, 100, 101 wide (only
/// 100), a square in the don't-care (only `pd`), one by the inner corner
/// (neither), two Ls apart (two each), a solid square (neither).
#[test]
fn pattern_matches_the_window_in_every_orientation() {
    const L: &str = "shapes: [0nm x 0nm, 300nm x 100nm, 0nm x 100nm, 100nm x 300nm]";
    let deck = new_deck(
        &["m"],
        &format!(
            "rule p pattern(m; window: 300nm x 300nm, {L}, ignore: none)\n\
             rule pd pattern(m; window: 300nm x 300nm, {L}, ignore: [150nm x 150nm, 300nm x 300nm])\n"
        ),
    );
    let ell = |layout: Layout, x: i64, arm: i64, run: i64| {
        layout
            .rect("m", x, 0, x + run, arm)
            .rect("m", x, arm, x + 100, run)
    };
    let case = |name: &str, layout: Layout, (p, pd): (usize, usize)| {
        let found = |n: usize| vec![Finding::area(50_000); n];
        check_everywhere(name, &deck, &layout, &[("p", found(p)), ("pd", found(pd))]);
    };
    for arm in [99, 100, 101] {
        let n = usize::from(arm == 100);
        case("arm", ell(Layout::default(), 0, arm, 300), (n, n));
    }
    case("long_arms", ell(Layout::default(), 0, 100, 600), (1, 1));
    case(
        "square_in_the_dont_care",
        ell(Layout::default(), 0, 100, 300).rect("m", 200, 200, 250, 250),
        (0, 1),
    );
    case(
        "square_by_the_corner",
        ell(Layout::default(), 0, 100, 300).rect("m", 120, 120, 140, 140),
        (0, 0),
    );
    case(
        "two",
        ell(ell(Layout::default(), 0, 100, 300), 2000, 100, 300),
        (2, 2),
    );
    case("solid", Layout::default().rect("m", 0, 0, 300, 300), (0, 0));
}
