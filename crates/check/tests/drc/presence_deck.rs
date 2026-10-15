//! `contains` (`must_contain`, DRC-048, DRC-049, DRC-085) from deck text on
//! rectilinear figures, under the eight symmetries of the square. The cases
//! are the root suite's exhaustive fixture (`tests/exhaustive/drc_overlay.rs`)
//! at the crate level, with the same oracle; each finding also states the
//! bound it broke.

use crate::common::deck::{check_everywhere, new_deck, Finding, Layout};
use gpurify_check::report::Measurement;

const TAP: &str = "rule one contains(tap, licon) >= 1\nrule two contains(tap, licon) >= 2\n\
                   rule most contains(tap, licon) <= 1\nrule exact contains(tap, licon) == 2";

/// `held` is what each tap figure holds; each rule's findings follow from
/// the count and its bound.
fn case(name: &str, layout: &Layout, held: &[u32]) {
    let rows: [(&'static str, fn(u32) -> bool, u32); 4] = [
        ("one", |h| h < 1, 1),
        ("two", |h| h < 2, 2),
        ("most", |h| h > 1, 1),
        ("exact", |h| h != 2, 2),
    ];
    let want: Vec<(&str, Vec<Finding>)> = rows
        .iter()
        .map(|&(rule, bad, bound)| {
            let findings = held
                .iter()
                .filter(|&&h| bad(h))
                .map(|&h| Finding::count(h).limit(Measurement::Count(bound)))
                .collect();
            (rule, findings)
        })
        .collect();
    check_everywhere(name, &new_deck(&["tap", "licon"], TAP), layout, &want);
}

fn licons(boxes: &[[i64; 4]]) -> Layout {
    boxes.iter().fold(
        Layout::default().rect("tap", 0, 0, 1000, 500),
        |layout, &[xlo, ylo, xhi, yhi]| layout.rect("licon", xlo, ylo, xhi, yhi),
    )
}

/// Oracle: each case states how many licons each tap holds, by
/// construction: none, one, two and three held; one touching the tap's
/// edge from inside (held); one straddling the edge and one touching it
/// from outside (not held); two touching or overlapping licons (one
/// figure); a tap of two abutting halves holding a licon across the seam;
/// two taps holding 1 and 0; a licon in a tap ring's hole (not held); an
/// empty tap layer (nothing judged).
#[test]
fn contains_counts_the_figures_each_outer_figure_holds_entirely() {
    let cases: [(&str, Vec<[i64; 4]>, u32); 9] = [
        ("none", vec![], 0),
        ("one", vec![[100, 100, 200, 200]], 1),
        ("two", vec![[100, 100, 200, 200], [400, 100, 500, 200]], 2),
        (
            "three",
            vec![
                [100, 100, 200, 200],
                [400, 100, 500, 200],
                [700, 100, 800, 200],
            ],
            3,
        ),
        ("edge_inside", vec![[0, 0, 100, 100]], 1),
        ("straddling", vec![[950, 100, 1050, 200]], 0),
        ("touching_outside", vec![[1000, 100, 1100, 200]], 0),
        (
            "touching_pair",
            vec![[100, 100, 200, 200], [200, 100, 300, 200]],
            1,
        ),
        (
            "overlapping_pair",
            vec![[100, 100, 250, 200], [200, 100, 300, 200]],
            1,
        ),
    ];
    for (name, boxes, held) in cases {
        case(name, &licons(&boxes), &[held]);
    }
    case(
        "tap_halves",
        &Layout::default()
            .rect("tap", 0, 0, 500, 500)
            .rect("tap", 500, 0, 1000, 500)
            .rect("licon", 450, 100, 550, 200),
        &[1],
    );
    let two = licons(&[[100, 100, 200, 200]]).rect("tap", 2000, 0, 3000, 500);
    case("two_taps", &two, &[1, 0]);
    case(
        "empty_tap",
        &Layout::default().rect("licon", 100, 100, 200, 200),
        &[],
    );
    case(
        "in_hole",
        &Layout::default()
            .rect("tap", 0, 0, 1000, 100)
            .rect("tap", 0, 400, 1000, 500)
            .rect("tap", 0, 100, 300, 400)
            .rect("tap", 700, 100, 1000, 400)
            .rect("licon", 450, 200, 550, 300),
        &[0],
    );
}

/// Oracle: the same definition for a well (sky130 nwell.4 "all n-wells
/// must contain a tap"): a well with a tap inside holds 1; one without,
/// or with its tap across the well's edge, holds 0 against 1.
#[test]
fn a_well_must_hold_a_whole_tap() {
    let deck = new_deck(
        &["nwell", "ntap"],
        "rule nwell.4 contains(nwell, ntap) >= 1",
    );
    let well = || Layout::default().rect("nwell", 0, 0, 2000, 1000);
    let zero = || vec![Finding::count(0).limit(Measurement::Count(1))];
    let cases: [(&str, Layout, Vec<Finding>); 3] = [
        ("tapped", well().rect("ntap", 100, 100, 300, 300), vec![]),
        ("untapped", well(), zero()),
        (
            "tap_across_edge",
            well().rect("ntap", 1900, 100, 2100, 300),
            zero(),
        ),
    ];
    for (name, layout, want) in cases {
        check_everywhere(name, &deck, &layout, &[("nwell.4", want)]);
    }
}
