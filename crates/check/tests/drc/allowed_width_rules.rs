//! `width(L; allowed: [...])` (`allowed_width`, DRC-015, DRC-090) from deck
//! text, with and without `open_last`. The cases are the root suite's
//! exhaustive fixtures (`tests/exhaustive/drc_dimension.rs`) at the crate
//! level, with the same oracles; each finding also states its limit, the
//! listed width nearest the measured one.

use crate::common::deck::{check, deck, len, rect, Shape, Want};
use gpurify_check::report::Measurement;
use gpurify_testgen::dbu;

fn met1(boxes: &[[i64; 4]]) -> Vec<Shape> {
    boxes
        .iter()
        .map(|&[xlo, ylo, xhi, yhi]| rect("met1", xlo, ylo, xhi, yhi))
        .collect()
}

fn nearest(w: i64) -> Measurement {
    Measurement::Length(dbu(if w < 150 { 100 } else { 200 }))
}

/// Oracle: widths fixed by construction (sky130 rpm.1b-1f's shape: a list
/// of legal widths): bars at 100 and 200 and one step either side, each off
/// width one finding at the bar's centre measuring its width against the
/// nearest listed width; a 150 square, between the two (its limit a tie,
/// left unstated); a 100 bar drawn as two abutting 50 halves (legal once
/// merged); an L of a 100 and a 200 arm, judged by its narrower; two plates
/// overlapping 100 x 100 at a corner, a neck of sqrt(20000) (141 floored).
#[test]
fn only_the_listed_widths_are_legal() {
    let deck = deck("rule aw width(met1; allowed: [100nm, 200nm])");
    for listed in [100, 200] {
        for w in [listed - 1, listed, listed + 1] {
            let want: Vec<Want> = if w == listed {
                vec![]
            } else {
                vec![len("aw", w).at2(w, 1000).limit(nearest(w))]
            };
            check(
                &format!("bar/{w}"),
                &deck,
                &met1(&[[0, 0, w, 1000]]),
                &["aw"],
                &want,
            );
        }
    }
    let cases: [(&str, Vec<Shape>, Vec<Want>); 4] = [
        (
            "between",
            met1(&[[0, 0, 150, 150]]),
            vec![len("aw", 150).at(75, 75)],
        ),
        (
            "halves",
            met1(&[[0, 0, 50, 1000], [50, 0, 100, 1000]]),
            vec![],
        ),
        (
            "l_of_two_widths",
            met1(&[[0, 0, 1000, 100], [0, 100, 200, 1000]]),
            vec![],
        ),
        (
            "corner_neck",
            met1(&[[0, 0, 1000, 1000], [900, 900, 1900, 1900]]),
            vec![len("aw", 141).limit(nearest(141))],
        ),
    ];
    for (name, shapes, want) in cases {
        check(name, &deck, &shapes, &["aw"], &want);
    }
}

/// Oracle: LEF58 `WIDTHTABLE 0.10 0.20` with its last width open: "all the
/// given widths are exact width values, except for the last one, which is
/// equal to or greater than the value". Bars swept one step around 100
/// (exact: 99 and 101 fail) and 200 (open: 199 fails, 200 and 201 pass); a
/// 1000 square passes, as LEF's 0.42 under a last 0.40 does (Figure 1-32
/// b); a 150 square fails; an L of a 100 and a 1000 arm is judged by its
/// narrower, and passes.
#[test]
fn an_open_last_width_admits_everything_wider() {
    let deck = deck("rule aw width(met1; allowed: [100nm, 200nm], open_last: true)");
    for listed in [100, 200] {
        for w in [listed - 1, listed, listed + 1] {
            let legal = w == 100 || w >= 200;
            let want: Vec<Want> = if legal {
                vec![]
            } else {
                vec![len("aw", w).at2(w, 1000).limit(nearest(w))]
            };
            check(
                &format!("open/{w}"),
                &deck,
                &met1(&[[0, 0, w, 1000]]),
                &["aw"],
                &want,
            );
        }
    }
    let cases: [(&str, Vec<Shape>, Vec<Want>); 3] = [
        ("wide", met1(&[[0, 0, 1000, 1000]]), vec![]),
        (
            "between",
            met1(&[[0, 0, 150, 150]]),
            vec![len("aw", 150).at(75, 75)],
        ),
        (
            "l_of_exact_and_wide",
            met1(&[[0, 0, 3000, 100], [0, 100, 1000, 1100]]),
            vec![],
        ),
    ];
    for (name, shapes, want) in cases {
        check(name, &deck, &shapes, &["aw"], &want);
    }
}
