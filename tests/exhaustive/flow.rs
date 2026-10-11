//! Flow features of the deck (FLOW-*): a staged run.

use crate::harness::{Depth, Expect, Finding, Fixture, Layout, Want, DRC};

/// The translations a fixture here is repeated at, beside every symmetry.
const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// A `met1` deck with a 100 nm minimum width `w` and a 200 nm minimum
/// spacing `s`; staged, `w` is the stage `gross` and `s` the stage `fine`.
fn deck(staged: bool) -> String {
    let (gross, fine) = if staged {
        ("stage gross\n", "stage fine\n")
    } else {
        ("", "")
    };
    format!(
        "grid 1nm\nlayer met1 = gds(68, 20)\n{gross}rule w width(met1) >= 100nm\n\
         {fine}rule s space(met1) >= 200nm\n"
    )
}

/// A 50 nm wide bar, too narrow for `w`, when `narrow`; and two 1 um bars
/// 150 nm apart, too close for `s`, far from it.
fn layout(narrow: bool) -> Layout {
    let pair = Layout::default()
        .rect("met1", 0, 5_000, 2_000, 6_000)
        .rect("met1", 0, 6_150, 2_000, 7_150);
    if narrow {
        pair.rect("met1", 0, 0, 2_000, 50)
    } else {
        pair
    }
}

/// FLOW-002: a staged deck checks its stages in order and, once a stage
/// finds an error, reports every later stage's rules skipped with nothing
/// found (the early, dirty-design run of Calibre nmDRC-Recon and IC
/// Validator Explorer). Oracle: hand-derived (one 50 nm width finding, one
/// 150 nm gap finding), and laws: the same deck unstaged reports both, and a
/// clean first stage lets the second run as it would unstaged; every case
/// under every symmetry and an offset. Fails if a later stage runs after a
/// dirty one, is reported clean or ran, or a clean stage holds the next back.
pub fn fixtures(_depth: Depth) -> Vec<Fixture> {
    let width = || Expect::rule("w", vec![Finding::length(50)]);
    let space = || Expect::rule("s", vec![Finding::length(150)]);
    let cases = [
        (
            "staged/dirty_first_stage",
            deck(true),
            layout(true),
            vec![width(), Expect::outcome("s", Want::Skipped)],
        ),
        (
            "staged/clean_first_stage",
            deck(true),
            layout(false),
            vec![Expect::clean("w"), space()],
        ),
        (
            "unstaged/both",
            deck(false),
            layout(true),
            vec![width(), space()],
        ),
    ];
    let mut out = Vec::new();
    for (name, deck, layout, expects) in cases {
        let mut fixture = Fixture::new(&format!("flow/{name}"), &["FLOW-002"], &deck, DRC)
            .layout(layout)
            .expect(Expect::Passes(false));
        for expect in expects {
            fixture = fixture.expect(expect);
        }
        out.extend(
            OFFSETS
                .iter()
                .flat_map(|&(dx, dy)| fixture.every_symmetry(dx, dy)),
        );
    }
    out
}
