//! Flow features of the deck (FLOW-*): a staged run, and waivers.

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
/// found (the early, dirty-design run of Calibre `nmDRC-Recon` and IC
/// Validator Explorer). Oracle: hand-derived (one 50 nm width finding, one
/// 150 nm gap finding), and laws: the same deck unstaged reports both, and a
/// clean first stage lets the second run as it would unstaged; every case
/// under every symmetry and an offset. Fails if a later stage runs after a
/// dirty one, is reported clean or ran, or a clean stage holds the next back.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    [staged(depth), waivers(depth)].concat()
}

fn staged(_depth: Depth) -> Vec<Fixture> {
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

/// A `met1` deck with a 100 nm minimum width `w`, a 200 nm minimum spacing
/// `s`, and a `waiver` layer that waives `rule`.
fn waiver_deck(rule: &str) -> String {
    format!(
        "grid 1nm\nlayer met1 = gds(68, 20)\nlayer waiver = gds(255, 0)\n\
         rule w width(met1) >= 100nm\nrule s space(met1) >= 200nm\nwaive {rule} waiver\n"
    )
}

/// FLOW-001: a waiver is a shape on the deck's waiver layer for a rule; a
/// violation of that rule whose marker lies on it is waived, reported
/// apart and not counted against the run (Calibre Auto-Waivers keeps its
/// waivers on "a specific geometry layer"). Oracle: hand-derived, a 50 nm
/// bar's one width finding at its middle; under every symmetry and an
/// offset. A waiver over it clears the rule and the run passes; one beside
/// it waives nothing; one for another rule waives nothing; with two narrow
/// bars, one waived, one finding stays. Fails if a waiver is ignored, waives
/// past its shape, or waives another rule's finding.
fn waivers(_depth: Depth) -> Vec<Fixture> {
    let bar = |y: i64| Layout::default().rect("met1", 0, y, 2_000, y + 50);
    let over = |layout: Layout, y: i64| layout.rect("waiver", -100, y - 100, 2_100, y + 150);
    let width = || Expect::rule("w", vec![Finding::length(50)]);
    let cases = [
        (
            "waiver/covered",
            waiver_deck("w"),
            over(bar(0), 0),
            vec![Expect::clean("w"), Expect::Passes(true)],
        ),
        (
            "waiver/beside",
            waiver_deck("w"),
            over(bar(0), 1_000),
            vec![width(), Expect::Passes(false)],
        ),
        (
            "waiver/another_rule",
            waiver_deck("s"),
            over(bar(0), 0),
            vec![width(), Expect::Passes(false)],
        ),
        (
            "waiver/one_of_two",
            waiver_deck("w"),
            over(bar(0).rect("met1", 0, 3_000, 2_000, 3_050), 0),
            vec![width(), Expect::Passes(false)],
        ),
    ];
    let mut out = Vec::new();
    for (name, deck, layout, expects) in cases {
        let mut fixture =
            Fixture::new(&format!("flow/{name}"), &["FLOW-001"], &deck, DRC).layout(layout);
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

/// FLOW-001: a waiver drawn in a cell waives at every placement of it, the
/// hierarchy-invariant waiver of Calibre Auto-Waivers. A cell `IP` holds a
/// 50 nm `met1` bar and a waiver over it; `TOP` places it plainly and
/// mirrored and turned a quarter, and has a narrow bar of its own with no
/// waiver.
/// Oracle: hand-derived through the real reader and engine: of three
/// width findings, the two inside `IP` are waived (each placement's waiver
/// moved with it) and `TOP`'s stays, so the run fails on one; and a law:
/// without the `waive` line all three are reported and none waived.
#[test]
fn a_waiver_drawn_in_a_cell_waives_at_every_placement() {
    use gpurify::check::lvs::CompareOptions;
    use gpurify::engine::pipeline::Inputs;
    use gpurify::engine::run::{run, RunOptions};
    use gpurify_testgen::gds::{write_library, Placement, Structure};

    let ip = Structure {
        name: "IP".into(),
        rects: vec![
            (68, 20, [0, 0, 2_000, 50]),
            (255, 0, [-100, -100, 2_100, 150]),
        ],
        refs: Vec::new(),
    };
    let place = |at: (i32, i32), quarter_turns: u8, reflect: bool| Placement {
        cell: "IP".into(),
        reflect,
        quarter_turns,
        mag: 1,
        at,
        array: None,
    };
    let top = Structure {
        name: "TOP".into(),
        rects: vec![(68, 20, [0, 10_000, 2_000, 10_050])],
        refs: vec![place((0, 0), 0, false), place((20_000, 0), 1, true)],
    };
    let mut bytes = Vec::new();
    write_library(&[ip, top], &mut bytes).expect("the library writes");
    let dir = std::env::temp_dir().join(format!("gpurify-flow-waiver-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let layout = dir.join("waived.gds");
    std::fs::write(&layout, &bytes).expect("the layout writes");
    let counts = |waive: bool| {
        let text = if waive {
            waiver_deck("w")
        } else {
            waiver_deck("w").replace("waive w waiver\n", "")
        };
        let deck = dir.join(format!("waive_{waive}.deck"));
        std::fs::write(&deck, text).expect("the deck writes");
        let inputs = Inputs {
            layout: layout.clone(),
            deck,
            ..Inputs::default()
        };
        let options = RunOptions {
            checks: DRC,
            lvs: CompareOptions::default(),
            quasistatic_nets: Vec::new(),
        };
        let (loaded, _, outputs, summary) = run(&inputs, &options).expect("the run completes");
        let w = loaded.strings.get("w").expect("the rule id");
        let rows =
            |v: &gpurify::check::report::Violations| v.rule.iter().filter(|&&r| r == w).count();
        let reported = outputs
            .runs
            .iter()
            .find(|run| run.rule == w)
            .map(|run| run.violations);
        (
            rows(&outputs.violations),
            rows(&outputs.waived),
            reported,
            summary.passed(),
        )
    };
    assert_eq!(counts(true), (1, 2, Some(1), false), "waived");
    assert_eq!(counts(false), (3, 0, Some(3), false), "unwaived");
    let _ = std::fs::remove_dir_all(&dir);
}
