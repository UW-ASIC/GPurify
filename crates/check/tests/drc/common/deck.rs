//! Deck-text fixtures: rules written in the deck language, compiled by
//! `RuleSet::from_deck`, run over polygons on the deck's layers, and every
//! finding compared with what the rule's definition says, under each of the
//! eight symmetries of the square and two translations.
//!
//! The crate-level counterpart of the root suite's exhaustive harness, without
//! GDS and extraction: the same deck lines and the same expectations, so the
//! crate's own tests reach what `cargo mutants` scores.

use gpurify_check::drc::RuleSet;
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_geom::Grid;
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::StrTable;
use gpurify_testgen::dbu;
use gpurify_testgen::shapes::LayoutBuilder;

/// The translations each case repeats at: the origin, and far off it in the
/// negative quadrant, so nothing depends on small or positive coordinates.
pub const OFFSETS: [(i64, i64); 2] = [(0, 0), (-1_234_567, 987_654)];

/// `grid 1nm`, `met1`, `met2` and `region`, then `rules`.
pub fn deck(rules: &str) -> String {
    format!(
        "grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n\
         layer region = gds(81, 1)\n{rules}\n"
    )
}

/// `grid 1nm` and `layers`, each on its own stream pair, then `rules`.
pub fn new_deck(layers: &[&str], rules: &str) -> String {
    let mut out = String::from("grid 1nm\n");
    for (gds, name) in (1..).zip(layers) {
        out += &format!("layer {name} = gds({gds}, 0)\n");
    }
    out + rules + "\n"
}

/// A polygon on a drawn layer of the deck, by name, counter-clockwise. Drawn
/// layers take their ids in name order, not declaration order.
pub type Shape = (&'static str, Vec<(i64, i64)>);

/// An axis-aligned rectangle on `layer`.
pub fn rect(layer: &'static str, xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Shape {
    (layer, vec![(xlo, ylo), (xhi, ylo), (xhi, yhi), (xlo, yhi)])
}

/// One finding a rule must report: its rule id, the measured value, and the
/// marker when it lies on the lattice under every symmetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Want {
    pub rule: &'static str,
    pub measured: Measurement,
    pub at: Option<(i64, i64)>,
}

/// A length finding.
pub fn len(rule: &'static str, nm: i64) -> Want {
    Want {
        rule,
        measured: Measurement::Length(dbu(nm)),
        at: None,
    }
}

/// An area finding, in square grid units.
pub fn area(rule: &'static str, nm2: i128) -> Want {
    Want {
        rule,
        measured: Measurement::Area(gpurify_geom::DbuArea::new(nm2)),
        at: None,
    }
}

/// A ratio finding.
pub fn ratio(rule: &'static str, value: f64) -> Want {
    Want {
        rule,
        measured: Measurement::Ratio(value),
        at: None,
    }
}

/// A count finding.
pub fn count(rule: &'static str, n: u32) -> Want {
    Want {
        rule,
        measured: Measurement::Count(n),
        at: None,
    }
}

impl Want {
    /// Pinned at `(x, y)`.
    pub fn at(mut self, x: i64, y: i64) -> Self {
        self.at = Some((x, y));
        self
    }

    /// Pinned at `(x2 / 2, y2 / 2)` when both are even: a midpoint off the
    /// lattice is floored, and a floor does not commute with a mirror.
    pub fn at2(self, x2: i64, y2: i64) -> Self {
        if x2 % 2 == 0 && y2 % 2 == 0 {
            self.at(x2 / 2, y2 / 2)
        } else {
            self
        }
    }
}

/// What one run reported: each finding as `(rule id, measured, at)` and each
/// rule's row as `(rule id, outcome, examined)`.
pub struct Ran {
    pub found: Vec<(String, Measurement, (i64, i64))>,
    pub runs: Vec<(String, Outcome, u64)>,
}

/// Compiles `deck` and runs every DRC rule over `shapes`.
///
/// # Panics
///
/// When the deck does not parse or compile.
pub fn run(deck: &str, shapes: &[Shape]) -> Ran {
    let mut strings = StrTable::default();
    let parsed = parse_deck(deck, Grid::new(1000).expect("a 1 nm grid"), &mut strings)
        .unwrap_or_else(|error| panic!("the deck parses: {error}\n{deck}"));
    let set = RuleSet::from_deck(&parsed, &strings)
        .unwrap_or_else(|error| panic!("the deck compiles: {error:?}\n{deck}"));
    let mut builder = LayoutBuilder::new(parsed.layers.len());
    for (layer, points) in shapes {
        let id = parsed
            .layers
            .id(&strings, layer)
            .unwrap_or_else(|| panic!("the deck declares {layer}"));
        let xs: Vec<i64> = points.iter().map(|p| p.0).collect();
        let ys: Vec<i64> = points.iter().map(|p| p.1).collect();
        builder.push(id, &xs, &ys);
    }
    let store = builder.finish().0;
    let (mut out, mut runs): (Violations, Vec<RuleRun>) = (Violations::default(), Vec::new());
    set.run(&store, &mut out, &mut runs);
    Ran {
        found: (0..out.len())
            .map(|i| {
                let v = out.get(i);
                (
                    strings.resolve(v.rule).to_owned(),
                    v.measured,
                    (v.at.x.raw(), v.at.y.raw()),
                )
            })
            .collect(),
        runs: runs
            .iter()
            .map(|r| (strings.resolve(r.rule).to_owned(), r.outcome, r.examined))
            .collect(),
    }
}

/// One of the eight symmetries of the square: `turns` counter-clockwise
/// quarter turns, then a mirror of x.
#[derive(Debug, Clone, Copy)]
pub struct Symmetry {
    pub turns: u8,
    pub mirror: bool,
}

impl Symmetry {
    pub fn all() -> impl Iterator<Item = Symmetry> {
        (0..8).map(|i| Symmetry {
            turns: i % 4,
            mirror: i >= 4,
        })
    }

    pub fn apply(self, (mut x, mut y): (i64, i64)) -> (i64, i64) {
        for _ in 0..self.turns {
            (x, y) = (-y, x);
        }
        if self.mirror {
            x = -x;
        }
        (x, y)
    }
}

/// Runs `deck` over `shapes` under every symmetry and offset and asserts each
/// rule in `rules` finds exactly `want` mapped the same way: the measured
/// values as a multiset, and each pinned marker at its image.
pub fn check(name: &str, deck: &str, shapes: &[Shape], rules: &[&str], want: &[Want]) {
    check_under(name, deck, shapes, rules, want, |_| true);
}

/// [`check`] under only the symmetries `keep` accepts: the identity alone
/// for a rule whose windows anchor on the die's corner, or those without a
/// quarter turn for one tied to an axis.
pub fn check_under(
    name: &str,
    deck: &str,
    shapes: &[Shape],
    rules: &[&str],
    want: &[Want],
    keep: fn(Symmetry) -> bool,
) {
    for s in Symmetry::all().filter(|&s| keep(s)) {
        for (dx, dy) in OFFSETS {
            let map = |p: (i64, i64)| {
                let (x, y) = s.apply(p);
                (x + dx, y + dy)
            };
            let moved: Vec<Shape> = shapes
                .iter()
                .map(|(layer, points)| {
                    let mut out: Vec<_> = points.iter().copied().map(map).collect();
                    if s.mirror {
                        out.reverse();
                    }
                    (*layer, out)
                })
                .collect();
            let ran = run(deck, &moved);
            let tag = format!("{name} under {s:?} at ({dx}, {dy})");
            for &rule in rules {
                let row = ran.runs.iter().find(|r| r.0 == rule);
                assert!(
                    matches!(row, Some((_, Outcome::Ran, _))),
                    "{tag}: {rule} did not run: {row:?}"
                );
                let mut got: Vec<_> = ran.found.iter().filter(|f| f.0 == rule).collect();
                let mut wanted: Vec<_> = want.iter().filter(|w| w.rule == rule).collect();
                // Pinned first, so an unpinned want cannot take a pinned one's match.
                wanted.sort_by_key(|w| w.at.is_none());
                for w in &wanted {
                    let at = w.at.map(map);
                    let hit = got
                        .iter()
                        .position(|f| f.1 == w.measured && at.is_none_or(|at| f.2 == at));
                    match hit {
                        Some(k) => {
                            got.swap_remove(k);
                        }
                        None => panic!(
                            "{tag}: {rule} misses {:?} at {at:?}; it found {:?}",
                            w.measured,
                            ran.found.iter().filter(|f| f.0 == rule).collect::<Vec<_>>()
                        ),
                    }
                }
                assert!(got.is_empty(), "{tag}: {rule} also found {got:?}");
            }
        }
    }
}
