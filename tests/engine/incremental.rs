//! Incremental DRC (FLOW-008): `engine::incremental::recheck` against a
//! full `check` of the same edited layout.

use gpurify::check::deck::{compile, CompiledDeck};
use gpurify::engine::incremental::{check, recheck, DrcState};
use gpurify_geom::{GeometryStore, GeometryStoreBuilder, Grid};
use gpurify_ingest::layout::derive_layers;
use gpurify_ingest::{Provenance, StrTable};
use gpurify_testgen::rng::Rng;
use gpurify_testgen::shapes::dbu;

/// Local kinds of every family the module docs name, derived layers grown
/// and shrunk (`m2big` reaching 1.1 um between two m2 shapes, past every
/// rule's own lengths), and two whole-layout kinds (density, count).
const DECK: &str = "grid 1nm
layer m1 = gds(1, 0)
layer v1 = gds(2, 0)
layer m2 = gds(3, 0)
layer fat = m1.sized(-200nm).sized(200nm)
layer halo = v1.sized(60nm)
layer m2big = m2.sized(500nm)
rule m1.w width(m1) >= 100nm
rule m1.s space(m1) >= 120nm
rule m1.a area(m1) >= 0.05um2
rule m1.n notch(m1) >= 120nm
rule m1.c corner_space(m1) >= 150nm
rule fat.s space(fat) >= 300nm
rule v.e enclosure(v1, m1) >= 20nm
rule v.s space(v1) >= 100nm
rule h.s space(halo, m2) >= 40nm
rule m12.s space(m1, m2) >= 50nm
rule m2.w width(m2) >= 150nm
rule big.s space(m2big) >= 100nm
rule m1.d density(m1; window: 2um, step: 1um) >= 0.1
rule m2.c count(m2) <= 12
";

/// A rectangle: layer index (0 m1, 1 v1, 2 m2) and its corners in nm.
type Rect = (u16, i64, i64, i64, i64);

fn deck(strings: &mut StrTable) -> CompiledDeck {
    compile(DECK, Grid::new(1000).expect("a 1 nm grid"), strings).expect("the deck compiles")
}

/// `rects` as a store with the deck's derived layers, as a consumer that
/// edits a layout in memory builds it (FLOW-005).
fn store(deck: &CompiledDeck, strings: &StrTable, rects: &[Rect]) -> GeometryStore {
    let id = |at: u16| {
        let name = ["m1", "v1", "m2"][usize::from(at)];
        deck.layers.id(strings, name).expect("a deck layer")
    };
    let mut builder = GeometryStoreBuilder::default();
    for &(layer, xlo, ylo, xhi, yhi) in rects {
        builder.push(
            id(layer),
            &[xlo, xhi, xhi, xlo].map(dbu),
            &[ylo, ylo, yhi, yhi].map(dbu),
        );
    }
    let (mut store, _) = builder.finish(deck.layers.len());
    derive_layers(&mut store, deck, &Provenance::default(), strings).expect("derives");
    store
}

/// A run's findings and rule rows as sorted text, `examined` left out (an
/// incremental run counts what it looked at again).
fn report(state: &DrcState, strings: &StrTable) -> Vec<String> {
    let mut lines: Vec<String> = (0..state.violations.len())
        .map(|row| {
            let v = state.violations.get(row);
            format!("{} {v:?}", strings.resolve(v.rule))
        })
        .chain(state.runs.iter().map(|run| {
            format!(
                "{} {:?} {}",
                strings.resolve(run.rule),
                run.outcome,
                run.violations
            )
        }))
        .collect();
    lines.sort();
    lines
}

fn random_rect(rng: &mut Rng) -> Rect {
    let layer = u16::try_from(rng.below(3)).expect("small");
    let (w, h) = (rng.range(5, 60) * 10, rng.range(5, 60) * 10);
    let (x, y) = (rng.range(0, 2_000) * 10, rng.range(0, 2_000) * 10);
    (layer, x, y, x + w, y + h)
}

/// One seed: a random layout, then three rounds of random edits (shapes
/// removed, added, moved), each rechecked from the last.
fn agree(seed: u64) {
    let mut strings = StrTable::default();
    let deck = deck(&mut strings);
    let mut rng = Rng::new(seed);
    let mut rects: Vec<Rect> = (0..rng.range(10, 120))
        .map(|_| random_rect(&mut rng))
        .collect();
    let mut state = check(&deck, store(&deck, &strings, &rects));
    for round in 0..3 {
        for _ in 0..rng.range(0, 3) {
            if !rects.is_empty() {
                let at = usize::try_from(rng.below(rects.len() as u64)).expect("an index");
                rects.remove(at);
            }
        }
        for _ in 0..rng.range(0, 3) {
            let at = usize::try_from(rng.below(rects.len() as u64 + 1)).expect("an index");
            rects.insert(at, random_rect(&mut rng));
        }
        if !rects.is_empty() && rng.below(2) == 0 {
            let at = usize::try_from(rng.below(rects.len() as u64)).expect("an index");
            let (dx, dy) = (rng.range(-30, 30) * 10, rng.range(-30, 30) * 10);
            let r = &mut rects[at];
            *r = (r.0, r.1 + dx, r.2 + dy, r.3 + dx, r.4 + dy);
        }
        let full = check(&deck, store(&deck, &strings, &rects));
        let edited = recheck(&deck, &strings, &state, store(&deck, &strings, &rects));
        assert_eq!(
            report(&edited, &strings),
            report(&full, &strings),
            "seed {seed}, round {round}: {rects:?}"
        );
        state = edited;
    }
}

/// Proves catalog FLOW-008.
///
/// Oracle: metamorphic relation. Rechecking an edited layout from the
/// previous run gives exactly the findings, each naming the same rows, and
/// the rule outcomes a full check of the edited layout gives, over 60
/// random layouts and three rounds of random removals, additions and moves
/// each. Keeping a previous finding the edit touched, dropping one it did
/// not, a reach too short for the derived layers, or a whole-layout kind
/// run on the dirty part alone, breaks it.
#[test]
fn a_recheck_finds_what_a_full_check_finds() {
    for seed in 0..60 {
        agree(seed);
    }
}

/// The same relation at nightly depth: 3000 layouts.
///
/// Oracle: metamorphic relation, as `a_recheck_finds_what_a_full_check_finds`.
#[test]
#[ignore = "nightly depth: cargo test --test engine -- --ignored"]
fn a_recheck_finds_what_a_full_check_finds_nightly() {
    for seed in 60..3060 {
        agree(seed);
    }
}

/// A recheck looks again only at the part of the layout an edit reaches.
///
/// Oracle: hand-derived. Two m1 squares 50 um apart, far beyond the deck's
/// reach (its longest local sum, `space(fat)`'s 300 nm, plus twice the
/// 400 nm, 120 nm and 1000 nm its derived layers grow by): narrowing one to 80 nm
/// makes one `m1.w` finding, and the recheck's `m1.w` row examined one
/// figure where the full check examines two. With nothing changed, the
/// recheck keeps every finding and examines nothing.
#[test]
fn a_recheck_examines_only_the_edited_part() {
    let mut strings = StrTable::default();
    let deck = deck(&mut strings);
    let before = [(0, 0, 0, 500, 500), (0, 50_000, 0, 50_500, 500)];
    let after = [(0, 0, 0, 80, 500), (0, 50_000, 0, 50_500, 500)];
    let state = check(&deck, store(&deck, &strings, &before));
    let edited = recheck(&deck, &strings, &state, store(&deck, &strings, &after));
    let full = check(&deck, store(&deck, &strings, &after));
    let row = |s: &DrcState| {
        *s.runs
            .iter()
            .find(|run| strings.resolve(run.rule) == "m1.w")
            .expect("m1.w runs")
    };
    assert_eq!((row(&edited).violations, row(&edited).examined), (1, 1));
    assert_eq!((row(&full).violations, row(&full).examined), (1, 2));
    assert_eq!(report(&edited, &strings), report(&full, &strings));

    let same = recheck(&deck, &strings, &edited, store(&deck, &strings, &after));
    assert_eq!(report(&same, &strings), report(&full, &strings));
    assert_eq!(row(&same).examined, 0);
}
