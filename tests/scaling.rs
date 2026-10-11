//! The bench gate (nightly): the engine's cost per polygon stays flat as the
//! layout grows, within one run, against no stored baseline.
//!
//! It times the engine end to end on one generated layout family
//! (`testgen::scale_corpus`, combs of rails, fingers and cuts) at 1x, 4x and
//! 16x a base size: read the GDSII bytes, flatten, extract nets, and run a
//! deck of width, spacing, enclosure and area rules. Each size is timed three
//! times, interleaved, and the fastest kept. A cost linear in the input keeps
//! ns per polygon flat; one quadratic path makes it 16 times the base's at
//! 16x the size.
//!
//! [`FACTOR`] is the bound on the 16x size's ns per polygon over the base's.

use gpurify::check::lvs::CompareOptions;
use gpurify::check::report::Outcome;
use gpurify::engine::pipeline::{extract, intern_report_ids, Loaded};
use gpurify::engine::run::{run_checks, Checks, RunOptions};
use gpurify::geom::{Grid, StrTable};
use gpurify::ingest::deck::parse_deck;
use gpurify::ingest::layout::{gds, UnknownLayers};
use gpurify_testgen::gds::write_store;
use gpurify_testgen::{scale_corpus, ScaleSpec};
use std::time::{Duration, Instant};

/// The corpus's three layers as the deck names them: base layers take ids
/// by name, so `m1` (rails), `m2` (fingers) and `v1` (cuts) are ids 0, 1
/// and 2, the corpus's own. The spacing limits reach the neighbours (rails
/// 800 apart, fingers 280), so every rule measures pairs.
const DECK: &str = "grid 1nm
layer m1 = gds(1, 0)
layer m2 = gds(2, 0)
layer v1 = gds(3, 0)
connect conductors [m1, m2]
connect via v1 [m1, m2]
rule m1.width width(m1) >= 100nm
rule m1.space space(m1) >= 801nm
rule m2.space space(m2) >= 300nm
rule v1.enclosure enclosure(v1, m1) >= 20nm
rule m2.area area(m2) >= 10000nm2
";

/// The smallest layout's polygons; the others are 4 and 16 times as many.
const BASE: u32 = 2_000;

/// The most the 16x layout's ns per polygon may exceed the base's.
///
/// Measured once on an i9-14900HX, in the debug build the nightly tier runs
/// (2026-10-11): 30 360, 34 464 and 49 038 ns per polygon at 1875, 7500 and
/// 30 000 polygons, so 1.14 at 4x and 1.62 at 16x. Three leaves 1.85 times
/// that for a slower, noisier runner, and still fails a quadratic path that
/// costs a tenth of the base's time (0.9 · 1.62 + 0.1 · 16 = 3.06); a path
/// quadratic throughout reads 16, one of `n^1.5` 4.
const FACTOR: f64 = 3.0;

/// One run of the engine on `bytes`: read, flatten, extract, check. Every
/// rule must run and examine something, or the time is of a vacuous run.
fn engine(bytes: &[u8]) -> Duration {
    let start = Instant::now();
    let mut strings = StrTable::default();
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let deck = parse_deck(DECK, grid, &mut strings).expect("the deck parses");
    let library = gds::Library::parse(bytes, &mut strings).expect("the corpus reads");
    let (store, mut provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("the corpus flattens");
    provenance
        .resolve_labels(&store, &deck.connectivity)
        .expect("no labels to bind");
    intern_report_ids(&mut strings);
    let loaded = Loaded {
        strings,
        grid,
        deck,
        store,
        provenance,
        reference: None,
        intent: None,
    };
    let extracted = extract(&loaded).expect("the corpus extracts");
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: false,
        },
        lvs: CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (outputs, _) = run_checks(&loaded, &extracted, &options).expect("the deck runs");
    let elapsed = start.elapsed();
    assert_eq!(outputs.runs.len(), 5);
    for run in &outputs.runs {
        assert!(
            matches!(run.outcome, Outcome::Ran) && run.examined > 0,
            "{run:?}"
        );
    }
    elapsed
}

#[test]
#[ignore = "nightly: the bench gate, a few seconds of a debug build"]
fn the_engine_costs_the_same_per_polygon_at_sixteen_times_the_size() {
    let layouts: Vec<(u32, Vec<u8>)> = [1, 4, 16]
        .into_iter()
        .map(|scale| {
            let polygons = BASE * scale;
            let corpus = scale_corpus(ScaleSpec {
                seed: 0x5EED,
                polygons,
                nets: polygons / 16,
                hierarchy_depth: 2,
            });
            let mut strings = StrTable::default();
            let deck = parse_deck(DECK, Grid::new(1000).expect("1 nm"), &mut strings)
                .expect("the deck parses");
            let mut bytes = Vec::new();
            write_store(&corpus.store, &deck.layers, "TOP", &mut bytes).expect("the corpus writes");
            (corpus.polygons, bytes)
        })
        .collect();
    let mut best = vec![Duration::MAX; layouts.len()];
    for _ in 0..3 {
        for (slot, (_, bytes)) in best.iter_mut().zip(&layouts) {
            *slot = (*slot).min(engine(bytes));
        }
    }
    let per: Vec<f64> = best
        .iter()
        .zip(&layouts)
        .map(|(time, (polygons, _))| time.as_secs_f64() * 1e9 / f64::from(*polygons))
        .collect();
    for ((polygons, _), (time, ns)) in layouts.iter().zip(best.iter().zip(&per)) {
        println!("{polygons:>8} polygons {time:>12?} {ns:>10.1} ns/poly");
    }
    assert!(
        per[2] <= FACTOR * per[0],
        "{:.1} ns per polygon at {} polygons, {:.2}x the {:.1} at {}: over {FACTOR}x",
        per[2],
        layouts[2].0,
        per[2] / per[0],
        per[0],
        layouts[0].0
    );
}
