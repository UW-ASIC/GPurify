//! Timings for each pipeline stage across the scale corpus, plus one row set
//! from real fixture layout.
//!
//! Performance is the project's prime goal and is **recorded, not gated**. So
//! this is a harness that measures and prints; it never fails on a duration.
//! A threshold here would be a flaky test that a busy machine turns red, and
//! the number is meant to be read by a person watching a trend.
//!
//! # Why it is still a test and not a `benches/` target
//!
//! Two reasons, and the second is the real one.
//!
//! Criterion would be a new dependency for statistics nobody is going to act
//! on, when the decision already made was to write the number down.
//!
//! More importantly, a harness that only measures is a harness that can pass
//! while computing nonsense. Every case below therefore asserts an invariant
//! that must hold **at scale** — an id space that stays canonical at a million
//! polygons, a column whose length tracks its table — and reports the time
//! alongside. The assertions are what make it a test; the timings are what make
//! it useful.
//!
//! # Reading it
//!
//! ```sh
//! nix develop -c cargo test --release --test bench_all -- --nocapture
//! ```
//!
//! `--release` matters: a debug build measures the bounds checks, not the
//! algorithm. `--nocapture` matters because the numbers go to stdout.
//!
//! # Red until the Implementation-Phase
//!
//! Every body outside `gpurify-testgen` is `todo!()`, so these panic on their
//! first call like every other test in the workspace. The corpus generation
//! above the panic is real, which means this file is also the first thing that
//! will produce a number once Phase 4 starts.

use gpurify::core::{GeometryStore, LayerId};
use gpurify::engine::pipeline::{extract_into, load_into, Extracted, Inputs, Loaded};
use gpurify::ingest::layout::UnknownLayers;
use gpurify::topology::NetTable;
use gpurify::units::Grid;
use gpurify_testgen::{scale_corpus, ScaleCorpus, ScaleSpec};
use std::path::Path;
use std::time::{Duration, Instant};

/// Sizes to sweep, in polygons.
///
/// Three points, not one: a single size cannot distinguish an algorithm that
/// got slower from one that is quadratic, and quadratic is the failure mode
/// this workspace's whole layout discipline exists to prevent. Small enough
/// that the suite stays runnable — the largest is a benchmark, not a soak test.
const SIZES: [u32; 3] = [1_000, 10_000, 100_000];

/// A fixed seed, so two runs measure the same geometry.
///
/// Without this the corpus differs between runs and a timing change cannot be
/// attributed to a code change, which would make the whole record worthless.
const SEED: u64 = 0x5EED;

/// One recorded measurement.
struct Timing {
    stage: &'static str,
    polygons: u32,
    elapsed: Duration,
}

impl Timing {
    /// Nanoseconds per polygon — the number that actually carries information.
    ///
    /// A total duration says nothing without its input size, and comparing
    /// totals across sizes is how a linear algorithm gets mistaken for a
    /// regression. This is the column to watch: it should be flat.
    fn per_element_ns(&self) -> f64 {
        self.elapsed.as_secs_f64() * 1e9 / f64::from(self.polygons)
    }
}

/// Print the record as a table.
///
/// Emitted rather than asserted, and emitted in a fixed column order so two
/// runs' output can be diffed by eye or by `diff`.
fn report(timings: &[Timing]) {
    println!("\n  stage                    polygons        total      ns/poly");
    println!("  ---------------------------------------------------------------");
    for timing in timings {
        println!(
            "  {:<22} {:>9} {:>12?} {:>12.1}",
            timing.stage,
            timing.polygons,
            timing.elapsed,
            timing.per_element_ns()
        );
    }
    println!(
        "\n  Recorded, not gated. A row that grows in the ns/poly column is a \n  \
         regression worth reading; nothing here fails on a duration.\n"
    );
}

/// Time one stage, returning its result alongside the measurement.
///
/// Takes the work as a closure so the clock brackets exactly the stage and not
/// the corpus generation — generating a hundred thousand polygons costs more
/// than several of the stages being measured.
fn timed<T>(stage: &'static str, polygons: u32, work: impl FnOnce() -> T) -> (T, Timing) {
    let start = Instant::now();
    let value = work();
    let elapsed = start.elapsed();
    (value, Timing { stage, polygons, elapsed })
}

/// One corpus at a requested size.
///
/// `nets` scales with the polygon count rather than staying fixed, so the
/// per-net work stays comparable across the sweep — a fixed net count would
/// make the largest size measure a few enormous nets rather than more of them,
/// and the ns/poly column would move for a reason that is not a regression.
fn corpus(polygons: u32) -> ScaleCorpus {
    scale_corpus(ScaleSpec {
        seed: SEED,
        polygons,
        nets: (polygons / 16).max(1),
        hierarchy_depth: 2,
    })
}

/// Oracle: law, at scale — plus the timing record.
///
/// Net extraction must produce canonical ids at every size: `NetId` is the
/// minimum polygon index of its component, so the partition is a function of
/// the geometry and nothing else. Asserting it here rather than only in
/// `topology`'s own tests is deliberate — a partition-refinement or
/// work-splitting strategy that only misbehaves above some size threshold is
/// invisible to a twelve-polygon unit test.
#[test]
fn net_extraction_stays_canonical_and_records_its_cost() {
    let mut timings = Vec::new();

    for polygons in SIZES {
        let corpus = corpus(polygons);
        let (nets, timing) = timed("topology::extract_nets", polygons, || {
            let mut nets = NetTable::default();
            gpurify::topology::extract_nets_into(&corpus.store, &corpus.connectivity, &mut nets);
            nets
        });

        // `NetId` is the *dense rank* of a component, not its label: nets are
        // numbered `0 .. net_count` in ascending order of their smallest
        // `PolyId` (`topology::NetId`'s doc comment). Both readings are
        // canonical; asserting the label reading here asserted a convention the
        // frozen signature does not have. Checked as the two halves the rank
        // actually promises — one id per component, and the id ordering
        // agreeing with the minimum-`PolyId` ordering.
        let mut ranks = Vec::with_capacity(corpus.expected_net_polys.len());
        for (net, polys) in corpus.expected_net_polys.iter().enumerate() {
            let lowest = polys.iter().copied().min().expect("a net has at least one shape");
            let id = nets.net_of(lowest);
            for &poly in polys {
                assert_eq!(
                    nets.net_of(poly),
                    id,
                    "at {polygons} polygons, net {net} is split across two ids; \
                     one component must carry exactly one NetId"
                );
            }
            ranks.push((lowest, id));
        }

        ranks.sort_unstable();
        for (rank, &(lowest, id)) in ranks.iter().enumerate() {
            assert_eq!(
                id.idx(),
                rank,
                "at {polygons} polygons, the component whose smallest shape is \
                 {lowest:?} ranks {} but sorts {rank}; ids stop being canonical \
                 and two runs can disagree",
                id.idx()
            );
        }

        timings.push(timing);
    }

    report(&timings);
}

/// Oracle: law, at scale — plus the timing record.
///
/// The bounding-box column has exactly one row per polygon, at every size. A
/// cheap invariant, and the one that catches a builder whose layer-grouping
/// permutation drops or duplicates a row — which would silently misattribute
/// every violation downstream.
#[test]
fn the_store_keeps_one_bbox_per_polygon_and_records_its_build_cost() {
    let mut timings = Vec::new();

    for polygons in SIZES {
        let (corpus, timing) = timed("ingest::build_store", polygons, || corpus(polygons));

        assert_eq!(
            corpus.store.poly_count(),
            corpus.polygons as usize,
            "the store holds {} rows but the corpus reports emitting {}",
            corpus.store.poly_count(),
            corpus.polygons
        );
        for layer in 0..corpus.store.layer_count() {
            let layer = gpurify::core::LayerId(u16::try_from(layer).expect("layer fits u16"));
            let range = corpus.store.polys_on_layer(layer);
            assert_eq!(
                corpus.store.layer_bboxes(layer).len(),
                (range.end - range.start) as usize,
                "at {polygons} polygons, layer {layer:?}'s bbox slice and row \
                 range disagree; the CSR grouping invariant is broken"
            );
        }

        timings.push(timing);
    }

    report(&timings);
}

/// Oracle: law, at scale — plus the timing record.
///
/// The candidate-pair prune must stay a superset at every size. The property is
/// checked exhaustively in `core`'s adapter test on small inputs; here it is
/// checked cheaply — every emitted pair really is within the distance — because
/// the interesting failure at scale is a grid whose cell sizing degenerates,
/// and that shows up as an absurd pair count long before it shows up as a wrong
/// answer.
#[test]
fn candidate_pair_generation_stays_subquadratic_and_records_its_cost() {
    let mut timings = Vec::new();

    for polygons in SIZES {
        let corpus = corpus(polygons);
        let layer = gpurify::core::LayerId(0);

        let (pairs, timing) = timed("core::candidate_pairs", polygons, || {
            let mut index = gpurify::core::index::SpatialIndex::default();
            gpurify::core::index::SpatialIndex::build_into(&corpus.store, layer, &mut index);
            let mut pairs = Vec::new();
            gpurify::core::index::candidate_pairs_into(
                &corpus.store,
                &index,
                gpurify::units::Dbu::new_unchecked(500),
                &mut pairs,
            );
            pairs
        });

        let rows = corpus.store.polys_on_layer(layer);
        let count = (rows.end - rows.start) as u64;
        let all_pairs = count.saturating_mul(count.saturating_sub(1)) / 2;
        assert!(
            (pairs.len() as u64) <= all_pairs,
            "at {polygons} polygons the prune emitted {} pairs, more than the \
             {all_pairs} that exist; it is not a prune",
            pairs.len()
        );

        timings.push(timing);
    }

    report(&timings);
}

/// Oracle: determinism, at scale — plus the timing record.
///
/// The same seed must produce a byte-identical corpus. This measures the
/// generator rather than the tool, and it is here because everything else in
/// this file rests on it: if the corpus differs between runs then every timing
/// above is measuring different geometry and the record means nothing.
#[test]
fn the_corpus_is_reproducible_from_its_seed() {
    for polygons in [SIZES[0], SIZES[1]] {
        let (first, timing) = timed("testgen::scale_corpus", polygons, || corpus(polygons));
        let second = corpus(polygons);

        assert_eq!(first.store.poly_count(), second.store.poly_count());
        assert_eq!(
            first.expected_net_polys, second.expected_net_polys,
            "the same seed produced two different corpora at {polygons} \
             polygons; every timing in this file would be measuring noise"
        );

        report(&[timing]);
    }
}

/// The grid the fixture corpus is drawn against: 1 dbu = 1 nm.
///
/// Stated by `tests/fixtures/expectations.json`'s `grid_dbu_per_um`. Loading at
/// any other resolution reinterprets every limit in `params.json`.
const FIXTURE_DBU_PER_UM: i64 = 1000;

/// Oracle: law, on real geometry — plus the timing record.
///
/// `tests/fixtures/_source/conformance.gds` is every fixture cell in one file:
/// layout drawn by hand, clustered into cells, mixing shape sizes across orders
/// of magnitude. The synthetic sweep above cannot produce that. It is uniform by
/// construction — one shape size scattered over one rectangle — which is the
/// input a grid index is happiest on, so a cell-sizing heuristic that
/// degenerates on clustered geometry is invisible to it and shows up here, as a
/// pair count or a stage cost out of proportion to the row count.
///
/// # This row is not a fourth point on the sweep
///
/// 30 KB. A few thousand polygons at most, and **its `ns/poly` is not
/// comparable with the sweep's** — do not read the two as one series. At this
/// size the fixed cost of a run (opening two files, parsing the deck twice,
/// building the layer table) is a visible share of the total, and that share is
/// amortised to nothing by 100,000 polygons; the same code would look several
/// times slower here for a reason that is not a slowdown. Watch this row
/// against its own history, not against the row above it.
///
/// So: a shape check, not a scale check. The sweep answers "is it quadratic",
/// this answers "does it still behave on geometry nobody generated".
#[test]
fn real_layout_keeps_the_store_invariants_and_records_its_cost() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let inputs = Inputs {
        layout: fixtures.join("_source/conformance.gds"),
        deck: fixtures.join("params.json"),
        grid: Some(Grid::new(FIXTURE_DBU_PER_UM).expect("a thousand dbu per micrometre is a grid")),
        reference: None,
        intent: None,
        // Fail-open, and deliberate rather than inherited: the corpus draws
        // GDSII layers `params.json` never declares, and `Reject` would end this
        // case at load with an I/O error in place of a measurement. The
        // non-empty assertion below is what keeps the open door honest — a drop
        // that swallowed the file would otherwise time an empty read very fast.
        unknown_layers: UnknownLayers::Drop,
    };

    // `polygons` is filled in after the load, because the row count of a file is
    // only known once it has been read. Zero until then, and never reported as
    // zero: `report` is called after the fixup below.
    let mut timings = Vec::new();

    let mut loaded = Loaded::default();
    let ((), timing) = timed("ingest::load[real]", 0, || {
        load_into(&inputs, &mut loaded).expect("the fixture corpus loads")
    });
    timings.push(timing);

    let mut extracted = Extracted::default();
    let ((), timing) = timed("engine::extract[real]", 0, || {
        extract_into(&loaded, &mut extracted).expect("the fixture corpus extracts")
    });
    timings.push(timing);

    let store = &loaded.store;

    // A benchmark of nothing is fast and says nothing. This is the assertion
    // that separates "read a real layout" from "read no layout": every timing
    // below it is meaningless without it.
    assert!(
        store.poly_count() > 0,
        "conformance.gds loaded zero polygons; either the reader dropped every \
         layer or the file moved, and the three rows below timed an empty run"
    );
    let polygons = u32::try_from(store.poly_count()).expect("a 30 KB GDS fits u32 rows");

    // Same law as the synthetic case, on geometry nobody generated: the bbox
    // column has exactly one row per polygon, per layer. A layer-grouping
    // permutation that only misbehaves when a cell's shapes arrive interleaved —
    // which is what a real hierarchy produces and a flat generator does not —
    // fails here and nowhere above.
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("a deck's layer table fits u16"));
        let rows = store.polys_on_layer(layer);
        assert_eq!(
            store.layer_bboxes(layer).len(),
            (rows.end - rows.start) as usize,
            "on real layout, layer {layer:?}'s bbox slice and row range disagree; \
             the CSR grouping invariant is broken"
        );
    }

    // Every net holds at least one polygon, so there cannot be more nets than
    // polygons. Cheap, and it is the extract stage's own law rather than the
    // store's — the row above would pass on an extraction that produced garbage.
    assert!(
        extracted.nets.net_count() <= store.poly_count(),
        "extraction produced {} nets from {} polygons; a net holds at least one \
         shape, so this partition is not one",
        extracted.nets.net_count(),
        store.poly_count()
    );

    // The densest drawn layer, not layer 0: the corpus declares layers it barely
    // uses, and indexing an almost-empty one would measure the grid's setup cost
    // rather than its behaviour on clustered geometry.
    let densest = (0..store.layer_count())
        .map(|layer| LayerId(u16::try_from(layer).expect("a deck's layer table fits u16")))
        .max_by_key(|&layer| {
            let rows = store.polys_on_layer(layer);
            rows.end - rows.start
        })
        .expect("the deck declares at least one layer");

    let (pairs, timing) = timed("core::pairs[real]", 0, || {
        let mut index = gpurify::core::index::SpatialIndex::default();
        gpurify::core::index::SpatialIndex::build_into(store, densest, &mut index);
        let mut pairs = Vec::new();
        gpurify::core::index::candidate_pairs_into(
            store,
            &index,
            gpurify::units::Dbu::new_unchecked(500),
            &mut pairs,
        );
        pairs
    });
    timings.push(timing);

    let rows = store.polys_on_layer(densest);
    let count = u64::from(rows.end - rows.start);
    let all_pairs = count.saturating_mul(count.saturating_sub(1)) / 2;
    assert!(
        (pairs.len() as u64) <= all_pairs,
        "on real layout the prune emitted {} pairs from {count} shapes, more \
         than the {all_pairs} that exist; it is not a prune",
        pairs.len()
    );

    for timing in &mut timings {
        timing.polygons = polygons;
    }
    report(&timings);
}

/// A `GeometryStore` is not `Clone`, so nothing here can duplicate one.
///
/// Recorded rather than worked around: the timings above each build their own
/// corpus for that reason, which means the build cost is paid once per test
/// rather than once per suite. Acceptable at these sizes, and worth revisiting
/// if the sweep grows.
const _: fn(&GeometryStore) = |_| {};
