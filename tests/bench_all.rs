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
//! # Two tables, not one
//!
//! The sweep below prints per *stage* — load, extract, index — against polygon
//! count. [`every_rule_in_the_deck_is_timed_on_its_own`] prints per *rule*,
//! against the population that rule examined. They answer different questions
//! ("is a stage quadratic" versus "which rule is the slow one") and have no
//! column in common but the duration, so they are two printers rather than one
//! with a union of columns that serves neither.

use gpurify::check::report::RuleRun;
use gpurify::check::topology::NetTable;
use gpurify::engine::pipeline::{extract_into, load_into, Extracted, Inputs, Loaded};
use gpurify::engine::run::{run_checks, Checks, Outputs, RunOptions};
use gpurify::geom::Grid;
use gpurify::geom::{GeometryStore, LayerId};
use gpurify::ingest::layout::UnknownLayers;
use gpurify_testgen::{scale_corpus, ScaleCorpus, ScaleSpec};
use std::path::Path;
use std::sync::OnceLock;
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
    (
        value,
        Timing {
            stage,
            polygons,
            elapsed,
        },
    )
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
            gpurify::check::topology::extract_nets_into(
                &corpus.store,
                &corpus.connectivity,
                &mut nets,
            );
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
            let lowest = polys
                .iter()
                .copied()
                .min()
                .expect("a net has at least one shape");
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
            let layer = gpurify::geom::LayerId(u16::try_from(layer).expect("layer fits u16"));
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
        let layer = gpurify::geom::LayerId(0);

        let (pairs, timing) = timed("core::candidate_pairs", polygons, || {
            let mut index = gpurify::geom::index::SpatialIndex::default();
            gpurify::geom::index::SpatialIndex::build_into(&corpus.store, layer, &mut index);
            let mut pairs = Vec::new();
            gpurify::geom::index::candidate_pairs_into(
                &corpus.store,
                &index,
                gpurify::geom::Dbu::new_unchecked(500),
                &mut pairs,
            );
            pairs
        });

        let rows = corpus.store.polys_on_layer(layer);
        let count = u64::from(rows.end - rows.start);
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

/// `params.json` with its `connectivity.labels` pairing removed, written to a
/// scratch file, and the path to it.
///
/// # Why the benchmark cannot claim the labels
///
/// Every test below loads `_source/conformance.gds` **whole**, and that library
/// is 134 cells all drawn starting at the origin — nearly every one of its 8911
/// cell pairs overlaps. `intra_layer_touch` is true, so flattening them into one
/// store merges nearly everything: measured, 391 polygons become 19 nets, one of
/// which holds 259 of the 313 that are on a net at all.
///
/// Those numbers moved when `ERC_EM_DEV` was drawn, and the direction is worth
/// stating: it is the corpus's **first `licon`**, and at (380, 60)-(460, 140) it
/// lands inside `ERC_EM`'s second li rectangle, so in the merged store it bridges
/// the giant diff net to the giant li net. One net fewer, and the largest one
/// larger by 48 polygons. Per-case fixtures see none of it.
///
/// The per-case fixtures are unaffected, because each is one cell in its own
/// file. But in the merged store one net carries a label from every cell that
/// contributed to it, and two different names on one net is
/// `PortError::ConflictingLabels` — which stops the load outright. Stripping
/// the pairing is what keeps the benchmark loading; nothing here reads a net
/// name.
///
/// # This is a workaround, and the thing being worked around is worth knowing
///
/// The merge is not new and is not caused by the labels — it is what this
/// benchmark has always measured. Ten of the ERC rules it times read the
/// `NetTable`, and they are timed against a net graph no real layout produces;
/// `check_soft_connection`'s per-net component labelling is the clearest case,
/// since one 211-polygon net does in a single call what a design spreads over
/// hundreds of independent small ones. The DRC rules and the geometry-only ERC
/// rules — `check_missing_tie` among them, which reads `design.store` and
/// `design.derived` and no net at all — are unaffected.
/// Written exactly once per process, behind a [`OnceLock`].
///
/// The scratch path is scoped by process id, but the two callers are separate
/// `#[test]`s in one binary and so run as parallel threads of one process:
/// both used to write the same path, and `fs::write` truncates before it
/// writes, so one could read the file while the other had emptied it. That is
/// a flake, and it reads as "params.json parses" failing on a deck that is
/// perfectly valid. The content is a pure function of the fixture deck, so one
/// copy serves every caller and there is nothing left to race on.
fn unlabelled_deck(fixtures: &Path) -> std::path::PathBuf {
    static DECK: OnceLock<std::path::PathBuf> = OnceLock::new();
    DECK.get_or_init(|| {
        let source = std::fs::read_to_string(fixtures.join("params.json"))
            .expect("the fixture deck is readable");
        let mut deck: serde_json::Value =
            serde_json::from_str(&source).expect("the fixture deck is JSON");
        deck["connectivity"]
            .as_object_mut()
            .expect("the deck declares connectivity")
            .remove("labels");

        let dir = std::env::temp_dir().join(format!("gpurify-bench-deck-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the scratch directory is writable");
        let path = dir.join("params.json");
        std::fs::write(&path, deck.to_string()).expect("the scratch directory is writable");
        path
    })
    .clone()
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
        deck: unlabelled_deck(&fixtures),
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
        load_into(&inputs, &mut loaded).expect("the fixture corpus loads");
    });
    timings.push(timing);

    let mut extracted = Extracted::default();
    let ((), timing) = timed("engine::extract[real]", 0, || {
        extract_into(&loaded, &mut extracted).expect("the fixture corpus extracts");
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
        let mut index = gpurify::geom::index::SpatialIndex::default();
        gpurify::geom::index::SpatialIndex::build_into(store, densest, &mut index);
        let mut pairs = Vec::new();
        gpurify::geom::index::candidate_pairs_into(
            store,
            &index,
            gpurify::geom::Dbu::new_unchecked(500),
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

// ---------------------------------------------------------------------------
// Per rule.
// ---------------------------------------------------------------------------

/// How many times each rule is run before the total is divided.
///
/// The cheap rules on this layout finish in single-digit microseconds, which is
/// inside the noise of one `Instant::now()` pair. Fifty runs of the same rule
/// over the same extracted store puts the total safely above the clock's
/// resolution without making the suite slow — the whole table is 40 × 50 runs
/// over a 30 KB layout.
const RULE_ITERS: u32 = 50;

/// One rule's cost, and the population it was paid over.
struct RuleTiming {
    /// The deck row id, which is also what a `RuleRun` reports against and what
    /// a violation names. One key, so a slow row here is grep-able in a report.
    rule: String,
    /// `Ran`, `Refused` or `Skipped(..)`, printed rather than assumed. A rule
    /// that skipped is not a fast rule, and a table that did not say so would
    /// read as though it were.
    outcome: String,
    examined: u64,
    /// One whole `run_checks` call with this rule as the deck's only row.
    call: Duration,
    /// What the same call costs on a deck with no rules at all, under the same
    /// [`Checks`] this row ran under. Held per row because a DRC row and an ERC
    /// row do not pay the same shared cost.
    baseline: Duration,
}

impl RuleTiming {
    /// The call, less the cost a deck with no rules at all pays.
    ///
    /// **This subtraction is what makes the table readable, and it is why the
    /// baseline is measured rather than assumed.** `run_checks` does work before
    /// any rule is dispatched — both rule sets are built from the deck, and ERC
    /// extracts the power nets — and that cost is paid once per call whatever
    /// the deck holds. Reporting it against each rule puts a floor under all
    /// forty rows and buries the one that actually costs something.
    ///
    /// Saturating, because a rule cheaper than the run-to-run variation in the
    /// baseline would otherwise report a negative duration. Such a row prints
    /// zero, which is the honest reading: below the noise of the shared cost.
    fn rule_only(&self) -> Duration {
        self.call.saturating_sub(self.baseline)
    }

    /// Nanoseconds per examined element, or `None` when the rule examined
    /// nothing and the ratio would be a division by zero dressed as a speed.
    fn per_examined_ns(&self) -> Option<f64> {
        (self.examined > 0).then(|| {
            self.rule_only().as_secs_f64() * 1e9
                / f64::from(u32::try_from(self.examined).unwrap_or(u32::MAX))
        })
    }
}

/// Print the per-rule record, slowest first.
///
/// Descending by the rule-only column, because the question this table answers
/// is "which rule is the slow one" and the answer should be line one.
fn report_rules(timings: &mut [RuleTiming], floors: [(&str, Duration, Duration); 2]) {
    // Descending, so `Reverse` rather than a flipped `cmp`.
    timings.sort_by_key(|timing| core::cmp::Reverse(timing.rule_only()));

    println!("\n  rule                             outcome                   examined          rule   ns/examined      whole call");
    println!("  --------------------------------------------------------------------------------------------------------------");
    for timing in timings.iter() {
        let ratio = timing
            .per_examined_ns()
            .map_or_else(|| "-".to_owned(), |value| format!("{value:.1}"));
        println!(
            "  {:<32} {:<24} {:>8} {:>13?} {:>13} {:>15?}",
            timing.rule,
            timing.outcome,
            timing.examined,
            timing.rule_only(),
            ratio,
            timing.call
        );
    }
    println!(
        "\n  {RULE_ITERS} runs per rule over tests/fixtures/_source/conformance.gds, \n  \
         each one a whole `run_checks` on a deck holding that rule alone. The \n  \
         `rule` column is `whole call` less the no-rules baseline for that row's \n  \
         domain:"
    );
    for (domain, floor, spread) in floors {
        println!(
            "    {domain:<4} {floor:?}, which itself moved {spread:?} across three measurements"
        );
    }
    println!(
        "  A `rule` under its domain's spread is the shared cost wobbling, not a \n  \
         rule; one worth finding is a multiple of it. Recorded, not gated — \n  \
         nothing here fails on a duration.\n"
    );
}

/// Oracle: law, per rule — plus the timing record.
///
/// Every deck row runs alone, so a row's cost is its own and not the tail of the
/// one before it. Isolation is the whole point: a 40-rule deck timed as one
/// number says a run took 8 ms and nothing about which of the 40 spent it.
///
/// The law underneath is that the table is not measuring an empty deck. A rule
/// that never reached any geometry is fast for a reason that is not speed, and
/// 40 such rows would print a beautiful table of nothing — the same fail-open
/// shape `examined > 0` closes on the corpus side.
#[test]
fn every_rule_in_the_deck_is_timed_on_its_own() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    // The pairing-free copy, for the reason `unlabelled_deck` gives: every load
    // below is of the whole library, where the cells overlap and one merged net
    // would carry a name from each of them.
    let deck: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(unlabelled_deck(&fixtures)).expect("the scratch deck is written"),
    )
    .expect("params.json parses");
    let rules = deck["rules"]
        .as_object()
        .expect("params.json declares a rules object")
        .clone();

    let dir = std::env::temp_dir().join(format!("gpurify-bench-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory can be created");

    // One `run_checks` averaged over `RULE_ITERS`, on the whole deck with
    // `rules` replaced by `rows`. The layer table, the connectivity and the
    // process stack all stay: a rule stripped of the layers it names cannot run
    // at all, and neither can ERC without a sheet resistance.
    let timed_deck =
        |tag: &str, rows: serde_json::Value, checks: Checks| -> (Duration, Option<RuleRun>) {
            let mut one = deck.clone();
            one["rules"] = rows;
            let deck_path = dir.join(format!("{tag}.json"));
            std::fs::write(&deck_path, one.to_string()).expect("the scratch directory is writable");

            let inputs = Inputs {
                layout: fixtures.join("_source/conformance.gds"),
                deck: deck_path,
                grid: Some(
                    Grid::new(FIXTURE_DBU_PER_UM).expect("a thousand dbu per micrometre is a grid"),
                ),
                reference: None,
                intent: None,
                unknown_layers: UnknownLayers::Drop,
            };

            // Loaded and extracted once, outside the clock. Both are shared by every
            // rule in a real run, so charging them to each row would time the
            // pipeline forty times and call it rule cost.
            let mut loaded = Loaded::default();
            load_into(&inputs, &mut loaded).expect("the fixture corpus loads");
            let mut extracted = Extracted::default();
            extract_into(&loaded, &mut extracted).expect("the fixture corpus extracts");

            let options = RunOptions {
                checks,
                lvs: gpurify::check::lvs::CompareOptions::default(),
                quasistatic_nets: Vec::new(),
                quasistatic_inductance: false,
                threads: Some(1),
            };

            let mut outputs = Outputs::default();
            let start = Instant::now();
            for _ in 0..RULE_ITERS {
                outputs = Outputs::default();
                run_checks(&loaded, &extracted, &options, &mut outputs)
                    .unwrap_or_else(|why| panic!("{tag}: {why}"));
            }
            let elapsed = start.elapsed();
            (elapsed / RULE_ITERS, outputs.runs.first().copied())
        };

    // ERC is selected only for rules ERC owns, and that is not tidiness — it is
    // what makes 24 of the 40 rows readable. `run_erc` extracts the power nets
    // before it dispatches anything, costing about 5 ms on this layout whatever
    // the deck holds, which is a hundred times what a DRC rule costs and swamps
    // it. A DRC row timed with ERC off has a floor a hundred microseconds high
    // instead. Each row is therefore compared against the baseline of its own
    // domain, never the other's.
    let checks_for = |kind: &str| Checks {
        drc: true,
        erc: gpurify::check::erc::ruleset::KINDS.contains(&kind),
        lvs: false,
        pex: false,
    };

    // The shared cost of a call, measured on a deck that declares no rules at
    // all. Everything above it in the table is rule work; everything below it is
    // the pipeline getting to the dispatcher.
    //
    // Measured four times: the first is thrown away and the other three are
    // kept, and every part of that is load-bearing.
    //
    // The first is discarded because the first `run_checks` in the process is
    // cold — measured at 7.9 ms against 5.5 warm, a 45% overshoot that is larger
    // than any rule in the table except one. Keeping it would inflate the spread
    // below to 2.4 ms and declare the entire table unreadable.
    //
    // The baseline is the **minimum** of the three, not the mean, because it is
    // a floor being subtracted: the smallest floor ever observed is the one that
    // cannot over-subtract, and over-subtracting reports a real cost as zero.
    let empty = || serde_json::Value::Object(serde_json::Map::new());
    let floor = |checks: Checks| -> (Duration, Duration) {
        let (_cold, no_rules) = timed_deck("baseline", empty(), checks);
        assert!(
            no_rules.is_none(),
            "a deck with no rules recorded a RuleRun, so the baseline is timing \
             a rule and every row below it is understated by that rule's cost"
        );
        let floors = [
            timed_deck("baseline", empty(), checks).0,
            timed_deck("baseline", empty(), checks).0,
            timed_deck("baseline", empty(), checks).0,
        ];
        let least = floors
            .into_iter()
            .min()
            .expect("three measurements have a minimum");
        // How far the floor moved while nothing about the deck changed. Carried
        // out to the printer, because it is the resolution of every other row:
        // a rule whose subtracted cost is under it is the shared cost wobbling.
        let spread = floors
            .into_iter()
            .max()
            .expect("three measurements have a maximum")
            .saturating_sub(least);
        (least, spread)
    };
    let (drc_floor, drc_spread) = floor(checks_for("min_width"));
    let (erc_floor, erc_spread) = floor(checks_for(gpurify::check::erc::ruleset::KINDS[0]));

    let mut timings = Vec::with_capacity(rules.len());
    for (id, spec) in &rules {
        let kind = spec["kind"].as_str().expect("every deck row states a kind");
        let checks = checks_for(kind);
        let rows = serde_json::Value::Object([(id.clone(), spec.clone())].into_iter().collect());
        let (call, record) = timed_deck(id, rows, checks);
        timings.push(RuleTiming {
            rule: id.clone(),
            outcome: record
                .map_or_else(|| "NoRecord".to_owned(), |run| format!("{:?}", run.outcome)),
            examined: record.map_or(0, |run| run.examined),
            call,
            baseline: if checks.erc { erc_floor } else { drc_floor },
        });
    }

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        timings.len(),
        rules.len(),
        "params.json declares {} rules and {} were timed",
        rules.len(),
        timings.len()
    );
    assert!(
        timings.iter().map(|timing| timing.examined).sum::<u64>() > 0,
        "all {} rules examined nothing; the table below would be forty rows of a \
         deck that never reached the layout, which is fast for a reason that is \
         not speed",
        timings.len()
    );

    report_rules(
        &mut timings,
        [
            ("drc", drc_floor, drc_spread),
            ("erc", erc_floor, erc_spread),
        ],
    );
}

/// A `GeometryStore` is not `Clone`, so nothing here can duplicate one.
///
/// Recorded rather than worked around: the timings above each build their own
/// corpus for that reason, which means the build cost is paid once per test
/// rather than once per suite. Acceptable at these sizes, and worth revisiting
/// if the sweep grows.
const _: fn(&GeometryStore) = |_| {};
