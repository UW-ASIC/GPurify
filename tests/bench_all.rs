//! Timing tables, recorded and never gated:
//!
//! ```sh
//! cargo test --release --test bench_all -- --ignored --nocapture
//! ```
//!
//! One table per stage against polygon count (watch `ns/poly` stay flat), and
//! one per deck rule on `tests/fixtures/_source/conformance.gds`.

use gpurify::check::topology::NetTable;
use gpurify::engine::pipeline::{extract, load, Inputs};
use gpurify::engine::run::{run_checks, Checks, RunOptions};
use gpurify::geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify::geom::{Dbu, Grid, LayerId};
use gpurify::ingest::layout::UnknownLayers;
use gpurify_testgen::{scale_corpus, ScaleCorpus, ScaleSpec};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SIZES: [u32; 3] = [1_000, 10_000, 100_000];

fn corpus(polygons: u32) -> ScaleCorpus {
    scale_corpus(ScaleSpec {
        seed: 0x5EED,
        polygons,
        nets: (polygons / 16).max(1),
        hierarchy_depth: 2,
    })
}

fn timed<T>(work: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = work();
    (value, start.elapsed())
}

fn row(stage: &str, polygons: usize, elapsed: Duration) {
    #[allow(clippy::cast_precision_loss, reason = "a printed ratio")]
    let per = elapsed.as_secs_f64() * 1e9 / polygons.max(1) as f64;
    println!("  {stage:<24} {polygons:>9} {elapsed:>12?} {per:>12.1}");
}

fn pairs_on(store: &gpurify::geom::GeometryStore, layer: LayerId) -> usize {
    let mut index = SpatialIndex::default();
    SpatialIndex::build_into(store, layer, &mut index);
    let mut pairs = Vec::new();
    candidate_pairs_into(store, &index, Dbu::new_unchecked(500), &mut pairs);
    pairs.len()
}

#[test]
#[ignore = "timing table; run with --release -- --ignored --nocapture"]
fn stage_timings_across_the_scale_corpus() {
    println!("\n  stage                    polygons        total      ns/poly");
    for polygons in SIZES {
        let n = polygons as usize;
        let (corpus, elapsed) = timed(|| corpus(polygons));
        row("testgen::scale_corpus", n, elapsed);
        let (_, elapsed) = timed(|| {
            let mut nets = NetTable::default();
            gpurify::check::topology::extract_nets_into(
                &corpus.store,
                &corpus.connectivity,
                &mut nets,
            );
        });
        row("topology::extract_nets", n, elapsed);
        let (_, elapsed) = timed(|| pairs_on(&corpus.store, LayerId(0)));
        row("geom::candidate_pairs", n, elapsed);
    }

    // Real, clustered geometry. Not comparable with the sweep: fixed per-run
    // costs dominate at this size.
    let dir = scratch_dir("stages");
    let deck = dir.join("rules.deck");
    std::fs::write(&deck, unlabelled_deck().join("\n")).expect("writable");
    let inputs = fixture_inputs(&deck);
    let (loaded, elapsed) = timed(|| load(&inputs).expect("the fixture corpus loads"));
    let n = loaded.store.poly_count();
    assert!(n > 0, "the fixture library loaded no polygons");
    row("engine::load[real]", n, elapsed);
    let (_, elapsed) = timed(|| extract(&loaded).expect("the fixture corpus extracts"));
    row("engine::extract[real]", n, elapsed);
    let densest = (0..loaded.store.layer_count())
        .map(|layer| LayerId(u16::try_from(layer).expect("a u16 layer")))
        .max_by_key(|&layer| loaded.store.polys_on_layer(layer).len())
        .expect("at least one layer");
    let (_, elapsed) = timed(|| pairs_on(&loaded.store, densest));
    row("geom::candidate_pairs[real]", n, elapsed);
    let _ = std::fs::remove_dir_all(&dir);
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// `params.deck`'s lines without its label pairing: the library's cells all
/// overlap at the origin, so merged nets would carry conflicting names.
fn unlabelled_deck() -> Vec<String> {
    let source = std::fs::read_to_string(fixtures().join("params.deck")).expect("readable");
    source
        .lines()
        .filter(|line| !line.starts_with("connect label"))
        .map(str::to_owned)
        .collect()
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gpurify-bench-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// The whole conformance library. `Drop`, because it draws layers `params.deck`
/// never declares.
fn fixture_inputs(deck: &Path) -> Inputs {
    Inputs {
        layout: fixtures().join("_source/conformance.gds"),
        deck: deck.to_path_buf(),
        grid: Some(Grid::new(1000).expect("a 1 nm grid")),
        reference: None,
        intent: None,
        unknown_layers: UnknownLayers::Drop,
    }
}

const RULE_ITERS: u32 = 50;

/// Each deck rule alone, averaged over `RULE_ITERS` `run_checks` calls, less the
/// cost of the same call on a deck with no rules (the minimum of three, after
/// one cold call).
#[test]
#[ignore = "timing table; run with --release -- --ignored --nocapture"]
fn every_rule_in_the_deck_timed_on_its_own() {
    let (rules, base): (Vec<String>, Vec<String>) = unlabelled_deck()
        .into_iter()
        .partition(|line| line.starts_with("rule "));
    let dir = scratch_dir("rules");

    let timed_deck = |tag: &str, rule: &str, checks: Checks| {
        let path = dir.join(format!("{tag}.deck"));
        std::fs::write(&path, format!("{}\n{rule}\n", base.join("\n"))).expect("writable");
        let loaded = load(&fixture_inputs(&path)).expect("the fixture corpus loads");
        let extracted = extract(&loaded).expect("the fixture corpus extracts");
        let options = RunOptions {
            checks,
            lvs: gpurify::check::lvs::CompareOptions::default(),
            quasistatic_nets: Vec::new(),
            quasistatic_inductance: false,
        };
        let start = Instant::now();
        let mut record = None;
        for _ in 0..RULE_ITERS {
            let (out, _) = run_checks(&loaded, &extracted, &options)
                .unwrap_or_else(|why| panic!("{tag}: {why}"));
            record = out.runs.first().copied();
        }
        (start.elapsed() / RULE_ITERS, record)
    };
    // ERC only for ERC's own kinds: its power-net extraction swamps a DRC rule.
    let checks_for = |kind: &str| Checks {
        drc: true,
        erc: gpurify::check::erc::ruleset::KINDS.contains(&kind),
        lvs: false,
        pex: false,
    };
    let floor = |checks: Checks| {
        let _cold = timed_deck("baseline", "", checks);
        (0..3)
            .map(|_| timed_deck("baseline", "", checks).0)
            .min()
            .expect("three measurements")
    };
    let drc_floor = floor(checks_for("min_width"));
    let erc_floor = floor(checks_for(gpurify::check::erc::ruleset::KINDS[0]));

    let mut rows = Vec::new();
    for rule in &rules {
        // `rule <id> [warning] <kind>(...`; an ERC kind is spelled as the engine spells it.
        let mut words = rule.split_whitespace().skip(1);
        let id = words.next().expect("a rule id").to_owned();
        let kind = words
            .find(|word| *word != "warning")
            .and_then(|word| word.split('(').next())
            .expect("a kind");
        let checks = checks_for(kind);
        let (call, record) = timed_deck(&id, rule, checks);
        let floor = if checks.erc { erc_floor } else { drc_floor };
        rows.push((call.saturating_sub(floor), id, record, call));
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        rows.iter()
            .any(|(_, _, record, _)| record.is_some_and(|run| run.examined > 0)),
        "no rule examined anything, so the table would time a deck that never reached the layout"
    );

    rows.sort_by_key(|row| std::cmp::Reverse(row.0));
    println!("\n  rule                             outcome                   examined          rule      whole call");
    for (rule_only, id, record, call) in rows {
        let outcome =
            record.map_or_else(|| "NoRecord".to_owned(), |run| format!("{:?}", run.outcome));
        let examined = record.map_or(0, |run| run.examined);
        println!("  {id:<32} {outcome:<24} {examined:>8} {rule_only:>13?} {call:>15?}");
    }
    println!("\n  baseline: drc {drc_floor:?}, erc {erc_floor:?}\n");
}
