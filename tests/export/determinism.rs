//! The gate: every writer, run twice, byte for byte.
//!
//! This is the defect that shipped from the old tree — eight of twenty-seven
//! parasitic outputs differed between runs of the same binary on the same input
//! — and it is the reason every writer in this workspace lives in one crate.
//! A file that differs from itself cannot be diffed against yesterday's, so a
//! regression in it cannot be seen.
//!
//! # What each run varies
//!
//! Three things, because one is not enough:
//!
//! - **A second run in the same thread** catches an iteration order that
//!   depends on allocator addresses or on a hash seed.
//! - **A run on another thread** catches thread-local scratch, a thread id in
//!   the output, and anything a writer memoised per thread. No writer here
//!   takes a thread count — they are single-pass transcribers — so this is the
//!   form the two-thread-count clause of the gate takes for this crate.
//! - **A run after the wall clock has moved past a second boundary** catches a
//!   writer that consulted the clock. Two back-to-back runs would agree even if
//!   one did, because a formatted time has second resolution at best.

use crate::fixture;

use fixture::World;
use gpurify::export::{gds, json, netlist, parasitic};
use gpurify_ingest::deck::LayerTable;
use gpurify_testgen::assert_bytes_identical;

/// Run a writer three ways and demand one answer.
///
/// The nonempty check is load-bearing: comparing two empty buffers proves
/// nothing, and a writer that failed early would otherwise pass the gate.
fn assert_writer_is_deterministic<F>(what: &str, run: F)
where
    F: Fn() -> Vec<u8> + Sync,
{
    let first = run();
    assert!(
        !first.is_empty(),
        "{what} produced no bytes, so comparing two runs of it proves nothing"
    );

    assert_bytes_identical(what, &first, &run());

    let elsewhere = std::thread::scope(|scope| {
        scope
            .spawn(&run)
            .join()
            .expect("the writer panicked on another thread")
    });
    assert_bytes_identical(what, &first, &elsewhere);

    fixture::wait_for_the_next_second();
    assert_bytes_identical(what, &first, &run());
}

/// Oracle: determinism.
#[test]
fn the_json_report_is_byte_identical_across_runs_threads_and_seconds() {
    let world = World::named();
    assert_writer_is_deterministic("the JSON report", || {
        let mut out = String::new();
        json::write_report(&world.report(), &mut out).expect("the report is writable");
        out.into_bytes()
    });
}

/// Oracle: determinism.
#[test]
fn the_rule_run_summary_is_byte_identical_across_runs_threads_and_seconds() {
    let world = World::named();
    assert_writer_is_deterministic("the rule-run summary", || {
        let mut out = String::new();
        json::write_summary(&world.runs, &world.strings, &mut out)
            .expect("the summary is writable");
        out.into_bytes()
    });
}

/// Oracle: determinism.
///
/// GDSII carries library modification and access timestamps in its header
/// record, and `gds::write_store` takes no `Header` — so whatever it puts there
/// cannot come from the clock. That is what the second boundary in the helper
/// checks, and it is the one place in this crate where the clock could leak in
/// without a parameter to blame.
#[test]
fn the_gds_library_is_byte_identical_across_runs_threads_and_seconds() {
    let store = fixture::empty_store();
    let layers = LayerTable::default();
    assert_writer_is_deterministic("the GDS library", || {
        let mut out = Vec::new();
        gds::write_store(&store, &layers, "TOP", &mut out).expect("an empty store is writable");
        out
    });
}

/// Oracle: determinism.
#[test]
fn the_gds_marker_layer_is_byte_identical_across_runs_threads_and_seconds() {
    let world = World::named();
    assert_writer_is_deterministic("the GDS marker layer", || {
        let mut out = Vec::new();
        gds::write_markers(&world.violations, &world.store, fixture::MARKER, &mut out)
            .expect("the markers are writable");
        out
    });
}

/// Oracle: determinism.
#[test]
fn the_spice_netlist_is_byte_identical_across_runs_threads_and_seconds() {
    let world = World::named();
    assert_writer_is_deterministic("the SPICE netlist", || {
        let mut out = String::new();
        netlist::write_spice(
            world.extraction(),
            Some(&world.parasitics),
            netlist::Detail::WithParasitics,
            &world.strings,
            &world.header,
            &mut out,
        )
        .expect("the netlist is writable");
        out.into_bytes()
    });
}

/// Oracle: determinism. The SPEF writer is the one with history: its
/// interlayer-capacitance rows used to carry their layer pair in whichever
/// order a hash map yielded.
#[test]
fn the_spef_file_is_byte_identical_across_runs_threads_and_seconds() {
    let world = World::named();
    assert_writer_is_deterministic("the SPEF file", || {
        let mut out = String::new();
        parasitic::write_spef(
            &world.parasitics,
            &world.ports,
            &world.strings,
            &world.header,
            &mut out,
        )
        .expect("every net in this world is named");
        out.into_bytes()
    });
}

/// Oracle: determinism.
#[test]
fn the_dspf_file_is_byte_identical_across_runs_threads_and_seconds() {
    let world = World::named();
    assert_writer_is_deterministic("the DSPF file", || {
        let mut out = String::new();
        parasitic::write_dspf(
            &world.parasitics,
            &world.ports,
            &world.strings,
            &world.header,
            &mut out,
        )
        .expect("every net in this world is named");
        out.into_bytes()
    });
}

/// Oracle: determinism. Two worlds built from the same recipe are the same
/// world, so everything downstream of them is the same too.
///
/// The three runs above share one set of tables, so they cannot see a writer
/// whose output depends on where its input was allocated. Building the world
/// twice does, and it is the closest this crate gets to the whole-run
/// reproducibility the gate is really about.
#[test]
fn two_independently_built_worlds_produce_the_same_report() {
    let first = World::named();
    let second = World::named();

    let mut left = String::new();
    json::write_report(&first.report(), &mut left).expect("the report is writable");
    let mut right = String::new();
    json::write_report(&second.report(), &mut right).expect("the report is writable");

    assert_bytes_identical("the JSON report", left.as_bytes(), right.as_bytes());
}

/// Oracle: determinism. `out` is appended to, so a caller may write several
/// reports into one buffer — and the second must be the same bytes it would
/// have been on its own. A writer that indexed from the start of the buffer,
/// or cleared it, breaks here.
#[test]
fn appending_a_second_report_leaves_the_first_untouched_and_repeats_it() {
    let world = World::named();

    let mut alone = String::new();
    json::write_report(&world.report(), &mut alone).expect("the report is writable");

    let mut twice = String::new();
    json::write_report(&world.report(), &mut twice).expect("the report is writable");
    json::write_report(&world.report(), &mut twice).expect("the report is writable");

    let doubled = format!("{alone}{alone}");
    assert_bytes_identical("two appended reports", twice.as_bytes(), doubled.as_bytes());
}
