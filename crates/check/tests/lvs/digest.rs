//! Byte-identity lock on the whole comparison: every verdict of a seeded corpus,
//! folded into one hash twice: as listed, and with each report's lines sorted.
//! Class numbering orders `ClassImbalance`, so a numbering change moves only the
//! first; a change in what is reported moves both. Last moved when unsized
//! transistors in parallel began to keep their count in `m` (testing-plan
//! F83): the generated graphs state no parameters and the comparison here
//! names no `m`, so parallel devices no longer merge at all. 186 of 325
//! verdicts match, down from 188: rounds 244 and 246 compare a copy with one
//! terminal moved, which made a device parallel to others, and they matched
//! only because the merge dropped the count. 27 other mismatches list more
//! unpaired devices, the parallel devices that now stay apart.
//!
//! When a hash moves, `cargo run --release -p gpurify-check --example
//! lvs_corpus` prints each canonical verdict on its own line, to diff two
//! builds case by case.
//!
//! Oracle: golden, and the change log above is its review. Nothing outside the
//! code computes these hashes; what makes a value right is that every move was
//! diffed case by case and explained here (which verdicts changed, how many,
//! and why the new ones are correct). A move without that entry is a
//! regression until someone writes it.

use crate::common::{canonical, seeded_corpus};
use gpurify_check::lvs::Verdict;

fn fnv(hash: &mut u64, text: &str) {
    for byte in text.bytes() {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
    }
}

fn digest(verdicts: &[Verdict], text: impl Fn(&Verdict) -> String) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for verdict in verdicts {
        fnv(&mut hash, &text(verdict));
    }
    hash
}

/// The order each report lists its discrepancies in, locked.
///
/// Oracle: golden, reviewed against the change log in the module doc.
#[test]
fn the_seeded_corpus_verdicts_are_unchanged() {
    let verdicts = seeded_corpus();
    assert_eq!(verdicts.len(), 325);
    assert_eq!(
        digest(&verdicts, |v| format!("{v:?}")),
        15_831_399_851_773_943_039
    );
}

/// What each report says, whatever its order.
///
/// Oracle: golden, reviewed against the change log in the module doc.
#[test]
fn the_seeded_corpus_verdicts_say_the_same_in_any_order() {
    assert_eq!(
        digest(&seeded_corpus(), canonical),
        13_774_904_995_842_023_266
    );
}
