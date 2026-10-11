//! Byte-identity lock on the whole comparison: every verdict of a seeded corpus,
//! folded into one hash twice: as listed, and with each report's lines sorted.
//! Class numbering orders `ClassImbalance`, so a numbering change moves only the
//! first; a change in what is reported moves both. Last moved when a series
//! merge began to need `L` on both devices (testing-plan F67): the generated
//! graphs state no parameters, so their stacks stop merging. The same 188 of
//! 325 verdicts match, and one mismatch lists one more unpaired device on
//! each side (10 to 11) and one more unpaired net on each (7 to 8), the stack
//! that is now two devices and keeps its middle net.
//!
//! When a hash moves, `cargo run --release -p gpurify-check --example
//! lvs_corpus` prints each canonical verdict on its own line, to diff two
//! builds case by case.

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
#[test]
fn the_seeded_corpus_verdicts_are_unchanged() {
    let verdicts = seeded_corpus();
    assert_eq!(verdicts.len(), 325);
    assert_eq!(
        digest(&verdicts, |v| format!("{v:?}")),
        4_344_967_435_229_249_166
    );
}

/// What each report says, whatever its order.
#[test]
fn the_seeded_corpus_verdicts_say_the_same_in_any_order() {
    assert_eq!(
        digest(&seeded_corpus(), canonical),
        9_965_298_889_440_497_151
    );
}
