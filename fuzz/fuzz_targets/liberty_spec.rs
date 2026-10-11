//! `cargo fuzz run liberty_spec`: the entry point and oracle are `oracles::liberty_spec`.
#![no_main]
#![allow(dead_code, reason = "one oracle per target; the harness is shared")]

#[path = "../../tests/exhaustive/harness.rs"]
mod harness;
#[path = "../../tests/exhaustive/bitmap.rs"]
mod bitmap;
#[path = "../oracles.rs"]
mod oracles;

libfuzzer_sys::fuzz_target!(|data: &[u8]| oracles::liberty_spec(data));
