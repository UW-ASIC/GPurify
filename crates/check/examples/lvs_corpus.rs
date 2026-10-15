//! Each canonical verdict of the seeded LVS corpus the `lvs` digest test
//! locks, one per line, to diff two builds case by case when a hash moves:
//!
//! ```sh
//! cargo run --release -p gpurify-check --example lvs_corpus > before.txt
//! ```

#[path = "../tests/lvs/common/mod.rs"]
mod common;

fn main() {
    for verdict in common::seeded_corpus() {
        println!("{}", common::canonical(&verdict));
    }
}
