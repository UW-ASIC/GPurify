//! How long a comparison takes, and the round budget it needs, on large
//! random graphs, SRAM arrays (all tie-breaks) and a long chain, each against
//! a permuted twin and a perturbed one. Printed, never gated:
//!
//! ```sh
//! cargo run --release -p gpurify-check --example lvs_timing
//! ```

#[path = "../tests/lvs/common/mod.rs"]
mod common;

use common::{chain, perm, permute, perturbed, random_graph, GraphBuilder, NCH, PCH};
use gpurify_check::lvs::{compare, CompareOptions, Graph, Verdict};
use gpurify_testgen::Rng;

/// A `rows` x `cols` array of 6T SRAM cells: every row, every column and each
/// cell's two halves are interchangeable, so matching it is all tie-breaks.
fn sram(rows: u32, cols: u32) -> Graph {
    use gpurify_check::topology::TerminalRole::{Bulk, Drain, Gate, Source};
    use gpurify_ingest::deck::DeviceKind::Mos;
    let (vdd, vss) = (0, 1);
    let wl = |r: u32| 2 + r;
    let bl = |c: u32| 2 + rows + 2 * c;
    let cell = |r: u32, c: u32| 2 + rows + 2 * cols + 2 * (r * cols + c);
    let mut b = GraphBuilder::new(2 + rows + 2 * cols + 2 * rows * cols);
    for r in 0..rows {
        for c in 0..cols {
            let (q, qb) = (cell(r, c), cell(r, c) + 1);
            for (store, other, line) in [(q, qb, bl(c)), (qb, q, bl(c) + 1)] {
                b.device(
                    Mos,
                    PCH,
                    &[(Gate, other), (Drain, store), (Source, vdd), (Bulk, vdd)],
                );
                b.device(
                    Mos,
                    NCH,
                    &[(Gate, other), (Drain, store), (Source, vss), (Bulk, vss)],
                );
                b.device(
                    Mos,
                    NCH,
                    &[(Gate, wl(r)), (Drain, line), (Source, store), (Bulk, vss)],
                );
            }
        }
    }
    b.finish()
}

/// The smallest round budget a comparison finishes under, and its verdict then.
fn rounds_needed(layout: &Graph, reference: &Graph) -> (u32, Verdict) {
    let (mut low, mut high) = (1u32, 1u32 << 16);
    while low < high {
        let mid = low + (high - low) / 2;
        let options = CompareOptions {
            max_rounds: mid,
            ..CompareOptions::default()
        };
        match compare(layout, reference, options) {
            Verdict::Inconclusive(_) => low = mid + 1,
            _ => high = mid,
        }
    }
    let options = CompareOptions {
        max_rounds: low,
        ..CompareOptions::default()
    };
    (low, compare(layout, reference, options))
}

/// Thread CPU time in ms; a loaded machine distorts it far less than wall time.
fn cpu_ms() -> u64 {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
    let ns: u64 = stat
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    ns / 1_000_000
}

/// Time one comparison with the round limit lifted, and find the budget it needs.
fn bench_one(label: &str, layout: &Graph, reference: &Graph) {
    let options = CompareOptions {
        max_rounds: u32::MAX,
        ..CompareOptions::default()
    };
    let start = cpu_ms();
    let verdict = std::hint::black_box(compare(layout, reference, options));
    let ms = cpu_ms() - start;
    let (rounds, _) = rounds_needed(layout, reference);
    let kind = match verdict {
        Verdict::Match => "match".to_owned(),
        Verdict::Mismatch(found) => format!("mismatch ({})", found.len()),
        Verdict::Inconclusive(why) => format!("{why:?}"),
    };
    println!("{label}: {ms} ms cpu, needs max_rounds {rounds}, {kind}");
}

fn main() {
    let mut rng = Rng::new(7);
    for (devices, nets) in [(2_000u32, 1_500u32), (50_000, 37_500)] {
        let graph = random_graph(&mut rng, devices, nets);
        let d = perm(&mut rng, graph.device_kind.len());
        let n = perm(&mut rng, graph.net_name.len());
        let twin = permute(&graph, &d, &n);
        bench_one(&format!("random {devices}"), &graph, &twin);
        let broken = perturbed(&mut rng, &twin);
        bench_one(&format!("random {devices} perturbed"), &graph, &broken);
    }
    for side in [16u32, 64] {
        let array = sram(side, side);
        let d = perm(&mut rng, array.device_kind.len());
        let n = perm(&mut rng, array.net_name.len());
        let twin = permute(&array, &d, &n);
        bench_one(&format!("sram {side}x{side}"), &array, &twin);
        let broken = perturbed(&mut rng, &twin);
        bench_one(&format!("sram {side}x{side} perturbed"), &array, &broken);
    }
    let long = chain(3_000);
    bench_one("chain 3000", &long, &long);
}
