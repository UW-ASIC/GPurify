//! Byte-identity lock on the whole comparison: every verdict of a seeded corpus,
//! folded into one hash twice: as listed, and with each report's lines sorted.
//! Class numbering orders `ClassImbalance`, so a numbering change moves only the
//! first; a change in what is reported moves both. Last moved when a net with
//! no terminal and no name stopped being reported unpaired: the same 188 of
//! 325 verdicts match, and only those lines left the reports.

use crate::common::{chain, differential_pair, permute, random_graph, GraphBuilder, NCH, PCH};
use gpurify_check::lvs::{compare, CompareOptions, Graph, Verdict};
use gpurify_testgen::Rng;

fn run(layout: &Graph, reference: &Graph) -> Verdict {
    compare(layout, reference, CompareOptions::default())
}

fn perm(rng: &mut Rng, n: usize) -> Vec<u32> {
    let mut map: Vec<u32> = (0..u32::try_from(n).expect("small")).collect();
    rng.shuffle(&mut map);
    map
}

/// A copy with one terminal moved to another net: a real mismatch.
fn perturbed(rng: &mut Rng, graph: &Graph) -> Graph {
    let mut out = graph.clone();
    let slot = usize::try_from(rng.below(out.terminal_net.len() as u64)).expect("small");
    let nets = out.net_name.len() as u64;
    out.terminal_net[slot] = u32::try_from(rng.below(nets)).expect("small");
    let net_count = out.net_name.len();
    // Rebuild the net side through a no-op reduce-free transpose: permute with identity.
    let ids: Vec<u32> = (0..u32::try_from(out.device_kind.len()).expect("small")).collect();
    let nets: Vec<u32> = (0..u32::try_from(net_count).expect("small")).collect();
    permute(&out, &ids, &nets)
}

fn fnv(hash: &mut u64, text: &str) {
    for byte in text.bytes() {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
    }
}

/// Every verdict of the seeded corpus, in a fixed order.
fn corpus() -> Vec<Verdict> {
    let mut verdicts = Vec::new();
    let mut rng = Rng::new(0x5eed);
    for round in 0..320u32 {
        let scale = if round < 300 { 40 } else { 400 };
        let devices = 1 + u32::try_from(rng.below(scale)).expect("small");
        let nets = 1 + u32::try_from(rng.below(scale * 3 / 4)).expect("small");
        let graph = random_graph(&mut rng, devices, nets);
        let d = perm(&mut rng, graph.device_kind.len());
        let n = perm(&mut rng, graph.net_name.len());
        let twin = permute(&graph, &d, &n);
        let other = if round % 2 == 0 {
            perturbed(&mut rng, &twin)
        } else {
            twin
        };
        verdicts.push(run(&graph, &other));
    }
    for length in [1u32, 2, 7, 40] {
        verdicts.push(run(&chain(length), &chain(length)));
    }
    verdicts.push(run(&differential_pair(), &differential_pair()));
    verdicts
}

/// A verdict's text with its discrepancies sorted: equal exactly when two
/// verdicts report the same differences, whatever order they list them in.
fn canonical(verdict: &Verdict) -> String {
    let Verdict::Mismatch(found) = verdict else {
        return format!("{verdict:?}");
    };
    let mut lines: Vec<String> = found.iter().map(|d| format!("{d:?}")).collect();
    lines.sort_unstable();
    format!("Mismatch{lines:?}")
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
    let verdicts = corpus();
    assert_eq!(verdicts.len(), 325);
    assert_eq!(
        digest(&verdicts, |v| format!("{v:?}")),
        12_557_331_768_539_182_788
    );
}

/// What each report says, whatever its order.
#[test]
fn the_seeded_corpus_verdicts_say_the_same_in_any_order() {
    assert_eq!(digest(&corpus(), canonical), 7_852_899_496_541_594_499);
}

/// `cargo test --release -p gpurify-check --test lvs dump_corpus -- --ignored`
/// writes each canonical verdict on its own line, to diff two builds case by case.
#[test]
#[ignore = "diagnostic, run by hand"]
fn dump_corpus() {
    let text: Vec<String> = corpus().iter().map(canonical).collect();
    let path = std::env::var("LVS_CORPUS_DUMP").unwrap_or_else(|_| "lvs_corpus.txt".into());
    std::fs::write(path, text.join("\n")).expect("writable");
}

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

/// `cargo test --release -p gpurify-check --test lvs bench -- --ignored --nocapture`
#[test]
#[ignore = "timing, run by hand"]
fn bench_compare_large_random_graph() {
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
