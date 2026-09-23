//! Byte-identity lock on the whole comparison: every verdict of a seeded corpus,
//! folded into one hash. Class numbering picks the tie-break and orders
//! `ClassImbalance`, so any change to refinement's hashing or sort shows here.

use crate::common::{chain, differential_pair, permute, random_graph};
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

fn corpus_digest() -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
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
        fnv(&mut hash, &format!("{:?}", run(&graph, &other)));
    }
    for length in [1u32, 2, 7, 40] {
        fnv(
            &mut hash,
            &format!("{:?}", run(&chain(length), &chain(length))),
        );
    }
    fnv(
        &mut hash,
        &format!("{:?}", run(&differential_pair(), &differential_pair())),
    );
    hash
}

#[test]
fn the_seeded_corpus_verdicts_are_unchanged() {
    assert_eq!(corpus_digest(), 7_113_623_324_654_528_209);
}

/// `cargo test --release -p gpurify-check --test lvs bench -- --ignored --nocapture`
/// Thread CPU time in ns; a loaded machine distorts it far less than wall time.
fn cpu_ms() -> u64 {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
    let ns: u64 = stat
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    ns / 1_000_000
}

#[test]
#[ignore = "timing, run by hand"]
fn bench_compare_large_random_graph() {
    let mut rng = Rng::new(7);
    for (devices, nets) in [(2_000u32, 1_500u32), (50_000, 37_500)] {
        let graph = random_graph(&mut rng, devices, nets);
        let d = perm(&mut rng, graph.device_kind.len());
        let n = perm(&mut rng, graph.net_name.len());
        let twin = permute(&graph, &d, &n);
        let start = cpu_ms();
        let verdict = std::hint::black_box(run(&graph, &twin));
        println!(
            "{devices} devices: {} ms cpu ({})",
            cpu_ms() - start,
            matches!(verdict, Verdict::Match)
        );
    }
    let long = chain(3_000);
    let start = cpu_ms();
    let verdict = std::hint::black_box(run(&long, &long));
    println!("chain 3000: {} ms cpu ({verdict:?})", cpu_ms() - start);
}
