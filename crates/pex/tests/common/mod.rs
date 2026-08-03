//! Fixtures shared by the `pex` integration tests.
//!
//! Three things live here and nothing else: a byte serialiser for the
//! determinism gate, the two accessors that get a number back out of a
//! [`Parasitic`], and the builders that assemble a [`ProcessStack`] and a
//! [`NetTable`] from the scale corpus.
//!
//! The serialiser is written out rather than reached for through `Debug`
//! because `Qty`'s `Debug` is a frozen signature over a `todo!()` body until
//! the Implementation-Phase (see `docs/NEED_TESTING.md`), and a determinism
//! check that panics inside its own comparison proves nothing. Bits are the
//! honest form anyway: `to_bits` distinguishes two `f64` that print the same.

#![allow(dead_code, reason = "each test binary links only the fixtures it uses")]

use gpurify_core::GeometryStore;
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use gpurify_pex::network::{Parasitic, ParasiticNetwork};
use gpurify_pex::quasistatic::CapMatrix;
use gpurify_testgen::{scale_corpus, ScaleCorpus, ScaleSpec};
use gpurify_topology::{extract_nets_into, NetId, NetTable};

/// Every column of a network, as bytes.
///
/// Node columns first, then element columns, each field little-endian and
/// floats by their bit pattern. Two networks serialise identically exactly
/// when they hold the same rows in the same order with the same values — which
/// is what "byte-identical across runs" has to mean for a table that is never
/// itself written to a file by this crate.
pub fn serialise(network: &ParasiticNetwork) -> Vec<u8> {
    assert_eq!(
        network.node_net.len(),
        network.node_layer.len(),
        "the node columns must stay parallel"
    );
    assert_eq!(
        network.from.len(),
        network.to.len(),
        "the element columns must stay parallel"
    );
    assert_eq!(
        network.from.len(),
        network.value.len(),
        "the element columns must stay parallel"
    );

    let mut out = Vec::with_capacity(6 * network.node_net.len() + 13 * network.from.len());
    for (net, layer) in network.node_net.iter().zip(&network.node_layer) {
        out.extend_from_slice(&net.0.to_le_bytes());
        out.extend_from_slice(&layer.0.to_le_bytes());
    }
    for ((from, to), value) in network.from.iter().zip(&network.to).zip(&network.value) {
        out.extend_from_slice(&from.0.to_le_bytes());
        // `None` is ground. `u32::MAX` is not a reachable node id here and is
        // only ever a marker inside this encoding.
        out.extend_from_slice(&to.map_or(u32::MAX, |node| node.0).to_le_bytes());
        let (tag, raw) = match *value {
            Parasitic::Resistance(q) => (0u8, q.raw()),
            Parasitic::GroundCap(q) => (1u8, q.raw()),
            Parasitic::CouplingCap(q) => (2u8, q.raw()),
            Parasitic::Inductance(q) => (3u8, q.raw()),
        };
        out.push(tag);
        out.extend_from_slice(&raw.to_bits().to_le_bytes());
    }
    out
}

/// A capacitance matrix's entries, as bytes. The determinism gate for a solve.
pub fn serialise_matrix(matrix: &CapMatrix) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * matrix.net.len() + 8 * matrix.value.len());
    for net in &matrix.net {
        out.extend_from_slice(&net.0.to_le_bytes());
    }
    for value in &matrix.value {
        out.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    out
}

/// Femtofarads on a capacitive element, `None` on any other kind.
pub fn capacitance_ff(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => Some(q.raw()),
        Parasitic::Resistance(_) | Parasitic::Inductance(_) => None,
    }
}

/// Ohms on a resistive element, `None` on any other kind.
pub fn resistance_ohm(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::Resistance(q) => Some(q.raw()),
        Parasitic::GroundCap(_) | Parasitic::CouplingCap(_) | Parasitic::Inductance(_) => None,
    }
}

/// A process stack of `rows` identical layers.
///
/// Uniform on purpose: a test scaling one coefficient wants every other number
/// held fixed, and a stack whose rows differ would let a layer mix-up cancel
/// against a coefficient error.
pub fn uniform_stack(rows: usize, area_af_um2: f64, fringe_af_um: f64) -> ProcessStack {
    ProcessStack {
        thickness_nm: vec![100.0; rows],
        height_nm: vec![300.0; rows],
        sheet_res_ohm_sq: vec![0.1; rows],
        area_cap_af_um2: vec![area_af_um2; rows],
        fringe_cap_af_um: vec![fringe_af_um; rows],
        dielectric_k: vec![3.9; rows],
    }
}

/// A corpus, its extracted nets, and the net ids its combs landed on.
pub struct Extracted {
    pub corpus: ScaleCorpus,
    pub nets: NetTable,
    /// One id per entry of `corpus.expected_net_polys`, read back through
    /// [`NetTable::net_of`] rather than assumed to be `NetId(n)`.
    pub selected: Vec<NetId>,
}

impl Extracted {
    pub fn store(&self) -> &GeometryStore {
        &self.corpus.store
    }

    pub fn connectivity(&self) -> &Connectivity {
        &self.corpus.connectivity
    }
}

/// Build a scale corpus and extract its nets.
///
/// The partition is known by construction — that is what `scale_corpus` is for
/// — so this is a construct-from-answer fixture and not a second oracle.
pub fn extracted(seed: u64, polygons: u32, nets: u32) -> Extracted {
    let corpus = scale_corpus(ScaleSpec {
        seed,
        polygons,
        nets,
        hierarchy_depth: 1,
    });
    let mut table = NetTable::default();
    extract_nets_into(&corpus.store, &corpus.connectivity, &mut table);
    let selected = corpus
        .expected_net_polys
        .iter()
        .map(|polys| table.net_of(*polys.first().expect("every comb has at least a rail")))
        .collect();
    Extracted {
        corpus,
        nets: table,
        selected,
    }
}
