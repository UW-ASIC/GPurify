//! Fixtures shared by the `quasistatic` integration tests.
//!
//! Two things live here and nothing else: a byte serialiser for the
//! determinism gate, and the builders that assemble a [`ProcessStack`] and a
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
use gpurify_quasistatic::CapMatrix;
use gpurify_testgen::{scale_corpus, ScaleCorpus, ScaleSpec};
use gpurify_topology::{extract_nets_into, NetId, NetTable};
use gpurify_units::Grid;

/// The 1 nm grid every case in this crate's tests is stated against.
///
/// A function rather than a `const`, because [`Grid::new`] is a `const fn` over
/// a `todo!()` body until the Implementation-Phase and a `const` would evaluate
/// it at compile time.
pub fn grid() -> Grid {
    Grid::new(1_000).expect("1000 database units per micrometre is a 1 nm grid")
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
