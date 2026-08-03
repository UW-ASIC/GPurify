//! Parasitic extraction: the resistance and capacitance the layout adds.
//!
//! Two paths, and they answer different questions.
//!
//! [`analytical`] applies per-layer closed forms from the deck's process stack —
//! sheet resistance times squares, area plus fringe capacitance, a coupling
//! term between neighbours. Fast, linear in the geometry, and accurate to the
//! extent the deck's coefficients are. This is what a full-chip run uses.
//!
//! [`quasistatic`] solves the field problem: a boundary-element formulation
//! with an FMM-accelerated matvec, no per-layer coefficients, no assumption
//! about geometry. Orders of magnitude slower and correct where the analytical
//! form is not. This is what a critical net gets.
//!
//! # Why the GPU survives only here
//!
//! Every other GPU path in the old tree was an advisory prefilter: the device
//! flagged candidates and the CPU then checked them exactly anyway, so the best
//! case was saving part of the work while paying all of the transfer cost, on
//! kernels with near-zero arithmetic intensity. Quasi-static PEX is the one
//! workload with real flop-per-byte — a dense BEM matvec — and it is the one
//! place a GPU can win. See `docs/GPU.md`.
//!
//! # Determinism
//!
//! Parasitics are floating point, and output must still be byte-identical
//! across runs and thread counts. That constrains this crate specifically:
//! accumulation order is fixed, no reduction reassociates, and nothing here
//! iterates a hash map. The old tree's interlayer-capacitance rows swapped
//! between runs of the same binary because a `HashMap` decided which of two
//! layers was printed first.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

pub mod analytical;
pub mod network;
pub mod quasistatic;
pub mod reduce;

pub use network::{Parasitic, ParasiticNetwork};
