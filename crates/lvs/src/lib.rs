//! Layout versus schematic: does the extracted netlist match the reference?
//!
//! This crate is **graph matching and nothing else**. In the old tree it was
//! 20k lines covering a SPICE parser, a Spectre parser, a SPICE writer, device
//! extraction, connectivity and hierarchy flattening — four concerns sharing a
//! filename prefix. Those live in `ingest`, `export` and `topology` now, and
//! what is left is one deep module: *given two netlists, do they correspond,
//! and if not, where*.
//!
//! # The answer must be actionable
//!
//! "Mismatch" is not a result. A useful LVS reports which device or net could
//! not be paired and what it was competing with, because that is what a human
//! fixes. So [`Verdict`] carries the discrepancies, not just a boolean, and the
//! matcher is built to preserve them rather than to bail at the first failure.
//!
//! # Never a false match
//!
//! A checker that reports a match after exhausting its search budget, or after
//! declining to compare part of its input, is worse than one that reports
//! failure. Every path out of this crate that could not complete returns
//! [`Verdict::Inconclusive`] with the reason. There is no code path from
//! "gave up" to "matched".

pub mod checks;
pub mod compare;
pub mod graph;
pub mod hierarchical;
pub mod reduce;
pub mod refine;
pub mod verdict;

pub use compare::{compare, CompareOptions};
pub use graph::{Graph, LayoutGraph, RefGraph};
pub use verdict::{Discrepancy, Verdict};
