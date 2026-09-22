//! Layout versus schematic: graph matching between an extracted and a
//! reference netlist.
//!
//! Every path that could not complete returns [`Verdict::Inconclusive`] with a
//! reason; there is no code path from "gave up" to "matched".

pub mod checks;
pub mod compare;
pub mod graph;
pub mod reduce;
pub mod refine;
pub mod verdict;

pub use compare::{compare, CompareOptions};
pub use graph::{Graph, LayoutGraph, RefGraph};
pub use verdict::{Discrepancy, Verdict};
