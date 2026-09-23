//! Layout versus schematic: graph matching between an extracted and a
//! reference netlist.
//!
//! Every path that could not complete returns [`Verdict::Inconclusive`] with a
//! reason; there is no code path from "gave up" to "matched".

pub mod checks;
mod compare;
pub mod graph;
pub mod reduce;
mod refine;
pub mod verdict;

pub use checks::{check_layout, intern_rule_ids, record_discrepancies};
pub use compare::{compare, CompareOptions};
pub use graph::Graph;
pub use verdict::{Discrepancy, Verdict};
