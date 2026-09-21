//! Everything that reads a design and reports on it.
//!
//! Extraction ([`topology`]) and the three rule engines ([`drc`], [`erc`],
//! [`lvs`]) are one crate because they are one shape: a transform over the same
//! borrowed tables, appending to the same [`report::Violations`] column set.
//! Sharing the shape was the point of the split and the cost of it.

pub mod drc;
pub mod erc;
pub mod lvs;
pub mod report;
pub mod topology;

use gpurify_geom::{Evaluator, GeometryStore};
use topology::{DeviceTable, NetTable};

/// Everything a rule reads about the layout, borrowed for the length of one run.
///
/// `nets` and `devices` are deliberately not `Option`: an absent topology and
/// an empty one are indistinguishable once inside a rule, and reading "no nets
/// extracted" as "nothing to report" is fail-open.
///
/// Role masks, design intent and the solved supply grid are deliberately *not*
/// here: they stay per-rule parameters, so that "this rule needs design intent"
/// is visible at the signature.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    pub store: &'a GeometryStore,
    /// Pre-evaluated named derived layers.
    pub derived: &'a Evaluator,
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
}
