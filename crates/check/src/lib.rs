//! Everything that reads a design and reports on it: extraction ([`topology`])
//! and the rule engines ([`drc`], [`erc`], [`lvs`]).
//!
//! Data in: the borrowed layout tables ([`Design`]). Data out: the shared
//! [`report::Violations`] columns plus one `RuleRun` per configured rule.

pub mod drc;
pub mod erc;
pub mod lvs;
pub mod report;
pub mod topology;

use gpurify_geom::GeometryStore;
use topology::{DeviceTable, NetTable};

/// Everything an ERC rule reads about the layout, borrowed for one run.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    pub store: &'a GeometryStore,
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
}
