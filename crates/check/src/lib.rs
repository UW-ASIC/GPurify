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
