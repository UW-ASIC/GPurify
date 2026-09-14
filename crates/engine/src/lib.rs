//! Orchestration: load, extract, then the four checks, once, in order.
//!
//! No stage returns an empty result to mean "not attempted": a check that could
//! not run is a [`StageStatus::Skipped`] carrying its reason.

pub mod pipeline;
pub mod run;

pub use pipeline::{Extracted, Inputs, Loaded};
pub use run::{Checks, EngineError, Outputs, RunOptions, StageStatus, Summary};
