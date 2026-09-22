//! Orchestration: load, extract, then the four checks, once, in order.
//!
//! A check that could not run is a [`StageStatus::Skipped`] carrying its reason,
//! never an empty result.

pub mod pipeline;
pub mod run;

pub use pipeline::{Extracted, Inputs, Loaded};
pub use run::{Checks, EngineError, Outputs, RunOptions, StageStatus, Summary};
