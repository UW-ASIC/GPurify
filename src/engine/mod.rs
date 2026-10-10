//! Orchestration: load, extract, then the four checks, once, in order.
//!
//! A check that could not run is a [`StageStatus::Skipped`] or
//! [`StageStatus::Refused`] carrying its reason, never an empty result, and
//! either fails [`Summary::passed`].

pub mod pipeline;
pub mod run;

pub use pipeline::{Extracted, Inputs, Loaded};
pub use run::{Checks, EngineError, Outputs, RunOptions, StageStatus, Summary};
