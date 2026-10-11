//! Orchestration: load, extract, then the four checks, once, in order; or,
//! for `gpurify xor`, two layouts compared layer by layer ([`xor`]).
//!
//! A check that could not run is a [`StageStatus::Skipped`] or
//! [`StageStatus::Refused`] carrying its reason, never an empty result, and
//! either fails [`Summary::passed`].

pub mod pipeline;
pub mod run;
pub mod xor;

pub use pipeline::{Extracted, Inputs, Loaded};
pub use run::{Checks, EngineError, Outputs, RunOptions, StageStatus, Summary};
