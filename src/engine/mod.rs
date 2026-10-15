//! Orchestration: load, extract, then the four checks, once, in order; or,
//! for `gpurify xor`, two layouts compared layer by layer ([`xor`]). The
//! layout edits the deck configures, `gpurify fill` ([`fill`]) and `gpurify
//! enhance` ([`enhance`]), write a layout that DRC then checks, and
//! [`incremental`] checks an edited layout again from the last run.
//!
//! A check that could not run is a [`StageStatus::Skipped`] or
//! [`StageStatus::Refused`] carrying its reason, never an empty result, and
//! either fails [`Summary::passed`].

pub mod enhance;
pub mod fill;
pub mod incremental;
pub mod integration;
pub mod p2p;
pub mod pipeline;
pub mod run;
pub mod system;
pub mod triage;
pub mod xor;

pub use pipeline::{Extracted, Inputs, Loaded};
pub use run::{Checks, EngineError, Outputs, RunOptions, StageStatus, Summary};
