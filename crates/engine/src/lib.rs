//! Orchestration: the whole pipeline, once, in order.
//!
//! Every stage below is a library call a caller could make directly. This crate
//! exists so they do not have to, and so the CLI is not the only place that
//! knows the order — a library consumer gets the same run the command line
//! gets, which is the point of orchestration living here rather than in `main`.
//!
//! # The pipeline
//!
//! ```text
//! deck ─┐
//!       ├─→ layout ─→ derived ─→ nets ─→ devices ─→ ports ─┬─→ drc ─┐
//! grid ─┘                                                  ├─→ erc ─┤
//! intent ──────────────────────────────────────────────────┤        ├─→ report
//! reference netlist ───────────────────────────────────────┼─→ lvs ─┤
//!                                                          └─→ pex ─┘
//! ```
//!
//! The left half is shared and runs once. The four checks on the right consume
//! it read-only and are independent of each other, so a run that asks for one
//! does not pay for the rest, and a run that asks for all four can execute them
//! concurrently without any of them observing another's state.
//!
//! # A stage that cannot run says so
//!
//! No stage returns an empty result to mean "not attempted". Every check
//! records a `RuleRun` per rule, and a check that could not run at all is a
//! [`StageStatus::Skipped`] with its reason. A caller reading only the
//! violation count is reading half the answer, so the summary makes the other
//! half hard to miss.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

pub mod pipeline;
pub mod run;

pub use pipeline::{Extracted, Inputs, Loaded};
pub use run::{Checks, EngineError, Outputs, RunOptions, StageStatus, Summary};
