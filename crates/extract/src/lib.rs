//! Parasitic extraction: the resistance, capacitance and inductance the layout adds.
//!
//! Data in: `GeometryStore` + `NetTable` + `ProcessStack`.
//! Data out: a [`ParasiticNetwork`] — [`analytical`] closed forms for the whole
//! design, [`quasistatic`] BEM field solve for selected nets.
//! Deterministic: fixed accumulation order, no reassociated reductions, no hash-map iteration.

pub mod analytical;
pub mod field;
pub mod network;
pub mod quasistatic;

pub use network::{Parasitic, ParasiticNetwork};
