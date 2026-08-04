//! Violations, and the discipline that makes them comparable.
//!
//! DRC and ERC emit the same shape — a rule fired, on a layer, at a coordinate,
//! measuring something against a limit — so they share one table. LVS emits a
//! comparison verdict and PEX a parasitic network; forcing those into a
//! violation shape would be a lie, so they keep their own types in their own
//! modules.
//!
//! # This is the assertion surface
//!
//! With no reference implementation to diff against, the physics tests assert
//! on reports: build a layout with a known violation, run the rule, and check
//! it is found *at that coordinate with that measurement*. So the table is
//! designed to be asserted on — every field a test would name is a column, and
//! the canonical order is part of the interface, not an implementation detail.
//!
//! # Determinism
//!
//! Byte-identical output across two runs at two thread counts is a gate.
//! [`Violations::sort_canonical`] is where that is established, and it is the
//! only ordering any consumer may rely on.

pub mod measure;
pub mod violation;

pub use measure::{LimitSense, Measurement};
pub use violation::{Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
