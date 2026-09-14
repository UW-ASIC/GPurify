//! Violations, and the discipline that makes them comparable.
//!
//! DRC and ERC emit the same shape — a rule fired, on a layer, at a coordinate,
//! measuring something against a limit — so they share one table. LVS and PEX
//! keep their own types: forcing a comparison verdict or a parasitic network
//! into a violation shape would be a lie.
//!
//! [`Violations::sort_canonical`] establishes the only ordering a consumer may
//! rely on. Byte-identical output across two runs at two thread counts is a
//! gate, and that sort is where it is established.

pub mod measure;
pub mod violation;

pub use measure::{LimitSense, Measurement};
pub use violation::{Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
