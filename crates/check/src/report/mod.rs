//! Violations, and the discipline that makes them comparable.
//!
//! DRC and ERC share one violation table; [`Violations::sort_canonical`] is
//! the only ordering a consumer may rely on (the byte-determinism gate).
//! [`record_run`] closes a rule row the same way for `drc`, `erc` and `lvs`.

pub mod measure;
pub mod violation;

pub use measure::{LimitSense, Measurement};
pub(crate) use violation::record_run;
pub use violation::{Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
