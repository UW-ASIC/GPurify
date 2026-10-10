//! Violations, and the discipline that makes them comparable.
//!
//! DRC, ERC and LVS write one violation table, [`Violations`];
//! [`Violations::sort_canonical`] is the only ordering a consumer may rely on
//! (the byte-determinism gate). Every configured rule also records one
//! [`RuleRun`], so a clean table can be told apart from rules that never ran.
//! `record_run` closes a rule row the same way for `drc`, `erc` and `lvs`.

pub mod measure;
pub mod violation;

pub use measure::{LimitSense, Measurement};
pub(crate) use violation::record_run;
pub use violation::{Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
