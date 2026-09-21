//! The whole tool, behind one import.
//!
//! Every module below is a re-export. There is no logic here and there must
//! never be any: a consumer who wants one stage reaches for that crate
//! directly, and this exists so a consumer who wants the pipeline does not have
//! to name twelve dependencies to get it.
//!
//! It also gives `tests/test_all.rs` and `tests/bench_all.rs` somewhere to
//! live. Those two link every crate at once, so they belong to no single one of
//! them, and a virtual workspace root cannot host a test target.

pub use gpurify_geom as geom;
pub use gpurify_check as check;
pub mod engine;
pub mod export;
pub use gpurify_ingest as ingest;
pub use gpurify_extract as extract;

/// What a caller needs for an ordinary run, without naming a crate.
pub mod prelude {
    pub use crate::engine::{Checks, Inputs, Outputs, RunOptions, StageStatus, Summary};
    pub use gpurify_check::report::{Measurement, Severity, Violation, Violations};
    pub use gpurify_geom::{Dbu, Grid};
}
