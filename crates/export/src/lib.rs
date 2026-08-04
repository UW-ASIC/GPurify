//! Every writer.
//!
//! GDS, SPICE, SPEF, DSPF and JSON. They have nothing in common as formats, and
//! they are in one module for one reason: **byte-identical output across two
//! runs at two thread counts is a gate**, and a gate is easier to hold when
//! every place it can be broken is in one crate.
//!
//! In the old tree these were in three: the GDS writer inside a file called
//! `read/gds.rs`, the SPICE writer in `lvs`, SPEF and DSPF in `pex`. The
//! determinism defect that shipped — parasitic rows whose layer pair swapped
//! between runs of the same binary — was in one of them, and nothing was
//! watching any of them.
//!
//! # The rules every writer here follows
//!
//! - Iterate a canonical order the source table guarantees. Never sort here; if
//!   the order is wrong it is wrong at the source, and fixing it here hides that.
//! - Never iterate a hash map. There are none in this workspace, and this is
//!   the module where reintroducing one would do the most damage.
//! - Format floats through [`json::format_f64`], so the same `f64` produces the
//!   same bytes everywhere.
//! - Write no timestamp, hostname or absolute path into a body. Those go in a
//!   [`Header`] a diff can skip, because a report that differs from itself
//!   cannot be diffed against yesterday's.

pub mod gds;
pub mod json;
pub mod netlist;
pub mod parasitic;

/// Writing into a `String` is infallible — `fmt::Write` returns a `Result`
/// because a formatter need not be one. [`WriteError::Io`] is for a writer that
/// can actually fail, and swallowing this one silently would make an impossible
/// case indistinguishable from a truncated file.
///
/// One spelling for the whole crate: three writers each invented their own, and
/// three `expect` messages for one impossible case is three things to grep for
/// when it somehow happens.
pub(crate) const INFALLIBLE: &str = "a String cannot fail to be written into";

/// A row index narrowed to the `u32` every id in this pipeline is made of.
///
/// One spelling for the whole crate, for [`INFALLIBLE`]'s reason: `netlist` and
/// `parasitic` each grew their own, and a checked conversion that is checked in
/// one writer and elided in the other is the shape of a truncated id nobody
/// notices.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("every table in this pipeline is addressed by a u32 id")
}

/// What a writer can fail at.
///
/// Deliberately narrow: a writer transcribes, and a writer that has to make a
/// decision is doing something else's job.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    #[error("io: {0}")]
    Io(String),
    #[error("{0} cannot be represented in this format")]
    Unrepresentable(&'static str),
    #[error("net {0} has no name, and this format requires one")]
    UnnamedNet(u32),
}

/// Run metadata, written to a header rather than into a body.
///
/// Everything that varies between two otherwise-identical runs lives here and
/// nowhere else. That is what makes "the rest is byte-identical" a checkable
/// claim rather than a hope.
#[derive(Debug, Clone)]
pub struct Header {
    pub tool_version: &'static str,
    pub deck_path: String,
    pub layout_path: String,
    /// Passed in, never read from the clock. A writer that calls `now()` cannot
    /// be tested for reproducibility.
    pub timestamp: Option<String>,
}
