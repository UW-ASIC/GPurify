//! Writers: GDS, SPICE, SPEF, DSPF and JSON.
//!
//! Every writer iterates a canonical order the source table guarantees and never
//! sorts, formats floats through [`json::format_f64`], and keeps run metadata in
//! a [`Header`], so two runs at two thread counts produce identical bytes.

pub mod gds;
pub mod json;
pub mod netlist;
pub mod parasitic;

/// The `expect` message for a `fmt::Write` into a `String`, which cannot fail.
pub(crate) const INFALLIBLE: &str = "a String cannot fail to be written into";

/// A row index narrowed to the `u32` every id in this pipeline is made of.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("every table in this pipeline is addressed by a u32 id")
}

/// What a writer can fail at.
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
/// nowhere else.
#[derive(Debug, Clone)]
pub struct Header {
    pub tool_version: &'static str,
    pub deck_path: String,
    pub layout_path: String,
    /// Passed in, never read from the clock: a writer that calls `now()` cannot
    /// be tested for reproducibility.
    pub timestamp: Option<String>,
}
