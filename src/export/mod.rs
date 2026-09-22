//! Writers: GDS, SPEF, DSPF and JSON.
//!
//! Every writer appends to a caller's buffer, iterates the canonical order its
//! table guarantees (never sorts), and formats floats through [`json::format_f64`].

pub mod gds;
pub mod json;
pub mod parasitic;

/// A row index narrowed to the `u32` every id in this pipeline is made of.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("every table in this pipeline is addressed by a u32 id")
}

/// What a writer can fail at.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    #[error("{0} cannot be represented in this format")]
    Unrepresentable(&'static str),
    #[error("net {0} has no name, and this format requires one")]
    UnnamedNet(u32),
}

/// Run metadata: everything that may differ between two otherwise-identical runs.
#[derive(Debug, Clone)]
pub struct Header {
    pub tool_version: &'static str,
    pub deck_path: String,
    pub layout_path: String,
    /// Passed in, never read from the clock, so output is reproducible.
    pub timestamp: Option<String>,
}
