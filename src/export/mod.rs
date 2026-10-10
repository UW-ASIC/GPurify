//! Writers: SPICE, SPEF, DSPF and JSON.
//!
//! Every writer appends to a caller's buffer, iterates the canonical order its
//! table guarantees (never sorts), and formats floats through [`json::format_f64`].
//!
//! So the bytes are a function of the inputs and the [`Header`] alone: the
//! same layout, deck and header give the same output on any machine and
//! thread count. A writer that returns an error may already have appended
//! part of its output, so the caller discards the buffer.
//!
//! | Writer | Format | Reads |
//! |---|---|---|
//! | [`json::write_report`] | the JSON check report | violations and rule records |
//! | [`parasitic::write_spef`] | SPEF (IEEE 1481), for a timing tool | the parasitic network |
//! | [`parasitic::write_dspf`] | DSPF, a flat SPICE-like form for a simulator | the parasitic network |
//! | [`netlist::write_spice`] | a SPICE subcircuit of the extracted devices, optionally with parasitics | the extraction and the network |
//!
//! The text report the CLI prints by default is written by the binary, not
//! this module.

pub mod json;
pub mod netlist;
pub mod parasitic;

/// A row index narrowed to the `u32` every id in this pipeline is made of.
pub(crate) fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("every table in this pipeline is addressed by a u32 id")
}

/// What a writer can fail at.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// The input holds something the format cannot say truthfully, such as
    /// a non-finite measurement, a network out of canonical order, a
    /// resistance with no far node, an element on a node outside the
    /// network, or a port on a net outside the extraction. Names what it was.
    #[error("{0} cannot be represented in this format")]
    Unrepresentable(&'static str),
    /// SPEF and DSPF name every node after its net, and this net has no
    /// label. Carries the net id. Refused rather than given an invented name.
    #[error("net {0} has no name, and this format requires one")]
    UnnamedNet(u32),
    /// One label names several disconnected nets, and the file names nets by
    /// label: SPEF and DSPF would write one `*D_NET` per piece under the same
    /// name, and SPICE would join the pieces into one node, hiding the open.
    /// Carries the label. Refused rather than written either way.
    #[error("label {0} names several disconnected nets, which this format cannot tell apart")]
    SplitLabel(String),
}

/// Refuse a net whose label also names another net. `nets` lists the nets
/// the file names; `net_of` answers no net for a label on several, so a
/// labelled net it does not answer is one piece of a split label.
pub(crate) fn check_unsplit(
    nets: impl IntoIterator<Item = gpurify_check::topology::NetId>,
    ports: &gpurify_check::topology::PortTable,
    strings: &gpurify_ingest::StrTable,
) -> Result<(), WriteError> {
    for net in nets {
        if let Some(name) = ports.name_of(net) {
            if ports.net_of(name) != Some(net) {
                return Err(WriteError::SplitLabel(strings.resolve(name).to_owned()));
            }
        }
    }
    Ok(())
}

/// Run metadata: everything that may differ between two otherwise-identical runs.
///
/// Every field is written as given, escaped only in JSON. The writers read
/// nothing else that varies between runs.
#[derive(Debug, Clone)]
pub struct Header {
    /// The tool's version; the CLI passes its crate version.
    pub tool_version: &'static str,
    /// The deck's path, as the caller spelled it.
    pub deck_path: String,
    /// The layout's path, as the caller spelled it. SPEF and DSPF use it as
    /// the design name.
    pub layout_path: String,
    /// Passed in, never read from the clock, so output is reproducible.
    /// `None` leaves the date line out; the CLI always passes `None`.
    pub timestamp: Option<String>,
}
