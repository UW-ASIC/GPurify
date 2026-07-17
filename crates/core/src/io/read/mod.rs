//! Format-agnostic layout reading.
//!
//! [`gds`] and [`oasis`] both decode into the same lossless [`gds::GdsLibrary`]
//! record database; this wrapper detects the format from the bytes and
//! dispatches, so callers diagnosing a layout never care which container it
//! arrived in.

pub mod gds;
pub mod oasis;

use crate::params::LayerTable;
use gds::{GdsLayout, GdsLibrary, GdsReadMode, LayoutError};
use oasis::OasisError;

/// Container format of a layout byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutFormat {
    Gds,
    Oasis,
}

/// Reading error from either decoder, tagged by format.
#[derive(Debug)]
pub enum ReadError {
    Gds(LayoutError),
    Oasis(OasisError),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gds(e) => write!(f, "gds: {e}"),
            Self::Oasis(e) => write!(f, "oasis: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Detect the container format. OASIS streams begin with the standard
/// `%SEMI-OASIS\r\n` magic; anything else is treated as GDSII (whose own
/// record validation rejects non-GDS bytes with a typed error).
pub fn detect_format(bytes: &[u8]) -> LayoutFormat {
    const OASIS_MAGIC: &[u8; 13] = b"%SEMI-OASIS\r\n";
    if bytes.starts_with(OASIS_MAGIC) {
        LayoutFormat::Oasis
    } else {
        LayoutFormat::Gds
    }
}

/// Read a layout of either format into the lossless record database.
/// `mode` applies to GDS parsing; OASIS is always strict by construction.
pub fn read_layout(bytes: &[u8], mode: GdsReadMode) -> Result<GdsLibrary, ReadError> {
    match detect_format(bytes) {
        LayoutFormat::Gds => gds::read_gds_library(bytes, mode).map_err(ReadError::Gds),
        LayoutFormat::Oasis => oasis::read_oasis(bytes).map_err(ReadError::Oasis),
    }
}

/// Format-agnostic checked import straight to per-cell [`GeometryStore`]s —
/// the agnostic counterpart of [`gds::read_gds_checked`].
pub fn read_layout_cells(
    bytes: &[u8],
    mode: GdsReadMode,
    lt: &LayerTable,
    options: &gds::GdsFlattenOptions,
) -> Result<GdsLayout, String> {
    let library = read_layout(bytes, mode).map_err(|e| e.to_string())?;
    gds::flatten_gds_library(&library, lt, options).map_err(|e| e.to_string())
}
