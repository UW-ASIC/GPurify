//! Layout I/O: format-agnostic reading and the PDK rule schema.
//!
//! * [`read`] — GDS/OASIS decoding into one lossless record database, with a
//!   format-agnostic wrapper ([`read::read_layout`]) and checked flattening.
//! * [`schema`] — serde-facing PDK rule schema.
//! * [`params`] — the validated, layer-resolved deck consumed by rule engines.
pub mod params;
mod pdk;
pub mod read;
pub mod schema;
