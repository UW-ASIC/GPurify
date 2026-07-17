//! Serde-facing PDK schema.
//!
//! Kept as a facade because callers historically also imported resolved deck
//! types from this path. The implementation is shared with [`super::params`].

pub use super::pdk::*;
