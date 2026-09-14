//! Parasitic extraction: the resistance and capacitance the layout adds.
//!
//! [`analytical`] applies the deck's per-layer closed forms; [`quasistatic`]
//! solves the field problem with a BEM formulation.
//!
//! Determinism is an interface constraint here: accumulation order is fixed, no
//! reduction reassociates, and nothing iterates a hash map.

pub mod analytical;
pub mod network;
pub mod quasistatic;
pub mod reduce;

pub use network::{Parasitic, ParasiticNetwork};
