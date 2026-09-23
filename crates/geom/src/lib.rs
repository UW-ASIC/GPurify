//! Coordinates, quantities, stored geometry, and exact integer geometry on it.
//!
//! Data in: rings in `Dbu` from `ingest`. Data out: a [`GeometryStore`],
//! [`ValidatedLayer`]s, candidate pairs, booleans, and exact measures.

mod arith;
mod dbu;
mod qty;
pub use dbu::{Dbu, DbuArea, Grid, GridError, MAX_ABS_DBU};
pub use qty::{
    celsius, Area, Capacitance, Current, CurrentDensity, Dimension, Inductance, Length, Qty,
    Resistance, Temperature, Voltage,
};

/// SI decimal exponents, as the `P` parameter of [`Qty`].
pub mod prefix {
    pub const ATTO: i8 = -18;
    pub const FEMTO: i8 = -15;
    pub const PICO: i8 = -12;
    pub const NANO: i8 = -9;
    pub const MICRO: i8 = -6;
    pub const MILLI: i8 = -3;
    pub const BASE: i8 = 0;
    pub const KILO: i8 = 3;
    pub const MEGA: i8 = 6;
    pub const GIGA: i8 = 9;
}

mod intern;
pub use intern::{StrId, StrTable};

/// Narrow a row count to the `u32` every table in this crate is indexed by.
pub(crate) fn narrow(rows: usize) -> u32 {
    u32::try_from(rows).expect("a table is indexed by u32 and cannot hold 2^32 rows")
}

pub mod bbox;
pub mod boolean;
pub mod connectivity;
pub mod ids;
pub mod index;
pub mod linalg;
pub mod ops;
pub mod rects;
pub mod store;
pub mod view;
pub use bbox::Bbox;
pub use ids::{LayerId, PolyId};
pub use store::{GeometryStore, GeometryStoreBuilder};
pub use view::{PolygonRef, RingRef, ValidatedLayer};
