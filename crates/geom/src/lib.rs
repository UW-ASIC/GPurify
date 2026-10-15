//! Coordinates, quantities, stored geometry, and exact integer geometry on it.
//!
//! Data in: rings in [`Dbu`] from `gpurify-ingest`. Data out: a
//! [`GeometryStore`], [`ValidatedLayer`]s, candidate pairs, booleans, and exact
//! measures. Nothing here reads a file or knows a process; a consumer that only
//! probes geometry can depend on this crate alone.
//!
//! # Units, and the exactness contract
//!
//! A layout coordinate is a [`Dbu`]: an integer count of database units on the
//! layout's [`Grid`], within `±`[`MAX_ABS_DBU`] (`2^40`). Two coordinates
//! multiply into a [`DbuArea`] (`i128`), which cannot overflow, so every
//! predicate and measure in [`ops`], [`width`] and [`rects`] is exact integer
//! arithmetic with no epsilon.
//!
//! A physical value is a [`Qty`]: an `f64` tagged with its [`Dimension`] and
//! an SI exponent from [`prefix`], so `Qty<Capacitance, -18>` is attofarads and
//! mixing up volts and millivolts is a type error. [`Grid::to_dbu`] crosses
//! from physical length to grid units **exactly or not at all**: an off-grid
//! length is a [`GridError`], never rounded, because rounding a spacing limit
//! down passes shapes the foundry would reject.
//!
//! # Geometry
//!
//! - [`GeometryStore`] holds every polygon of a layout as structure-of-arrays
//!   columns, rows grouped by [`LayerId`]. [`GeometryStoreBuilder`] takes rings
//!   in arrival order and sorts them by layer, returning the permutation.
//!   A ring is stored open (its first vertex is not repeated at the end);
//!   counter-clockwise is an outer boundary and clockwise a hole.
//! - [`view::validate_layer_into`] turns one layer of the store into a
//!   [`ValidatedLayer`]: rings checked rectilinear and simple but where a
//!   figure meets itself at a corner, holes bound to their innermost outer.
//!   Every algorithm below takes a validated layer, so none of them re-checks
//!   its input. Arbitrary angles are refused, not approximated.
//! - [`boolean`] computes union, intersection and difference exactly by an
//!   integer sweep. Its corner model is "connected": material that meets only
//!   at a corner is one figure, joined there by a neck of width 0, and a ring
//!   closed only at a corner encloses a hole ([`boolean::union_into`]).
//!   [`derive`](mod@derive) builds the deck's layer operations (sizing,
//!   selection by relation or measure, holes, extents, edge layers) on top.
//! - [`width`] measures the narrowest width across a polygon's own material
//!   ([`width::narrowest_width`]): between facing edges
//!   ([`width::narrowest_facing`]) or across the diagonal neck between two
//!   concave corners ([`width::narrowest_neck`]).
//! - [`index`] finds candidate pairs within a distance by bounding box. The
//!   result is a **superset** of the true pairs and never misses one: a check
//!   prunes with it, then measures each pair exactly.
//! - [`connectivity::components_into`] labels connected components by their
//!   lowest node, so a net's id does not depend on edge order.
//! - [`linalg`] holds the `f64` vector kernels the power-grid and field
//!   solvers share, with a fixed summation order so results are reproducible.
//!
//! Functions named `*_into` clear and refill a caller-owned output, so a loop
//! over layers reuses one allocation.
//!
//! # Examples
//!
//! ```
//! use gpurify_geom::prefix::NANO;
//! use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
//! use gpurify_geom::width::{narrowest_width, FacingScratch};
//! use gpurify_geom::{Dbu, GeometryStoreBuilder, Grid, GridError, LayerId, Length, Qty};
//!
//! // 1000 database units per micrometre: a 1 nm grid.
//! let grid = Grid::new(1000)?;
//! assert_eq!(grid.to_dbu(Qty::<Length, NANO>::new(140.0))?.raw(), 140);
//! assert_eq!(grid.to_dbu(Qty::<Length, NANO>::new(140.5)), Err(GridError::NotOnGrid));
//!
//! // One 500 x 140 rectangle on layer 0, wound counter-clockwise.
//! let d = Dbu::new_unchecked;
//! let mut builder = GeometryStoreBuilder::default();
//! builder.push(LayerId(0), &[d(0), d(500), d(500), d(0)], &[d(0), d(0), d(140), d(140)]);
//! let (store, _permutation) = builder.finish(1);
//!
//! let mut layer = ValidatedLayer::default();
//! validate_layer_into(&store, LayerId(0), &mut layer)?;
//! let width = narrowest_width(layer.get(0), &mut FacingScratch::default());
//! assert_eq!(width.raw(), 140);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// fearless_simd kernels must inline into the `target_feature` fn `dispatch!` makes.
#![allow(clippy::inline_always)]

mod arith;
mod dbu;
mod qty;
pub use dbu::{Dbu, DbuArea, Grid, GridError, MAX_ABS_DBU};
pub use qty::{
    celsius, Area, Capacitance, Current, CurrentDensity, Dimension, Inductance, Length, Qty,
    Resistance, Temperature, Voltage,
};

/// SI decimal exponents, as the `P` parameter of [`Qty`].
///
/// A [`Qty`] whose exponent is one of these formats with its prefix letter
/// (`3 aF`); any other exponent formats as `3e-7 F`.
pub mod prefix {
    /// `10^-18`, formatted `a`.
    pub const ATTO: i8 = -18;
    /// `10^-15`, formatted `f`.
    pub const FEMTO: i8 = -15;
    /// `10^-12`, formatted `p`.
    pub const PICO: i8 = -12;
    /// `10^-9`, formatted `n`.
    pub const NANO: i8 = -9;
    /// `10^-6`, formatted `u` (ASCII, not `µ`).
    pub const MICRO: i8 = -6;
    /// `10^-3`, formatted `m`.
    pub const MILLI: i8 = -3;
    /// `10^0`: the base unit, no prefix letter. Cross-dimension products and
    /// quotients of [`Qty`](crate::Qty) always land here.
    pub const BASE: i8 = 0;
    /// `10^3`, formatted `k`.
    pub const KILO: i8 = 3;
    /// `10^6`, formatted `M`.
    pub const MEGA: i8 = 6;
    /// `10^9`, formatted `G`.
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
pub mod derive;
pub mod ids;
pub mod index;
pub mod linalg;
pub mod ops;
pub mod rects;
pub mod relation;
pub mod store;
pub mod view;
mod wide;
pub mod width;
pub use bbox::Bbox;
pub use ids::{LayerId, PolyId};
pub use store::{GeometryStore, GeometryStoreBuilder};
pub use view::{PolygonRef, RingRef, ValidatedLayer};
