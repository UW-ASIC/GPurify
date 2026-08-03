//! Physical quantities and database units.
//!
//! Two unrelated numeric worlds live here, and keeping them unrelated is the
//! point.
//!
//! [`Qty`] is a physical quantity: a dimension (volts, ohms, farads) and an SI
//! prefix, both in the type. Adding volts to amps does not compile. It is
//! backed by `f64` because every producer of one — the PEX solver, the power
//! grid solve — computes in `f64`.
//!
//! [`Dbu`] is a database unit: an integer grid coordinate. It is *not* a
//! [`Qty<Length>`] and does not convert to one implicitly, because the
//! conversion needs a [`Grid`] and can fail. Layout geometry is exact integer
//! arithmetic and stays that way.
//!
//! The boundary between them is [`Grid`], and it is exact-or-rejected: a deck
//! that asks for a 47 nm limit on a 5 nm grid is an error, not a rounding.
//! (45 nm would be fine — it is exactly nine grid units. The example has to be
//! a length the grid cannot express, or it argues for the opposite rule.)

// Definition-Phase only. Every body is `todo!()`, so every parameter is unused
// and the real warnings drown. Removed in the Implementation-Phase — see the
// phase table in CLAUDE.md.
#![allow(unused_variables)]

mod arith;
mod dbu;
mod qty;

pub use dbu::{Dbu, DbuArea, Grid, GridError, MAX_ABS_DBU};
pub use qty::{
    celsius, Area, Capacitance, Current, CurrentDensity, Dimension, Inductance, Length, Qty,
    Resistance, Temperature, Voltage,
};

/// Named prefix exponents, for readability at call sites.
///
/// `Qty<Capacitance, ATTO>` reads better than `Qty<Capacitance, -18>`, and the
/// constants are the only place a prefix's meaning is written down.
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
