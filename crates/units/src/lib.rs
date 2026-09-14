//! Physical quantities ([`Qty`]) and integer layout coordinates ([`Dbu`]).
//!
//! The two are unrelated types on purpose; [`Grid`] is the only bridge, and it
//! converts exactly or rejects — never rounds.

mod arith;
mod dbu;
mod qty;

pub use dbu::{Dbu, DbuArea, Grid, GridError, MAX_ABS_DBU};
pub use qty::{
    celsius, Area, Capacitance, Current, CurrentDensity, Dimension, Inductance, Length, Qty,
    Resistance, Temperature, Voltage,
};

/// Named SI prefix exponents.
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
