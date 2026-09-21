//! Analytic and semi-analytic near-field element integrals for the Laplace
//! kernel — the accuracy foundation shared by both front ends.
//!
//! * [`filament`] — partial inductance integrals for current filaments
//!   (Grover/Hoer parallel closed form, Neumann quadrature, rectangular-bar
//!   self term). Used by the `FastHenry` front end.
//!
//! main's `integrals::panel` (Wilton polygonal potentials, the `FastCap` front
//! end) is not ported here; the capacitance path in this crate collocates via
//! [`crate::matvec`] instead.

pub mod filament;
