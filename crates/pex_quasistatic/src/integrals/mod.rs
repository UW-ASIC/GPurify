//! Analytic and semi-analytic near-field element integrals for the Laplace
//! kernel — the accuracy foundation shared by both front ends.
//!
//! * [`filament`] — partial inductance integrals for current filaments
//!   (Grover/Hoer parallel closed form, Neumann quadrature, rectangular-bar
//!   self term). Used by the FastHenry front end.
//! * [`panel`] — Wilton polygonal potential integrals for surface charge on
//!   flat panels. Used by the FastCap front end.

pub mod filament;
pub mod panel;
