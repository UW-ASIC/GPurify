//! Database units: integer layout coordinates, and the exact-or-rejected
//! boundary to physical length.
//!
//! A [`Dbu`] is an index into a manufacturing grid, not a distance. Two layouts
//! on different grids have incomparable `Dbu` values, which is why this is a
//! newtype and not an `i64` alias, and why converting to or from [`Qty<Length>`]
//! requires a [`Grid`].

use crate::qty::{Length, Qty};

/// Largest legal absolute coordinate, `2^40` ≈ 1.1e12.
///
/// This bound is what makes [`DbuArea`] safe: the product of two coordinates is
/// at most `2^80`, which fits `i128` with 47 bits to spare, so no area
/// computation can overflow. Every coordinate entering the tree is checked
/// against it once, at ingest, and never rechecked.
///
/// At a 1 nm grid it is 1.1 km of layout — four orders of magnitude beyond any
/// reticle.
pub const MAX_ABS_DBU: i64 = 1 << 40;

/// One grid coordinate.
///
/// **Five questions.** In: an `i64` checked once at ingest. Out: the same.
/// How many: two per point, millions per layout — `repr(transparent)` so a
/// `Vec<Dbu>` is a `Vec<i64>` and `SoA` coordinate columns stay contiguous and
/// vectorisable. Lifetime: individual, `Copy`. Parallelisable: it is a scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Dbu(i64);

/// The product of two [`Dbu`], in `i128`.
///
/// Separate from `Dbu` because it is a different unit — adding an area to a
/// coordinate is the bug this type exists to prevent — and because it needs the
/// wider integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct DbuArea(i128);

impl Dbu {
    /// The only checked constructor. Rejects anything outside
    /// `±MAX_ABS_DBU`, which is what every downstream `i128` product relies on.
    ///
    /// Parse, don't validate: ingest calls this once per coordinate and
    /// everything downstream takes `Dbu` and never rechecks.
    pub const fn new(raw: i64) -> Option<Self> {
        todo!()
    }

    /// Construct without the range check.
    ///
    /// For coordinates derived from already-checked ones by an operation that
    /// cannot leave the range — a midpoint, a min, a clamp. Not for parsed
    /// input.
    pub const fn new_unchecked(raw: i64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> i64 {
        todo!()
    }

    /// Absolute value. Cannot overflow: `MAX_ABS_DBU` is far from `i64::MIN`.
    #[must_use]
    pub const fn abs(self) -> Self {
        todo!()
    }

    /// Widening multiply. The only route from coordinates to an area, and the
    /// reason [`MAX_ABS_DBU`] is what it is.
    pub const fn mul_wide(self, rhs: Self) -> DbuArea {
        todo!()
    }
}

impl std::ops::Add for Dbu {
    type Output = Self;
    /// Unchecked. Two values bounded by `2^40` sum well inside `i64`; a result
    /// outside the legal range is caught where it re-enters the tree, not here.
    fn add(self, rhs: Self) -> Self {
        todo!()
    }
}

impl std::ops::Sub for Dbu {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        todo!()
    }
}

impl std::ops::Neg for Dbu {
    type Output = Self;
    fn neg(self) -> Self {
        todo!()
    }
}

impl DbuArea {
    pub const fn new(raw: i128) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> i128 {
        todo!()
    }
}

impl std::ops::Add for DbuArea {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        todo!()
    }
}

impl std::ops::Sub for DbuArea {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        todo!()
    }
}

/// The manufacturing grid a layout is expressed on.
///
/// Held once per run and passed to every conversion, so a deck written in
/// nanometres is portable across grids: the same deck loads against a 1 nm and
/// a 5 nm grid, and fails loudly on the second if a limit is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grid {
    /// Database units per micrometre. `1000` for a 1 nm grid.
    dbu_per_um: i64,
}

/// Why a conversion was refused. Never a rounding — a deck limit that does not
/// land on the grid is a deck error, because silently rounding a spacing limit
/// down passes shapes the foundry would reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GridError {
    #[error("length is not an exact multiple of the grid")]
    NotOnGrid,
    #[error("length exceeds the representable coordinate range")]
    OutOfRange,
    #[error("grid resolution must be a positive number of database units per micrometre")]
    BadResolution,
}

impl Grid {
    /// Validate a resolution read from a deck or a layout header.
    pub const fn new(dbu_per_um: i64) -> Result<Self, GridError> {
        todo!()
    }

    pub const fn dbu_per_um(self) -> i64 {
        todo!()
    }

    /// Convert a physical length to grid units, exactly or not at all.
    ///
    /// **Decision, not transform** — small data in, one value out, pure, and
    /// the test plan names it: a table of (grid, length) → expected result,
    /// including the off-grid and out-of-range rejections.
    pub fn to_dbu<const P: i8>(self, length: Qty<Length, P>) -> Result<Dbu, GridError> {
        todo!()
    }

    /// Convert a coordinate to physical nanometres. Always succeeds: every
    /// `Dbu` is on the grid by construction.
    pub fn to_length(self, coord: Dbu) -> Qty<Length, { crate::prefix::NANO }> {
        todo!()
    }

    /// Bulk form of [`Grid::to_dbu`], for a deck's worth of limits.
    ///
    /// **Transform** — caller owns `out`, which is cleared and refilled. All
    /// data flow is in the signature. Stops on the first rejection and reports
    /// which row failed, because a deck with one bad limit is not partially
    /// usable.
    pub fn to_dbu_into<const P: i8>(
        self,
        lengths: &[Qty<Length, P>],
        out: &mut Vec<Dbu>,
    ) -> Result<(), (usize, GridError)> {
        todo!()
    }
}
