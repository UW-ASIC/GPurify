//! Integer layout coordinates and the conversion to physical length.

use crate::qty::{Length, Qty};

/// Largest legal absolute coordinate, `2^40`: the product of two in-domain
/// coordinates is then at most `2^80`, which is what keeps [`DbuArea`]'s
/// `i128` overflow-free.
pub const MAX_ABS_DBU: i64 = 1 << 40;

/// `unsigned_abs`, not `abs`: `abs` overflows on `i64::MIN`.
pub(crate) const fn in_domain(raw: i64) -> bool {
    raw.unsigned_abs() <= MAX_ABS_DBU.unsigned_abs()
}

/// One grid coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Dbu(i64);

/// The product of two [`Dbu`], in `i128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct DbuArea(i128);

impl Dbu {
    /// Checked constructor; rejects anything outside `±MAX_ABS_DBU`.
    pub const fn new(raw: i64) -> Option<Self> {
        if in_domain(raw) {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Construct without the range check; only for values derived from
    /// already-checked ones by an operation that cannot leave the range.
    pub const fn new_unchecked(raw: i64) -> Self {
        debug_assert!(
            in_domain(raw),
            "new_unchecked outside the coordinate domain"
        );
        Self(raw)
    }

    /// The underlying integer.
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Absolute value.
    #[must_use]
    pub const fn abs(self) -> Self {
        // Not `in_domain`: `Add` and `Sub` legally produce out-of-range
        // results, and `abs` of one of those is fine. Only `i64::MIN` is not.
        debug_assert!(self.0 != i64::MIN, "no positive counterpart to i64::MIN");
        Self(self.0.abs())
    }

    /// Widening multiply: the only route from coordinates to an area.
    pub const fn mul_wide(self, rhs: Self) -> DbuArea {
        DbuArea(self.0 as i128 * rhs.0 as i128)
    }
}

impl std::ops::Add for Dbu {
    type Output = Self;
    /// Unchecked: an out-of-range result is legal here by contract, and is
    /// caught where it re-enters the tree.
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Dbu {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::Neg for Dbu {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl DbuArea {
    /// Wrap a raw area.
    pub const fn new(raw: i128) -> Self {
        Self(raw)
    }

    /// The underlying integer.
    pub const fn raw(self) -> i128 {
        self.0
    }
}

impl std::ops::Add for DbuArea {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for DbuArea {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

/// The manufacturing grid a layout is expressed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grid {
    /// Database units per micrometre. `1000` for a 1 nm grid.
    dbu_per_um: i64,
}

/// Why a conversion was refused. Never a rounding: rounding a spacing limit
/// down passes shapes the foundry would reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GridError {
    /// The length was `NaN` or an infinity.
    #[error("length is not a finite number")]
    NotFinite,
    /// The length is not an exact multiple of the grid.
    #[error("length is not an exact multiple of the grid")]
    NotOnGrid,
    /// The length is outside `±MAX_ABS_DBU`.
    #[error("length exceeds the representable coordinate range")]
    OutOfRange,
    /// The resolution was not positive.
    #[error("grid resolution must be a positive number of database units per micrometre")]
    BadResolution,
}

impl Grid {
    /// Validate a resolution read from a deck or a layout header.
    pub const fn new(dbu_per_um: i64) -> Result<Self, GridError> {
        if dbu_per_um <= 0 {
            return Err(GridError::BadResolution);
        }
        Ok(Self { dbu_per_um })
    }

    /// Database units per micrometre.
    pub const fn dbu_per_um(self) -> i64 {
        self.dbu_per_um
    }

    /// Convert a physical length to grid units, exactly or not at all.
    /// Check order (finite, range, exact) is part of the interface.
    pub fn to_dbu<const P: i8>(self, length: Qty<Length, P>) -> Result<Dbu, GridError> {
        if !length.is_finite() {
            return Err(GridError::NotFinite);
        }

        // Separate power-of-ten multiply or divide, never one factor: 10^-3 is inexact in f64.
        let exponent = i32::from(P) + 6;
        #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
        let per_um = self.dbu_per_um as f64;
        let units = if exponent >= 0 {
            length.raw() * 10f64.powi(exponent) * per_um
        } else {
            length.raw() * per_um / 10f64.powi(-exponent)
        };

        #[expect(
            clippy::cast_precision_loss,
            reason = "MAX_ABS_DBU is 2^40, exact in f64"
        )]
        let limit = MAX_ABS_DBU as f64;
        // Negated rather than `>`, so a `NaN` born of `0.0 * inf` is refused.
        if !(units.abs() <= limit) {
            return Err(GridError::OutOfRange);
        }

        // Second clause: a non-zero length that underflowed to 0 is refused (fail-open otherwise).
        if units.fract() != 0.0 || (units == 0.0 && length.raw() != 0.0) {
            return Err(GridError::NotOnGrid);
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "integral and within +/-MAX_ABS_DBU, both checked above"
        )]
        Ok(Dbu::new_unchecked(units as i64))
    }

    /// Convert a coordinate to nanometres. Always succeeds.
    pub fn to_length(self, coord: Dbu) -> Qty<Length, { crate::prefix::NANO }> {
        // Numerator <= 2^40 * 1000 < 2^53: exact, so the round trip through `to_dbu` is an equality.
        #[expect(
            clippy::cast_precision_loss,
            reason = "|coord| <= 2^40 and the resolution is a small count; both exact in f64"
        )]
        Qty::new(coord.raw() as f64 * 1_000.0 / self.dbu_per_um as f64)
    }
}
