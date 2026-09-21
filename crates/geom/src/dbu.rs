//! Integer layout coordinates and the conversion to physical length.

use crate::qty::{Length, Qty};

/// Largest legal absolute coordinate, `2^40`: the product of two in-domain
/// coordinates is then at most `2^80`, which is what keeps [`DbuArea`]'s
/// `i128` overflow-free.
pub const MAX_ABS_DBU: i64 = 1 << 40;

/// Whether `raw` is a legal coordinate. `unsigned_abs`, not `abs`: `abs`
/// overflows on `i64::MIN`, one of the values this check exists to refuse.
const fn in_domain(raw: i64) -> bool {
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
        debug_assert!(in_domain(self.0));
        debug_assert!(in_domain(rhs.0));
        let area = DbuArea(self.0 as i128 * rhs.0 as i128);
        debug_assert!(
            area.0.unsigned_abs() <= 1u128 << 80,
            "area past the 2^80 ceiling"
        );
        area
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
    ///
    /// Check order is part of the interface — finiteness, range, exactness: a
    /// `NaN` reaching the exactness test compares false against everything and
    /// would be refused as [`GridError::NotOnGrid`] by accident.
    pub fn to_dbu<const P: i8>(self, length: Qty<Length, P>) -> Result<Dbu, GridError> {
        debug_assert!(self.dbu_per_um > 0, "a Grid is positive by construction");

        if !length.is_finite() {
            return Err(GridError::NotFinite);
        }

        // One micrometre is `10^(P + 6)` of this quantity's units. Applied as
        // an exact power-of-ten multiply *or* divide, never one combined
        // factor: at `P == NANO` that factor is `10^-3`, which `f64` cannot
        // hold, whereas `45.0 * 1000.0 / 1000.0` is exact.
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

        // The second clause is the underflow: a non-zero length that scaled to
        // nothing must not become a limit of zero, which is fail-open.
        if units.fract() != 0.0 || (units == 0.0 && length.raw() != 0.0) {
            return Err(GridError::NotOnGrid);
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "integral and within +/-MAX_ABS_DBU, both checked above"
        )]
        let raw = units as i64;
        debug_assert!(in_domain(raw));
        Ok(Dbu::new_unchecked(raw))
    }

    /// Convert a coordinate to nanometres. Always succeeds.
    pub fn to_length(self, coord: Dbu) -> Qty<Length, { crate::prefix::NANO }> {
        debug_assert!(self.dbu_per_um > 0, "a Grid is positive by construction");
        debug_assert!(in_domain(coord.raw()));

        // The numerator is at most `2^40 * 1000`, under `2^53`, so it is exact
        // and the division correctly rounded — which is what makes the round
        // trip through `to_dbu` an equality.
        #[expect(
            clippy::cast_precision_loss,
            reason = "|coord| <= 2^40 and the resolution is a small count; both exact in f64"
        )]
        let nanometres = coord.raw() as f64 * 1_000.0 / self.dbu_per_um as f64;
        debug_assert!(
            nanometres.is_finite(),
            "a bounded coordinate over a positive grid"
        );
        Qty::new(nanometres)
    }

    /// Bulk form of [`Grid::to_dbu`]; stops on the first rejection and names the
    /// row that failed.
    pub fn to_dbu_into<const P: i8>(
        self,
        lengths: &[Qty<Length, P>],
        out: &mut Vec<Dbu>,
    ) -> Result<(), (usize, GridError)> {
        debug_assert!(self.dbu_per_um > 0, "a Grid is positive by construction");

        out.clear();
        out.reserve(lengths.len());

        for (row, &length) in lengths.iter().enumerate() {
            match self.to_dbu(length) {
                Ok(coord) => out.push(coord),
                Err(reason) => {
                    // Fail closed: a caller that mishandles the `Err` reads an
                    // empty limit table, not a short one that looks complete.
                    out.clear();
                    return Err((row, reason));
                }
            }
        }

        debug_assert_eq!(out.len(), lengths.len(), "one output row per input row");
        Ok(())
    }
}
