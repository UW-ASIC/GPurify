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

/// Whether `raw` is a legal coordinate. The one spelling of the `±MAX_ABS_DBU`
/// test, so the checked constructor and every `debug_assert` that restates it
/// cannot drift apart.
///
/// `unsigned_abs`, not `abs`: `i64::MIN` has no positive counterpart, so `abs`
/// overflows on exactly one of the values this check exists to refuse.
const fn in_domain(raw: i64) -> bool {
    raw.unsigned_abs() <= MAX_ABS_DBU.unsigned_abs()
}

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
        if in_domain(raw) {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Construct without the range check.
    ///
    /// For coordinates derived from already-checked ones by an operation that
    /// cannot leave the range — a midpoint, a min, a clamp. Not for parsed
    /// input.
    pub const fn new_unchecked(raw: i64) -> Self {
        // "Cannot leave the range" is the caller's claim, and this is where it
        // is checked. Unchecked means no `Option` to unwrap in release, not
        // unexamined in a test run.
        debug_assert!(in_domain(raw), "new_unchecked outside the coordinate domain");
        Self(raw)
    }

    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Absolute value. Cannot overflow: `MAX_ABS_DBU` is far from `i64::MIN`.
    #[must_use]
    pub const fn abs(self) -> Self {
        // Not `in_domain`: `Add` and `Sub` are documented to produce results
        // outside `±MAX_ABS_DBU` legally, and `abs` of one of those is fine.
        // `i64::MIN` is the single value with no positive counterpart, and it
        // is the precondition the doc comment above is claiming.
        debug_assert!(self.0 != i64::MIN, "no positive counterpart to i64::MIN");
        Self(self.0.abs())
    }

    /// Widening multiply. The only route from coordinates to an area, and the
    /// reason [`MAX_ABS_DBU`] is what it is.
    pub const fn mul_wide(self, rhs: Self) -> DbuArea {
        // The `2^80` ceiling this type's safety rests on is the product of two
        // in-domain coordinates, so both operands are asserted, not the result.
        debug_assert!(in_domain(self.0));
        debug_assert!(in_domain(rhs.0));
        let area = DbuArea(self.0 as i128 * rhs.0 as i128);
        // The claim `MAX_ABS_DBU` exists to make, checked where it is made.
        debug_assert!(area.0.unsigned_abs() <= 1u128 << 80, "area past the 2^80 ceiling");
        area
    }
}

impl std::ops::Add for Dbu {
    type Output = Self;
    /// Unchecked. Two values bounded by `2^40` sum well inside `i64`; a result
    /// outside the legal range is caught where it re-enters the tree, not here.
    fn add(self, rhs: Self) -> Self {
        // Plain `+` is the assert: it panics on `i64` overflow in a debug
        // build, which is the only failure this operation can have. A result
        // merely outside `±MAX_ABS_DBU` is legal here by contract.
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
    pub const fn new(raw: i128) -> Self {
        Self(raw)
    }

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
    /// The length was `NaN` or an infinity. Its own variant rather than a
    /// nearby one, because both of the nearby ones are wrong by accident: a
    /// `NaN` is not on the grid only in the sense that it is not on anything,
    /// and an infinity would be reported as a coordinate that is merely too
    /// large. Fail closed on the value the caller cannot have meant.
    #[error("length is not a finite number")]
    NotFinite,
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
        if dbu_per_um <= 0 {
            return Err(GridError::BadResolution);
        }
        Ok(Self { dbu_per_um })
    }

    pub const fn dbu_per_um(self) -> i64 {
        self.dbu_per_um
    }

    /// Convert a physical length to grid units, exactly or not at all.
    ///
    /// **Decision, not transform** — small data in, one value out, pure, and
    /// the test plan names it: a table of (grid, length) → expected result,
    /// including the off-grid and out-of-range rejections.
    ///
    /// The checks run in this order, and the order is part of the interface
    /// because each later check gives a wrong answer on an input the earlier
    /// one owns: [`Qty::is_finite`] first, then the coordinate range, then
    /// exactness on the grid. A `NaN` reaching an exactness test compares false
    /// against everything and is refused as [`GridError::NotOnGrid`] by
    /// accident rather than by decision, which is the shape this crate exists
    /// to prevent.
    pub fn to_dbu<const P: i8>(self, length: Qty<Length, P>) -> Result<Dbu, GridError> {
        debug_assert!(self.dbu_per_um > 0, "a Grid is positive by construction");

        if !length.is_finite() {
            return Err(GridError::NotFinite);
        }

        // `dbu = length_in_micrometres * dbu_per_um`, and one micrometre is
        // `10^(P + 6)` of this quantity's own units. The scale is applied as an
        // exact power-of-ten multiply or divide rather than as one factor: at
        // `P == NANO` that factor is `10^-3`, which `f64` cannot hold, and
        // `45.0 * 0.001 * 1000.0` is the arithmetic that decides whether 45 nm
        // is on a 1 nm grid. `45.0 * 1000.0 / 1000.0` is exact.
        //
        // The sign test is on a const generic, so it folds at compile time —
        // there is one branch here in the source and none in the object code.
        let exponent = i32::from(P) + 6;
        #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
        let per_um = self.dbu_per_um as f64;
        let units = if exponent >= 0 {
            length.raw() * 10f64.powi(exponent) * per_um
        } else {
            length.raw() * per_um / 10f64.powi(-exponent)
        };

        #[expect(clippy::cast_precision_loss, reason = "MAX_ABS_DBU is 2^40, exact in f64")]
        let limit = MAX_ABS_DBU as f64;
        // Negated rather than `>`, so a `NaN` born of `0.0 * inf` at an absurd
        // prefix is refused instead of accepted.
        if !(units.abs() <= limit) {
            return Err(GridError::OutOfRange);
        }

        // Exact or refused, never rounded. The second clause is the underflow:
        // a non-zero length that scaled to nothing is off the grid, and must
        // not become a limit of zero — a zero spacing limit is fail-open.
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

    /// Convert a coordinate to physical nanometres. Always succeeds: every
    /// `Dbu` is on the grid by construction.
    pub fn to_length(self, coord: Dbu) -> Qty<Length, { crate::prefix::NANO }> {
        debug_assert!(self.dbu_per_um > 0, "a Grid is positive by construction");
        debug_assert!(in_domain(coord.raw()));

        // One micrometre is a thousand nanometres, so one unit is
        // `1000 / dbu_per_um` of them. The numerator is at most `2^40 * 1000`,
        // under `2^53`, so it is exact and the division is correctly rounded
        // from an exact operand — which is what lets the round trip through
        // `to_dbu` be stated as an equality.
        #[expect(
            clippy::cast_precision_loss,
            reason = "|coord| <= 2^40 and the resolution is a small count; both exact in f64"
        )]
        let nanometres = coord.raw() as f64 * 1_000.0 / self.dbu_per_um as f64;
        debug_assert!(nanometres.is_finite(), "a bounded coordinate over a positive grid");
        Qty::new(nanometres)
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
        debug_assert!(self.dbu_per_um > 0, "a Grid is positive by construction");

        out.clear();
        out.reserve(lengths.len());

        // Scalar, and it stays scalar. The row body is fallible and the loop
        // stops at the first rejected row to name it, so there is an early exit
        // in the body — the chain dependency `/simd-loops` triage names as the
        // blocker. A deck's worth of limits is hundreds of rows, not bulk, so
        // the exit costs nothing worth reshaping the loop to recover.
        for (row, &length) in lengths.iter().enumerate() {
            match self.to_dbu(length) {
                Ok(coord) => out.push(coord),
                Err(reason) => {
                    // Fail closed: a rejected deck leaves no partially
                    // converted buffer behind, so a caller that mishandles the
                    // `Err` reads an empty limit table rather than a silently
                    // short one that still looks like a complete deck.
                    out.clear();
                    return Err((row, reason));
                }
            }
        }

        debug_assert_eq!(out.len(), lengths.len(), "one output row per input row");
        Ok(())
    }
}
