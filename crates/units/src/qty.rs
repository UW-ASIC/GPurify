//! The quantity type, its dimensions, and operations that stay within one
//! dimension.
//!
//! Cross-dimension arithmetic (`V / A -> Ω`) lives in [`crate::arith`].

use std::marker::PhantomData;

/// A physical dimension. Implemented only by the marker types below.
///
/// `SYMBOL` is the SI symbol of the **base** unit, with no prefix — a report
/// formatting `Qty<Resistance, MILLI>` prints `SYMBOL` prefixed by `m`.
pub trait Dimension: Copy + Clone + 'static {
    const SYMBOL: &'static str;
}

macro_rules! dimensions {
    ($($(#[$doc:meta])* $name:ident => $symbol:literal),* $(,)?) => {$(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name;
        impl Dimension for $name {
            const SYMBOL: &'static str = $symbol;
        }
    )*};
}

dimensions! {
    /// Physical distance. Distinct from [`crate::Dbu`], which is a grid index.
    Length => "m",
    /// Physical area. Distinct from [`crate::DbuArea`].
    Area => "m^2",
    Voltage => "V",
    Current => "A",
    Resistance => "ohm",
    Capacitance => "F",
    Inductance => "H",
    /// Current per unit width, as electromigration limits are specified.
    CurrentDensity => "A/m",
}

/// A quantity of dimension `D`, expressed in units of `10^P` of `D`'s base unit.
///
/// `Qty<Capacitance, -18>` is a count of attofarads. `raw` is that count, not
/// the value in base units — `Qty::<Capacitance, -18>::new(3.0)` is 3 aF.
///
/// **Five questions.** In: one `f64` plus two compile-time tags. Out: the same,
/// with the tags checked. How many: one per measurement in a report, so
/// hundreds of thousands per run — which is why this is `repr(transparent)` and
/// a `Vec<Qty<D, P>>` has the layout of a `Vec<f64>`, keeping `SoA` columns
/// intact. Lifetime: individual, `Copy`, never allocated. Parallelisable:
/// trivially, it is a scalar.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Qty<D: Dimension, const P: i8> {
    raw: f64,
    _dimension: PhantomData<D>,
}

impl<D: Dimension, const P: i8> Qty<D, P> {
    /// Wrap a count of `10^P` base units. No validation: any `f64` is a legal
    /// quantity, including negative (a voltage drop) and zero.
    pub const fn new(raw: f64) -> Self {
        Self { raw, _dimension: PhantomData }
    }

    /// The count of `10^P` base units. The inverse of [`Qty::new`].
    pub const fn raw(self) -> f64 {
        todo!()
    }

    /// The value in base units, regardless of `P`. `3 aF` becomes `3e-18`.
    ///
    /// Used at the one boundary where a solver wants plain `f64`.
    pub fn base(self) -> f64 {
        todo!()
    }

    /// Restate at a different prefix. `Qty<Voltage, 0>::to::<MILLI>()` scales by
    /// `1e3`.
    ///
    /// Lossy in the ordinary `f64` sense and deliberately explicit, so a
    /// rescale is visible at the call site rather than happening inside an
    /// operator.
    pub fn to<const Q: i8>(self) -> Qty<D, Q> {
        todo!()
    }

    /// True when the value is finite. Every quantity entering a report is
    /// asserted finite: a `NaN` limit compares false against everything and
    /// silently passes a rule, which is the fail-open mode this project treats
    /// as a defect.
    pub fn is_finite(self) -> bool {
        todo!()
    }
}

impl<D: Dimension, const P: i8> std::ops::Add for Qty<D, P> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        todo!()
    }
}

impl<D: Dimension, const P: i8> std::ops::Sub for Qty<D, P> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        todo!()
    }
}

impl<D: Dimension, const P: i8> std::ops::Neg for Qty<D, P> {
    type Output = Self;
    fn neg(self) -> Self {
        todo!()
    }
}

/// Scaling by a dimensionless factor. `Mul<f64>` only — `f64 * Qty` would need
/// an impl on `f64` for every dimension, and the asymmetry is not worth it.
impl<D: Dimension, const P: i8> std::ops::Mul<f64> for Qty<D, P> {
    type Output = Self;
    fn mul(self, rhs: f64) -> Self {
        todo!()
    }
}

impl<D: Dimension, const P: i8> std::ops::Div<f64> for Qty<D, P> {
    type Output = Self;
    fn div(self, rhs: f64) -> Self {
        todo!()
    }
}

/// Ratio of two quantities of the same dimension: dimensionless.
///
/// This is what an antenna ratio is, and why antenna limits are bare `f64`.
impl<D: Dimension, const P: i8> std::ops::Div for Qty<D, P> {
    type Output = f64;
    fn div(self, rhs: Self) -> f64 {
        todo!()
    }
}

/// Formats as `<value> <prefix><symbol>` — `1.8 V`, `3.0 aF`, `200 mohm`.
///
/// The prefix letter is a function of `P` alone, so this is where the SI
/// prefix table is written down once.
impl<D: Dimension, const P: i8> std::fmt::Display for Qty<D, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// Same text as [`Display`](std::fmt::Display).
///
/// Not derived: the derived form prints `Qty { raw: 1.8, _dimension: PhantomData<Voltage> }`,
/// and this type's main appearance in a developer's life is a failed assertion
/// in a physics test, where `1.8 V` is the useful thing to read.
impl<D: Dimension, const P: i8> std::fmt::Debug for Qty<D, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// Serialises as the bare number. The dimension and prefix are schema, not
/// data: they are the same for every row of a report column, so writing them
/// per row would be 20 bytes of redundancy per measurement.
impl<D: Dimension, const P: i8> serde::Serialize for Qty<D, P> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        todo!()
    }
}

impl<'de, D: Dimension, const P: i8> serde::Deserialize<'de> for Qty<D, P> {
    fn deserialize<De: serde::Deserializer<'de>>(deserializer: De) -> Result<Self, De::Error> {
        todo!()
    }
}
