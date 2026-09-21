//! The quantity type, its dimensions, and same-dimension operations.

use std::marker::PhantomData;

/// A physical dimension. `SYMBOL` is the SI symbol of the **base** unit, with
/// no prefix.
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
    /// Electric potential.
    Voltage => "V",
    /// Electric current.
    Current => "A",
    /// Electrical resistance.
    Resistance => "ohm",
    /// Capacitance.
    Capacitance => "F",
    /// Inductance.
    Inductance => "H",
    /// Current per unit width, as electromigration limits are specified.
    CurrentDensity => "A/m",
    /// Absolute temperature. Kelvin, always: Celsius is an interval scale, so
    /// `1/T` — what an Arrhenius factor needs — divides by zero at 0 °C.
    /// [`celsius`] converts at the deck boundary.
    Temperature => "K",
}

/// A Celsius reading as an absolute temperature. The one place the 273.15
/// offset appears.
pub fn celsius(degrees: f64) -> Qty<Temperature, 0> {
    debug_assert!(
        degrees >= -ABSOLUTE_ZERO_C,
        "{degrees} C is below absolute zero"
    );
    let kelvin = Qty::new(degrees + ABSOLUTE_ZERO_C);
    debug_assert!(kelvin.raw() >= 0.0 && kelvin.is_finite());
    kelvin
}

/// The offset added to a Celsius reading to obtain kelvin.
const ABSOLUTE_ZERO_C: f64 = 273.15;

/// The SI prefix letter for `10^P`, or `None` when the exponent is outside
/// [`crate::prefix`] and there is no letter to invent.
const fn prefix_letter(exponent: i8) -> Option<&'static str> {
    use crate::prefix;
    Some(match exponent {
        prefix::ATTO => "a",
        prefix::FEMTO => "f",
        prefix::PICO => "p",
        prefix::NANO => "n",
        // ASCII, for the same reason `Resistance` is `ohm` and not the glyph.
        prefix::MICRO => "u",
        prefix::MILLI => "m",
        prefix::BASE => "",
        prefix::KILO => "k",
        prefix::MEGA => "M",
        prefix::GIGA => "G",
        _ => return None,
    })
}

/// A quantity of dimension `D`, as a count of `10^P` of `D`'s base unit —
/// `Qty::<Capacitance, -18>::new(3.0)` is 3 aF, not 3 F.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Qty<D: Dimension, const P: i8> {
    raw: f64,
    _dimension: PhantomData<D>,
}

impl<D: Dimension, const P: i8> Qty<D, P> {
    /// Wrap a count of `10^P` base units.
    pub const fn new(raw: f64) -> Self {
        Self {
            raw,
            _dimension: PhantomData,
        }
    }

    /// The count of `10^P` base units.
    pub const fn raw(self) -> f64 {
        self.raw
    }

    /// The value in base units, regardless of `P`. `3 aF` becomes `3e-18`.
    pub fn base(self) -> f64 {
        self.to::<0>().raw()
    }

    /// Restate at a different prefix. Explicit, so a lossy rescale is visible
    /// at the call site.
    pub fn to<const Q: i8>(self) -> Qty<D, Q> {
        // One multiply, not a `powi` and a division: at Q == P the factor is
        // exactly 1.0 and the result is the original bit for bit.
        let scale = 10f64.powi(i32::from(P) - i32::from(Q));
        debug_assert!(
            scale.is_finite() && scale != 0.0,
            "10^({P}-{Q}) is unusable"
        );
        Qty::new(self.raw * scale)
    }

    /// True when the value is finite. A `NaN` limit compares false against
    /// everything and silently passes a rule, so reports assert this.
    pub fn is_finite(self) -> bool {
        self.raw.is_finite()
    }
}

impl<D: Dimension, const P: i8> std::ops::Add for Qty<D, P> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::new(self.raw + rhs.raw)
    }
}

impl<D: Dimension, const P: i8> std::ops::Sub for Qty<D, P> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.raw - rhs.raw)
    }
}

impl<D: Dimension, const P: i8> std::ops::Neg for Qty<D, P> {
    type Output = Self;
    fn neg(self) -> Self {
        Self::new(-self.raw)
    }
}

/// Scaling by a dimensionless factor.
impl<D: Dimension, const P: i8> std::ops::Mul<f64> for Qty<D, P> {
    type Output = Self;
    fn mul(self, rhs: f64) -> Self {
        Self::new(self.raw * rhs)
    }
}

/// Division by a dimensionless factor.
impl<D: Dimension, const P: i8> std::ops::Div<f64> for Qty<D, P> {
    type Output = Self;
    fn div(self, rhs: f64) -> Self {
        Self::new(self.raw / rhs)
    }
}

/// Ratio of two quantities of the same dimension: dimensionless. This is what
/// an antenna ratio is, and why antenna limits are bare `f64`.
impl<D: Dimension, const P: i8> std::ops::Div for Qty<D, P> {
    type Output = f64;
    fn div(self, rhs: Self) -> f64 {
        // Same prefix on both, so the 10^P factors cancel.
        self.raw / rhs.raw
    }
}

/// Formats as `<value> <prefix><symbol>` — `1.8 V`, `3 aF`, `200 mohm`.
///
/// `f64`'s own `Display`, not a fixed precision: reports are diffed between
/// runs, and the shortest round-tripping decimal keeps that diff about the
/// number. An exponent outside [`crate::prefix`] rides on the value: `1.8e7 V`.
impl<D: Dimension, const P: i8> std::fmt::Display for Qty<D, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match prefix_letter(P) {
            Some(letter) => write!(f, "{} {letter}{}", self.raw, D::SYMBOL),
            None => write!(f, "{}e{P} {}", self.raw, D::SYMBOL),
        }
    }
}

/// Same text as [`Display`](std::fmt::Display).
impl<D: Dimension, const P: i8> std::fmt::Debug for Qty<D, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Serialises as the bare number; the dimension and prefix are schema, not data.
impl<D: Dimension, const P: i8> serde::Serialize for Qty<D, P> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Fail closed. `serde_json` writes NaN and infinity as `null` with no
        // error, and a `null` limit reads to every consumer as "no limit".
        if !self.is_finite() {
            return Err(serde::ser::Error::custom(format_args!(
                "{} is not a finite measurement",
                self.raw
            )));
        }
        serializer.serialize_f64(self.raw)
    }
}

/// Deserialises from a bare number.
impl<'de, D: Dimension, const P: i8> serde::Deserialize<'de> for Qty<D, P> {
    fn deserialize<De: serde::Deserializer<'de>>(deserializer: De) -> Result<Self, De::Error> {
        // Fail closed: anything that is not a number is the deserializer's own
        // typed error, never a default.
        <f64 as serde::Deserialize>::deserialize(deserializer).map(Self::new)
    }
}
