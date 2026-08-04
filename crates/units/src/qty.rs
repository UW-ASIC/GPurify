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
    /// Absolute temperature. **Kelvin, always.**
    ///
    /// Celsius is not a `Qty` and cannot be: it is an interval scale with an
    /// offset, so a ratio of two Celsius values is meaningless and `1/T` — which
    /// is exactly what an Arrhenius factor needs — divides by zero at 0 °C and
    /// changes sign below it. Decks state temperatures in Celsius; [`celsius`]
    /// converts at that boundary and nothing downstream sees the offset.
    Temperature => "K",
}

/// A Celsius reading as an absolute temperature.
///
/// The one place the 273.15 offset appears. Deck parsers call this; nothing
/// else needs to know Celsius exists.
///
/// **Decision** — pure, one value in, one out, and worth a table of cases
/// precisely because it is the kind of conversion that gets silently skipped:
/// absolute zero, the freezing point, and a negative reading.
pub fn celsius(degrees: f64) -> Qty<Temperature, 0> {
    // Absolute zero is the floor of the scale; below it there is no kelvin to
    // return and `1/T` is what the caller is about to compute.
    debug_assert!(
        degrees >= -ABSOLUTE_ZERO_C,
        "{degrees} C is below absolute zero"
    );
    let kelvin = Qty::new(degrees + ABSOLUTE_ZERO_C);
    debug_assert!(kelvin.raw() >= 0.0 && kelvin.is_finite());
    kelvin
}

/// Absolute zero in degrees Celsius, sign-flipped: the offset added to a
/// Celsius reading to obtain kelvin. The one place 273.15 is written down.
const ABSOLUTE_ZERO_C: f64 = 273.15;

/// The SI prefix letter for `10^P`, or `None` when the exponent is outside
/// [`crate::prefix`] and there is no letter to invent.
///
/// **Decision** — pure, one value in, one out. `P` is a const generic at every
/// call site, so this folds to a string literal at monomorphisation and the
/// `match` is not a runtime branch at all.
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
        self.raw
    }

    /// The value in base units, regardless of `P`. `3 aF` becomes `3e-18`.
    ///
    /// Used at the one boundary where a solver wants plain `f64`.
    pub fn base(self) -> f64 {
        // Base units *are* `10^0`, so this is the restatement `to` already
        // performs — including its usability check on the scale factor. Written
        // once, in `to`.
        self.to::<0>().raw()
    }

    /// Restate at a different prefix. `Qty<Voltage, 0>::to::<MILLI>()` scales by
    /// `1e3`.
    ///
    /// Lossy in the ordinary `f64` sense and deliberately explicit, so a
    /// rescale is visible at the call site rather than happening inside an
    /// operator.
    pub fn to<const Q: i8>(self) -> Qty<D, Q> {
        // raw_Q * 10^Q == raw_P * 10^P, so the factor is 10^(P-Q). One
        // multiplication, not a `powi` and a division: at Q == P the factor is
        // exactly 1.0 and the result is the original bit for bit.
        let scale = 10f64.powi(i32::from(P) - i32::from(Q));
        debug_assert!(scale.is_finite() && scale != 0.0, "10^({P}-{Q}) is unusable");
        Qty::new(self.raw * scale)
    }

    /// True when the value is finite. Every quantity entering a report is
    /// asserted finite: a `NaN` limit compares false against everything and
    /// silently passes a rule, which is the fail-open mode this project treats
    /// as a defect.
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

/// Scaling by a dimensionless factor. `Mul<f64>` only — `f64 * Qty` would need
/// an impl on `f64` for every dimension, and the asymmetry is not worth it.
impl<D: Dimension, const P: i8> std::ops::Mul<f64> for Qty<D, P> {
    type Output = Self;
    fn mul(self, rhs: f64) -> Self {
        Self::new(self.raw * rhs)
    }
}

impl<D: Dimension, const P: i8> std::ops::Div<f64> for Qty<D, P> {
    type Output = Self;
    fn div(self, rhs: f64) -> Self {
        Self::new(self.raw / rhs)
    }
}

/// Ratio of two quantities of the same dimension: dimensionless.
///
/// This is what an antenna ratio is, and why antenna limits are bare `f64`.
impl<D: Dimension, const P: i8> std::ops::Div for Qty<D, P> {
    type Output = f64;
    fn div(self, rhs: Self) -> f64 {
        // Both counts are at the same prefix, so the 10^P factors cancel and
        // the bare ratio needs no rescaling.
        self.raw / rhs.raw
    }
}

/// Formats as `<value> <prefix><symbol>` — `1.8 V`, `3 aF`, `200 mohm`.
///
/// The value is written by `f64`'s own `Display`: the shortest decimal that
/// reads back as the same bits, no fixed precision and no padding. `3.0` prints
/// as `3`, so a reader parsing the numeric head recovers [`Qty::raw`] exactly.
/// Pinned here because reports are diffed between runs, and a fixed-precision
/// format would make that diff depend on the precision rather than on the
/// number.
///
/// The prefix letter is a function of `P` alone, so this is where the SI prefix
/// table is written down once: `a f p n u m` below the base unit, nothing at
/// all at `10^0`, `k M G` above. Micro is ASCII `u`, for the same reason
/// [`Resistance`]'s symbol is `ohm` and not `Ω` — nothing in this tree emits a
/// non-ASCII symbol. An exponent outside [`crate::prefix`] has no letter and is
/// written on the value instead, so `Qty::<Voltage, 7>::new(1.8)` prints
/// `1.8e7 V`; it means the same thing and there is no letter to invent.
impl<D: Dimension, const P: i8> std::fmt::Display for Qty<D, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `P` is a const generic, so this `match` is resolved at
        // monomorphisation and no branch survives into the binary.
        match prefix_letter(P) {
            Some(letter) => write!(f, "{} {letter}{}", self.raw, D::SYMBOL),
            // No letter to invent: the exponent rides on the value instead, so
            // `Qty::<Voltage, 7>::new(1.8)` reads `1.8e7 V`.
            None => write!(f, "{}e{P} {}", self.raw, D::SYMBOL),
        }
    }
}

/// Same text as [`Display`](std::fmt::Display).
///
/// Not derived: the derived form prints `Qty { raw: 1.8, _dimension: PhantomData<Voltage> }`,
/// and this type's main appearance in a developer's life is a failed assertion
/// in a physics test, where `1.8 V` is the useful thing to read.
impl<D: Dimension, const P: i8> std::fmt::Debug for Qty<D, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Serialises as the bare number. The dimension and prefix are schema, not
/// data: they are the same for every row of a report column, so writing them
/// per row would be 20 bytes of redundancy per measurement.
impl<D: Dimension, const P: i8> serde::Serialize for Qty<D, P> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Fail closed. `serde_json` writes NaN and infinity as `null` with no
        // error, and a `null` limit reads to every consumer as "no limit" —
        // exactly the fail-open mode `is_finite` exists to stop. Escape valve:
        // the branch is false in every non-defective run, so it predicts
        // perfectly, and the taken side allocates an error.
        if !self.is_finite() {
            return Err(serde::ser::Error::custom(format_args!(
                "{} is not a finite measurement",
                self.raw
            )));
        }
        serializer.serialize_f64(self.raw)
    }
}

impl<'de, D: Dimension, const P: i8> serde::Deserialize<'de> for Qty<D, P> {
    fn deserialize<De: serde::Deserializer<'de>>(deserializer: De) -> Result<Self, De::Error> {
        // Fail closed: anything that is not a number is the deserializer's own
        // typed error, never a default.
        <f64 as serde::Deserialize>::deserialize(deserializer).map(Self::new)
    }
}
