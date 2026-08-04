//! What a rule measured.
//!
//! DRC measures distances and areas in exact layout units. ERC measures volts,
//! amps and ohms. One column has to hold both, so this is a sum type over the
//! dimensions that actually occur — not a bare `f64`, which is how the old tree
//! reported a resistance and a spacing in the same field and left the reader to
//! guess.

use gpurify_units::{prefix, Current, Dbu, DbuArea, Qty, Resistance, Voltage};

/// A measured quantity, carrying its dimension.
///
/// The geometric variants are exact integers; the electrical ones are `Qty` at
/// a fixed prefix chosen to be readable in a report — millivolts, microamps,
/// ohms. Fixing the prefix per variant means a report column has one scale, so
/// two rows are comparable without conversion and the serialised form is a bare
/// number.
///
/// A closed enum: a rule that measures something new must add a variant, and
/// every formatter breaks until it handles it. That is the intent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Measurement {
    /// A distance, exact. Spacing, width, enclosure, extension.
    Length(Dbu),
    /// An area, exact. Minimum area, enclosed area, density numerator.
    Area(DbuArea),
    /// Dimensionless. Antenna ratios, density fractions.
    Ratio(f64),
    /// A count. Vias in an array, drivers on a net, fingers on a device.
    Count(u32),
    Voltage(Qty<Voltage, { prefix::MILLI }>),
    Current(Qty<Current, { prefix::MICRO }>),
    Resistance(Qty<Resistance, { prefix::BASE }>),
}

impl Measurement {
    /// Whether this measurement violates a limit.
    ///
    /// **Decision** — pure, two values in, one bool out, and the single place
    /// the sense of a comparison is decided. Mismatched dimensions are a
    /// programming error and are asserted, not silently answered.
    ///
    /// The direction is the rule's, not the measurement's: a width rule fails
    /// below its limit, a density rule above it. So [`LimitSense`] is a
    /// parameter rather than being inferred, which is what stopped the old
    /// tree's `min_spacing` and `max_width` sharing a comparison that was
    /// right for one of them.
    pub fn violates(self, limit: Self, sense: LimitSense) -> bool {
        // A non-finite operand compares false against everything, so the rule
        // reads clean without having checked anything. That is the fail-open
        // mode `is_finite` exists to catch, and this is the entry point it
        // guards.
        debug_assert!(self.is_finite(), "{self:?} is not a finite measurement");
        debug_assert!(limit.is_finite(), "{limit:?} is not a finite limit");

        // One comparison for both senses: `Maximum` is `Minimum` with the
        // operands swapped, so the sense is spent here and the dimension match
        // below only ever asks `lo < hi`. `sense` is a property of the rule,
        // constant across every row of a run, so this predicts perfectly.
        let (lo, hi) = match sense {
            LimitSense::Minimum => (self, limit),
            LimitSense::Maximum => (limit, self),
        };

        // Strict: a value exactly at its limit is legal under both senses,
        // which is what "minimum" and "maximum" mean.
        match (lo, hi) {
            (Self::Length(a), Self::Length(b)) => a < b,
            (Self::Area(a), Self::Area(b)) => a < b,
            (Self::Ratio(a), Self::Ratio(b)) => a < b,
            (Self::Count(a), Self::Count(b)) => a < b,
            (Self::Voltage(a), Self::Voltage(b)) => a.raw() < b.raw(),
            (Self::Current(a), Self::Current(b)) => a.raw() < b.raw(),
            (Self::Resistance(a), Self::Resistance(b)) => a.raw() < b.raw(),
            // Fail closed. A bool here is uninterpretable — there is no sense
            // in which a resistance is below a spacing — and returning `false`
            // would report the rule clean. `panic!`, not `debug_assert`: a
            // release signoff run must not answer either.
            _ => panic!("{lo:?} and {hi:?} are different dimensions and do not compare"),
        }
    }

    /// True when the value is finite and representable.
    ///
    /// Asserted on every measurement entering a report: a `NaN` compares false
    /// against every limit and therefore passes every rule silently, which is
    /// the fail-open mode this tool exists to avoid.
    pub fn is_finite(self) -> bool {
        match self {
            // Integers. Every bit pattern is a representable measurement, so a
            // blanket refusal here would reject most of a real report.
            Self::Length(_) | Self::Area(_) | Self::Count(_) => true,
            Self::Ratio(value) => value.is_finite(),
            Self::Voltage(value) => value.is_finite(),
            Self::Current(value) => value.is_finite(),
            Self::Resistance(value) => value.is_finite(),
        }
    }
}

/// Which side of a limit is the violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitSense {
    /// Violated when the measurement is below the limit. Widths, spacings,
    /// enclosures, areas.
    Minimum,
    /// Violated when above. Densities, antenna ratios, resistances, IR drop.
    Maximum,
}

/// Formats with its unit — `200 dbu`, `1.8 V`, `12.4 ohm`.
///
/// **Database units, not nanometres.** `std::fmt` has nowhere to carry a
/// `Grid`, and a `Dbu` is a grid index rather than a length, so this impl
/// prints the raw integer with a unit that says exactly that. Converting to
/// nanometres is the job of whoever holds the run's grid: `export`'s
/// `json::Report` and the cli's text renderer both take a `Grid` for that
/// reason, and applying it in one place is what keeps the two agreeing. A
/// report saying `200` with no unit at all is the failure both are avoiding.
///
/// One spelling per variant, so an expected string is derivable rather than
/// invented:
///
/// | variant | text |
/// |---|---|
/// | `Length(Dbu(200))` | `200 dbu` |
/// | `Area(DbuArea(10000))` | `10000 dbu^2` |
/// | `Ratio(2.0)` | `2` — the `f64` through `{}`, shortest round-trip |
/// | `Count(3)` | `3` — dimensionless, no suffix |
/// | the three electrical variants | `Qty`'s own `Display`, unchanged |
impl std::fmt::Display for Measurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Length(value) => write!(f, "{} dbu", value.raw()),
            Self::Area(value) => write!(f, "{} dbu^2", value.raw()),
            Self::Ratio(value) => write!(f, "{value}"),
            Self::Count(value) => write!(f, "{value}"),
            Self::Voltage(value) => write!(f, "{value}"),
            Self::Current(value) => write!(f, "{value}"),
            Self::Resistance(value) => write!(f, "{value}"),
        }
    }
}
