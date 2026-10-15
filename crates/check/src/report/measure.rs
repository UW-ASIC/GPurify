//! What a rule measured.

use gpurify_geom::{prefix, Current, Dbu, DbuArea, Qty, Resistance, Voltage};

/// A measured quantity, carrying its dimension. The electrical variants fix a
/// prefix so a report column has one scale.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Measurement {
    /// A distance in grid units, exact. Spacing, width, enclosure, extension.
    Length(Dbu),
    /// An area in square grid units, exact. Minimum area, enclosed area.
    Area(DbuArea),
    /// Dimensionless. Antenna ratios, density fractions.
    Ratio(f64),
    /// A count. Vias in an array, drivers on a net, fingers on a device.
    Count(u32),
    /// A voltage, in millivolts.
    Voltage(Qty<Voltage, { prefix::MILLI }>),
    /// A current, in microamps.
    Current(Qty<Current, { prefix::MICRO }>),
    /// A resistance, in ohms.
    Resistance(Qty<Resistance, { prefix::BASE }>),
}

impl Measurement {
    /// Whether this measurement violates a limit. The direction is the rule's,
    /// not the measurement's, so [`LimitSense`] is a parameter. Strict: a value
    /// exactly at its limit is legal under both senses.
    ///
    /// # Panics
    ///
    /// When `self` and `limit` are different variants. In a debug build, also
    /// when either is not finite ([`Self::is_finite`]).
    pub fn violates(self, limit: Self, sense: LimitSense) -> bool {
        debug_assert!(self.is_finite(), "{self:?} is not a finite measurement");
        debug_assert!(limit.is_finite(), "{limit:?} is not a finite limit");

        let (lo, hi) = match sense {
            LimitSense::Minimum => (self, limit),
            LimitSense::Maximum => (limit, self),
        };

        // Strict: a value exactly at its limit is legal under both senses.
        match (lo, hi) {
            (Self::Length(a), Self::Length(b)) => a < b,
            (Self::Area(a), Self::Area(b)) => a < b,
            (Self::Ratio(a), Self::Ratio(b)) => a < b,
            (Self::Count(a), Self::Count(b)) => a < b,
            (Self::Voltage(a), Self::Voltage(b)) => a.raw() < b.raw(),
            (Self::Current(a), Self::Current(b)) => a.raw() < b.raw(),
            (Self::Resistance(a), Self::Resistance(b)) => a.raw() < b.raw(),
            _ => panic!("{lo:?} and {hi:?} are different dimensions and do not compare"),
        }
    }

    /// True when the value is finite; a `NaN` would pass every rule silently.
    /// The exact variants (`Length`, `Area`, `Count`) are always finite.
    pub fn is_finite(self) -> bool {
        match self {
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
    /// Violated when the measurement is below the limit. Widths, spacings.
    Minimum,
    /// Violated when above. Densities, antenna ratios, resistances, IR drop.
    Maximum,
}

/// Formats with its unit, at the variant's fixed scale: `200 dbu`, `400 dbu^2`,
/// `1800 mV`, `120 uA`, `12.4 ohm`. Lengths stay in database units: converting
/// needs the run's [`Grid`](gpurify_geom::Grid).
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
