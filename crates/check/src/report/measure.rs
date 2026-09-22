//! What a rule measured.

use gpurify_geom::{prefix, Current, Dbu, DbuArea, Qty, Resistance, Voltage};

/// A measured quantity, carrying its dimension. The electrical variants fix a
/// prefix so a report column has one scale.
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
    /// Whether this measurement violates a limit. The direction is the rule's,
    /// not the measurement's, so [`LimitSense`] is a parameter.
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

/// Formats with its unit — `200 dbu`, `1.8 V`, `12.4 ohm`. Lengths stay in
/// database units: converting needs the run's `Grid`.
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
