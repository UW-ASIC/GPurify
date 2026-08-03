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
        todo!()
    }

    /// True when the value is finite and representable.
    ///
    /// Asserted on every measurement entering a report: a `NaN` compares false
    /// against every limit and therefore passes every rule silently, which is
    /// the fail-open mode this tool exists to avoid.
    pub fn is_finite(self) -> bool {
        todo!()
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

/// Formats with its unit — `200 nm`, `1.8 V`, `12.4 ohm`.
///
/// Layout units are printed in nanometres against the run's grid, which the
/// formatter is given, because a report saying `200` without a unit is what
/// makes two tools disagree silently.
impl std::fmt::Display for Measurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
