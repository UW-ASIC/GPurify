//! Rules about surviving conditions the layout does not contain.
//!
//! Three kinds, all gated on design intent, all asking a question geometry
//! cannot answer on its own: what voltage is on this net, what stress does it
//! see, and for how long.
//!
//! - [`check_hv_domain`] — a device straddling two voltage domains, with no
//!   isolation. Needs to know the domains, which is intent.
//! - [`check_esd_latchup`] — a pad with no low-resistance discharge path to a
//!   supply, or an injector with no guard ring. Needs to know which nets are
//!   supplies, which is intent.
//! - [`check_reliability`] — voltage, thermal and aging stress against a
//!   required lifetime. Needs the required lifetime and the operating point,
//!   both of which are intent.
//!
//! Each records [`Skipped`]`(`[`NoDesignIntent`]`)` when its inputs are absent.
//! There is no configuration of this module that produces an empty clean result
//! from a run that could not check anything.
//!
//! [`Skipped`]: gpurify_report::Outcome::Skipped
//! [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent

use crate::facts::IntentMap;
use crate::power::{NetNetworks, Solved};
use crate::ruleset::RuleHead;
use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::{prefix, Current, Dbu, Qty, Resistance, Temperature, Voltage};

/// Lifetime under sustained stress.
///
/// One inverse-power-and-Arrhenius model, parameterised per row, standing in
/// for whichever mechanism the foundry characterised — BTI, HCI, TDDB, stress
/// migration. One model rather than four, because the four differ only in their
/// coefficients and a separate table per mechanism would be the same six
/// columns four times.
///
/// The *applied* stress is not here. It comes from the solve and the design's
/// domain voltages, which is what makes this rule intent-gated: a lifetime
/// computed against a stress nobody stated is a number, not a verdict.
#[derive(Debug, Default)]
pub struct ReliabilityTable {
    pub head: RuleHead,
    /// How long the design must last. The denominator of every verdict here.
    pub required_lifetime_hours: Vec<f64>,
    /// The mechanism's name, interned, so a report says which one failed.
    pub mechanism: Vec<StrId>,
    /// The characterised point: this lifetime, at this stress, at this
    /// temperature.
    pub reference_lifetime_hours: Vec<f64>,
    pub reference_stress: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Exponent of the inverse-power law. Positive; higher means more sensitive
    /// to stress.
    pub stress_exponent: Vec<f64>,
    /// Absolute, in kelvin — the lifetime model needs `1/T`, which the Celsius
    /// scale cannot express. `gpurify_units::celsius` converts at the deck
    /// boundary.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// Fraction of the lifetime spent under stress, in `0.0 ..= 1.0`. A signal
    /// toggling half the time ages at half the rate, and a rule that assumed
    /// unity would reject every working design.
    pub duty_cycle: Vec<f64>,
    /// Absolute voltage above which the oxide is out of specification, checked
    /// directly rather than through the lifetime model.
    pub max_abs_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// A device or net bridging two voltage domains.
///
/// The physical failure is gate-oxide breakdown: a thin-oxide device with its
/// gate in a 3.3 V domain and its channel in a 1.8 V one sees the difference
/// across an oxide characterised for neither. So the test is over *devices* and
/// their terminal domains, not over conductors crossing a well boundary —
/// which is what the old implementation tested, and which flags every
/// correctly-built PMOS in the design.
#[derive(Debug, Default)]
pub struct HvDomainTable {
    pub head: RuleHead,
    /// Largest voltage difference two of a device's terminals may span before
    /// the device needs to be a thick-oxide or isolated one.
    pub max_domain_delta: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Marker layer identifying a legal crossing — a level shifter, an
    /// isolation cell, a thick-oxide region. A device inside one is exempt.
    ///
    /// `None` when the deck configures no exemption, in which case every
    /// crossing is a violation. An `Option` in a table of a handful of rows
    /// read once per run, for the same reason as the antenna diode column.
    pub isolation: Vec<Option<LayerId>>,
}

/// Pad discharge paths and latch-up guard rings.
///
/// Two failures with one set of inputs, which is why they share a table: both
/// need to know where the pads are, which nets are supplies, and where the
/// guard rings sit.
///
/// - **ESD**: every pad net must reach a supply through a clamp whose on-
///   resistance, current capacity and clamp voltage all satisfy the row.
/// - **Latch-up**: every injector must sit inside a guard ring of at least the
///   stated width, biased from a supply, with a tap no further than the stated
///   distance.
#[derive(Debug, Default)]
pub struct EsdLatchupTable {
    pub head: RuleHead,
    /// Marker layer whose polygons are bond pads or I/O.
    pub pad: Vec<LayerId>,
    /// Marker layer whose polygons are guard rings.
    pub guard_ring: Vec<LayerId>,

    /// `clamp_*[clamp_start[i] .. clamp_start[i + 1]]` describe row `i`'s
    /// acceptable clamps, parallel columns. CSR.
    pub clamp_start: Vec<u32>,
    pub clamp_model: Vec<StrId>,
    /// On-resistance of the clamp itself. Added to the interconnect resistance
    /// the per-net networks give, so the reported path resistance is the whole
    /// path and not the wiring alone.
    pub clamp_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    pub clamp_capacity: Vec<Qty<Current, { prefix::MILLI }>>,
    /// Highest voltage the clamp lets the protected node reach while
    /// conducting.
    pub clamp_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    /// The discharge event the path must carry.
    pub required_current: Vec<Qty<Current, { prefix::MILLI }>>,
    pub max_path_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    pub max_clamp_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    pub min_guard_ring_width: Vec<Dbu>,
    /// Furthest an injector may be from a tap in its guard ring.
    pub max_tap_distance: Vec<Dbu>,
}

/// Predicted lifetime against the required one, plus the absolute voltage cap.
///
/// **Transform, intent-gated.** Per rule row: the applied stress is the worst
/// solved node voltage on each domain, the applied temperature is the edge
/// temperature at that node, and the model turns the pair into hours. One
/// compare per stressed node.
///
/// A predicted lifetime that is not finite is [`Refused`], not a pass. So is a
/// duty cycle outside `0.0 ..= 1.0` — [`crate::RuleSet::from_deck`] rejects
/// that at load, and the assertion here is the second line of the same defence.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when `power` is `None` or
/// [`IntentMap::is_usable`] is false.
///
/// `examined` is the number of nodes evaluated against the model.
///
/// [`Refused`]: gpurify_report::Outcome::Refused
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_reliability(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    table: &ReliabilityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every device whose terminals span more than `max_domain_delta`.
///
/// **Transform, intent-gated.** One pass over the device table: look each
/// terminal's net up in [`IntentMap`], take the widest nominal-voltage spread
/// across the device's terminals, and compare. A device with a terminal on an
/// undeclared net contributes nothing and is not counted in `examined` —
/// silence about a net nobody classified, rather than a guess.
///
/// The isolation marker is tested by containment of the device's marker
/// polygon, so a level shifter drawn correctly exempts the devices inside it
/// and nothing else.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when [`IntentMap::is_usable`] is
/// false. This is the rule where that matters most: with no domains declared,
/// every device spans a delta of zero and the whole design reads clean.
///
/// `examined` is the number of devices with every terminal on a declared net.
///
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_hv_domain(
    design: Design<'_>,
    intent: &IntentMap,
    table: &HvDomainTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every pad without a qualifying discharge path, and every unguarded
/// injector.
///
/// **Transform, intent-gated.** Per rule row: for each pad net, search the
/// clamp graph for the lowest-resistance path to a declared supply, summing
/// clamp on-resistance and the interconnect resistance `networks` gives for
/// each net on the way. The search is over the row's clamp list, so it is a
/// handful of edges per pad and a plain best-first over `scratch`'s edge and
/// label buffers.
///
/// A pad with **no** path at all is a violation with an absent measurement
/// rather than an infinite one: infinity in a report column is a value a reader
/// has to interpret, and the two cases mean different things to a fix.
///
/// The guard-ring half runs in the same pass: each guard ring's width and its
/// distance to the nearest tap, both exact in [`Dbu`].
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when [`IntentMap::is_usable`] is
/// false — with no declared supplies there is no target for a discharge path,
/// and every pad would trivially pass.
///
/// `examined` is the number of pad nets plus the number of guard rings.
///
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_esd_latchup(
    design: Design<'_>,
    intent: &IntentMap,
    networks: &NetNetworks,
    table: &EsdLatchupTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
