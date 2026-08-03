//! Rules over a solved resistive network.
//!
//! Four kinds, and the line between them is which network they read.
//!
//! [`check_p2p_resistance`] reads [`NetNetworks`] — one resistor network per
//! net, built from geometry and the process stack. It needs no design intent
//! and **always runs**.
//!
//! The other three read the solved supply grid, and the supply grid exists only
//! because design intent said which nets are supplies, at what voltage, drawing
//! what current. With no intent there is no grid, `power` is `None`, and all
//! three record [`Skipped`]`(`[`NoDesignIntent`]`)`.
//!
//! # The one thing these rules must never do
//!
//! Return early with an empty violation list. "No IR-drop violations" and "no
//! supply voltage was ever declared, so nothing was compared" produce the same
//! empty [`Violations`], and only the [`RuleRun`] tells them apart. Every path
//! out of every transform below goes through `record_run` for exactly
//! that reason.
//!
//! [`Skipped`]: gpurify_report::Outcome::Skipped
//! [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent

use crate::facts::IntentMap;
use crate::power::{NetNetworks, Solved};
use crate::ruleset::RuleHead;
use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::{prefix, Current, CurrentDensity, Qty, Resistance, Temperature};

/// Effective resistance between the device attach points of a net.
///
/// A net that is one node in the netlist and kilohms across in the silicon. The
/// measurement is the **effective** resistance of the whole network between two
/// terminals, not a path length and not a sum of squares: effective resistance
/// obeys Rayleigh monotonicity, so adding a parallel strap can only lower the
/// reported number. That is a law, it is one of this project's three oracles,
/// and the old sum-of-squares proxy violated it — it went *up* when a designer
/// added metal to fix it.
#[derive(Debug, Default)]
pub struct P2pResistanceTable {
    pub head: RuleHead,
    /// Worst permitted effective resistance between any two attach points on
    /// one net.
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Voltage a node actually sits at, against what the design allows.
///
/// The table holds no limits. Every one of them — absolute drop, drop as a
/// fraction of nominal, overvoltage — is a per-net number in
/// [`NetLimits`], because a chip's own owner states it and no process
/// can. The row exists to say the deck enabled the rule, and to carry the id
/// and severity it reports at.
///
/// [`NetLimits`]: gpurify_ingest::intent::NetLimits
#[derive(Debug, Default)]
pub struct IrDropTable {
    pub head: RuleHead,
}

/// Current per unit conductor width, against a per-layer limit.
///
/// The instantaneous check: does this wire carry more current than its width
/// allows, right now, at nominal conditions. Distinct from
/// [`ElectromigrationTable`], which asks whether it survives ten years of it.
///
/// The limit is per layer because it is a property of the metallisation —
/// thickness, grain structure, liner — and the deck states it. What the rule
/// cannot get from the deck is the current, which is why it needs the solve and
/// therefore the intent.
#[derive(Debug, Default)]
pub struct EmCurrentDensityTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` and the parallel
    /// `max_density` are row `i`'s per-layer limits. CSR.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
}

/// Lifetime under sustained current, with temperature derating.
///
/// Black's equation, reduced to what a DC signoff can state: the allowed
/// current scales by an Arrhenius factor between the edge's temperature and the
/// temperature the foundry limit was characterised at, and a segment short
/// enough to be Blech-immortal is exempt.
#[derive(Debug, Default)]
pub struct ElectromigrationTable {
    pub head: RuleHead,
    /// Per-layer limits, CSR, as in [`EmCurrentDensityTable`]. Characterised at
    /// [`ElectromigrationTable::reference_temperature`], which is why that field is not optional.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut, not per width: a via array carries what its cut
    /// count allows, and the width of the metal above it is irrelevant.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,

    /// The Blech product `J · L`, above which a segment is not immortal.
    ///
    /// With [`CurrentDensity`] defined as current per unit *width*, this
    /// product has the dimension of current — the literature's A/cm assumes
    /// current per unit *area*. Same physics, stated in this tree's units, and
    /// written down here because the two differ by a thickness and a reader
    /// comparing against a foundry document needs to know which is which.
    pub blech_limit: Vec<Qty<Current, { prefix::MICRO }>>,

    /// Arrhenius parameters, per row.
    ///
    /// Absolute, in kelvin. Black's equation needs `1/T`, which is meaningless
    /// on the Celsius scale — it divides by zero at 0 °C and changes sign
    /// below it. Decks state Celsius; `gpurify_units::celsius` converts once at
    /// the deck boundary so no arithmetic here ever sees the offset.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// `n` in Black's equation. Two for void nucleation, one for growth.
    pub current_exponent: Vec<f64>,
}

/// Worst-pair effective resistance, per net.
///
/// **Transform.** One row of [`NetNetworks`] per net that has one, probed by
/// [`effective_resistance_into`] into a `scratch` buffer, worst pair taken, one
/// compare. Nets are independent, so this is the tasker pattern and partitions
/// by row.
///
/// A net with fewer than two attach points has no row in `networks` and is not
/// examined — there is no pair to measure, so reporting it as clean would be a
/// claim about nothing.
///
/// `measured` is a [`Resistance`], `limit` is `max_resistance`, sense
/// [`Maximum`]. The violation names both attach polygons, so a viewer shows the
/// two ends of the offending run.
///
/// `examined` is the number of nets probed.
///
/// [`effective_resistance_into`]: crate::power::effective_resistance_into
/// [`Maximum`]: gpurify_report::LimitSense::Maximum
pub fn check_p2p_resistance(
    design: Design<'_>,
    networks: &NetNetworks,
    table: &P2pResistanceTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Node voltages against the drop each net is allowed.
///
/// **Transform, intent-gated.** One pass over the solution's node column; each
/// node's verdict is its own drop against its net's [`NetLimits`], so the pass
/// is a kernel over nodes.
///
/// Three independent limits, each reported separately when it is stated and
/// **not** reported at all when it is not: absolute drop, drop as a fraction of
/// the domain's nominal, and overvoltage. A net with none of the three
/// contributes to `examined` and produces no violation, which is honest —
/// the run row says how many nodes were looked at, and a design that limited
/// nothing gets a number it can read.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when `power` is `None` or
/// [`IntentMap::is_usable`] is false. Not a silent empty result, ever.
///
/// `examined` is the number of nodes on nets with at least one stated limit.
///
/// [`NetLimits`]: gpurify_ingest::intent::NetLimits
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_ir_drop(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    table: &IrDropTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Branch currents against each layer's current-density limit.
///
/// **Transform, intent-gated.** One pass over the solution's branch column.
/// Density is `|current| / edge_width` for a metal edge — the units crate's
/// `Current / Length` operator, so the dimension is checked by the compiler
/// rather than by a comment — and `|current| / cuts` for a via.
///
/// An edge on a layer the row does not limit is skipped and not counted in
/// `examined`. A deck that limits no layer therefore produces a run row with
/// `examined == 0`, which reads as "this rule ran and had nothing to check" and
/// is a different claim from clean.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when there is no solve.
///
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_em_current_density(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    table: &EmCurrentDensityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Branch currents against a temperature-derated lifetime limit.
///
/// **Transform, intent-gated.** As [`check_em_current_density`], with the
/// limit scaled by the Arrhenius factor between the edge's temperature and the
/// row's reference, and with Blech-immortal segments exempted before the
/// compare rather than after — an exempt segment is not a violation that was
/// waived, it is a segment the mechanism does not apply to, and the two read
/// differently in a report.
///
/// A derating factor that overflows to infinity is [`Refused`], not a pass. An
/// infinite allowed current passes every branch silently, which is the
/// fail-open shape this crate is built to refuse.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when there is no solve.
///
/// `examined` is the number of non-exempt edges on limited layers.
///
/// [`Refused`]: gpurify_report::Outcome::Refused
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_electromigration(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    table: &ElectromigrationTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
