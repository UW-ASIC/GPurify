//! The macro spec: what a layout cannot say about its own interface.
//!
//! A layout names its pins; it cannot say which one is a clock, which one is
//! analog, which arcs exist, or what voltage each supply sits at in each corner.
//! One JSON file per macro carries that, versioned with the block.
//!
//! `deny_unknown_fields` throughout: a misspelled key would otherwise silently
//! drop an arc or a corner from the model.
//!
//! Units: volts for every voltage, °C, ns for times and transitions, pF for
//! loads, Hz, and percent of a pin's swing for thresholds. The format, with
//! a worked example, is in
//! [liberty.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/liberty.md#the-spec).
//! Build a spec with [`parse`], never by hand: the characterizer trusts every
//! relation [`parse`] checks.

use super::Accuracy;
use serde::Deserialize;
use std::collections::BTreeMap;

/// One macro's interface, arcs and corners.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacroSpec {
    /// The Liberty cell and Verilog module name.
    pub cell: String,
    /// Port order is this order: the Verilog blackbox and the cross-check use it.
    pub pins: Vec<PinSpec>,
    /// The pin the deck's global (substrate) nets are tied to in simulation.
    /// Without it a substrate no label names floats.
    #[serde(default)]
    pub substrate: Option<String>,
    /// The timing arcs, measured at `spice` and above. Empty: a model of
    /// pins, capacitance and leakage only.
    #[serde(default)]
    pub arcs: Vec<ArcSpec>,
    /// One `.lib` each, in this order. At least one.
    pub corners: Vec<CornerSpec>,
    /// The states leakage is measured in, each a sequence of vectors applied
    /// in order (a latch's state is its history, not its inputs). Empty: every
    /// arc case's preparation.
    #[serde(default)]
    pub leakage_states: Vec<Vec<Vector>>,
    /// Table indices, thresholds and timing of every measurement.
    #[serde(default)]
    pub characterization: Characterization,
    /// How the simulator is run and its device cards spelled.
    #[serde(default)]
    pub simulator: Simulator,
    /// The levels `gpurify lib` generates, cheapest first: in JSON one
    /// level's name or number (`"spice"`, `"3"`; [`Accuracy::parse`]), or
    /// `"all"` for every level. Default `"spice"`. A library caller states
    /// its level in [`Request`](super::Request) instead.
    #[serde(default = "spice", deserialize_with = "accuracy")]
    pub accuracy: Vec<Accuracy>,
}

fn spice() -> Vec<Accuracy> {
    vec![Accuracy::Spice]
}

/// `"all"` is every level; anything [`Accuracy::parse`] reads is that one.
fn accuracy<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Vec<Accuracy>, D::Error> {
    let text = String::deserialize(de)?;
    if text == "all" {
        return Ok(Accuracy::ALL.to_vec());
    }
    Accuracy::parse(&text)
        .map(|level| vec![level])
        .ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown accuracy {text:?}; expected interface, analytical, field, spice, \
             statistical (or 0 to 4), or all"
            ))
        })
}

/// Pin values applied together, by pin name. Unnamed pins keep their previous
/// value.
pub type Vector = BTreeMap<String, Level>;

/// A pin value: a logic level of the pin's related supplies, or volts. In
/// JSON, `"0"`, `"1"` or a finite number; anything else is refused.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Level {
    /// `"0"`: the voltage of the pin's related ground.
    Low,
    /// `"1"`: the voltage of the pin's related power.
    High,
    /// A number: that many volts. The only value an analog pin may take.
    Volts(f64),
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Number(f64),
        }
        match Raw::deserialize(de)? {
            Raw::Text(text) if text == "0" => Ok(Self::Low),
            Raw::Text(text) if text == "1" => Ok(Self::High),
            Raw::Number(volts) if volts.is_finite() => Ok(Self::Volts(volts)),
            Raw::Text(text) => Err(serde::de::Error::custom(format!(
                "a pin value is \"0\", \"1\" or a number of volts, not {text:?}"
            ))),
            Raw::Number(_) => Err(serde::de::Error::custom("a pin voltage must be finite")),
        }
    }
}

/// One port of the macro.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinSpec {
    /// The port name. It must match the layout's label, and the reference
    /// `.subckt`'s port and the LEF's `PIN` when those are given, exactly.
    pub name: String,
    /// What the pin is, which decides how it is driven and written.
    pub role: Role,
    /// `related_power_pin`: a `power` or `nwell` pin of this spec. Required
    /// on every signal pin, forbidden on a supply; its voltage is the pin's
    /// logic high.
    #[serde(default)]
    pub power: Option<String>,
    /// `related_ground_pin`: a `ground` or `pwell` pin of this spec. Required
    /// on every signal pin, forbidden on a supply; its voltage is the pin's
    /// logic low.
    #[serde(default)]
    pub ground: Option<String>,
    /// An analog pin's direction; digital roles fix their own. Default `inout`.
    #[serde(default)]
    pub direction: Option<Direction>,
    /// An analog pin's DC voltage, V, while anything else is characterized,
    /// and the operating point its capacitance is taken at. Required on an
    /// analog pin, forbidden on any other.
    #[serde(default)]
    pub bias: Option<f64>,
    /// An output's Liberty `function`, copied through unread.
    #[serde(default)]
    pub function: Option<String>,
}

/// What a pin is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A `pg_pin` of type `primary_power`, held at its corner's voltage.
    Power,
    /// A `pg_pin` of type `primary_ground`, held at its corner's voltage.
    Ground,
    /// A `pg_pin` of type `nwell`, a body bias; may be a signal pin's related
    /// power.
    Nwell,
    /// A `pg_pin` of type `pwell`, a body bias; may be a signal pin's related
    /// ground.
    Pwell,
    /// A digital input, driven between its related rails; `clock : false`.
    Input,
    /// A digital input marked `clock : true`: the related pin of clocked arcs.
    Clock,
    /// A digital output: loaded and measured, never driven.
    Output,
    /// Direction and capacitance only, never an arc. Held at its `bias` and
    /// marked `is_analog : true`, which `OpenSTA` does not read.
    Analog,
}

impl Role {
    /// Whether the pin is a `pg_pin` rather than a `pin`: power, ground or a
    /// well, which takes a corner voltage and no related pins.
    pub const fn is_supply(self) -> bool {
        matches!(self, Self::Power | Self::Ground | Self::Nwell | Self::Pwell)
    }

    /// Whether the characterizer drives the pin as a logic level: an input or
    /// a clock. Only these may start an arc or take `"0"`/`"1"` in a vector.
    pub const fn is_digital_input(self) -> bool {
        matches!(self, Self::Input | Self::Clock)
    }
}

/// An analog pin's direction, in both the `.lib` and the Verilog blackbox.
/// Digital roles fix their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Into the macro.
    Input,
    /// Out of the macro.
    Output,
    /// Either way: the default for an analog pin.
    Inout,
}

impl Direction {
    /// The keyword, which Liberty and Verilog spell alike.
    pub const fn liberty(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Inout => "inout",
        }
    }
}

/// One timing arc, measured once per case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArcSpec {
    /// The related pin: the input of a delay arc, the clock of a constraint.
    pub from: String,
    /// The output of a delay arc, the constrained data pin of a constraint.
    pub to: String,
    /// The Liberty `timing_type`, which decides whether this is a delay or a
    /// constraint.
    pub kind: ArcKind,
    /// At least one. Each is one measurement; when they disagree, the main
    /// `.lib` keeps the worst at each table point and `min/` the best.
    pub cases: Vec<CaseSpec>,
}

/// Liberty `timing_type`: a delay from an input or clock to an output, or a
/// setup or hold constraint on a data pin against a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArcKind {
    /// Input to output with no clock. Each case names its input edge; a
    /// self-timed `go -> done` is one of these.
    Combinational,
    /// Clock rise to output: a clock-to-Q delay.
    RisingEdge,
    /// Clock fall to output.
    FallingEdge,
    /// How long before a rising clock the data must settle.
    SetupRising,
    /// How long after a rising clock the data must hold.
    HoldRising,
    /// How long before a falling clock the data must settle.
    SetupFalling,
    /// How long after a falling clock the data must hold.
    HoldFalling,
}

impl ArcKind {
    /// The `timing_type` keyword.
    pub const fn liberty(self) -> &'static str {
        match self {
            Self::Combinational => "combinational",
            Self::RisingEdge => "rising_edge",
            Self::FallingEdge => "falling_edge",
            Self::SetupRising => "setup_rising",
            Self::HoldRising => "hold_rising",
            Self::SetupFalling => "setup_falling",
            Self::HoldFalling => "hold_falling",
        }
    }

    /// Whether the arc is setup or hold: a constraint table on the data pin,
    /// not a delay on an output.
    pub const fn is_constraint(self) -> bool {
        matches!(
            self,
            Self::SetupRising | Self::HoldRising | Self::SetupFalling | Self::HoldFalling
        )
    }

    /// Whether the data edge is placed after the clock (hold) rather than
    /// before it (setup).
    pub const fn is_hold(self) -> bool {
        matches!(self, Self::HoldRising | Self::HoldFalling)
    }

    /// The related pin's edge a clocked arc is defined on.
    pub const fn clock_edge(self) -> Option<Edge> {
        match self {
            Self::RisingEdge | Self::SetupRising | Self::HoldRising => Some(Edge::Rise),
            Self::FallingEdge | Self::SetupFalling | Self::HoldFalling => Some(Edge::Fall),
            Self::Combinational => None,
        }
    }
}

/// A signal transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edge {
    /// Low to high.
    Rise,
    /// High to low.
    Fall,
}

impl Edge {
    /// The opposite edge.
    #[must_use]
    pub const fn flip(self) -> Self {
        match self {
            Self::Rise => Self::Fall,
            Self::Fall => Self::Rise,
        }
    }

    /// `rise` or `fall`, as Liberty group names spell it (`cell_rise`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rise => "rise",
            Self::Fall => "fall",
        }
    }
}

/// One measurement of an arc: a state to start from and what must happen.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Applied in order, one `vector_ns` apart, before the measured edge. The
    /// first must give every digital input a value.
    pub vectors: Vec<Vector>,
    /// The related pin's edge. Required for a combinational arc; a clocked arc
    /// takes it from its kind.
    #[serde(default)]
    pub edge: Option<Edge>,
    /// A delay arc: the edge `to` must make.
    #[serde(default)]
    pub output: Option<Edge>,
    /// A constraint: the edge the data pin makes.
    #[serde(default)]
    pub data: Option<Edge>,
    /// A constraint: what a correctly captured value looks like.
    #[serde(default)]
    pub check: Option<Check>,
}

/// The pin and value a constraint's pass criterion reads.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    /// The signal pin watched, usually the captured output.
    pub pin: String,
    /// The value it must hold at the end of the trial for the capture to
    /// count; `"0"` and `"1"` are read through that pin's rails.
    pub value: Level,
}

/// One PVT corner, one `.lib` file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CornerSpec {
    /// The file's corner suffix, `tt_025C_1v80`.
    pub name: String,
    /// Liberty `nom_process` and the operating condition's `process`; written,
    /// never simulated. Default 1.
    #[serde(default = "one")]
    pub process: f64,
    /// °C: the simulator's `.temp`, and the `.lib`'s `nom_temperature`.
    pub temperature: f64,
    /// Volts on every supply pin, by pin name: each supply pin needs one, and
    /// no other pin may have one. The highest `power` pin's voltage is the
    /// `.lib`'s `nom_voltage`.
    pub supplies: BTreeMap<String, f64>,
    /// Simulator lines that load this corner's models, written verbatim.
    pub models: Vec<String>,
    /// The same with statistical variation switched on. Needed only, and then
    /// for every corner, at `statistical`.
    #[serde(default)]
    pub mc_models: Vec<String>,
}

const fn one() -> f64 {
    1.0
}

/// How each quantity is measured. Defaults are `sky130_fd_sc_hd`'s tables and
/// thresholds, so a result diffs against a shipped library. Every field is
/// optional in JSON.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Characterization {
    /// Input transitions of every delay, transition and energy table, ns,
    /// measured from `slew_lower_pct` to `slew_upper_pct`: the tables'
    /// `index_1`. Positive and strictly ascending; the last is each input's
    /// `max_transition`.
    pub slews_ns: Vec<f64>,
    /// Output loads of the same tables, pF: their `index_2`. Positive and
    /// strictly ascending; the last is each output's `max_capacitance`.
    pub loads_pf: Vec<f64>,
    /// Clock and data transitions of every constraint table, ns: `index_1` is
    /// the clock's, `index_2` the data pin's. Positive and strictly ascending.
    pub constraint_slews_ns: Vec<f64>,
    /// Delay starts where the related pin crosses this percent of its swing.
    /// Default 50.
    pub input_threshold_pct: f64,
    /// Delay ends where the output crosses this percent of its swing; also
    /// where a constraint's check pin is read. Default 50.
    pub output_threshold_pct: f64,
    /// A transition is timed from this percent of the swing. In (0, 100),
    /// below `slew_upper_pct`. Default 20.
    pub slew_lower_pct: f64,
    /// A transition is timed to this percent of the swing. Default 80.
    pub slew_upper_pct: f64,
    /// A constraint passes while clock-to-check delay stays within this
    /// percent of its relaxed value (`violation_delay_degrade_pct`). Default
    /// 10.
    pub pushout_pct: f64,
    /// Time each preparation vector is held, ns; the measured edge comes one
    /// period after the last. Default 2.
    pub vector_ns: f64,
    /// The longest an output may take to respond, ns. An output still not
    /// switched by then is an error, never a long delay. Default 10.
    pub settle_ns: f64,
    /// The widest setup or hold searched, ns either side of the clock. A
    /// capture that passes even this far on the wrong side is clamped to
    /// minus this, with a note. Default 4.
    pub constraint_window_ns: f64,
    /// Monte Carlo samples per table point, `statistical` only. At least 2.
    /// Default 64.
    pub mc_samples: u32,
    /// Small-signal frequency an analog pin's capacitance is read at, Hz.
    /// Default 1 MHz.
    pub analog_frequency_hz: f64,
}

impl Default for Characterization {
    fn default() -> Self {
        Self {
            slews_ns: vec![
                0.01,
                0.023_050_6,
                0.053_132_9,
                0.122_474,
                0.282_311,
                0.650_743,
                1.5,
            ],
            loads_pf: vec![
                0.000_5,
                0.001_335_17,
                0.003_565_33,
                0.009_520_62,
                0.025_423_2,
                0.067_888_3,
                0.181_284,
            ],
            constraint_slews_ns: vec![0.01, 0.5, 1.5],
            input_threshold_pct: 50.0,
            output_threshold_pct: 50.0,
            slew_lower_pct: 20.0,
            slew_upper_pct: 80.0,
            pushout_pct: 10.0,
            vector_ns: 2.0,
            settle_ns: 10.0,
            constraint_window_ns: 4.0,
            mc_samples: 64,
            analog_frequency_hz: 1e6,
        }
    }
}

/// How to drive the simulator and spell its device cards.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Simulator {
    /// The simulator executable, looked up on `PATH`. It is run as ngspice
    /// in batch mode (`-b`), so it must be ngspice. Default `ngspice`.
    pub binary: String,
    /// `.option scale`: lengths are written divided by it. sky130 is `1e-6`.
    pub scale: f64,
    /// The card letter of an extracted device. `X` for subcircuit models.
    pub prefix: String,
    /// Extra `.option` lines.
    pub options: Vec<String>,
    /// Concurrent simulator processes; each loads the corner's models once.
    /// Default: available parallelism. Zero is refused.
    pub workers: Option<usize>,
}

impl Default for Simulator {
    fn default() -> Self {
        Self {
            binary: "ngspice".to_owned(),
            scale: 1e-6,
            prefix: "X".to_owned(),
            options: Vec::new(),
            workers: None,
        }
    }
}

/// Why [`parse`] refused a spec. The message says which key or relation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SpecError {
    /// The text is not JSON of the spec's shape: a syntax error, a missing
    /// required key, an unknown key, a misspelled role, kind or edge, or a pin
    /// value that is not `"0"`, `"1"` or a finite number.
    #[error("macro spec: {0}")]
    Malformed(String),
    /// Well-formed JSON whose parts disagree, such as a signal pin with no
    /// related supply or an arc between the wrong kinds of pin. [`parse`]
    /// lists every relation checked.
    #[error("macro spec: {0}")]
    Invalid(String),
}

/// Parses a macro spec from JSON and validates every relation a
/// characterizer would otherwise trip over mid-run.
///
/// # Errors
///
/// [`SpecError::Malformed`] when the text does not deserialize.
/// [`SpecError::Invalid`], naming the first offence, when:
///
/// - there are no pins, or a pin name repeats;
/// - a supply pin has a `power`, `ground` or `bias`, or a signal pin lacks a
///   related `power` (a `power` or `nwell` pin) or `ground` (a `ground` or
///   `pwell` pin);
/// - an analog pin has no `bias`, or another pin has a `bias` or `direction`;
/// - `substrate` is not a supply pin;
/// - there are no corners, or a corner gives a supply pin no voltage or sets
///   one on a pin that is not a supply;
/// - an arc's ends are not pins, its `from` is not an input or clock, a
///   delay's `to` is not an output, or a constraint's `to` is not an input
///   or clock;
/// - an arc has no cases, a case has no vectors, or its first vector leaves a
///   digital input undriven;
/// - a vector names a pin that is not an input or clock, or gives an analog
///   pin anything but volts;
/// - a combinational case lacks `edge`, or a clocked case has one;
/// - a delay case lacks `output` or has `data` or `check`, or a constraint
///   case lacks `data` or `check`, has `output`, or checks a supply pin;
/// - a leakage state is empty;
/// - `slews_ns`, `loads_pf` or `constraint_slews_ns` is empty, not positive or
///   not strictly ascending;
/// - a threshold is outside (0, 100), or `slew_lower_pct` is not below
///   `slew_upper_pct`;
/// - `pushout_pct`, `vector_ns`, `settle_ns`, `constraint_window_ns` or
///   `analog_frequency_hz` is not positive, or `mc_samples` is below 2;
/// - the simulator's `scale` is not positive, or `workers` is zero.
pub fn parse(text: &str) -> Result<MacroSpec, SpecError> {
    let spec: MacroSpec =
        serde_json::from_str(text).map_err(|why| SpecError::Malformed(why.to_string()))?;
    spec.validate()?;
    Ok(spec)
}

impl MacroSpec {
    /// The pin named `name`, if the spec lists one.
    pub fn pin(&self, name: &str) -> Option<&PinSpec> {
        self.pins.iter().find(|pin| pin.name == name)
    }

    /// Every relation a characterizer would otherwise trip over mid-run.
    fn validate(&self) -> Result<(), SpecError> {
        let bad = |why: String| Err(SpecError::Invalid(why));
        if self.pins.is_empty() {
            return bad("a macro has at least one pin".to_owned());
        }
        for (i, pin) in self.pins.iter().enumerate() {
            if self.pins[..i].iter().any(|other| other.name == pin.name) {
                return bad(format!("pin {} is listed twice", pin.name));
            }
            if pin.role.is_supply() {
                if pin.power.is_some() || pin.ground.is_some() || pin.bias.is_some() {
                    return bad(format!(
                        "supply pin {} takes no power, ground or bias",
                        pin.name
                    ));
                }
                continue;
            }
            for (what, related, want) in [
                ("power", &pin.power, [Role::Power, Role::Nwell]),
                ("ground", &pin.ground, [Role::Ground, Role::Pwell]),
            ] {
                let Some(name) = related else {
                    return bad(format!(
                        "signal pin {} needs a related {what} pin",
                        pin.name
                    ));
                };
                match self.pin(name) {
                    Some(other) if want.contains(&other.role) => {}
                    _ => {
                        return bad(format!(
                            "pin {}'s {what} {name} is not a {what} pin of this macro",
                            pin.name
                        ))
                    }
                }
            }
            if pin.role == Role::Analog {
                if pin.bias.is_none() {
                    return bad(format!(
                        "analog pin {} needs a bias: the voltage it sits at while \
                         everything else is measured",
                        pin.name
                    ));
                }
            } else if pin.direction.is_some() || pin.bias.is_some() {
                return bad(format!(
                    "pin {}: only an analog pin takes a direction or a bias",
                    pin.name
                ));
            }
        }
        if let Some(name) = &self.substrate {
            if !self.pin(name).is_some_and(|pin| pin.role.is_supply()) {
                return bad(format!("substrate {name} is not a supply pin"));
            }
        }
        if self.corners.is_empty() {
            return bad("at least one corner is needed, one .lib per corner".to_owned());
        }
        for corner in &self.corners {
            for pin in self.pins.iter().filter(|pin| pin.role.is_supply()) {
                if !corner.supplies.contains_key(&pin.name) {
                    return bad(format!(
                        "corner {} gives supply {} no voltage",
                        corner.name, pin.name
                    ));
                }
            }
            if let Some(stray) = corner
                .supplies
                .keys()
                .find(|name| !self.pin(name).is_some_and(|pin| pin.role.is_supply()))
            {
                return bad(format!(
                    "corner {} sets a voltage on {stray}, which is not a supply pin",
                    corner.name
                ));
            }
        }
        for arc in &self.arcs {
            self.validate_arc(arc)?;
        }
        for sequence in &self.leakage_states {
            if sequence.is_empty() {
                return bad("a leakage state is at least one vector".to_owned());
            }
            for vector in sequence {
                self.validate_vector(vector, "a leakage state")?;
            }
        }
        let c = &self.characterization;
        let positive = |values: &[f64]| !values.is_empty() && values.iter().all(|v| *v > 0.0);
        let ascending = |values: &[f64]| values.windows(2).all(|w| w[0] < w[1]);
        for (what, values) in [
            ("slews_ns", &c.slews_ns),
            ("loads_pf", &c.loads_pf),
            ("constraint_slews_ns", &c.constraint_slews_ns),
        ] {
            if !positive(values) || !ascending(values) {
                return bad(format!("{what} must be positive and strictly ascending"));
            }
        }
        let pct = |v: f64| v > 0.0 && v < 100.0;
        if !(pct(c.input_threshold_pct)
            && pct(c.output_threshold_pct)
            && pct(c.slew_lower_pct)
            && pct(c.slew_upper_pct)
            && c.slew_lower_pct < c.slew_upper_pct)
        {
            return bad("thresholds are percentages in (0, 100), lower below upper".to_owned());
        }
        if !(c.pushout_pct > 0.0
            && c.vector_ns > 0.0
            && c.settle_ns > 0.0
            && c.constraint_window_ns > 0.0
            && c.analog_frequency_hz > 0.0
            && c.mc_samples >= 2)
        {
            return bad(
                "pushout, vector, settle, window and frequency are positive; mc_samples >= 2"
                    .to_owned(),
            );
        }
        if !(self.simulator.scale > 0.0) || self.simulator.workers == Some(0) {
            return bad("simulator scale is positive and workers, if given, nonzero".to_owned());
        }
        Ok(())
    }

    fn validate_arc(&self, arc: &ArcSpec) -> Result<(), SpecError> {
        let name = format!("arc {} -> {} ({})", arc.from, arc.to, arc.kind.liberty());
        let bad = |why: String| Err(SpecError::Invalid(format!("{name}: {why}")));
        let (Some(from), Some(to)) = (self.pin(&arc.from), self.pin(&arc.to)) else {
            return bad("both ends must be pins of this macro".to_owned());
        };
        if !from.role.is_digital_input() {
            return bad(format!("{} is not an input or clock pin", from.name));
        }
        if arc.kind.is_constraint() {
            if !to.role.is_digital_input() {
                return bad(format!(
                    "{} is not an input, so nothing constrains it",
                    to.name
                ));
            }
        } else if to.role != Role::Output {
            return bad(format!("{} is not an output pin", to.name));
        }
        if arc.cases.is_empty() {
            return bad("an arc needs at least one case".to_owned());
        }
        for case in &arc.cases {
            if case.vectors.is_empty() {
                return bad("a case starts from at least one vector".to_owned());
            }
            for vector in &case.vectors {
                self.validate_vector(vector, &name)?;
            }
            let missing: Vec<&str> = self
                .pins
                .iter()
                .filter(|pin| pin.role.is_digital_input())
                .filter(|pin| !case.vectors[0].contains_key(&pin.name))
                .map(|pin| pin.name.as_str())
                .collect();
            if !missing.is_empty() {
                return bad(format!(
                    "the first vector leaves {} undriven",
                    missing.join(", ")
                ));
            }
            match (arc.kind, case.edge) {
                (ArcKind::Combinational, None) => {
                    return bad("a combinational case names its input edge".to_owned())
                }
                (ArcKind::Combinational, Some(_)) | (_, None) => {}
                (_, Some(_)) => {
                    return bad("a clocked case takes its edge from the arc kind".to_owned())
                }
            }
            if arc.kind.is_constraint() {
                let Some(check) = &case.check else {
                    return bad("a constraint case needs a check".to_owned());
                };
                if case.data.is_none() || case.output.is_some() {
                    return bad("a constraint case gives data, never output".to_owned());
                }
                if self.pin(&check.pin).is_none_or(|pin| pin.role.is_supply()) {
                    return bad(format!("check pin {} is not a signal pin", check.pin));
                }
            } else if case.output.is_none() || case.data.is_some() || case.check.is_some() {
                return bad("a delay case gives output, never data or check".to_owned());
            }
        }
        Ok(())
    }

    fn validate_vector(&self, vector: &Vector, what: &str) -> Result<(), SpecError> {
        for (name, level) in vector {
            match self.pin(name) {
                Some(pin) if pin.role.is_digital_input() => {}
                Some(pin) if pin.role == Role::Analog && matches!(level, Level::Volts(_)) => {}
                _ => {
                    return Err(SpecError::Invalid(format!(
                        "{what}: {name} is not an input (or an analog pin given volts)"
                    )))
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Level};

    const INVERTER: &str = r#"{
        "cell": "inv",
        "pins": [
            {"name": "A", "role": "input", "power": "VPWR", "ground": "VGND"},
            {"name": "Y", "role": "output", "power": "VPWR", "ground": "VGND", "function": "!A"},
            {"name": "VPWR", "role": "power"},
            {"name": "VGND", "role": "ground"}
        ],
        "arcs": [{"from": "A", "to": "Y", "kind": "combinational", "cases": [
            {"vectors": [{"A": "0"}], "edge": "rise", "output": "fall"},
            {"vectors": [{"A": "1"}], "edge": "fall", "output": "rise"}
        ]}],
        "corners": [{"name": "tt_025C_1v80", "temperature": 25,
                     "supplies": {"VPWR": 1.8, "VGND": 0}, "models": []}]
    }"#;

    /// Oracle: construct-from-answer. `INVERTER` drives `A` low in its first
    /// case, and with no `characterization` block the slews are the documented
    /// default, `sky130_fd_sc_hd`'s seven-point table.
    #[test]
    fn an_inverter_spec_parses() {
        let spec = parse(INVERTER).expect("valid");
        assert_eq!(spec.arcs[0].cases[0].vectors[0]["A"], Level::Low);
        assert_eq!(spec.characterization.slews_ns.len(), 7);
    }

    /// Oracle: `docs/liberty.md`: `accuracy` defaults to `spice`, `"all"`
    /// is the five levels, `"2"` is `field` (levels 0 to 4 from
    /// `interface`), and anything else is refused with the levels named.
    #[test]
    fn the_accuracy_field_reads_a_level_or_all() {
        use crate::liberty::Accuracy;
        let with =
            |value: &str| parse(&INVERTER.replacen('{', &format!("{{\"accuracy\": {value}, "), 1));
        assert_eq!(parse(INVERTER).expect("valid").accuracy, [Accuracy::Spice]);
        assert_eq!(with("\"all\"").expect("valid").accuracy, Accuracy::ALL);
        assert_eq!(with("\"2\"").expect("valid").accuracy, [Accuracy::Field]);
        assert_eq!(
            with("\"interface\"").expect("valid").accuracy,
            [Accuracy::Interface]
        );
        let refused = with("\"9\"").expect_err("not a level").to_string();
        assert!(
            refused.contains(
                "unknown accuracy \"9\"; expected interface, analytical, field, spice, \
                 statistical (or 0 to 4), or all"
            ),
            "{refused}"
        );
    }

    /// Each refusal is a spec that would otherwise characterize the wrong thing.
    ///
    /// Oracle: the relations `parse` documents. Each edit breaks one (a supply
    /// pin with no corner voltage, a combinational case with no `edge`, a first
    /// vector leaving an input undriven, a ground pin turned input, a level
    /// that is not one, an unknown arc kind), so each is refused.
    #[test]
    fn every_broken_relation_is_refused() {
        for (from, to) in [
            (r#""VPWR": 1.8, "VGND": 0"#, r#""VPWR": 1.8"#),
            (r#""edge": "rise", "output""#, r#""output""#),
            (r#"{"A": "0"}], "edge""#, r#"{}], "edge""#),
            (r#""role": "ground"}"#, r#""role": "input"}"#),
            (r#""A": "1""#, r#""A": "2""#),
            (r#""kind": "combinational""#, r#""kind": "combinatorial""#),
        ] {
            let broken = INVERTER.replacen(from, to, 1);
            assert_ne!(broken, INVERTER, "{from} not found");
            assert!(parse(&broken).is_err(), "accepted with {to}");
        }
    }
}
