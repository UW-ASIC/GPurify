//! Design intent: the per-chip inputs a PDK cannot supply.
//!
//! Optional. Rules needing an absent intent are reported as skipped, never as
//! clean.

use gpurify_geom::{celsius, prefix, Qty, Temperature, Voltage};
use gpurify_geom::{StrId, StrTable};

/// Why an intent file was rejected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IntentError {
    /// Not JSON of the schema (an unknown key, a wrong type), more than 64
    /// domains, a domain voltage that is not finite, a supply naming an
    /// undeclared domain, two `limits` entries for one net, a temperature
    /// that is not finite or not above absolute zero, or a `dynamic` entry
    /// that cannot be simulated: no `budget_current_ua` beside it, a toggle
    /// rate above 1, a rise time longer than the clock period, or a negative
    /// decap, or a power state that repeats a name, turns off a net no
    /// supply declares, or pins an input twice or to a voltage that is not
    /// finite.
    #[error("malformed intent file: {0}")]
    Malformed(String),
    /// A net listed more than once in `supplies`, in one domain or two.
    #[error("net {0} is listed more than once in supplies")]
    DomainConflict(String),
    /// A declared domain that no supply net belongs to.
    #[error("domain {0} has no supply net")]
    DomainWithoutSupply(String),
    /// A stated limit of a net (drop, drop fraction, overvoltage, current
    /// budget, or a `dynamic` drop, toggle rate, clock period or rise time)
    /// is zero, negative, `NaN` or infinite.
    #[error("net {net}: {limit} is not a positive finite number")]
    BadLimit {
        /// The net the limit belongs to.
        net: String,
        /// The limit's key in the file, such as `max_drop_mv`.
        limit: &'static str,
    },
    /// The intent file could not be read.
    #[error("io: {0}")]
    Io(String),
}

/// A named voltage domain: its position among the file's domain names in
/// ascending byte order, from 0, below 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DomainId(pub u32);

/// Which side of a supply pair a net is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyRole {
    /// Sits at its domain's voltage.
    Power,
    /// Sits at 0 V; its drop is how far it rises.
    Ground,
}

/// Everything the design's owner must state that the process does not.
///
/// Built by [`parse_intent`] or [`read_intent`]; nets are named by [`StrId`]
/// in the run's table, so a net matches when its layout label has the same text.
#[derive(Debug, Default)]
pub struct DesignIntent {
    /// Nominal supply voltage, indexed by [`DomainId`].
    domain_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Declared supply nets, strictly ascending by name id.
    supplies: Vec<(StrId, DomainId, SupplyRole)>,
    /// Per-net limits, strictly ascending by net. Sparse.
    limits: Vec<(StrId, NetLimits)>,
    /// The junction temperature the chip runs at (`temperature_c`).
    temperature: Option<Qty<Temperature, { prefix::BASE }>>,
    /// Declared power states, in file order.
    states: Vec<PowerState>,
}

/// One power state of the design: which supplies are switched off, and which
/// inputs are held at a voltage, while it lasts (IEEE 1801 power states, cited
/// for scope; Calibre PERC's vectored inputs, public white paper 81822).
///
/// Every supply not listed in `off` stays on at its domain's voltage.
#[derive(Debug, Clone)]
pub struct PowerState {
    /// The state's name, unique in the file.
    pub name: StrId,
    /// Declared supply nets switched off: they hold no voltage in this state.
    pub off: Vec<StrId>,
    /// Nets held at a voltage in this state, mV, each named once: an enable
    /// tied low, a control input driven high.
    pub inputs: Vec<(StrId, Qty<Voltage, { prefix::MILLI }>)>,
}

/// The limits a design states for one net. `None` means *not checked*, never
/// *unlimited*.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetLimits {
    /// Absolute IR drop permitted from the supply pad to any point, mV
    /// (`max_drop_mv`).
    pub max_drop: Option<Qty<Voltage, { prefix::MILLI }>>,
    /// The same as a fraction of the domain's nominal voltage
    /// (`max_drop_fraction`), for a power or a ground net.
    pub max_drop_fraction: Option<f64>,
    /// Voltage above nominal that constitutes an overvoltage, mV
    /// (`max_overvoltage_mv`).
    pub max_overvoltage: Option<Qty<Voltage, { prefix::MILLI }>>,
    /// Current the net is budgeted to carry, µA (`budget_current_ua`), for
    /// electromigration and IR drop.
    pub budget_current_ua: Option<f64>,
    /// The vectorless switching the dynamic drop is simulated from, and its
    /// limit (`dynamic`). Stated only beside `budget_current_ua`.
    pub dynamic: Option<Switching>,
}

/// One net's worst switching cycle, for vectorless dynamic IR drop: every load
/// on the net switches at once, each drawing the charge of its share of the
/// budget over the cycles it switches in.
#[derive(Debug, Clone, Copy)]
pub struct Switching {
    /// The dynamic drop permitted at any node of the net, mV
    /// (`max_drop_mv`).
    pub max_drop: Qty<Voltage, { prefix::MILLI }>,
    /// The fraction of clock cycles in which a load switches, `0 < α <= 1`
    /// (`toggle_rate`). The budget is the average over every cycle, so one
    /// switching event carries the budget's charge over `1 / α` cycles.
    pub toggle_rate: f64,
    /// The clock period, ps (`clock_period_ps`): the cycle simulated.
    pub clock_period_ps: f64,
    /// The current pulse's base, ps (`rise_time_ps`), at most the period.
    pub rise_time_ps: f64,
    /// Decoupling capacitance on the net, intrinsic and placed, pF
    /// (`decap_pf`); zero or more, zero when left out.
    pub decap_pf: f64,
}

impl DesignIntent {
    /// Whether a net is a declared supply, and in which domain and role.
    /// `O(log supplies)`.
    pub fn supply_role(&self, net: StrId) -> Option<(DomainId, SupplyRole)> {
        let row = self.supplies.binary_search_by_key(&net, |s| s.0).ok()?;
        let (_, domain, role) = self.supplies[row];
        Some((domain, role))
    }

    /// The limits declared for a net. Default (all `None`) when undeclared.
    pub fn limits(&self, net: StrId) -> NetLimits {
        self.limits
            .binary_search_by_key(&net, |l| l.0)
            .map_or_else(|_| NetLimits::default(), |row| self.limits[row].1)
    }

    /// Returns a domain's nominal voltage, as the file states it (any finite
    /// value). Panics on an id from another intent.
    pub fn domain_voltage(&self, domain: DomainId) -> Qty<Voltage, { prefix::MILLI }> {
        self.domain_voltage[domain.0 as usize]
    }

    /// The declared power states, in file order; empty when the file has none.
    pub fn states(&self) -> &[PowerState] {
        &self.states
    }

    /// The junction temperature the file states, absolute; `None` leaves the
    /// run's default.
    pub fn temperature(&self) -> Option<Qty<Temperature, { prefix::BASE }>> {
        self.temperature
    }

    /// True when nothing was declared, so every intent-dependent rule reports skipped, not clean.
    pub fn is_empty(&self) -> bool {
        self.domain_voltage.is_empty()
            && self.supplies.is_empty()
            && self.limits.is_empty()
            && self.states.is_empty()
    }
}

/// The intent file's wire shape.
///
/// `deny_unknown_fields` throughout: a typo'd key would silently ungate a rule.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentFile {
    /// `BTreeMap`: a [`DomainId`] is this map's iteration position.
    #[serde(default)]
    domains: std::collections::BTreeMap<String, DomainSpec>,
    #[serde(default)]
    supplies: Vec<SupplySpec>,
    #[serde(default)]
    limits: Vec<LimitSpec>,
    temperature_c: Option<f64>,
    #[serde(default)]
    states: Vec<StateSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StateSpec {
    name: String,
    #[serde(default)]
    off: Vec<String>,
    #[serde(default)]
    inputs: Vec<InputSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InputSpec {
    net: String,
    voltage_mv: f64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainSpec {
    voltage_mv: f64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplySpec {
    net: String,
    domain: String,
    role: RoleSpec,
}

/// The wire spelling of [`SupplyRole`].
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum RoleSpec {
    Power,
    Ground,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitSpec {
    net: String,
    max_drop_mv: Option<f64>,
    max_drop_fraction: Option<f64>,
    max_overvoltage_mv: Option<f64>,
    budget_current_ua: Option<f64>,
    dynamic: Option<DynamicSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicSpec {
    max_drop_mv: f64,
    toggle_rate: f64,
    clock_period_ps: f64,
    rise_time_ps: f64,
    #[serde(default)]
    decap_pf: f64,
}

/// A stated limit must be a strictly positive, finite number. Zero, negative,
/// NaN and infinity are refused rather than carried: a NaN compares false
/// against every measurement, so it would check nothing.
fn checked_limit(
    value: Option<f64>,
    net: &str,
    limit: &'static str,
) -> Result<Option<f64>, IntentError> {
    match value {
        Some(v) if !(v.is_finite() && v > 0.0) => Err(IntentError::BadLimit {
            net: net.to_owned(),
            limit,
        }),
        v => Ok(v),
    }
}

/// A net's `dynamic` entry, validated: every number positive and finite
/// (`decap_pf` zero or more), a toggle rate of at most 1, a rise within the
/// period, and a budget beside it for the charge to come from.
fn checked_switching(
    spec: &DynamicSpec,
    net: &str,
    budget: Option<f64>,
) -> Result<Switching, IntentError> {
    let positive =
        |value: f64, limit: &'static str| checked_limit(Some(value), net, limit).map(|_| value);
    let switching = Switching {
        max_drop: Qty::new(positive(spec.max_drop_mv, "dynamic.max_drop_mv")?),
        toggle_rate: positive(spec.toggle_rate, "dynamic.toggle_rate")?,
        clock_period_ps: positive(spec.clock_period_ps, "dynamic.clock_period_ps")?,
        rise_time_ps: positive(spec.rise_time_ps, "dynamic.rise_time_ps")?,
        decap_pf: spec.decap_pf,
    };
    let why = if budget.is_none() {
        "needs budget_current_ua, the current it switches"
    } else if switching.toggle_rate > 1.0 {
        "toggle_rate is a fraction of cycles, at most 1"
    } else if switching.rise_time_ps > switching.clock_period_ps {
        "rise_time_ps is longer than clock_period_ps"
    } else if !(switching.decap_pf.is_finite() && switching.decap_pf >= 0.0) {
        "decap_pf is negative or not finite"
    } else {
        return Ok(switching);
    };
    Err(IntentError::Malformed(format!("net {net}: dynamic {why}")))
}

/// Parse and validate design intent from memory.
///
/// # Schema
///
/// ```json
/// {
///   "temperature_c": <n>,
///   "domains":  { "<domain>": { "voltage_mv": <n> } },
///   "supplies": [{ "net": "<name>", "domain": "<domain>",
///                  "role": "power"|"ground" }],
///   "limits":   [{ "net": "<name>", "max_drop_mv": <n>,
///                  "max_drop_fraction": <f>, "max_overvoltage_mv": <n>,
///                  "budget_current_ua": <f>,
///                  "dynamic": { "max_drop_mv": <n>, "toggle_rate": <f>,
///                               "clock_period_ps": <n>, "rise_time_ps": <n>,
///                               "decap_pf": <n> } }],
///   "states":   [{ "name": "<state>", "off": ["<supply net>"],
///                  "inputs": [{ "net": "<name>", "voltage_mv": <n> }] }]
/// }
/// ```
///
/// Every section is optional; an absent key is [`NetLimits`]'s `None`, and an
/// absent `decap_pf` is zero. `temperature_c` is the junction temperature
/// the reliability rules run at. `supplies` and `limits` are arrays so a net
/// stated twice is expressible, and therefore refusable.
///
/// # Errors
///
/// Any [`IntentError`] but [`IntentError::Io`]; nothing partial is returned.
/// On error, `strings` may have gained names.
pub fn parse_intent(source: &str, strings: &mut StrTable) -> Result<DesignIntent, IntentError> {
    let file: IntentFile =
        serde_json::from_str(source).map_err(|e| IntentError::Malformed(e.to_string()))?;

    let mut out = DesignIntent::default();
    if let Some(degrees) = file.temperature_c {
        let kelvin = celsius(degrees);
        if !(kelvin.is_finite() && kelvin.raw() > 0.0) {
            return Err(IntentError::Malformed(format!(
                "temperature_c is {degrees}, not a temperature above absolute zero"
            )));
        }
        out.temperature = Some(kelvin);
    }

    // ponytail: a domain is one bit of a u64 in ERC's voltage propagation; widen the mask past 64.
    if file.domains.len() > 64 {
        return Err(IntentError::Malformed(format!(
            "{} domains declared; at most 64 are supported",
            file.domains.len()
        )));
    }
    // A domain's index in the `BTreeMap` *is* its `DomainId`.
    let domain_names: Vec<&str> = file.domains.keys().map(String::as_str).collect();
    for (name, spec) in &file.domains {
        if !spec.voltage_mv.is_finite() {
            return Err(IntentError::Malformed(format!(
                "domain {name}: voltage_mv is {} rather than a number",
                spec.voltage_mv
            )));
        }
        strings.intern(name); // Not stored; interning order is report order.
        out.domain_voltage.push(Qty::new(spec.voltage_mv));
    }

    let mut supply = Vec::with_capacity(file.supplies.len());
    let mut domain_has_supply = vec![false; domain_names.len()];
    for spec in &file.supplies {
        let Ok(index) = domain_names.binary_search(&spec.domain.as_str()) else {
            return Err(IntentError::Malformed(format!(
                "supply {} names domain {}, which the file does not declare",
                spec.net, spec.domain
            )));
        };
        let role = match spec.role {
            RoleSpec::Power => SupplyRole::Power,
            RoleSpec::Ground => SupplyRole::Ground,
        };
        let domain = DomainId(crate::narrow(index));
        supply.push((strings.intern(&spec.net), domain, role));
        domain_has_supply[index] = true;
    }

    if let Some(index) = domain_has_supply.iter().position(|&used| !used) {
        return Err(IntentError::DomainWithoutSupply(
            domain_names[index].to_owned(),
        ));
    }

    // Sorted so the file may state its nets in any order.
    supply.sort_unstable_by_key(|&(net, _, _)| net);
    // Any repeat is refused, not only a repeat under two different domains.
    if let Some(pair) = supply.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(IntentError::DomainConflict(
            strings.resolve(pair[0].0).to_owned(),
        ));
    }

    out.supplies = supply;

    let mut limit = Vec::with_capacity(file.limits.len());
    for spec in &file.limits {
        limit.push((
            strings.intern(&spec.net),
            NetLimits {
                max_drop: checked_limit(spec.max_drop_mv, &spec.net, "max_drop_mv")?.map(Qty::new),
                max_drop_fraction: checked_limit(
                    spec.max_drop_fraction,
                    &spec.net,
                    "max_drop_fraction",
                )?,
                max_overvoltage: checked_limit(
                    spec.max_overvoltage_mv,
                    &spec.net,
                    "max_overvoltage_mv",
                )?
                .map(Qty::new),
                budget_current_ua: checked_limit(
                    spec.budget_current_ua,
                    &spec.net,
                    "budget_current_ua",
                )?,
                dynamic: match &spec.dynamic {
                    None => None,
                    Some(dynamic) => Some(checked_switching(
                        dynamic,
                        &spec.net,
                        spec.budget_current_ua,
                    )?),
                },
            },
        ));
    }

    limit.sort_unstable_by_key(|&(net, _)| net);
    if let Some(pair) = limit.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(IntentError::Malformed(format!(
            "net {} has two limits entries",
            strings.resolve(pair[0].0)
        )));
    }

    out.limits = limit;

    for spec in &file.states {
        let name = strings.intern(&spec.name);
        if out.states.iter().any(|state| state.name == name) {
            return Err(IntentError::Malformed(format!(
                "power state {} is declared twice",
                spec.name
            )));
        }
        let mut off = Vec::with_capacity(spec.off.len());
        for net in &spec.off {
            let id = strings.intern(net);
            if out.supply_role(id).is_none() {
                return Err(IntentError::Malformed(format!(
                    "power state {} turns off {net}, which no supply declares",
                    spec.name
                )));
            }
            off.push(id);
        }
        let mut inputs: Vec<(StrId, Qty<Voltage, { prefix::MILLI }>)> =
            Vec::with_capacity(spec.inputs.len());
        for input in &spec.inputs {
            if !input.voltage_mv.is_finite() {
                return Err(IntentError::Malformed(format!(
                    "power state {}: input {} has voltage_mv {}, not a number",
                    spec.name, input.net, input.voltage_mv
                )));
            }
            let id = strings.intern(&input.net);
            if inputs.iter().any(|&(seen, _)| seen == id) {
                return Err(IntentError::Malformed(format!(
                    "power state {}: input {} is held twice",
                    spec.name, input.net
                )));
            }
            inputs.push((id, Qty::new(input.voltage_mv)));
        }
        out.states.push(PowerState { name, off, inputs });
    }
    Ok(out)
}

/// Reads design intent from a file; see [`parse_intent`] for the schema.
///
/// # Errors
///
/// [`IntentError::Io`] naming the path when it cannot be read, else as
/// [`parse_intent`].
pub fn read_intent(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<DesignIntent, IntentError> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| IntentError::Io(format!("{}: {e}", path.display())))?;
    parse_intent(&source, strings)
}
