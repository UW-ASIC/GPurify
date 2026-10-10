//! Design intent: the per-chip inputs a PDK cannot supply.
//!
//! Optional. Rules needing an absent intent are reported as skipped, never as
//! clean.

use gpurify_geom::{prefix, Qty, Voltage};
use gpurify_geom::{StrId, StrTable};

/// Why an intent file was rejected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IntentError {
    /// Not JSON of the schema (an unknown key, a wrong type), more than 64
    /// domains, a domain voltage that is not finite, a supply naming an
    /// undeclared domain, or two `limits` entries for one net.
    #[error("malformed intent file: {0}")]
    Malformed(String),
    /// A net listed more than once in `supplies`, in one domain or two.
    #[error("net {0} is listed more than once in supplies")]
    DomainConflict(String),
    /// A declared domain that no supply net belongs to.
    #[error("domain {0} has no supply net")]
    DomainWithoutSupply(String),
    /// A stated limit of a net (drop, drop fraction, overvoltage or current
    /// budget) is zero, negative, `NaN` or infinite.
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

    /// True when nothing was declared, so every intent-dependent rule reports skipped, not clean.
    pub fn is_empty(&self) -> bool {
        self.domain_voltage.is_empty() && self.supplies.is_empty() && self.limits.is_empty()
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

/// Parse and validate design intent from memory.
///
/// # Schema
///
/// ```json
/// {
///   "domains":  { "<domain>": { "voltage_mv": <n> } },
///   "supplies": [{ "net": "<name>", "domain": "<domain>",
///                  "role": "power"|"ground" }],
///   "limits":   [{ "net": "<name>", "max_drop_mv": <n>,
///                  "max_drop_fraction": <f>, "max_overvoltage_mv": <n>,
///                  "budget_current_ua": <f> }]
/// }
/// ```
///
/// Every section is optional; an absent key is [`NetLimits`]'s `None`. `supplies` and
/// `limits` are arrays so a net stated twice is expressible, and therefore refusable.
///
/// # Errors
///
/// Any [`IntentError`] but [`IntentError::Io`]; nothing partial is returned.
/// On error, `strings` may have gained names.
pub fn parse_intent(source: &str, strings: &mut StrTable) -> Result<DesignIntent, IntentError> {
    let file: IntentFile =
        serde_json::from_str(source).map_err(|e| IntentError::Malformed(e.to_string()))?;

    let mut out = DesignIntent::default();

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
