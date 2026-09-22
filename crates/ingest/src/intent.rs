//! Design intent: the per-chip inputs a PDK cannot supply.
//!
//! Optional. Rules needing an absent intent are reported as skipped, never as
//! clean.

use gpurify_geom::{prefix, Qty, Voltage};
use gpurify_geom::{StrId, StrTable};

/// Why an intent file was rejected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IntentError {
    #[error("malformed intent file: {0}")]
    Malformed(String),
    #[error("net {0} is declared in two power domains")]
    DomainConflict(String),
    #[error("domain {0} has no supply net")]
    DomainWithoutSupply(String),
    #[error("net {0}: IR-drop limit is not a positive voltage")]
    BadLimit(String),
    #[error("io: {0}")]
    Io(String),
}

/// A named voltage domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DomainId(pub u32);

/// Which side of a supply pair a net is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyRole {
    Power,
    Ground,
}

/// Everything the design's owner must state that the process does not.
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
    /// Absolute IR drop permitted from the supply pad to any point.
    pub max_drop: Option<Qty<Voltage, { prefix::MILLI }>>,
    /// The same as a fraction of the domain's nominal voltage.
    pub max_drop_fraction: Option<f64>,
    /// Voltage above nominal that constitutes an overvoltage.
    pub max_overvoltage: Option<Qty<Voltage, { prefix::MILLI }>>,
    /// Current the net is budgeted to carry, for electromigration.
    pub budget_current_ua: Option<f64>,
}

impl DesignIntent {
    /// Whether a net is a declared supply, and in which role.
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
fn checked_limit(value: Option<f64>, net: &str) -> Result<Option<f64>, IntentError> {
    match value {
        Some(v) if !(v.is_finite() && v > 0.0) => Err(IntentError::BadLimit(net.to_owned())),
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
pub fn parse_intent(source: &str, strings: &mut StrTable) -> Result<DesignIntent, IntentError> {
    let file: IntentFile =
        serde_json::from_str(source).map_err(|e| IntentError::Malformed(e.to_string()))?;

    let mut out = DesignIntent::default();

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
                max_drop: checked_limit(spec.max_drop_mv, &spec.net)?.map(Qty::new),
                max_drop_fraction: checked_limit(spec.max_drop_fraction, &spec.net)?,
                max_overvoltage: checked_limit(spec.max_overvoltage_mv, &spec.net)?.map(Qty::new),
                budget_current_ua: checked_limit(spec.budget_current_ua, &spec.net)?,
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

/// Read design intent from a file.
pub fn read_intent(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<DesignIntent, IntentError> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| IntentError::Io(format!("{}: {e}", path.display())))?;
    parse_intent(&source, strings)
}
