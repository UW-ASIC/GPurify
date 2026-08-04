//! Design intent: the per-chip inputs a PDK cannot supply.
//!
//! Six ERC rules need facts about *this design* rather than this process —
//! which nets are supplies, what voltage they sit at, how much current a net is
//! budgeted, what IR drop is acceptable. No PDK knows any of that, so putting
//! it in the deck would make the deck per-chip.
//!
//! # Optional, but never silently so
//!
//! A run without an intent file is legitimate: DRC, LVS, PEX and the
//! topological ERC rules do not need one. The rules that do are **skipped and
//! reported as skipped**. An empty clean result standing in for "we could not
//! check this" is the false-clean failure this whole tool is built against.

use crate::intern::{StrId, StrTable};
use gpurify_units::{prefix, Qty, Voltage};

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
///
/// **Five questions.** In: a small declarative file. Out: interned nets and
/// per-net limits. How many: tens of domains, hundreds of declared nets — small
/// enough that everything here is a sorted `Vec` and nothing is hashed.
/// Lifetime: whole run, read-only after load. Parallelisable: read-only.
#[derive(Debug, Default)]
pub struct DesignIntent {
    /// Domain names, indexed by [`DomainId`].
    domain_name: Vec<StrId>,
    /// Nominal supply voltage of each domain.
    domain_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    /// Declared supply nets, sorted by name id so lookup is a binary search.
    supply_net: Vec<StrId>,
    supply_domain: Vec<DomainId>,
    supply_role: Vec<SupplyRole>,

    /// Per-net limits, sorted by net. Sparse: most nets have none.
    limit_net: Vec<StrId>,
    limit: Vec<NetLimits>,
}

/// The limits a design states for one net.
///
/// Every field is optional and a `None` means *not checked*, which the report
/// records. It does not mean *unlimited*.
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
        debug_assert_eq!(self.supply_net.len(), self.supply_domain.len());
        debug_assert_eq!(self.supply_net.len(), self.supply_role.len());

        // `binary_search` on an empty column is `Err(0)`, so this is total for
        // any `StrId` — including one interned after the intent was built.
        let row = self.supply_net.binary_search(&net).ok()?;
        Some((self.supply_domain[row], self.supply_role[row]))
    }

    /// The limits declared for a net. Default (all `None`) when undeclared.
    pub fn limits(&self, net: StrId) -> NetLimits {
        debug_assert_eq!(self.limit_net.len(), self.limit.len());

        self.limit_net
            .binary_search(&net)
            .map_or_else(|_| NetLimits::default(), |row| self.limit[row])
    }

    pub fn domain_voltage(&self, domain: DomainId) -> Qty<Voltage, { prefix::MILLI }> {
        debug_assert_eq!(self.domain_name.len(), self.domain_voltage.len());
        debug_assert!(
            (domain.0 as usize) < self.domain_voltage.len(),
            "DomainId {} is not one of the {} declared domains",
            domain.0,
            self.domain_voltage.len()
        );
        self.domain_voltage[domain.0 as usize]
    }

    pub fn domain_count(&self) -> usize {
        debug_assert_eq!(self.domain_name.len(), self.domain_voltage.len());
        self.domain_name.len()
    }

    /// True when nothing was declared, so every intent-dependent rule must
    /// report itself skipped rather than clean.
    pub fn is_empty(&self) -> bool {
        // All three, not just the supplies: a file stating only limits declared
        // something, and the sense of this predicate is "nobody wrote one".
        self.domain_name.is_empty() && self.supply_net.is_empty() && self.limit_net.is_empty()
    }
}

/// The intent file's wire shape.
///
/// `deny_unknown_fields` throughout: a typo'd key on a file that *gates* six
/// rules would leave them running against a declaration nobody made, and the
/// run would report clean. Every section is optional, so an absent one is an
/// empty column and not an error.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentFile {
    /// A `BTreeMap` rather than a `HashMap`: [`DomainId`] is this map's
    /// iteration position, so the id a domain gets must not depend on a
    /// per-process hash seed.
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
///
/// A separate type so the frozen public enum needs no `Deserialize` impl — the
/// file format is this module's business, not its callers'.
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

/// A stated limit must be a strictly positive, finite number.
///
/// `None` is *unchecked* and stays `None`. Zero, negative, NaN and infinity are
/// each refused rather than carried: a NaN compares false against every
/// measurement, so it is a limit that can never be exceeded — a limit stated by
/// the operator that silently checks nothing is the false-clean this file's
/// header names.
fn checked_limit(value: Option<f64>, net: &str) -> Result<Option<f64>, IntentError> {
    match value {
        Some(v) if !(v.is_finite() && v > 0.0) => Err(IntentError::BadLimit(net.to_owned())),
        v => Ok(v),
    }
}

/// Parse and validate design intent from memory.
///
/// Reopened in the Testing-Phase. [`read_intent`] took a `&Path` and was the
/// only producer of a [`DesignIntent`] whose fields are all private, so the only
/// intent any test could build was the absent one: `is_empty` could be shown
/// true and never false, `DomainConflict`, `DomainWithoutSupply` and `BadLimit`
/// were unreachable, and `erc::resolve_intent_into` — the re-keying every
/// intent-gated rule reads — had no populated input.
///
/// # Schema
///
/// JSON, stated here because it was stated nowhere:
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
/// Every section is optional and every key of a `limits` entry but `net` is
/// optional — an absent one is [`NetLimits`]'s `None`, which means *unchecked*
/// and never *unlimited*. A file with all three sections empty parses to an
/// intent [`DesignIntent::is_empty`] reports as empty, which is the same verdict
/// as no file at all.
///
/// `supplies` and `limits` are arrays rather than objects keyed by net so that a
/// net stated twice is *expressible*, and therefore refusable: a JSON object
/// with a repeated key silently keeps the last, which would turn
/// `DomainConflict` into a preference for whichever declaration came last.
///
/// ## What each refusal is
///
/// `Malformed` for anything not this shape, including a net repeated in
/// `limits`; `DomainConflict` for a net in `supplies` twice under two domains;
/// `DomainWithoutSupply` for a declared domain no supply entry names; `BadLimit`
/// for an IR-drop limit that is not strictly positive. Never a silent drop: an
/// intent file the tool half-understood is worse than none, because the rules it
/// gates would run against it and report clean.
///
/// The two sorted columns are sorted here, by [`StrId`], so the file may state
/// its nets in any order and the binary searches downstream hold regardless.
pub fn parse_intent(source: &str, strings: &mut StrTable) -> Result<DesignIntent, IntentError> {
    let file: IntentFile =
        serde_json::from_str(source).map_err(|e| IntentError::Malformed(e.to_string()))?;

    let mut out = DesignIntent::default();

    // `domains` is a `BTreeMap`, so its keys are already ascending and a
    // domain's index in this slice *is* its `DomainId`. That makes the
    // name-to-id lookup below a binary search over a sorted slice rather than a
    // second map.
    let domain_names: Vec<&str> = file.domains.keys().map(String::as_str).collect();
    out.domain_name.reserve(domain_names.len());
    out.domain_voltage.reserve(domain_names.len());
    // Tens of domains, hundreds of nets — declaration data, not bulk data. Every
    // loop in this function is scalar for that reason, and each pass below can
    // refuse the file mid-way, which no uniform kernel could.
    for (name, spec) in &file.domains {
        if !spec.voltage_mv.is_finite() {
            return Err(IntentError::Malformed(format!(
                "domain {name}: voltage_mv is {} rather than a number",
                spec.voltage_mv
            )));
        }
        out.domain_name.push(strings.intern(name));
        out.domain_voltage.push(Qty::new(spec.voltage_mv));
    }
    debug_assert_eq!(out.domain_name.len(), domain_names.len());

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
        return Err(IntentError::DomainWithoutSupply(domain_names[index].to_owned()));
    }

    // Sorted here so the file may state its nets in any order, and so the
    // duplicate scan below is a single adjacent-pair pass.
    supply.sort_unstable_by_key(|&(net, _, _)| net);
    // Any repeat is refused, not only a repeat under two different domains: a
    // net stated twice under one domain in two roles is the same ambiguity, and
    // `DomainConflict` is the variant that says "this net's declaration is not
    // single-valued".
    if let Some(pair) = supply.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(IntentError::DomainConflict(strings.resolve(pair[0].0).to_owned()));
    }

    // One pass writing three columns rather than three passes writing one each:
    // the row is already in registers when it is destructured. No branch in the
    // body, and the three `reserve`s put the `push` capacity checks outside the
    // loop where they are loop-invariant.
    out.supply_net.reserve(supply.len());
    out.supply_domain.reserve(supply.len());
    out.supply_role.reserve(supply.len());
    for &(net, domain, role) in &supply {
        out.supply_net.push(net);
        out.supply_domain.push(domain);
        out.supply_role.push(role);
    }
    // The columns must agree in length. This was the check `Cols::len` made on a
    // multi-column source; splitting one source into three columns owes the same
    // guarantee, and a short column here is a supply whose role or domain reads
    // off the row next door.
    debug_assert_eq!(out.supply_net.len(), supply.len());
    debug_assert_eq!(out.supply_domain.len(), supply.len());
    debug_assert_eq!(out.supply_role.len(), supply.len());

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

    out.limit_net.reserve(limit.len());
    out.limit.reserve(limit.len());
    for &(net, limits) in &limit {
        out.limit_net.push(net);
        out.limit.push(limits);
    }
    debug_assert_eq!(out.limit_net.len(), limit.len());
    debug_assert_eq!(out.limit.len(), limit.len());

    debug_assert_eq!(out.domain_name.len(), out.domain_voltage.len());
    debug_assert_eq!(out.supply_net.len(), file.supplies.len());
    debug_assert_eq!(out.supply_net.len(), out.supply_domain.len());
    debug_assert_eq!(out.supply_net.len(), out.supply_role.len());
    debug_assert_eq!(out.limit_net.len(), file.limits.len());
    debug_assert_eq!(out.limit_net.len(), out.limit.len());
    debug_assert!(
        out.supply_net.windows(2).all(|pair| pair[0] < pair[1]),
        "supply_net must be strictly ascending or its binary search is wrong"
    );
    debug_assert!(out.limit_net.windows(2).all(|pair| pair[0] < pair[1]));
    debug_assert!(out
        .supply_domain
        .iter()
        .all(|d| (d.0 as usize) < out.domain_name.len()));
    Ok(out)
}

/// Read design intent from a file.
///
/// A thin wrapper over [`parse_intent`]: reads the bytes, and every decision
/// after that belongs to the parser. Keeping the file read out of the parser is
/// what makes the parser testable.
pub fn read_intent(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<DesignIntent, IntentError> {
    // Never a silently-empty intent: a file the operator passed and the tool
    // could not open must stop the run, not turn six rules into skips the
    // operator did not ask for. Non-UTF-8 lands here too, which is the same
    // verdict for the same reason.
    let source = std::fs::read_to_string(path)
        .map_err(|e| IntentError::Io(format!("{}: {e}", path.display())))?;
    parse_intent(&source, strings)
}
