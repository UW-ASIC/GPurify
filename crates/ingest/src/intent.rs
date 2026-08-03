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
        todo!()
    }

    /// The limits declared for a net. Default (all `None`) when undeclared.
    pub fn limits(&self, net: StrId) -> NetLimits {
        todo!()
    }

    pub fn domain_voltage(&self, domain: DomainId) -> Qty<Voltage, { prefix::MILLI }> {
        todo!()
    }

    pub fn domain_count(&self) -> usize {
        todo!()
    }

    /// True when nothing was declared, so every intent-dependent rule must
    /// report itself skipped rather than clean.
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

pub fn read_intent(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<DesignIntent, IntentError> {
    todo!()
}
