//! The nineteen tables, and the dispatcher that runs each one once.

use crate::facts::{IntentMap, NetFacts};
use crate::power::{NetNetworks, Solved};
use crate::rules::{antenna, electrical, reliability, supply, topology};
use crate::{Design, ErcError, Scratch};
use gpurify_core::Bbox;
use gpurify_ingest::deck::Deck;
use gpurify_ingest::{StrId, StrTable};
use gpurify_report::{RuleRun, Severity, Violations};

/// Every rule kind this crate implements, as the deck spells it.
///
/// The list is here rather than spread over nineteen files because it is the
/// deck's contract: a kind absent from it is [`ErcError::UnknownKind`], and a
/// kind present in it must have a table and a transform. Adding a kind means
/// touching this array, [`RuleSet`], and [`RuleSet::run`] — three places the
/// compiler names.
pub const KINDS: [&str; 19] = [
    "antenna",
    "antenna_electrical",
    "density_cmp",
    "electromigration",
    "em_current_density",
    "esd_latchup",
    "esd_topological",
    "floating_gate",
    "floating_well",
    "hv_domain",
    "ir_drop",
    "missing_tie",
    "multiple_drivers",
    "p2p_resistance",
    "reliability",
    "soft_connection",
    "supply_short",
    "tie_high_low",
    "unconnected_pin",
];

/// The two columns every rule table has.
///
/// Discovered by repetition, not anticipated: all nineteen tables need the
/// deck's id to report against and the severity to report at, and neither has
/// anything to do with what the rule measures. Embedding one struct rather than
/// repeating two fields nineteen times also puts `len` in one place, which is
/// what the dispatcher branches on.
///
/// **Five questions.** In: rule rows from the deck. Out: the same, column-wise.
/// How many: one row per configured rule, so tens per table at most. Access
/// pattern: read once per rule row at the top of a transform, then again when a
/// violation is pushed. Lifetime: whole run, read-only after
/// [`RuleSet::from_deck`]. Parallelisable: read-only.
#[derive(Debug, Default)]
pub struct RuleHead {
    /// The deck's id for this rule, interned. What a human greps the report
    /// for, and what [`RuleRun`] is attributed to.
    pub rule: Vec<StrId>,
    pub severity: Vec<Severity>,
}

impl RuleHead {
    pub fn len(&self) -> usize {
        todo!()
    }

    /// True when the deck configured no row of this kind.
    ///
    /// The dispatcher's condition: a run is one transform per **non-empty**
    /// table, and an empty one produces no [`RuleRun`] at all. That is the
    /// correct silence — the deck did not ask for this rule, so nothing claims
    /// it was checked.
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// Every configured rule, one table per kind.
///
/// **Five questions.** In: a [`Deck`]. Out: nineteen `SoA` tables. How many:
/// one per run. Access pattern: each table is read exactly once, front to back,
/// by its own transform. Lifetime: whole run, immutable after construction.
/// Parallelisable: the tables are disjoint, so the nineteen transforms are
/// independent given per-worker scratch and violation tables.
///
/// The fields are public. This is a bag of tables, not a module with an
/// invariant to protect — accessors would be nineteen pass-throughs, and the
/// deletion test says they earn nothing.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub floating_gate: topology::FloatingGateTable,
    pub floating_well: topology::FloatingWellTable,
    pub multiple_drivers: topology::MultipleDriversTable,
    pub unconnected_pin: topology::UnconnectedPinTable,

    pub supply_short: supply::SupplyShortTable,
    pub soft_connection: supply::SoftConnectionTable,
    pub missing_tie: supply::MissingTieTable,
    pub tie_high_low: supply::TieHighLowTable,
    pub esd_topological: supply::EsdTopologicalTable,

    pub antenna: antenna::AntennaTable,
    pub antenna_electrical: antenna::AntennaElectricalTable,
    pub density_cmp: antenna::DensityCmpTable,

    pub p2p_resistance: electrical::P2pResistanceTable,
    pub ir_drop: electrical::IrDropTable,
    pub em_current_density: electrical::EmCurrentDensityTable,
    pub electromigration: electrical::ElectromigrationTable,

    pub reliability: reliability::ReliabilityTable,
    pub hv_domain: reliability::HvDomainTable,
    pub esd_latchup: reliability::EsdLatchupTable,
}

/// Everything one run reads, borrowed.
///
/// `Copy`, public fields, and every one of them is a parameter of some
/// transform below — this is the dispatcher's argument list written down once
/// instead of nine times.
#[derive(Debug, Clone, Copy)]
pub struct RunInputs<'a> {
    pub design: Design<'a>,
    /// Per-net role masks from [`crate::classify_nets_into`].
    pub facts: &'a NetFacts,
    /// Design intent re-keyed onto nets. Carries its own "nothing was
    /// declared" flag, which is what six of these rules read first.
    pub intent: &'a IntentMap,
    /// Per-net resistor networks from [`crate::power::extract_nets_into`].
    pub networks: &'a NetNetworks,
    /// The solved supply grid, or `None` when intent declared no supplies and
    /// therefore no grid was built. Four rules read this and record themselves
    /// skipped on `None`.
    pub power: Option<Solved<'a>>,
    /// The die boundary. Density is a fraction of an area, and the denominator
    /// has to come from somewhere the layout does not state: empty space inside
    /// the die is checked, empty space outside it is not there.
    pub die: Bbox,
}

impl RuleSet {
    /// Build the tables from a deck.
    ///
    /// **Transform, dispatcher.** This is the one place a rule kind is matched
    /// against a string, and it happens once per rule row at load time. After
    /// it, every loop in this crate is uniform over one table.
    ///
    /// Fails closed on anything it does not understand: an unknown kind, a
    /// missing parameter, a non-positive limit. A deck with one bad rule is not
    /// partially usable, because a caller cannot tell a rule that was dropped
    /// from a rule that found nothing.
    ///
    /// Allocating rather than `_into`: called once per run, against a deck of
    /// hundreds of rows. The `_into` form exists for transforms called in a
    /// loop, and this one is not.
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, ErcError> {
        todo!()
    }

    /// How many rule rows are configured across every table.
    ///
    /// The number of [`RuleRun`] rows a run must produce. A test comparing this
    /// against `runs.len()` after [`RuleSet::run`] is what catches a transform
    /// that returned early without recording itself — the exact shape of the
    /// false-clean failure.
    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    /// Run every non-empty table's transform once.
    ///
    /// **Transform, dispatcher.** Caller owns `scratch`, `out` and `runs`; all
    /// three are appended to, not cleared, so a caller may accumulate several
    /// cells into one report. Nothing here allocates per rule row.
    ///
    /// Order is the field order above — topological rules first, then the
    /// geometric ones, then the electrical ones. It is not load-bearing:
    /// `Violations::sort_canonical` establishes the report order, and `runs` is
    /// sorted by rule id by the caller. Stating it anyway, because a test that
    /// reads `runs` positionally would otherwise depend on something no one
    /// promised.
    ///
    /// Every configured rule row produces exactly one [`RuleRun`], including
    /// the ones that could not run. A transform that returns without recording
    /// is the defect this crate is shaped to prevent.
    pub fn run(
        &self,
        inputs: RunInputs<'_>,
        scratch: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        todo!()
    }
}
