//! Electrical rule checking: one table per rule kind, one transform per table.
//!
//! Nineteen kinds, and the only thing they share is the shape of their answer —
//! a rule fired, on a net or a shape, measuring something against a limit.
//! Everything else about them differs, so nothing here is a trait object and
//! nothing matches on a rule kind inside a loop. Every kind owns an `SoA` table
//! of the rows the deck configured for it and one uniform transform over that
//! table; a run is [`RuleSet::run`] calling each transform once, on each
//! non-empty table. That is the dispatcher pattern from `docs/CONVENTIONS.md`
//! §2, and it is the same shape `drc` uses.
//!
//! # The split that shapes this crate
//!
//! Nine kinds need only what `topology` extracted — nets, devices, terminals.
//! They always run, and their verdicts are as good as the extraction.
//!
//! Six kinds need facts about *this design* that no process can supply: which
//! nets are supplies, what voltage they sit at, how much current a net is
//! budgeted, what IR drop is acceptable. Those read an [`IntentMap`], and when
//! it does not declare what they need they record themselves **skipped**:
//!
//! ```text
//! RuleRun { outcome: Outcome::Skipped(SkipReason::NoDesignIntent), .. }
//! ```
//!
//! **Never an empty clean result.** A report saying "no IR-drop violations"
//! when the run never had a supply voltage to compare against is the single
//! failure this tool is built against. It is why [`RuleRun`] exists, why
//! [`record_run`] is the only way a rule finishes a row, and why
//! [`IntentMap::declared`] is a field rather than an inference from emptiness.
//!
//! The remaining four — antenna, cumulative antenna, density/CMP, and
//! point-to-point resistance — need geometry and deck limits but no design
//! intent, so they always run too.
//!
//! # Order of operations
//!
//! `engine` sequences a run. Nothing here does it implicitly, because every
//! step allocates and the caller owns every buffer:
//!
//! 1. [`classify_nets_into`] — one pass over device terminals producing the
//!    per-net role mask that six topological rules read, instead of six passes.
//! 2. [`resolve_intent_into`] — design intent re-keyed from names to
//!    [`NetId`]. The one place `Option<&DesignIntent>` becomes a table, and the
//!    one place the skip decision is made.
//! 3. [`power::extract_nets_into`] — per-net resistor networks, for
//!    point-to-point resistance.
//! 4. [`power::extract_into`] then [`power::solve_into`] — the supply grid and
//!    its DC solve, computed **once** and shared by IR drop, EM current
//!    density, electromigration and reliability. Absent when intent declared no
//!    supplies, which is exactly what makes those four report skipped.
//! 5. [`RuleSet::run`].
//!
//! [`NetId`]: gpurify_topology::NetId

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

pub mod facts;
pub mod power;
pub mod rules;
pub mod ruleset;

pub use facts::{classify_nets_into, resolve_intent_into, IntentMap, NetFacts, RoleMask};
pub use power::{NetNetworks, PowerError, PowerGrid, PowerSolution, Process, Solved};
pub use ruleset::{RuleHead, RuleSet, RunInputs, KINDS};

use gpurify_core::connectivity::ComponentLabel;
use gpurify_core::index::SpatialIndex;
use gpurify_core::{Bbox, GeometryStore, PolyId, ValidatedLayer};
use gpurify_derived::Evaluator;
use gpurify_ingest::StrId;
use gpurify_report::{Outcome, RuleRun, Violations};
use gpurify_topology::{DeviceTable, NetTable};
use gpurify_units::{prefix, DbuArea, Qty, Resistance};

/// Why a deck could not be turned into a [`RuleSet`].
///
/// Construction-time only. Nothing here is returned from a check: a rule that
/// meets an input it cannot use records [`Outcome::Skipped`] or
/// [`Outcome::Refused`] against itself and the run continues, because one
/// unusable net must not suppress every other rule's verdict.
///
/// Stringly on purpose — these are read once, by a human, out of a deck that is
/// already wrong. The hot structures below carry [`StrId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErcError {
    /// The deck names a rule kind this crate does not implement.
    ///
    /// Fail closed. Skipping it would leave a deck that looks fully checked and
    /// is not.
    #[error("rule {rule}: unknown rule kind {kind}")]
    UnknownKind { rule: String, kind: String },
    #[error("rule {rule}: missing required parameter {param}")]
    MissingParam { rule: String, param: &'static str },
    #[error("rule {rule}: parameter {param} is not the kind of value this rule takes")]
    WrongParamType { rule: String, param: &'static str },
    #[error("rule {rule}: takes {expected} layers, the deck names {found}")]
    WrongLayerCount {
        rule: String,
        expected: u32,
        found: u32,
    },
    /// A limit that is zero or negative. Every limit in this crate is a
    /// distance, a resistance, a voltage, a current or a ratio, and none of them
    /// has a meaningful non-positive value — a `0` antenna ratio flags
    /// everything, a `0` resistance limit flags nothing.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: String },
    /// A fraction outside `0.0 ..= 1.0` — a density target, a duty cycle.
    #[error("rule {rule}: {param} must be a fraction in [0, 1]")]
    NotAFraction { rule: String, param: &'static str },
    /// The deck defines the same rule id twice. Two [`RuleRun`] rows sharing an
    /// id are attributable to nothing.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

/// Everything a rule reads about the layout, borrowed for the length of one run.
///
/// A bundle of shared references, `Copy` and with public fields, so all data
/// flow is still visible in every signature that takes one — this is not a
/// context object hiding state, it is four `&` that would otherwise be four
/// parameters on nineteen functions. Deliberately the same four fields as
/// `drc`'s bundle of the same name, so the two crates read alike.
///
/// The electrical inputs — role masks, design intent, the solved supply grid —
/// are **not** here. They are per-rule parameters precisely because which rules
/// need them is the whole subject of this crate, and burying them in a shared
/// bundle would make "this rule needs design intent" invisible at the signature.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    pub store: &'a GeometryStore,
    /// Pre-evaluated named derived layers. A rule whose deck layer is derived —
    /// a gate as `poly AND diff`, a well tap as `nsdm AND diff` — looks it up
    /// here rather than recomputing the boolean per rule.
    pub derived: &'a Evaluator,
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
}

/// The buffer set every rule transform borrows and refills.
///
/// **Five questions.** In: nothing — it is storage. Out: nothing that outlives
/// a rule. How many: exactly one per run, threaded through all nineteen
/// transforms. Access pattern: each transform clears the buffers it wants and
/// fills them; no transform reads what another left behind. Lifetime: phase —
/// this is the allocation that would otherwise be nineteen independent spatial
/// indexes, pair lists and solver workspaces per run. Parallelisable: no, and
/// that is the stated cost of one shared scratch.
///
/// The fields are private. They are storage, not interface: which buffers exist
/// is a question the Implementation-Phase gets to answer without touching a
/// frozen signature. Rules reach them directly because they are descendants of
/// this module.
///
/// ponytail: one scratch means rules run sequentially. Right at this scale — an
/// ERC run is dominated by the single power-grid solve and the per-net
/// resistance probes, both of which parallelise *inside* the transform. Upgrade
/// to one `Scratch` per worker plus the gatherer merge `Violations::extend`
/// already provides, if a profile on the scale corpus says otherwise. No
/// signature changes.
#[derive(Debug, Default)]
pub struct Scratch {
    /// Validated geometry of a rule's primary layer — a well, a pad marker, a
    /// gate.
    layer_a: ValidatedLayer,
    /// The second operand, for two-layer rules: the tap inside the well, the
    /// collector over the gate. Never aliases `layer_a`.
    layer_b: ValidatedLayer,
    index_a: SpatialIndex,
    index_b: SpatialIndex,
    /// Candidate pairs from the proximity prune. A superset; every pair here is
    /// still checked exactly.
    pairs: Vec<(PolyId, PolyId)>,
    /// One `u32` per net: a mark, a count, a driver signature. Cleared by
    /// whichever rule wants it, never read across rules.
    net_marks: Vec<u32>,
    /// Per-net or per-window area accumulator: antenna collecting area,
    /// windowed density numerator, gate area.
    areas: Vec<DbuArea>,
    /// Edge list and component labels for the rules that partition a net —
    /// soft connection removing the resistive layers, ESD path search over the
    /// clamp network.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// The linear-solve workspace. One per run, so a grid solve and a thousand
    /// per-net resistance probes share one set of vectors.
    solve: power::SolveScratch,
    /// Effective resistance between terminal pairs of one net, from
    /// [`power::effective_resistance_into`]. `(terminal_a, terminal_b, r)`.
    probes: Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
    /// Bounding boxes of one layer's shapes, for the rules that measure
    /// containment and distance rather than exact area.
    boxes: Vec<Bbox>,
}

impl Scratch {
    /// Drop every buffer's capacity.
    ///
    /// The only reason this exists is a long-lived process running many decks:
    /// the scratch grows to the largest net it ever saw and never shrinks,
    /// which is exactly what a single run wants and exactly what a server does
    /// not.
    pub fn shrink(&mut self) {
        todo!()
    }
}

/// Close out one rule row: append its [`RuleRun`], with the violation count
/// derived rather than counted by the caller.
///
/// **Decision, and the invariant lives here.** Every one of the nineteen
/// transforms ends each row through this function, so "a rule row always
/// produces exactly one run row, and its `violations` always equals what that
/// row actually pushed" is one line of code rather than nineteen chances to
/// forget.
///
/// `violations_before` is `out.len()` read before the row's work started. That
/// is what makes the count derived: a rule cannot report a violation it did not
/// push, or push one it did not report. A skipped row passes the two as equal
/// and an `examined` of zero, which is the pair a test distinguishes from a
/// clean run.
pub(crate) fn record_run(
    runs: &mut Vec<RuleRun>,
    out: &Violations,
    violations_before: usize,
    rule: StrId,
    outcome: Outcome,
    examined: u64,
) {
    todo!()
}
