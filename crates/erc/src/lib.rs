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
//! `record_run` is the only way a rule finishes a row, and why
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

pub mod facts;
pub mod power;
pub mod rules;
pub mod ruleset;

pub use facts::{classify_nets_into, resolve_intent_into, IntentMap, NetFacts, RoleMask};
pub use power::{NetNetworks, PowerError, PowerGrid, PowerSolution, Process, Solved};
pub use ruleset::{RuleHead, RuleSet, RunInputs, KINDS};

use gpurify_core::connectivity::ComponentLabel;
use gpurify_core::ops::Point;
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_derived::{Evaluator, LayerRef};
use gpurify_ingest::StrId;
use gpurify_report::{Outcome, RuleRun, Violations};
use gpurify_topology::{DeviceTable, NetTable};
use gpurify_units::{prefix, Dbu, DbuArea, Qty, Resistance};

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
/// One scratch means the nineteen rule transforms run sequentially. Right at
/// this scale — an ERC run is dominated by the single power-grid solve and the
/// per-net resistance probes, both of which parallelise *inside* the transform.
///
/// Running the *transforms* in parallel is not a body change and cannot be done
/// from here: eleven of them take `scratch: &mut Scratch`, and one `&mut` does
/// not split into eleven. Per-worker scratch is a signature change to every one
/// of them plus a `rayon` dependency this crate does not have, so it is recorded
/// in `docs/SIGNATURE_DEFECTS.md` rather than attempted. The merge half of it is
/// already in place — `Violations::extend` is the gatherer.
#[derive(Debug, Default)]
pub struct Scratch {
    /// Validated geometry of a rule's primary layer — a well, a pad marker, a
    /// gate.
    layer_a: ValidatedLayer,
    /// The second operand, for two-layer rules: the tap inside the well, the
    /// collector over the gate. Never aliases `layer_a`.
    layer_b: ValidatedLayer,
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
    ///
    /// **No observable postcondition, by construction.** Capacity is not part
    /// of this crate's interface — the fields are private and neither length
    /// nor capacity is exposed — so no test can distinguish this body from an
    /// empty one, and a mutant that empties it is an *equivalent mutant*
    /// rather than a survivor. That is the accepted resolution and not an
    /// oversight: adding a capacity accessor would widen the interface of a
    /// type whose whole doc comment says which buffers exist is an
    /// implementation question. The Implementation-Phase records the
    /// equivalence argument here, next to the body.
    pub fn shrink(&mut self) {
        // Reassignment rather than per-field `shrink_to_fit`: `ValidatedLayer`,
        // `SpatialIndex` and `SolveScratch` own their columns privately and
        // expose no way to release them. Every field is storage refilled before
        // it is read, so dropping the lot is exactly "capacity gone, nothing
        // else changed" — and it is the same body `drc::Scratch::shrink` uses.
        *self = Self::default();
    }
}

/// The store layer a rule row names, or `None` when it names a derived one.
///
/// **Decision** — one value in, one out, and the single place this crate decides
/// what it can check.
///
/// Most rules here reach their geometry through a [`PolyId`]: a supply short is
/// a tap's *net*, a soft connection is a net's polygons partitioned by layer, an
/// antenna ratio is reported at the gate it accumulated onto, and a floating
/// well is reported at the well. A derived layer supplies none of those —
/// [`ValidatedLayer`] keeps its provenance column private and hands out no
/// [`PolyId`] — so a row naming one records [`Outcome::Refused`] rather than
/// being checked against geometry it cannot attribute. Fail closed: a clean
/// result for a layer the rule never managed to read is the report this crate
/// exists to prevent.
///
/// One copy for the crate. Three rule modules each made this decision and a
/// fourth answer to "may this row name a derived layer" is a rule silently
/// checking different geometry than the deck asked for. The exception is
/// [`rules::supply`]'s tap, which is only ever measured *to* and so needs no
/// `PolyId`; it takes the other branch through its own `tap_geometry`.
pub(crate) const fn base_layer(layer: LayerRef) -> Option<LayerId> {
    match layer {
        LayerRef::Base(id) => Some(id),
        LayerRef::Named(_) => None,
    }
}

/// A point on a polygon, for [`gpurify_report::Violation::at`].
///
/// **Decision** — one store row in, one point out. Vertex zero, not a
/// bounding-box corner: the coordinate contract is that the point lies *on* the
/// geometry the row names, and an L-shaped conductor's box corner sits in the
/// notch. It is canonical because a store row's vertex order is.
///
/// One copy for the whole crate. Three rule modules each reported at a
/// polygon's first vertex, and three copies of "which point does a per-shape
/// violation name" is three chances for one of them to answer differently.
pub(crate) fn first_vertex(store: &GeometryStore, poly: PolyId) -> Point {
    let (xs, ys) = store.poly_verts(poly);
    debug_assert_eq!(xs.len(), ys.len(), "the store's columns are parallel");
    debug_assert!(!xs.is_empty(), "a polygon in the store has vertices");
    Point { x: xs[0], y: ys[0] }
}

/// The centre of a box: where a violation over a region marks, and where
/// [`power`] puts a shape's node.
///
/// **Decision** — four coordinates in, one point out. Truncating division, so a
/// box of odd span reports the coordinate just inside its lower half rather
/// than a half unit, which is not a coordinate. Both bounds are in domain, so
/// each sum is within `2^41` and the halved result is back inside it.
pub(crate) fn centre(box_: Bbox) -> Point {
    debug_assert!(
        box_.xlo.raw() <= box_.xhi.raw() && box_.ylo.raw() <= box_.yhi.raw(),
        "a box's bounds run low to high"
    );
    debug_assert!(
        box_.xlo.raw().abs() <= gpurify_units::MAX_ABS_DBU
            && box_.ylo.raw().abs() <= gpurify_units::MAX_ABS_DBU
            && box_.xhi.raw().abs() <= gpurify_units::MAX_ABS_DBU
            && box_.yhi.raw().abs() <= gpurify_units::MAX_ABS_DBU,
        "a box outside the coordinate domain has no representable centre"
    );
    Point {
        x: Dbu::new_unchecked(i64::midpoint(box_.xlo.raw(), box_.xhi.raw())),
        y: Dbu::new_unchecked(i64::midpoint(box_.ylo.raw(), box_.yhi.raw())),
    }
}

/// `0 .. n` as a column, so a `compact_into` over a per-net column can carry the
/// net each kept row came from.
///
/// **Transform, generative.** `compact_into`'s destination holds `C::Item`, so a
/// compact over a bare `&[RoleMask]` comes back holding masks and not the nets
/// that own them. Pairing the mask column with this one is what makes the kept
/// rows addressable, and it is built once per call rather than once per rule
/// row.
pub(crate) fn ascending(n: usize) -> Vec<u32> {
    let n = u32::try_from(n).expect("an extracted net count fits a u32");
    (0..n).collect()
}

/// Report one violation per flagged net, at that net's lowest-numbered polygon.
///
/// **Transform, gatherer.** Discovered by repetition: four rules across
/// [`rules::supply`] and [`rules::topology`] decide per net and report per net,
/// and the canonical shape to name is the same one every time —
/// [`NetTable::polys_of`] is ascending, so its first row is the net's lowest
/// [`PolyId`] and therefore does not depend on how the rule arrived at the net.
/// Four rules answering "which shape does a per-net violation name" separately
/// is four chances for one of them to answer differently.
///
/// Not a vector shape, and it stays scalar: a violation is eight output columns
/// written from three gathers, and the append is data-dependent, so the output
/// index is not an affine function of the input index. The trip count is one
/// row per flagged net — the flagging pass above it is the bulk dimension.
///
/// [`NetTable::polys_of`]: gpurify_topology::NetTable::polys_of
pub(crate) fn push_net_violations<T: Copy>(
    design: Design<'_>,
    flagged: &[(u32, T)],
    rule: StrId,
    severity: gpurify_report::Severity,
    measured: gpurify_report::Measurement,
    limit: gpurify_report::Measurement,
    out: &mut Violations,
) {
    let before = out.len();
    for &(net, _) in flagged {
        let polys = design.nets.polys_of(gpurify_topology::NetId(net));
        // Surviving `if`, spelled as a `let else`: extraction numbers a net only
        // when a polygon claims it, so this is not taken on a table
        // `extract_nets_into` produced. `NetTable::from_assignment` documents
        // the empty net it can build, and a violation naming no shape is worse
        // than none at all.
        let Some(&poly) = polys.first() else {
            continue;
        };
        out.push(gpurify_report::Violation {
            rule,
            layer: design.store.poly_layer(poly),
            severity,
            at: first_vertex(design.store, poly),
            measured,
            limit,
            shapes: (poly, None),
        });
    }
    debug_assert!(
        out.len() - before <= flagged.len(),
        "one violation per flagged net at most"
    );
}

/// Record every row of a rule table as skipped for want of design intent.
///
/// **Decision.** The gate is a property of the call and not of a row — a run
/// either has a usable [`IntentMap`] and a solve or it has neither — so it is
/// tested once above the row loop and spent here, and every row still produces
/// exactly one [`RuleRun`], which is the invariant [`record_run`] exists for.
///
/// One copy for the crate: seven of the eight intent-gated transforms reach
/// this state, and a rule that returned early without it would report nothing
/// at all, which reads as clean.
///
/// [`IntentMap`]: facts::IntentMap
pub(crate) fn skip_rows(head: &RuleHead, out: &Violations, runs: &mut Vec<RuleRun>) {
    // Not bulk: a deck configures tens of rows per kind.
    for row in 0..head.len() {
        record_run(
            runs,
            out,
            out.len(),
            head.rule[row],
            Outcome::Skipped(gpurify_report::SkipReason::NoDesignIntent),
            0,
        );
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
    let after = out.len();
    debug_assert!(
        violations_before <= after,
        "a rule row started at {violations_before} of a table that now holds {after}: \
         the shared violation table was truncated under a running rule"
    );
    let pushed = after - violations_before;
    debug_assert!(
        u32::try_from(pushed).is_ok(),
        "{pushed} violations from one rule row overflow the run's count column"
    );
    // No assert tying `pushed`/`examined` to a non-`Ran` outcome: a rule that
    // refuses partway through (`rules::electrical.rs:244`) has legitimately
    // examined and pushed rows before hitting the input it will not represent.

    let before_rows = runs.len();
    runs.push(RuleRun {
        rule,
        outcome,
        examined,
        // Saturating rather than wrapping: past 4 billion violations from one
        // rule the exact count is noise, but wrapping it to a small number
        // would read as a nearly-clean rule, which is fail-open.
        violations: u32::try_from(pushed).unwrap_or(u32::MAX),
    });
    debug_assert_eq!(
        runs.len(),
        before_rows + 1,
        "one rule row produces exactly one run row"
    );
}
