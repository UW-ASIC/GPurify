//! Running the checks, and reporting honestly about which ones ran.

use crate::pipeline::{Extracted, Inputs, Loaded};
use gpurify_core::ops::Point;
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::{StrId, StrTable};
use gpurify_lvs::verdict::Inconclusive;
use gpurify_lvs::{Discrepancy, Verdict};
use gpurify_pex::network::NodeId;
use gpurify_pex::ParasiticNetwork;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_units::{celsius, prefix, Dbu, Grid, Qty, Temperature};

/// Which checks to run.
///
/// Named flags rather than a bitmask: `Checks { drc: true, .. }` reads at the
/// call site, and there is no combination that is illegal, so a struct of
/// `bool` is honest here where a sum type would be forced.
///
/// CONVENTIONS §3 prefers a sum type over a flag-bag, but the rule it states is
/// "an `enum` beats a struct of `bool`s **whose combinations are mostly
/// illegal**". All sixteen combinations here are meaningful, including none,
/// so the condition does not hold and the lint is answered rather than obeyed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    pub drc: bool,
    pub erc: bool,
    pub lvs: bool,
    pub pex: bool,
}

impl Checks {
    /// All four.
    pub const ALL: Self = Self { drc: true, erc: true, lvs: true, pex: true };
}

/// How to run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub checks: Checks,
    pub lvs: gpurify_lvs::CompareOptions,
    /// Nets to extract by field solve. Empty means analytical extraction only,
    /// which is what a full-chip run wants.
    pub quasistatic_nets: Vec<String>,
    /// Worker threads. Affects speed only: the determinism gate requires
    /// byte-identical output at any value of this, so if changing it changes
    /// the output that is a bug this field exists to catch.
    pub threads: Option<usize>,
}

/// Whether a check ran, and if not, why.
///
/// The distinction the whole tool turns on. `Skipped` is not a quieter
/// `Ran` — a caller that treats them alike has learned nothing from a clean
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageStatus {
    Ran,
    /// Not requested.
    NotSelected,
    /// Requested, but a required input was absent — no reference netlist for
    /// LVS, no design intent for the electrical ERC rules.
    Skipped(&'static str),
    /// Requested, attempted, and refused because the input was outside what
    /// this tool represents exactly.
    Refused(String),
}

/// Everything a run produced.
#[derive(Debug, Default)]
pub struct Outputs {
    /// DRC and ERC findings, in one table because they are one shape. Sorted
    /// canonically before this is returned.
    pub violations: Violations,
    /// One row per rule, including rules that found nothing and rules that did
    /// not run. This is what makes an empty `violations` interpretable.
    pub runs: Vec<RuleRun>,
    pub lvs: Option<Verdict>,
    pub parasitics: Option<ParasiticNetwork>,
}

/// What happened, at a glance.
///
/// Deliberately not just counts. A summary reporting `0 violations` without
/// reporting `3 rules skipped` is the false-clean failure in report form.
///
/// `PartialEq` was added in the Testing-Phase: the determinism gate is two runs
/// compared, and without it every caller writes the nine-field comparison out
/// by hand. Every field is a `u32` or a [`StageStatus`], so the derive is the
/// whole of the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub drc: StageStatus,
    pub erc: StageStatus,
    pub lvs: StageStatus,
    pub pex: StageStatus,
    pub violations: u32,
    pub errors: u32,
    pub warnings: u32,
    /// Rules that ran and found nothing. Evidence the run did work.
    pub rules_clean: u32,
    /// Rules that did not run. The number to look at before believing a clean
    /// result.
    pub rules_skipped: u32,
}

impl Summary {
    /// Whether the run is a pass.
    ///
    /// **Decision** — pure, and the single place the pass criterion is written.
    /// A skipped rule is **not** a pass: this returns `false` when anything was
    /// skipped, so a run missing an input fails loudly instead of appearing to
    /// succeed. A caller that genuinely wants a partial run says so explicitly
    /// by not selecting the check, which is `NotSelected` rather than `Skipped`.
    ///
    /// [`Self::rules_clean`] is evidence, not criterion: this does not read it.
    /// A run that selected nothing has no clean rule and is still a pass, so a
    /// nonzero count cannot be required without failing that run.
    ///
    /// An LVS mismatch reaches this through [`Self::errors`] and nowhere else.
    /// [`run_checks`] maps every [`Discrepancy`] in a [`Verdict::Mismatch`] into
    /// one [`Severity::Error`] row of [`Outputs::violations`], so a comparison
    /// that found two different netlists is a nonzero `errors` and a failing
    /// run. That is why no field here names the verdict: the criterion already
    /// reads it, and the discrepancy is in the report a human opens rather than
    /// only in the exit code a CI job reads.
    ///
    /// The verdict stays on [`Outputs::lvs`] in its structured form, because
    /// [`Violation`] has no field for a device index — see
    /// `docs/SIGNATURE_DEFECTS.md`. A caller wanting to know *which* device
    /// mismatched reads it there; a caller wanting to know whether the run
    /// passed reads this.
    pub fn passed(&self) -> bool {
        debug_assert!(
            self.errors <= self.violations && self.warnings <= self.violations,
            "a severity count larger than the table it counts: {self:?}"
        );

        // A stage that was asked for and did not run blocks the pass; a stage
        // the caller never asked for does not. `Refused` sits with `Skipped`
        // rather than with `Ran` — fail closed — and neither is ever collapsed
        // into the other, which is the distinction the whole tool turns on.
        let denied = |status: &StageStatus| {
            matches!(status, StageStatus::Skipped(_) | StageStatus::Refused(_))
        };

        // `&&` rather than `&`: the criterion runs once per run, the operands
        // are already in registers, and short-circuiting is the readable form.
        // `rules_clean` is deliberately absent — evidence, not criterion, per
        // this function's doc comment.
        self.errors == 0
            && self.rules_skipped == 0
            && !denied(&self.drc)
            && !denied(&self.erc)
            && !denied(&self.lvs)
            && !denied(&self.pex)
    }
}

/// The reason a stage that needs a grid did not get one.
///
/// One `&'static str` rather than four spellings: [`StageStatus::Skipped`]
/// carries the reason a human reads, and two stages skip for the same reason.
const NO_GRID: &str =
    "no grid resolution reached this run, so no length in the deck has a meaning";

/// The temperature every ERC derating is computed at.
///
/// ponytail: 85 °C, hard-coded, because nothing in [`Inputs`] or [`RunOptions`]
/// carries a sign-off corner and [`gpurify_erc::RunInputs`] requires one that is
/// positive and finite. It is the same point `crates/erc/tests/common` derates
/// at, so a rule characterised there and run here sees one temperature. Upgrade
/// path: a `sign_off_temperature` field on [`RunOptions`], which is a
/// Definition-Phase change rather than a body — filed in
/// `docs/SIGNATURE_DEFECTS.md`, and blocked there rather than unexamined.
///
/// A wrong corner is wrong in both directions, and only one of them is loud.
/// Black's derating is monotone — hotter derates the allowed current *down* —
/// so a part signed off at 125 °C derates less here than it should and
/// an electromigration limit reads more generous than the corner allows: a
/// marginal net passes a check it would fail, silently. A part signed off at
/// 55 °C derates more than it should and fails nets the corner permits, which
/// is noise a human sees and argues with. The first is the reason this is a
/// defect and not a default.
///
/// No in-body route reaches a better number. The only temperature a deck states
/// is `reference_temperature` per rule row, which is the *characterisation*
/// point: for electromigration that
/// is an accelerated-test oven, hundreds of degrees above any use condition, so
/// reading it — or the maximum of it — as the applied corner derates against a
/// temperature the part never sees. Reading it as equal to the applied point is
/// worse still, collapsing the factor to unity, which
/// `crates/erc/src/rules/reliability.rs` names as a lifetime overstated rather
/// than unmeasured. 85 °C stands until an input states one.
///
/// The sibling marker on `gpurify_erc::rules::electrical::check_electromigration`
/// is this same scalar seen from the other end: it is one temperature for every
/// edge, where a self-heated wire runs hotter than the applied point. The two
/// gaps compose in the same direction — both put the number below the true
/// junction temperature of a hot wire in a hot part — and neither closes the
/// other.
fn sign_off_temperature() -> Qty<Temperature, { prefix::BASE }> {
    celsius(85.0)
}

/// The layer names a deck may declare its die outline under, tried in this
/// order.
///
/// A PDK names its own layers, and the outline is spelled three ways in the
/// wild: Cadence's `prBoundary`, DEF's `DIEAREA`, and the plain `die` that
/// [`gpurify_erc::RunInputs::die`] is named after. First one the deck declares
/// wins, so the die is a function of the deck alone and two runs over one deck
/// cannot disagree.
///
/// Three `&'static str`s looked up once per run through
/// [`gpurify_ingest::deck::LayerTable::id`], which is a `StrTable` hit and a
/// binary search — not a scan, and nowhere near bulk data.
const DIE_LAYER_NAMES: [&str; 3] = ["prBoundary", "DIEAREA", "die"];

/// The die boundary every density in this run divides by.
///
/// **Decision** — a load in, one box out, pure. This is what
/// [`gpurify_erc::RunInputs::die`] wants: the denominator of every density.
///
/// The extent of the deck's outline layer when the deck declares one — see
/// [`DIE_LAYER_NAMES`]. That is the real die edge, so the empty margin between
/// the outermost shape and the edge is swept like any other region and a
/// minimum-density rule is evaluated over it.
///
/// The union of every polygon's bounding box when the deck declares none. That
/// fallback is **fail-open for a minimum-density rule**: the margin outside the
/// outermost shape is never swept, so a region that would fail a fill floor is
/// not evaluated and the run reports clean over ground it never covered. It
/// cannot be closed here — nothing in [`Inputs`] or the deck schema declares a
/// die, and adding either is a Definition-Phase change. Filed in
/// `docs/SIGNATURE_DEFECTS.md`. Declaring an outline layer in the deck is what a
/// caller does today to avoid it.
///
/// [`Bbox::EMPTY`] for a store holding no geometry, which is what makes the
/// caller's skip reachable rather than a density divided by a reversed
/// interval.
fn design_extent(loaded: &Loaded) -> Bbox {
    // The declared outline, when there is one. Two guards, both fail-closed
    // into the fallback rather than into a wrong denominator: a name the deck
    // never declared is `None`, and a declared layer the store has no column
    // for would make `layer_bboxes` panic. An outline layer carrying no
    // geometry is `Bbox::EMPTY` and is treated as undeclared — an empty
    // denominator is worse than a tight one.
    let declared = DIE_LAYER_NAMES
        .iter()
        .find_map(|name| loaded.deck.layers.id(&loaded.strings, name))
        .filter(|layer| layer.idx() < loaded.store.layer_count())
        .map(|layer| union_bboxes(loaded.store.layer_bboxes(layer)))
        .filter(|outline| !outline.is_empty());

    let die = declared.unwrap_or_else(|| design_bbox(&loaded.store));
    debug_assert!(
        die.is_empty() || (die.xlo.raw() <= die.xhi.raw() && die.ylo.raw() <= die.yhi.raw()),
        "a non-empty die runs low to high on both axes"
    );
    debug_assert!(
        die.is_empty() || !design_bbox(&loaded.store).is_empty(),
        "a die boundary over a store holding no geometry"
    );
    die
}

/// The union of one contiguous bbox column.
///
/// **Decision** — a column in, one box out, pure. The bulk half of both
/// [`design_extent`] and [`design_bbox`], written once because they fold the
/// same column the same way.
///
/// A strict left fold. [`Bbox::union`] is `min`/`max` on four `i64`s, so it is
/// an associative monoid seeded with its own identity [`Bbox::EMPTY`]: the body
/// carries no branch at all, and the association order is unobservable — which
/// is why [`design_bbox`] may fold layer by layer rather than through one
/// accumulator. Integer, so there is no reassociation to be careful about.
/// The trip count is the column's own length and the fold walks the slice
/// itself, so no bounds check survives.
fn union_bboxes(boxes: &[Bbox]) -> Bbox {
    let mut acc = Bbox::EMPTY;
    for &b in boxes {
        acc = acc.union(b);
    }
    acc
}

/// The union of every polygon's bounding box.
///
/// **Decision** — a store in, one box out, pure. The fallback half of
/// [`design_extent`], and what "the design's extent" means everywhere else.
fn design_bbox(store: &GeometryStore) -> Bbox {
    // The loop here is over layers — tens of them, one per deck row, and not
    // bulk. The bulk fold is [`union_bboxes`], once per layer.
    let mut die = Bbox::EMPTY;
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("a LayerId is a u16"));
        die = die.union(union_bboxes(store.layer_bboxes(layer)));
    }
    debug_assert!(
        die.is_empty() || (die.xlo.raw() <= die.xhi.raw() && die.ylo.raw() <= die.yhi.raw()),
        "a non-empty extent runs low to high on both axes"
    );
    die
}

/// The grid this run's lengths are expressed against, if it has one.
///
/// [`Loaded::grid`] is what a successful load establishes; `deck.grid` is the
/// echo [`gpurify_ingest::deck::parse_deck`] leaves behind. Either answers the
/// question, and a `Loaded` that has neither has not been filled.
fn run_grid(loaded: &Loaded) -> Option<Grid> {
    loaded.grid.or(loaded.deck.grid)
}

/// Refuse a deck row whose kind no domain implements.
///
/// **Decision.** Reads the deck and the run's string table, returns a verdict;
/// no table is touched and nothing is allocated unless it fails.
///
/// This is the half of fail-closed that `drc::RuleSet::from_deck` and
/// `erc::RuleSet::from_deck` gave up when they started stepping over each
/// other's rows. A kind in neither vocabulary is nobody's rule, and a rule
/// nobody runs is a report that looks complete and is not.
///
/// The error is `DrcError::UnknownKind` rather than a variant of this enum's
/// own: it is already the sentence this wants to say, its two fields are
/// exactly the two facts a deck author needs, and adding a second spelling of
/// one error is a thing a caller then has to match on twice.
fn reject_unknown_rule_kinds(loaded: &Loaded) -> Result<(), EngineError> {
    for spec in &loaded.deck.rules.spec {
        let kind = loaded.strings.resolve(spec.kind);
        // Two linear scans over 26 and 19 `&'static str`s, once per deck row at
        // load. The branch is on one row's own kind, not on anything a check
        // iterates.
        let known = gpurify_drc::ruleset::KINDS.contains(&kind)
            || gpurify_erc::ruleset::KINDS.contains(&kind);
        if !known {
            return Err(gpurify_drc::DrcError::UnknownKind {
                rule: loaded.strings.resolve(spec.id).to_owned(),
                kind: kind.to_owned(),
            }
            .into());
        }
    }
    Ok(())
}

/// Run the selected checks against an extraction.
///
/// **Transform.** Caller owns `out`. The four checks read `loaded` and
/// `extracted` immutably and write into separate buffers that are concatenated
/// here, so they are independent and the concatenation order does not affect
/// the result — `Violations::sort_canonical` is called before returning.
///
/// This is also where `loaded.deck` becomes rule tables, through
/// `gpurify_drc::RuleSet::from_deck` and `gpurify_erc::RuleSet::from_deck`.
/// Both are fail-closed at construction on a row they own, so a deck omitting a
/// required parameter returns [`EngineError::Drc`] or [`EngineError::Erc`] and
/// no check runs. It does not become a skipped rule: the deck is wrong, and a
/// run against a wrong deck has no verdict to report.
///
/// # The one rule table, two vocabularies
///
/// `ingest` produces one [`RuleTable`] and does not know what any kind means,
/// so both rule sets read every row and each files only the kinds it spells.
/// The consequence is that neither can refuse an unrecognised kind — the other
/// domain's rows are unrecognised to it — and refusing it is what stops a
/// misspelled rule from reading as a clean design. So the refusal lives here,
/// against the union of `gpurify_drc::ruleset::KINDS` and
/// `gpurify_erc::ruleset::KINDS`: this is the only layer that holds both.
///
/// [`RuleTable`]: gpurify_ingest::deck::RuleTable
pub fn run_checks(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<Summary, EngineError> {
    debug_assert!(
        extracted.ports.len() <= extracted.nets.net_count(),
        "the port table names more nets than the extraction produced"
    );
    debug_assert!(
        options.lvs.param_tolerance >= 0.0,
        "a negative parametric tolerance rejects every device parameter"
    );
    // `threads` affects speed only, and it is read here and nowhere else
    // because nothing below this line is parallel: `drc` and `erc` each thread
    // one `Scratch` through their dispatcher and `pex` extracts net by net. The
    // determinism gate therefore holds by construction rather than by care.
    // Zero workers is still refused, since a run that does nothing would report
    // a clean design.
    debug_assert!(
        options.threads.is_none_or(|threads| threads > 0),
        "a run with no worker would report a clean design it never checked"
    );

    // Before `options.checks` is read at all: a kind nobody implements is a
    // wrong deck whichever checks the caller asked for, and deciding it inside
    // the `if` would let a misspelled ERC rule through a DRC-only run.
    //
    // A deck is hundreds of rows read once at load — cold, not bulk — and the
    // vocabularies are 26 and 19 names, so this is a linear scan and not an
    // index.
    reject_unknown_rule_kinds(loaded)?;

    // The caller owns `out` and may be looping over cells with it. Cleared
    // column by column rather than reassigned, so the allocation survives;
    // `Violations` is `SoA` and has no `clear` of its own.
    out.violations.rule.clear();
    out.violations.layer.clear();
    out.violations.severity.clear();
    out.violations.at.clear();
    out.violations.measured.clear();
    out.violations.limit.clear();
    out.violations.shape_a.clear();
    out.violations.shape_b.clear();
    out.runs.clear();
    out.lvs = None;
    out.parasitics = None;
    debug_assert!(out.violations.is_empty(), "a stale finding survived the clear");

    // Four `if`s on `options.checks`, each constant for the whole run and each
    // guarding a whole check — this is the dispatcher's condition, not a
    // data-dependent branch, and the skipped side is the entire cost of a check
    // the caller declined.
    let drc = if options.checks.drc {
        run_drc(loaded, extracted, out)?
    } else {
        StageStatus::NotSelected
    };

    let erc = if options.checks.erc {
        run_erc(loaded, extracted, out)?
    } else {
        StageStatus::NotSelected
    };

    let lvs = if options.checks.lvs {
        run_lvs(loaded, extracted, options, out)
    } else {
        StageStatus::NotSelected
    };

    let pex = if options.checks.pex {
        run_pex(loaded, extracted, options, out)?
    } else {
        StageStatus::NotSelected
    };

    // Both orders are established here and nowhere else, which is what makes
    // the concatenation order above unobservable — and therefore what would let
    // the four checks run concurrently without changing a byte of output.
    out.violations.sort_canonical();
    out.runs.sort_by_key(|run| run.rule);

    // Two strict left folds over the two output columns. Each body is
    // arithmetic on its own row: the predicate is widened to `0`/`1` and added
    // in, so neither carries a data-dependent branch. Both trip counts are the
    // column's own length — the first walks the slice itself, the second's index
    // is the induction variable — so no bounds check survives into either loop.
    let severities = &out.violations.severity[..];
    let mut errors = 0_u32;
    let mut warnings = 0_u32;
    for &severity in severities {
        let is_error = u32::from(severity == Severity::Error);
        errors += is_error;
        warnings += 1 - is_error;
    }

    let n = out.runs.len();
    let mut rules_clean = 0_u32;
    let mut rules_skipped = 0_u32;
    for i in 0..n {
        let run = out.runs[i];
        let ran = u32::from(run.outcome == Outcome::Ran);
        let found = u32::from(run.violations > 0);
        // Clean is *ran and found nothing*; skipped is everything that did not
        // run, `Refused` included — a rule that refused its geometry learned no
        // more about the design than one that never started.
        rules_clean += ran * (1 - found);
        rules_skipped += 1 - ran;
    }

    let violations = u32::try_from(out.violations.len())
        .expect("a violation table indexes rows with a u32; see CONVENTIONS");
    debug_assert_eq!(
        errors + warnings,
        violations,
        "a violation without a severity, or a severity without a violation"
    );
    debug_assert!(
        (rules_clean + rules_skipped) as usize <= out.runs.len(),
        "more rules accounted for than rules recorded"
    );

    Ok(Summary {
        drc,
        erc,
        lvs,
        pex,
        violations,
        errors,
        warnings,
        rules_clean,
        rules_skipped,
    })
}

/// Run one rule set into the run's outputs.
///
/// **Transform.** Caller owns `out`; appends. `drc` and `erc` both *clear* the
/// tables their `run` is handed — each is the one place its crate clears — so
/// neither can be given `out` directly without making that stage's position in
/// the sequence load-bearing. Both therefore fill a separate pair of buffers and
/// concatenate here, which is why this is one function rather than the same six
/// lines twice: the concatenation order, the reservation and the postcondition
/// that every configured rule recorded itself are written once.
///
/// `rule_count` is the reservation *and* the expected row count, which is what
/// makes the assert free of a second source: a rule set that files fewer rows
/// than it holds rules has lost a rule silently, and a lost rule is a clean
/// report for a check that never ran.
fn append_stage(
    out: &mut Outputs,
    domain: &str,
    rule_count: usize,
    run: impl FnOnce(&mut Violations, &mut Vec<RuleRun>),
) {
    let mut violations = Violations::default();
    let mut runs: Vec<RuleRun> = Vec::with_capacity(rule_count);
    run(&mut violations, &mut runs);
    debug_assert_eq!(
        runs.len(),
        rule_count,
        "a configured {domain} rule finished without recording that it ran"
    );

    out.violations.extend(&violations);
    out.runs.append(&mut runs);
}

/// Assemble everything DRC reads, then dispatch its rules.
///
/// **Transform.** Appends to `out`. Geometric throughout: it reads the store,
/// the derived layers and the two topology tables, and needs neither a grid nor
/// a die, so it has no skip of its own — a deck it cannot become rule tables for
/// is the run's failure rather than this stage's.
fn run_drc(
    loaded: &Loaded,
    extracted: &Extracted,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    // Fail closed at construction: a deck naming an unknown rule kind is the
    // run's failure, not a skipped rule, because a run against a wrong deck has
    // no verdict to report.
    let rules = gpurify_drc::RuleSet::from_deck(&loaded.deck, &loaded.strings)?;
    let design = gpurify_drc::Design {
        store: &loaded.store,
        derived: &extracted.derived,
        nets: &extracted.nets,
        devices: &extracted.devices,
    };

    let mut scratch = gpurify_drc::Scratch::default();
    append_stage(out, "drc", rules.rule_count(), |violations, runs| {
        rules.run(design, &mut scratch, violations, runs);
    });
    Ok(StageStatus::Ran)
}

/// Assemble everything ERC reads, then dispatch its rules.
///
/// **Transform.** Appends to `out`. The five steps are the order
/// `gpurify_erc`'s crate doc fixes — classify, resolve intent, per-net
/// networks, grid and solve, run — and none of them can move.
///
/// Returns the stage's status rather than a `bool`: a supply grid that cannot
/// be built or solved is [`gpurify_erc::PowerError`], which has no
/// [`EngineError`] variant to carry it. That is a frozen signature, so it
/// becomes [`StageStatus::Refused`] here — fail closed either way, since a
/// refused stage never passes.
fn run_erc(
    loaded: &Loaded,
    extracted: &Extracted,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    // Before any skip: a deck that cannot become rule tables fails the run, and
    // a skip decided ahead of it would hide the wrong deck behind a missing
    // input.
    let rules = gpurify_erc::RuleSet::from_deck(&loaded.deck, &loaded.strings)?;

    let Some(grid) = run_grid(loaded) else {
        return Ok(StageStatus::Skipped(NO_GRID));
    };
    let die = design_extent(loaded);
    if die.is_empty() {
        // Every density in this crate divides by the die area, and `Bbox::EMPTY`
        // runs high to low. Skipped rather than defaulted to a point: a
        // denominator invented here would put a number on a report that nothing
        // measured.
        return Ok(StageStatus::Skipped(
            "the layout holds no geometry, so no die boundary bounds a density",
        ));
    }

    let design = gpurify_erc::Design {
        store: &loaded.store,
        derived: &extracted.derived,
        nets: &extracted.nets,
        devices: &extracted.devices,
    };
    let process = gpurify_erc::power::Process {
        grid,
        stack: &loaded.deck.stack,
        connectivity: &loaded.deck.connectivity,
    };

    let mut facts = gpurify_erc::NetFacts::default();
    gpurify_erc::classify_nets_into(&extracted.nets, &extracted.devices, &mut facts);
    debug_assert!(
        facts.len() <= extracted.nets.net_count(),
        "the role column names more nets than the extraction produced"
    );

    let mut intent = gpurify_erc::IntentMap::default();
    gpurify_erc::resolve_intent_into(
        loaded.intent.as_ref(),
        &extracted.ports,
        &extracted.nets,
        &mut intent,
    );

    let mut networks = gpurify_erc::NetNetworks::default();
    let mut power_grid = gpurify_erc::PowerGrid::default();
    if let Err(error) = gpurify_erc::power::extract_nets_into(
        &loaded.store,
        &extracted.nets,
        &extracted.devices,
        process,
        &mut networks,
    )
    .and_then(|()| {
        gpurify_erc::power::extract_into(
            &loaded.store,
            &extracted.nets,
            &extracted.devices,
            &intent,
            process,
            &mut power_grid,
        )
    }) {
        return Ok(StageStatus::Refused(error.to_string()));
    }

    // `None` is not an absence of information here, it is the information: no
    // declared supply means no grid, and the four electrical rules read exactly
    // that before recording themselves skipped.
    let mut solution = gpurify_erc::PowerSolution::default();
    let power = if power_grid.is_empty() {
        None
    } else {
        let mut solve_scratch = gpurify_erc::power::SolveScratch::default();
        if let Err(error) = gpurify_erc::power::solve_into(
            &power_grid,
            gpurify_erc::power::SolveConfig::default(),
            &mut solve_scratch,
            &mut solution,
        ) {
            return Ok(StageStatus::Refused(error.to_string()));
        }
        Some(gpurify_erc::Solved {
            grid: &power_grid,
            solution: &solution,
        })
    };

    let mut scratch = gpurify_erc::Scratch::default();
    append_stage(out, "erc", rules.len(), |violations, runs| {
        rules.run(
            gpurify_erc::RunInputs {
                design,
                facts: &facts,
                intent: &intent,
                networks: &networks,
                power,
                die,
                grid,
                operating_temperature: sign_off_temperature(),
            },
            &mut scratch,
            violations,
            runs,
        );
    });
    Ok(StageStatus::Ran)
}

/// Project both netlists into matching graphs and compare them.
///
/// **Transform.** Writes [`Outputs::lvs`]. Flat, on the reference's unique top
/// cell: `topology`'s tables are flat, so there is no layout hierarchy to pair
/// against and `gpurify_lvs::hierarchical::plan` has nothing to order.
///
/// A verdict that did not conclude is [`StageStatus::Refused`], not `Ran`.
/// [`Verdict::Inconclusive`] means the comparison did not complete, and a stage
/// that reported `Ran` on one would let a round limit read as a pass.
fn run_lvs(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
    out: &mut Outputs,
) -> StageStatus {
    let Some(reference) = loaded.reference.as_ref() else {
        return StageStatus::Skipped(
            "no reference netlist was supplied, so no comparison was made",
        );
    };

    let mut layout = gpurify_lvs::LayoutGraph::default();
    gpurify_lvs::graph::from_layout_into(
        &extracted.nets,
        &extracted.devices,
        &extracted.ports,
        &mut layout,
    );

    let verdict = match reference.top() {
        // No unique top is the reference's own ambiguity, and guessing which
        // subcircuit was meant is the one thing a comparison must never do.
        None => Verdict::Inconclusive(Inconclusive::AmbiguousTop),
        Some(top) => {
            let mut expected = gpurify_lvs::RefGraph::default();
            gpurify_lvs::graph::from_reference_into(reference, top, &loaded.strings, &mut expected);
            let mut partition = gpurify_lvs::refine::Partition::default();
            gpurify_lvs::compare(&layout, &expected, options.lvs, &mut partition)
        }
    };

    let status = match &verdict {
        Verdict::Match => StageStatus::Ran,
        // The stage still *ran* — it concluded, and the conclusion is that the
        // two netlists differ. The failure is carried by the rows this records,
        // not by the status, which is what keeps `Ran` meaning "concluded".
        Verdict::Mismatch(found) => {
            record_discrepancies(found, &loaded.strings, &mut out.violations);
            StageStatus::Ran
        }
        Verdict::Inconclusive(why) => {
            StageStatus::Refused(format!("the comparison did not conclude: {why:?}"))
        }
    };
    out.lvs = Some(verdict);
    status
}

/// The rule id each [`Discrepancy`] variant is reported under, in the order
/// [`gpurify_lvs::verdict::Discrepancy`] declares its variants.
///
/// Interned by [`crate::pipeline::load_into`] so that
/// [`gpurify_ingest::StrTable::resolve`] answers for every row this crate
/// produces. `run_checks` borrows `Loaded` shared and therefore cannot intern —
/// see [`lvs_rule_id`].
pub(crate) const LVS_RULE_IDS: [&str; 6] = [
    "lvs.unpaired_device",
    "lvs.unpaired_net",
    "lvs.terminal_mismatch",
    "lvs.parameter_mismatch",
    "lvs.duplicate_name",
    "lvs.class_imbalance",
];

/// The layer an LVS violation names.
///
/// # The convention for a violation that is not geometric
///
/// [`Violation`] was shaped for DRC and ERC, where every finding has a layer, a
/// point and a shape. An LVS discrepancy has none of the three — it is a
/// difference between two netlist graphs, and the indices it names are nodes of
/// a [`gpurify_lvs::LayoutGraph`] and a [`gpurify_lvs::RefGraph`], not rows of
/// the geometry store. So rather than borrow a plausible coordinate from a shape
/// that happens to be nearby, which would send a viewer somewhere nothing was
/// measured, all three carry an out-of-range sentinel:
///
/// - `layer` is `LayerId(u16::MAX)`, past the end of any deck's layer table.
/// - `at` is [`NO_LOCATION`], the origin, which is a real coordinate and is the
///   one field here that cannot be filled honestly. `layer` and `shape_a` are
///   what tell a reader not to navigate to it. Filed in
///   `docs/SIGNATURE_DEFECTS.md`.
/// - `shape_a` is [`NO_SHAPE`], `PolyId(u32::MAX)`, past the end of any store.
///   `export::gds::write_markers` refuses such a row with
///   `WriteError::Unrepresentable`, which is the right answer: a netlist
///   difference has no marker geometry to draw.
const NO_LAYER: LayerId = LayerId(u16::MAX);

/// See [`NO_LAYER`]. The origin, standing in for "this finding is not at a
/// place".
const NO_LOCATION: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};

/// See [`NO_LAYER`]. Past the end of any [`gpurify_core::GeometryStore`].
const NO_SHAPE: PolyId = PolyId(u32::MAX);

/// Map every discrepancy of a mismatch into the violation table.
///
/// **Transform.** Caller owns `out`; appends, and [`run_checks`] sorts
/// afterwards. Every row is [`Severity::Error`], which is how a mismatch reaches
/// [`Summary::passed`] — `errors == 0` is already in the criterion, so this
/// needs no new field on [`Summary`] and no signature change.
fn record_discrepancies(found: &[Discrepancy], strings: &StrTable, out: &mut Violations) {
    let before = out.len();
    for discrepancy in found {
        let (measured, limit) = lvs_measurement(discrepancy);
        out.push(Violation {
            rule: lvs_rule_id(discrepancy, strings),
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NO_LOCATION,
            measured,
            limit,
            shapes: (NO_SHAPE, None),
        });
    }
    debug_assert_eq!(
        out.len() - before,
        found.len(),
        "a discrepancy the comparison found reached no row of the report"
    );
}

/// The interned rule id for one discrepancy.
///
/// [`run_checks`] borrows [`Loaded`] shared, so it cannot intern a name the
/// table does not already carry. [`crate::pipeline::load_into`] interns all six
/// of [`LVS_RULE_IDS`], which covers every run that read its inputs from disk.
///
/// A `Loaded` assembled by hand — the per-crate tests do this — may carry a
/// string table that has none of them, and then the row is reported under a
/// sentinel that [`gpurify_ingest::StrTable::resolve`] panics on. Deliberate,
/// and the safer of the two failures: `StrId(0)` would resolve to whatever name
/// happened to be interned first and attribute the mismatch to it silently.
fn lvs_rule_id(discrepancy: &Discrepancy, strings: &StrTable) -> StrId {
    let name = match discrepancy {
        Discrepancy::UnpairedDevice { .. } => LVS_RULE_IDS[0],
        Discrepancy::UnpairedNet { .. } => LVS_RULE_IDS[1],
        Discrepancy::TerminalMismatch { .. } => LVS_RULE_IDS[2],
        Discrepancy::ParameterMismatch { .. } => LVS_RULE_IDS[3],
        Discrepancy::DuplicateName { .. } => LVS_RULE_IDS[4],
        Discrepancy::ClassImbalance { .. } => LVS_RULE_IDS[5],
    };
    strings.get(name).unwrap_or(StrId(u32::MAX))
}

/// What a discrepancy measured, and what it was measured against.
///
/// Two of the six carry numbers, and those numbers are the finding:
/// a parameter's two values, and a class's two node counts. `measured` is always
/// the layout's side and `limit` the reference's, which is the direction
/// [`gpurify_lvs::verdict::Side`] already fixes.
///
/// The other four are not measurements of anything. They report `Count(1)`
/// against `Count(0)` — one occurrence where none is allowed — which is the
/// only honest reading of a difference that is either present or absent.
///
/// [`Measurement::Ratio`] is dimensionless and a device parameter is not, but it
/// is the one variant that carries a bare `f64`; the parameter's `StrId` on the
/// [`Discrepancy`] is what names the dimension. A non-finite value on either
/// side falls back to the count form: `compare_params` reports a `NaN` rather
/// than swallowing it, and [`Violations::push`] refuses to store one.
fn lvs_measurement(discrepancy: &Discrepancy) -> (Measurement, Measurement) {
    const ONE: Measurement = Measurement::Count(1);
    const NONE_ALLOWED: Measurement = Measurement::Count(0);

    match *discrepancy {
        Discrepancy::ParameterMismatch {
            layout_value,
            ref_value,
            ..
        } if layout_value.is_finite() && ref_value.is_finite() => (
            Measurement::Ratio(layout_value),
            Measurement::Ratio(ref_value),
        ),
        Discrepancy::ClassImbalance {
            layout_nodes,
            ref_nodes,
        } => (
            Measurement::Count(layout_nodes),
            Measurement::Count(ref_nodes),
        ),
        _ => (ONE, NONE_ALLOWED),
    }
}

/// Extract parasitics.
///
/// **Transform.** Writes [`Outputs::parasitics`]. Analytical for the whole
/// design when [`RunOptions::quasistatic_nets`] is empty, which is what a
/// full-chip run wants.
///
/// A non-empty selection field-solves *those* nets and keeps the analytical
/// network for every other one, merged by [`merge_field_solved_into`]. Both
/// paths therefore describe the whole design, which is what makes the
/// [`StageStatus::Ran`] this returns true: a net absent from
/// [`Outputs::parasitics`] is a net the extraction found nothing on, and no
/// longer also a net that was never asked about.
///
/// # The solve's accuracy is read, not assumed
///
/// [`gpurify_pex::quasistatic::extract_into`] returns an
/// [`gpurify_pex::quasistatic::Accuracy`], and its own doc comment says a caller
/// that ignores it is asserting the answer is good without having looked. This
/// one does not ignore it: an asymmetry outside the solve's tolerance is
/// [`StageStatus::Refused`], and no parasitics are written. See
/// [`reciprocity_refusal`] for why the residual is not the same check.
///
/// ponytail: the solve's [`gpurify_pex::quasistatic::CapMatrix`] is still
/// dropped, because [`Outputs`] has no slot for it. The per-net totals it
/// summarises survive as [`gpurify_pex::Parasitic::CouplingCap`] rows in the
/// merged network, so the loss is the off-diagonal *matrix* form a field solver
/// reports, not the coupling itself. [`gpurify_pex::quasistatic::Accuracy`]'s
/// other four fields — the achieved residual, the tolerance, the iteration
/// count and the backend that ran — have nowhere to land either, so a run's
/// numbers cannot be attributed after the fact. Upgrade path: a matrix field and
/// an accuracy field on [`Outputs`], a Definition-Phase change — filed in
/// `docs/SIGNATURE_DEFECTS.md`, and blocked there rather than unexamined.
fn run_pex(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    let Some(grid) = run_grid(loaded) else {
        return Ok(StageStatus::Skipped(NO_GRID));
    };

    let mut network = ParasiticNetwork::default();
    if options.quasistatic_nets.is_empty() {
        gpurify_pex::analytical::extract_into(
            &loaded.store,
            &extracted.nets,
            &extracted.devices,
            &loaded.deck.stack,
            grid,
            &mut network,
        );
    } else {
        // A selection is the handful of nets a human named on a command line,
        // and each iteration may return a typed refusal.
        let mut selected = Vec::with_capacity(options.quasistatic_nets.len());
        for name in &options.quasistatic_nets {
            // `get`, never `intern` — `loaded.strings` is borrowed shared, and
            // a name the run never saw is a net that is not there. Fail closed:
            // field-solving the rest and saying nothing would answer a request
            // that was never met.
            let Some(net) = loaded
                .strings
                .get(name)
                .and_then(|id| extracted.ports.net_of(id))
            else {
                return Ok(StageStatus::Refused(format!(
                    "no extracted net is named {name}, so it cannot be field solved"
                )));
            };
            selected.push(net);
        }

        // The rest of the design, closed form. Run first and unconditionally:
        // it is what the merge below overlays the solved nets onto, and a run
        // that field-solves one net must still describe every other one or the
        // artefact it writes is a design with one net in it.
        let mut coarse = ParasiticNetwork::default();
        gpurify_pex::analytical::extract_into(
            &loaded.store,
            &extracted.nets,
            &extracted.devices,
            &loaded.deck.stack,
            grid,
            &mut coarse,
        );

        let mut matrix = gpurify_pex::quasistatic::CapMatrix::default();
        let mut solved = ParasiticNetwork::default();
        let accuracy = gpurify_pex::quasistatic::extract_into(
            &loaded.store,
            &extracted.nets,
            &selected,
            &loaded.deck.stack,
            grid,
            gpurify_pex::quasistatic::solve::Options::default(),
            &mut matrix,
            &mut solved,
        )?;

        // Refuse before the merge, so nothing a failed reciprocity check
        // produced reaches `out.parasitics`. One `if` per run, not per element.
        if let Some(refusal) = reciprocity_refusal(&accuracy) {
            return Ok(StageStatus::Refused(refusal));
        }

        merge_field_solved_into(&coarse, &solved, &mut network);
    }

    // Both accessors carry their own column-parity asserts, so calling them is
    // the check; the condition on top is the one they cannot make — an element
    // column over a network with no nodes to name.
    debug_assert!(
        network.element_count() == 0 || network.node_count() > 0,
        "parasitic elements naming nodes the network does not have"
    );
    out.parasitics = Some(network);
    Ok(StageStatus::Ran)
}

/// Whether a solve's own accuracy disqualifies its capacitance matrix.
///
/// **Decision** — one [`gpurify_pex::quasistatic::Accuracy`] in, the refusal
/// text out, pure. `None` is "reciprocal within the tolerance the solve was
/// given".
///
/// # Why the residual is not this check
///
/// [`gpurify_pex::quasistatic::solve::refine`] converges each column against its
/// own right-hand side and `columns_into` refuses a column that did not, so a
/// returned matrix has already passed a per-column residual test. Reciprocity is
/// a statement *between* columns — `C[i][j]` and `C[j][i]` are computed by two
/// different solves and physics says they are the same number — and no
/// per-column residual can see it. A mesh that couples two conductors
/// differently in each direction converges twice and disagrees with itself, and
/// [`gpurify_pex::quasistatic::CapMatrix::asymmetry`] is the only place that
/// disagreement is measured. Dropping it left the run reporting
/// [`StageStatus::Ran`] over a matrix nothing had checked, which is the
/// clean-result-that-was-never-checked shape.
///
/// # What it does not catch
///
/// A uniformly coarse mesh is coarse for both halves of a pair, so it is
/// symmetric about its own error: `docs/SIGNATURE_DEFECTS.md` records a 500 dbu
/// mesh that was 2.6% low on a self term with an asymmetry an order of magnitude
/// *better* than the finer mesh beside it. This gate is reciprocity and nothing
/// more; under-meshing needs a mesh-convergence number no signature carries.
///
/// The bound is [`gpurify_pex::quasistatic::Accuracy::tolerance`], carried on
/// the value for exactly this comparison rather than re-derived from
/// `solve::Options` here — `asymmetry`'s own doc names the solver's tolerance as
/// the line above which the answer has not converged, whatever the residual
/// says.
fn reciprocity_refusal(accuracy: &gpurify_pex::quasistatic::Accuracy) -> Option<String> {
    debug_assert!(
        accuracy.tolerance > 0.0,
        "a tolerance of zero refuses every solve"
    );
    debug_assert!(
        !accuracy.asymmetry.is_sign_negative(),
        "a relative gap is non-negative"
    );

    // Two predicates, `or`-ed rather than a negated comparison: a NaN or an
    // infinite asymmetry compares false against every bound, so `> tolerance`
    // alone would pass exactly the matrices nothing could check. `is_finite`
    // first is what makes this fail closed. An infinity is what `asymmetry`
    // reports for an entry mirrored by an exact zero, and it is a refusal.
    let refused = !accuracy.asymmetry.is_finite() || accuracy.asymmetry > accuracy.tolerance;
    refused.then(|| {
        format!(
            "the capacitance matrix is not reciprocal: asymmetry {:e} against a solve tolerance of {:e}, after {} iterations",
            accuracy.asymmetry, accuracy.tolerance, accuracy.iterations
        )
    })
}

/// The node id a source row keeps when it did not survive the merge.
///
/// `u32::MAX` is past the end of any [`ParasiticNetwork`], so a remap that
/// escaped the compaction in [`merge_field_solved_into`] indexes nothing and
/// trips a bounds check, where `0` would silently name the first node of the
/// first net.
const DROPPED_NODE: u32 = u32::MAX;

/// Overlay a field-solved network on an analytical one.
///
/// **Transform.** Caller owns `out`, cleared and refilled; both inputs are read
/// shared. A net the solve produced nodes for arrives from `solved` and its
/// analytical rows are dropped; every other net arrives from `analytical`. So
/// the result covers the whole design at whichever accuracy each net was
/// extracted at, which is what lets [`run_pex`] report [`StageStatus::Ran`]
/// honestly for a partial selection.
///
/// # Membership is read off `solved`, not off the selection
///
/// A net the caller selected but the mesh produced no node for keeps its
/// analytical rows. The alternative — trusting the selection — drops a net's
/// coarse numbers in exchange for none at all, which is the fail-open shape
/// this whole merge exists to close.
///
/// # The node-order invariant
///
/// [`ParasiticNetwork`] states that every net's nodes occupy one contiguous
/// range of `node_net` and the ranges ascend. Both inputs arrive that way and
/// the surviving net sets are disjoint, so the two-way merge below — take the
/// lower net at each step — reproduces it rather than restoring it. That is why
/// this is a merge and not the concatenation `pex`'s writers could not scan.
///
/// Element order is *not* reproduced: the two element runs are renumbered into
/// interleaved node ids, so canonical order is re-established by
/// [`ParasiticNetwork::sort_canonical`] at the end. Its key is total — it ends
/// in the value's bits — so the result is a function of the two inputs alone and
/// two runs agree byte for byte.
fn merge_field_solved_into(
    analytical: &ParasiticNetwork,
    solved: &ParasiticNetwork,
    out: &mut ParasiticNetwork,
) {
    debug_assert!(
        analytical.node_net.is_sorted(),
        "an analytical network whose nets are not one ascending range each"
    );
    debug_assert!(
        solved.node_net.is_sorted(),
        "a field-solved network whose nets are not one ascending range each"
    );

    // `ParasiticNetwork::clear` is `pub(crate)` to `pex`, so the five columns
    // are cleared by name here — same reason and same shape as `run_checks`
    // clearing `Violations` column by column: the caller's allocation survives.
    out.node_net.clear();
    out.node_layer.clear();
    out.from.clear();
    out.to.clear();
    out.value.clear();

    let (coarse_nodes, fine_nodes) = (analytical.node_count(), solved.node_count());
    let (coarse_elements, fine_elements) = (analytical.element_count(), solved.element_count());

    // Which nets the solve produced nodes for. A dense byte per net rather than
    // a binary search per analytical node: both columns are already ascending,
    // so the last row of each is its maximum and the table is exactly as wide
    // as the net space the two networks between them name.
    let highest_net = analytical
        .node_net
        .last()
        .map_or(0, |net| net.0)
        .max(solved.node_net.last().map_or(0, |net| net.0));
    let mut replaced = vec![0_u8; highest_net as usize + 1];
    // Map, one row in, one byte out, scattered by the row's own net. No branch:
    // every row writes the same constant, so a net named by many nodes is
    // written many times with the same byte and the order is irrelevant.
    for i in 0..fine_nodes {
        replaced[solved.node_net[i].0 as usize] = 1;
    }

    let mut coarse_map = vec![DROPPED_NODE; coarse_nodes];
    let mut fine_map = vec![DROPPED_NODE; fine_nodes];
    out.node_net.reserve(coarse_nodes + fine_nodes);
    out.node_layer.reserve(coarse_nodes + fine_nodes);

    // The two-way merge. Its branches are the algorithm rather than a body
    // branch: each step commits exactly one row, the trip count is bounded by
    // `coarse_nodes + fine_nodes`, and the comparison is between two loaded
    // `u32`s. It runs once per run over the node columns, not per element of a
    // rule.
    let mut coarse = 0_usize;
    let mut fine = 0_usize;
    loop {
        // Skip the analytical rows of every net the solve replaced. Ascending
        // net order means each replaced net is one contiguous run, so this
        // advances over a run and then predicts correctly for the whole of it.
        while coarse < coarse_nodes && replaced[analytical.node_net[coarse].0 as usize] != 0 {
            coarse += 1;
        }

        let next_coarse = analytical.node_net.get(coarse).copied();
        let next_fine = solved.node_net.get(fine).copied();
        let take_coarse = match (next_coarse, next_fine) {
            (None, None) => break,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            // Never equal — a net present in both was skipped above — so the
            // tie-break is unreachable and either side would do.
            (Some(left), Some(right)) => left <= right,
        };

        let id = u32::try_from(out.node_net.len()).expect("a NodeId is a u32");
        let (source, row) = if take_coarse {
            coarse_map[coarse] = id;
            coarse += 1;
            (analytical, coarse - 1)
        } else {
            fine_map[fine] = id;
            fine += 1;
            (solved, fine - 1)
        };
        out.node_net.push(source.node_net[row]);
        out.node_layer.push(source.node_layer[row]);
    }
    debug_assert_eq!(fine, fine_nodes, "a field-solved node reached no merged row");

    out.from.reserve(coarse_elements + fine_elements);
    out.to.reserve(coarse_elements + fine_elements);
    out.value.reserve(coarse_elements + fine_elements);

    // Compact, one predicate per element: an analytical element survives when
    // its nodes did. `analytical::extract_into` emits nothing that spans two
    // nets, so the two endpoints always agree on survival — asserted rather
    // than assumed, because an element that did span the boundary would be
    // dropped here silently, which is the failure this function exists to stop.
    for i in 0..coarse_elements {
        let from = coarse_map[analytical.from[i].0 as usize];
        let to = analytical.to[i].map(|node| coarse_map[node.0 as usize]);
        debug_assert!(
            to.is_none_or(|far| (far == DROPPED_NODE) == (from == DROPPED_NODE)),
            "an analytical element spans a field-solved net and an analytical one"
        );
        if from != DROPPED_NODE {
            out.push(NodeId(from), to.map(NodeId), analytical.value[i]);
        }
    }

    // Map, no predicate: every field-solved node survived, so every element
    // naming one does too. Only the renumbering applies.
    for i in 0..fine_elements {
        let from = fine_map[solved.from[i].0 as usize];
        let to = solved.to[i].map(|node| fine_map[node.0 as usize]);
        debug_assert_ne!(from, DROPPED_NODE, "a field-solved element lost its near node");
        debug_assert!(
            to.is_none_or(|far| far != DROPPED_NODE),
            "a field-solved element lost its far node"
        );
        out.push(NodeId(from), to.map(NodeId), solved.value[i]);
    }

    out.sort_canonical();

    debug_assert!(
        out.node_net.is_sorted(),
        "the merge broke the range-per-net invariant every writer scans on"
    );
    debug_assert_eq!(
        out.node_count(),
        coarse_nodes + fine_nodes - replaced_node_count(analytical, &replaced),
        "the merged node columns do not account for every source row"
    );
    debug_assert!(
        out.element_count() <= coarse_elements + fine_elements,
        "the merge invented an element"
    );
}

/// How many analytical nodes the solve replaced.
///
/// **Decision** — two columns in, one count out, pure. Only ever called from a
/// `debug_assert!`, which is why it is a fold and not a counter threaded
/// through the merge: a release build must not pay for the accounting, and a
/// counter incremented inside the merge would be checking the merge against
/// itself.
///
/// A strict left fold over the analytical net column, the predicate widened to
/// `0`/`1` and added in, so the body carries no branch.
fn replaced_node_count(analytical: &ParasiticNetwork, replaced: &[u8]) -> usize {
    let n = analytical.node_net.len();
    let mut count = 0_usize;
    for i in 0..n {
        count += usize::from(replaced[analytical.node_net[i].0 as usize]);
    }
    count
}

/// Load, extract and check in one call.
///
/// The whole pipeline, and what the CLI calls. Kept thin — it sequences
/// [`crate::pipeline::load_into`], [`crate::pipeline::extract_into`] and
/// [`run_checks`] and does nothing else, so a caller wanting to run two layouts
/// against one deck can call the stages directly and skip the reload.
pub fn run(
    inputs: &Inputs,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<Summary, EngineError> {
    // Nothing touches `out` before the load, deliberately: a run that failed to
    // read its inputs must not have left findings behind.
    let mut loaded = Loaded::default();
    crate::pipeline::load_into(inputs, &mut loaded)?;

    let mut extracted = Extracted::default();
    crate::pipeline::extract_into(&loaded, &mut extracted)?;

    run_checks(&loaded, &extracted, options, out)
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Load(#[from] crate::pipeline::LoadError),
    #[error(transparent)]
    Extract(#[from] crate::pipeline::ExtractError),
    /// The deck could not be turned into a DRC rule set.
    ///
    /// Added in the Testing-Phase. `RuleSet::from_deck` is documented as
    /// fail-closed at construction and [`run_checks`] is the only caller that
    /// holds a `Deck`, so without this variant a deck naming an unknown rule
    /// kind had nowhere to be reported and the guarantee stopped at this seam.
    #[error(transparent)]
    Drc(#[from] gpurify_drc::DrcError),
    /// The deck could not be turned into an ERC rule set. Same reason as
    /// [`EngineError::Drc`].
    #[error(transparent)]
    Erc(#[from] gpurify_erc::ErcError),
    #[error(transparent)]
    Solve(#[from] gpurify_pex::quasistatic::solve::SolveError),
    #[error(transparent)]
    Mesh(#[from] gpurify_pex::quasistatic::mesh::MeshError),
}

/// [`merge_field_solved_into`] and [`reciprocity_refusal`] are private, so their
/// checks live beside them.
///
/// One test each, not a suite: the merge's own `debug_assert!`s carry the column
/// parities and the node-order invariant, and its input here is the smallest one
/// that reaches all of them and pins the thing they cannot — *which* of the two
/// networks a net's numbers come out of. The refusal's is the boundary and the
/// two non-finite values, which is the whole of a decision over one `f64`.
#[cfg(test)]
mod tests {
    use super::{merge_field_solved_into, reciprocity_refusal};
    use gpurify_core::LayerId;
    use gpurify_pex::network::NodeId;
    use gpurify_pex::quasistatic::Accuracy;
    use gpurify_pex::quasistatic::matvec::Backend;
    use gpurify_pex::{Parasitic, ParasiticNetwork};
    use gpurify_topology::NetId;
    use gpurify_units::Qty;

    fn ground(ff: f64) -> Parasitic {
        Parasitic::GroundCap(Qty::new(ff))
    }

    #[test]
    fn a_field_solved_net_replaces_its_analytical_rows_and_the_others_survive() {
        // Net 0 has two nodes, net 1 has one. Ascending and contiguous, which
        // is what `analytical::extract_into` promises.
        let mut analytical = ParasiticNetwork {
            node_net: vec![NetId(0), NetId(0), NetId(1)],
            node_layer: vec![LayerId(0); 3],
            ..ParasiticNetwork::default()
        };
        analytical.push(NodeId(0), None, ground(1.0));
        analytical.push(NodeId(0), Some(NodeId(1)), Parasitic::Resistance(Qty::new(10.0)));
        analytical.push(NodeId(2), None, ground(7.0));

        // The solve was asked for net 1 and meshed it into two nodes.
        let mut solved = ParasiticNetwork {
            node_net: vec![NetId(1), NetId(1)],
            node_layer: vec![LayerId(0); 2],
            ..ParasiticNetwork::default()
        };
        solved.push(NodeId(0), None, ground(2.0));

        let mut out = ParasiticNetwork::default();
        merge_field_solved_into(&analytical, &solved, &mut out);

        assert_eq!(out.node_net, vec![NetId(0), NetId(0), NetId(1), NetId(1)]);
        // Net 0's two elements survived; net 1's single analytical element was
        // replaced by the solve's, not added to it.
        assert_eq!(out.element_count(), 3);
        assert!((out.net_capacitance(NetId(0)).raw() - 1.0).abs() < f64::EPSILON);
        assert!((out.net_capacitance(NetId(1)).raw() - 2.0).abs() < f64::EPSILON);
    }

    fn accuracy(asymmetry: f64) -> Accuracy {
        Accuracy {
            residual: 1e-12,
            tolerance: 1e-10,
            iterations: 7,
            backend: Backend::Cpu,
            asymmetry,
        }
    }

    /// The three answers that are not "reciprocal", and the one that is. The
    /// non-finite pair is the whole reason this is not a `>` comparison.
    #[test]
    fn a_matrix_that_is_not_reciprocal_is_refused_and_a_non_finite_one_too() {
        assert!(reciprocity_refusal(&accuracy(1e-11)).is_none());
        assert!(reciprocity_refusal(&accuracy(0.0)).is_none());
        assert!(reciprocity_refusal(&accuracy(1e-9)).is_some());
        assert!(reciprocity_refusal(&accuracy(f64::INFINITY)).is_some());
        assert!(reciprocity_refusal(&accuracy(f64::NAN)).is_some());
    }
}
