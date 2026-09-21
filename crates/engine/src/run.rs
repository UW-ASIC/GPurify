//! Running the checks, and reporting honestly about which ones ran.

use crate::pipeline::{Extracted, Inputs, Loaded};
use gpurify_geom::ops::Point;
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::{StrId, StrTable};
use gpurify_check::lvs::verdict::Inconclusive;
use gpurify_check::lvs::{Discrepancy, Verdict};
use gpurify_extract::network::NodeId;
use gpurify_extract::ParasiticNetwork;
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::{celsius, prefix, Dbu, Grid, Qty, Temperature};

/// Which checks to run.
// All sixteen combinations are meaningful, including none, so the sum type
// CONVENTIONS §3 prefers would be forced here.
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
    pub const ALL: Self = Self {
        drc: true,
        erc: true,
        lvs: true,
        pex: true,
    };
}

/// How to run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub checks: Checks,
    pub lvs: gpurify_check::lvs::CompareOptions,
    /// Nets to extract by field solve. Empty means analytical extraction only.
    pub quasistatic_nets: Vec<String>,
    /// Also solve the quasi-static nets for inductance and resistance. Off by
    /// default, and with it off the run's output is byte-identical to a build
    /// without the flag: the inductance bridge is never invoked.
    pub quasistatic_inductance: bool,
    /// Worker threads. Affects speed only: output must be byte-identical at any
    /// value of this.
    pub threads: Option<usize>,
}

/// Whether a check ran, and if not, why. `Skipped` is not a quieter `Ran`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageStatus {
    Ran,
    /// Not requested.
    NotSelected,
    /// Requested, but a required input was absent.
    Skipped(&'static str),
    /// Requested, attempted, and refused: the input is outside what this tool
    /// represents exactly.
    Refused(String),
}

/// Everything a run produced.
#[derive(Debug, Default)]
pub struct Outputs {
    /// DRC and ERC findings, sorted canonically before this is returned.
    pub violations: Violations,
    /// One row per rule, run or not — what makes an empty `violations`
    /// interpretable.
    pub runs: Vec<RuleRun>,
    pub lvs: Option<Verdict>,
    pub parasitics: Option<ParasiticNetwork>,
}

/// What happened, at a glance.
///
/// Deliberately not just counts: `0 violations` without `3 rules skipped` is
/// the false-clean failure in report form.
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
    /// Rules that did not run. Read this before believing a clean result.
    pub rules_skipped: u32,
}

impl Summary {
    /// Whether the run is a pass, and the single place that criterion is written.
    ///
    /// A skipped rule is **not** a pass; a check never selected is `NotSelected`
    /// and does not block one. [`Self::rules_clean`] is evidence, not criterion,
    /// and an LVS mismatch arrives through [`Self::errors`] and nowhere else.
    pub fn passed(&self) -> bool {
        debug_assert!(
            self.errors <= self.violations && self.warnings <= self.violations,
            "a severity count larger than the table it counts: {self:?}"
        );

        // A stage asked for and not run blocks the pass; one never asked for
        // does not. `Refused` sits with `Skipped` rather than with `Ran`.
        let denied = |status: &StageStatus| {
            matches!(status, StageStatus::Skipped(_) | StageStatus::Refused(_))
        };

        self.errors == 0
            && self.rules_skipped == 0
            && !denied(&self.drc)
            && !denied(&self.erc)
            && !denied(&self.lvs)
            && !denied(&self.pex)
    }
}

/// The reason a stage that needs a grid did not get one.
const NO_GRID: &str = "no grid resolution reached this run, so no length in the deck has a meaning";

/// The temperature every ERC derating is computed at.
///
/// ponytail: 85 °C, hard-coded, because nothing in [`Inputs`] or [`RunOptions`]
/// carries a sign-off corner and [`gpurify_check::erc::RunInputs`] requires one that is
/// positive and finite. It is the same point `crates/erc/tests/common` derates
/// at, so a rule characterised there and run here sees one temperature. Upgrade
/// path: a `sign_off_temperature` field on [`RunOptions`], which is a
/// signature change rather than a body.
fn sign_off_temperature() -> Qty<Temperature, { prefix::BASE }> {
    celsius(85.0)
}

/// The layer names a deck may declare its die outline under, tried in this
/// order. First one the deck declares wins.
const DIE_LAYER_NAMES: [&str; 3] = ["prBoundary", "DIEAREA", "die"];

/// The die boundary every density in this run divides by.
///
/// The deck's outline layer when it declares one, otherwise the union of every
/// polygon's bounding box. That fallback is **fail-open for a minimum-density
/// rule**: the margin outside the outermost shape is never swept, and nothing in
/// [`Inputs`] declares a die.
/// [`Bbox::EMPTY`] for a store with no geometry, so the caller's skip is
/// reachable.
fn design_extent(loaded: &Loaded) -> Bbox {
    // Both guards fail closed into the fallback: a declared layer the store has
    // no column for would make `layer_bboxes` panic, and an empty outline is a
    // worse denominator than a tight one.
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
fn union_bboxes(boxes: &[Bbox]) -> Bbox {
    let mut acc = Bbox::EMPTY;
    for &b in boxes {
        acc = acc.union(b);
    }
    acc
}

/// The union of every polygon's bounding box.
fn design_bbox(store: &GeometryStore) -> Bbox {
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
fn run_grid(loaded: &Loaded) -> Option<Grid> {
    loaded.grid.or(loaded.deck.grid)
}

/// Refuse a deck row whose kind no domain implements.
///
/// Neither rule set can do this alone — the other domain's rows are
/// unrecognised to it — and a rule nobody runs is a report that looks complete.
fn reject_unknown_rule_kinds(loaded: &Loaded) -> Result<(), EngineError> {
    for spec in &loaded.deck.rules.spec {
        let kind = loaded.strings.resolve(spec.kind);
        let known = gpurify_check::drc::ruleset::KINDS.contains(&kind)
            || gpurify_check::erc::ruleset::KINDS.contains(&kind);
        if !known {
            return Err(gpurify_check::drc::DrcError::UnknownKind {
                rule: loaded.strings.resolve(spec.id).to_owned(),
                kind: kind.to_owned(),
            }
            .into());
        }
    }
    Ok(())
}

/// Run the selected checks against an extraction, appending into `out`.
///
/// Concatenation order is unobservable: `Violations::sort_canonical` runs before
/// returning. A deck that cannot become rule tables fails the whole run — not a
/// skipped rule, because a run against a wrong deck has no verdict to report.
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
    // `threads` is read here and nowhere else: nothing below this line is
    // parallel. Zero workers is still refused, since a run that does nothing
    // would report a clean design.
    debug_assert!(
        options.threads.is_none_or(|threads| threads > 0),
        "a run with no worker would report a clean design it never checked"
    );

    // Before `options.checks` is read at all: deciding it inside the `if` would
    // let a misspelled ERC rule through a DRC-only run.
    reject_unknown_rule_kinds(loaded)?;

    // Cleared column by column rather than reassigned, so the caller's
    // allocation survives; `Violations` is `SoA` and has no `clear` of its own.
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
    debug_assert!(
        out.violations.is_empty(),
        "a stale finding survived the clear"
    );

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
    // the concatenation order above unobservable.
    out.violations.sort_canonical();
    out.runs.sort_by_key(|run| run.rule);

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
        // run, `Refused` included.
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

/// Run one rule set into fresh buffers, then append them to `out`.
///
/// `drc` and `erc` both *clear* the tables their `run` is handed, so neither can
/// be given `out` directly. `rule_count` is the reservation *and* the expected
/// row count: filing fewer rows than a rule set holds rules lost one silently.
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
/// Geometric throughout — it needs neither a grid nor a die, so it has no skip
/// of its own.
fn run_drc(
    loaded: &Loaded,
    extracted: &Extracted,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    let rules = gpurify_check::drc::RuleSet::from_deck(&loaded.deck, &loaded.strings)?;
    let design = gpurify_check::drc::Design {
        store: &loaded.store,
        derived: &extracted.derived,
        nets: &extracted.nets,
        devices: &extracted.devices,
    };

    let mut scratch = gpurify_check::drc::Scratch::default();
    append_stage(out, "drc", rules.rule_count(), |violations, runs| {
        rules.run(design, &mut scratch, violations, runs);
    });
    Ok(StageStatus::Ran)
}

/// Assemble everything ERC reads, then dispatch its rules.
///
/// The five steps are the order `gpurify_check`'s crate doc fixes and none can
/// move. A supply grid that cannot be built or solved is
/// [`gpurify_check::erc::PowerError`], which has no [`EngineError`] variant, so it
/// becomes [`StageStatus::Refused`] — fail closed either way.
fn run_erc(
    loaded: &Loaded,
    extracted: &Extracted,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    // Before any skip: a skip decided ahead of this would hide a wrong deck
    // behind a missing input.
    let rules = gpurify_check::erc::RuleSet::from_deck(&loaded.deck, &loaded.strings)?;

    let Some(grid) = run_grid(loaded) else {
        return Ok(StageStatus::Skipped(NO_GRID));
    };
    let die = design_extent(loaded);
    if die.is_empty() {
        // Skipped rather than defaulted to a point: a denominator invented here
        // would put a number on a report that nothing measured.
        return Ok(StageStatus::Skipped(
            "the layout holds no geometry, so no die boundary bounds a density",
        ));
    }

    let design = gpurify_check::erc::Design {
        store: &loaded.store,
        derived: &extracted.derived,
        nets: &extracted.nets,
        devices: &extracted.devices,
    };
    let process = gpurify_check::erc::power::Process {
        grid,
        stack: &loaded.deck.stack,
        connectivity: &loaded.deck.connectivity,
    };

    let mut facts = gpurify_check::erc::NetFacts::default();
    gpurify_check::erc::classify_nets_into(&extracted.nets, &extracted.devices, &mut facts);
    debug_assert!(
        facts.len() <= extracted.nets.net_count(),
        "the role column names more nets than the extraction produced"
    );

    let mut intent = gpurify_check::erc::IntentMap::default();
    gpurify_check::erc::resolve_intent_into(
        loaded.intent.as_ref(),
        &extracted.ports,
        &extracted.nets,
        &mut intent,
    );

    let mut networks = gpurify_check::erc::NetNetworks::default();
    let mut power_grid = gpurify_check::erc::PowerGrid::default();
    if let Err(error) = gpurify_check::erc::power::extract_nets_into(
        &loaded.store,
        &extracted.nets,
        &extracted.devices,
        process,
        &mut networks,
    )
    .and_then(|()| {
        gpurify_check::erc::power::extract_into(
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

    // `None` is the information: no declared supply means no grid, and the four
    // electrical rules read exactly that before recording themselves skipped.
    let mut solution = gpurify_check::erc::PowerSolution::default();
    let power = if power_grid.is_empty() {
        None
    } else {
        let mut solve_scratch = gpurify_check::erc::power::SolveScratch::default();
        if let Err(error) = gpurify_check::erc::power::solve_into(
            &power_grid,
            gpurify_check::erc::power::SolveConfig::default(),
            &mut solve_scratch,
            &mut solution,
        ) {
            return Ok(StageStatus::Refused(error.to_string()));
        }
        Some(gpurify_check::erc::Solved {
            grid: &power_grid,
            solution: &solution,
        })
    };

    let mut scratch = gpurify_check::erc::Scratch::default();
    append_stage(out, "erc", rules.len(), |violations, runs| {
        rules.run(
            gpurify_check::erc::RunInputs {
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
/// Flat, on the reference's unique top cell. A verdict that did not conclude is
/// [`StageStatus::Refused`], not `Ran`.
///
/// The six layout-only checks run first, on the *unreduced* graph: a check run
/// after a transformation of its input is a check on the transformation. The
/// comparison then reduces **both** sides, because either netlist may be written
/// unreduced and reducing one would let the reduction choose the verdict.
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

    let mut layout = gpurify_check::lvs::LayoutGraph::default();
    gpurify_check::lvs::graph::from_layout_into(
        &extracted.nets,
        &extracted.devices,
        &extracted.ports,
        &loaded.strings,
        run_grid(loaded),
        &mut layout,
    );

    append_stage(out, "lvs", LVS_CHECK_RULE_IDS.len(), |violations, runs| {
        gpurify_check::lvs::checks::check_floating_nets(
            &extracted.nets,
            &extracted.devices,
            &extracted.ports,
            violations,
            runs,
        );
        gpurify_check::lvs::checks::check_label_conflicts(
            &extracted.nets,
            &extracted.ports,
            violations,
            runs,
        );
        gpurify_check::lvs::checks::check_net_seed_conflicts(
            &extracted.nets,
            &extracted.ports,
            violations,
            runs,
        );
        gpurify_check::lvs::checks::check_device_counts(&extracted.devices, violations, runs);
        gpurify_check::lvs::checks::check_parametric(&extracted.devices, violations, runs);
        gpurify_check::lvs::checks::check_topology(&layout, violations, runs);
        name_lvs_check_rows(&loaded.strings, violations, runs);
    });

    let verdict = match reference.top() {
        // Guessing which subcircuit was meant is the one thing a comparison
        // must never do.
        None => Verdict::Inconclusive(Inconclusive::AmbiguousTop),
        Some(top) => {
            let mut declared = gpurify_check::lvs::RefGraph::default();
            gpurify_check::lvs::graph::from_reference_into(reference, top, &loaded.strings, &mut declared);
            // A 3-terminal MOS recogniser extracts no bulk; the reference's
            // card-mandated fourth net must not unpair the comparison.
            gpurify_check::lvs::graph::drop_unextracted_bulk(&layout, &mut declared);

            let mut reduced_layout = gpurify_check::lvs::LayoutGraph::default();
            gpurify_check::lvs::reduce::reduce_into(&layout.0, &mut reduced_layout.0);
            let mut expected = gpurify_check::lvs::RefGraph::default();
            gpurify_check::lvs::reduce::reduce_into(&declared.0, &mut expected.0);

            let mut partition = gpurify_check::lvs::refine::Partition::default();
            gpurify_check::lvs::compare(&reduced_layout, &expected, options.lvs, &mut partition)
        }
    };

    let status = match &verdict {
        Verdict::Match => StageStatus::Ran,
        // The stage still *ran*: it concluded. The failure is carried by the
        // rows this records, which is what keeps `Ran` meaning "concluded".
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
/// [`gpurify_check::lvs::verdict::Discrepancy`] declares its variants.
///
/// Interned by [`crate::pipeline::load_into`], because `run_checks` borrows
/// `Loaded` shared and cannot intern.
pub(crate) const LVS_RULE_IDS: [&str; 7] = [
    "lvs.unpaired_device",
    "lvs.unpaired_net",
    "lvs.terminal_mismatch",
    "lvs.parameter_mismatch",
    "lvs.undeclared_param",
    "lvs.duplicate_name",
    "lvs.class_imbalance",
];

/// The rule id each of [`gpurify_check::lvs::checks`]'s eight run rows is reported
/// under, indexed by the sentinel the check filed it with.
///
/// Row `k` here is `StrId(u32::MAX - k)`: no check signature takes a
/// [`StrTable`], so `lvs::checks` counts ids down from `u32::MAX` and a row
/// escaping into a report dies in [`StrTable::resolve`] rather than resolving to
/// a real name. [`name_lvs_check_rows`] asserts the order.
pub(crate) const LVS_CHECK_RULE_IDS: [&str; 8] = [
    "lvs.floating_net",
    "lvs.label_conflict",
    "lvs.net_seed_conflict",
    "lvs.device_count_mos",
    "lvs.device_count_bjt",
    "lvs.parametric",
    "lvs.terminal_net",
    "lvs.terminal_count",
];

/// Replace every sentinel rule id the six checks filed with the run's interned
/// one, in place, before [`append_stage`] concatenates the buffers.
///
/// Fail closed: an id this table does not know is left exactly as it was, since
/// a wrong name attributed silently is worse than a `resolve` that panics.
fn name_lvs_check_rows(strings: &StrTable, violations: &mut Violations, runs: &mut [RuleRun]) {
    debug_assert_eq!(
        runs.len(),
        LVS_CHECK_RULE_IDS.len(),
        "the six checks filed {} rows, not the {} this table names",
        runs.len(),
        LVS_CHECK_RULE_IDS.len()
    );
    debug_assert!(
        runs.iter()
            .zip(0u32..)
            .all(|(run, k)| run.rule == StrId(u32::MAX - k)),
        "lvs::checks changed which sentinel it files a row under, or in what \
         order; the names in LVS_CHECK_RULE_IDS no longer line up with them"
    );

    // `u32::MAX - id` is the row; a real interned id is small, so it lands far
    // past the end and `get` answers `None`, the fail-closed arm.
    let named = |id: StrId| {
        LVS_CHECK_RULE_IDS
            .get((u32::MAX - id.0) as usize)
            .and_then(|name| strings.get(name))
            .unwrap_or(id)
    };
    for run in runs.iter_mut() {
        run.rule = named(run.rule);
    }
    for rule in &mut violations.rule {
        *rule = named(*rule);
    }
}

/// The layer an LVS violation names: `u16::MAX`, past the end of any deck's
/// layer table.
///
/// An LVS discrepancy has no layer, point or shape, so all three fields carry a
/// sentinel rather than a plausible coordinate borrowed from a nearby shape.
const NO_LAYER: LayerId = LayerId(u16::MAX);

/// See [`NO_LAYER`]. The origin, standing in for "this finding is not at a
/// place".
const NO_LOCATION: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};

/// See [`NO_LAYER`]. Past the end of any [`gpurify_geom::GeometryStore`].
const NO_SHAPE: PolyId = PolyId(u32::MAX);

/// Map every discrepancy of a mismatch into the violation table, every row a
/// [`Severity::Error`] — which is how a mismatch reaches [`Summary::passed`].
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
/// A name the table does not carry falls back to a sentinel
/// [`gpurify_ingest::StrTable::resolve`] panics on — the safer failure, since
/// `StrId(0)` would attribute the mismatch to whatever was interned first.
fn lvs_rule_id(discrepancy: &Discrepancy, strings: &StrTable) -> StrId {
    let name = match discrepancy {
        Discrepancy::UnpairedDevice { .. } => LVS_RULE_IDS[0],
        Discrepancy::UnpairedNet { .. } => LVS_RULE_IDS[1],
        Discrepancy::TerminalMismatch { .. } => LVS_RULE_IDS[2],
        Discrepancy::ParameterMismatch { .. } => LVS_RULE_IDS[3],
        Discrepancy::UndeclaredParam { .. } => LVS_RULE_IDS[4],
        Discrepancy::DuplicateName { .. } => LVS_RULE_IDS[5],
        Discrepancy::ClassImbalance { .. } => LVS_RULE_IDS[6],
    };
    strings.get(name).unwrap_or(StrId(u32::MAX))
}

/// What a discrepancy measured, and what it was measured against.
///
/// `measured` is always the layout's side and `limit` the reference's. Only two
/// of the seven carry numbers; the rest report `Count(1)` against `Count(0)`. A
/// non-finite value falls back to that form, as [`Violations::push`] refuses it.
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

/// Extract parasitics into [`Outputs::parasitics`].
///
/// Analytical for the whole design when [`RunOptions::quasistatic_nets`] is
/// empty; a non-empty selection field-solves *those* nets and keeps the
/// analytical network for every other one. Both paths cover the whole design,
/// which is what makes the [`StageStatus::Ran`] honest.
///
/// An asymmetry outside the solve's own tolerance is [`StageStatus::Refused`]
/// and nothing is written — see [`reciprocity_refusal`].
///
/// ponytail: the solve's [`gpurify_extract::quasistatic::CapMatrix`] is still
/// dropped, because [`Outputs`] has no slot for it. The per-net totals it
/// summarises survive as [`gpurify_extract::Parasitic::CouplingCap`] rows in the
/// merged network, so the loss is the off-diagonal *matrix* form a field solver
/// reports, not the coupling itself. [`gpurify_extract::quasistatic::Accuracy`]'s
/// other four fields — the achieved residual, the tolerance, the iteration
/// count and the backend that ran — have nowhere to land either, so a run's
/// numbers cannot be attributed after the fact. Upgrade path: a matrix field and
/// an accuracy field on [`Outputs`], a signature change rather than a body.
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
        gpurify_extract::analytical::extract_into(
            &loaded.store,
            &extracted.nets,
            &extracted.devices,
            &loaded.deck.connectivity,
            &loaded.deck.stack,
            grid,
            &mut network,
        );
    } else {
        let mut selected = Vec::with_capacity(options.quasistatic_nets.len());
        for name in &options.quasistatic_nets {
            // `get`, never `intern`: a name the run never saw is a net that is
            // not there. Fail closed — field-solving the rest and saying nothing
            // would answer a request that was never met.
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

        // The rest of the design, closed form. Unconditional: a run that
        // field-solves one net must still describe every other one.
        let mut coarse = ParasiticNetwork::default();
        gpurify_extract::analytical::extract_into(
            &loaded.store,
            &extracted.nets,
            &extracted.devices,
            &loaded.deck.connectivity,
            &loaded.deck.stack,
            grid,
            &mut coarse,
        );

        let mut matrix = gpurify_extract::quasistatic::CapMatrix::default();
        let mut solved = ParasiticNetwork::default();
        let accuracy = gpurify_extract::quasistatic::extract_into(
            &loaded.store,
            &extracted.nets,
            &selected,
            &loaded.deck.stack,
            grid,
            gpurify_extract::quasistatic::solve::Options::default(),
            &mut matrix,
            &mut solved,
        )?;

        // Refuse before the merge, so nothing a failed reciprocity check
        // produced reaches `out.parasitics`.
        if let Some(refusal) = reciprocity_refusal(&accuracy) {
            return Ok(StageStatus::Refused(refusal));
        }

        // Opt-in inductance: the same selection, one magnetoquasistatic solve,
        // appended onto `solved`'s one-node-per-net anchors before the merge.
        // A bridge refusal (a layer with no sheet resistance) is a refusal
        // here too, not a skip. `quasistatic_inductance == false` never
        // reaches the bridge, which is what keeps the default byte-identical.
        //
        // ponytail: the per-net `InductMatrix` is dropped like `CapMatrix` is —
        // `Outputs` has no slot for it.
        if options.quasistatic_inductance {
            let mut inductance = gpurify_extract::quasistatic::InductMatrix::default();
            if let Err(refusal) = gpurify_extract::quasistatic::extract_inductance_into(
                &loaded.store,
                &extracted.nets,
                &selected,
                &loaded.deck.stack,
                grid,
                &gpurify_extract::quasistatic::InductanceOptions::default(),
                &mut inductance,
                &mut solved,
            ) {
                return Ok(StageStatus::Refused(refusal.to_string()));
            }
        }

        merge_field_solved_into(&coarse, &solved, &mut network);
    }

    debug_assert!(
        network.element_count() == 0 || network.node_count() > 0,
        "parasitic elements naming nodes the network does not have"
    );
    out.parasitics = Some(network);
    Ok(StageStatus::Ran)
}

/// Whether a solve's own accuracy disqualifies its capacitance matrix. `None`
/// is "reciprocal within the tolerance the solve was given".
///
/// Not the residual, which is per-column: reciprocity is a statement *between*
/// columns, `C[i][j]` and `C[j][i]` being two solves of one number. It does not
/// catch under-meshing, which is symmetric about its own error.
fn reciprocity_refusal(accuracy: &gpurify_extract::quasistatic::Accuracy) -> Option<String> {
    debug_assert!(
        accuracy.tolerance > 0.0,
        "a tolerance of zero refuses every solve"
    );
    debug_assert!(
        !accuracy.asymmetry.is_sign_negative(),
        "a relative gap is non-negative"
    );

    // `is_finite` first, not a negated comparison: a NaN or infinite asymmetry
    // compares false against every bound, so `> tolerance` alone would pass
    // exactly the matrices nothing could check.
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
/// `u32::MAX` is past the end of any [`ParasiticNetwork`], so an escaped remap
/// trips a bounds check where `0` would silently name the first node.
const DROPPED_NODE: u32 = u32::MAX;

/// Overlay a field-solved network on an analytical one, into `out`.
///
/// Membership is read off `solved`, not off the selection: a net the caller
/// selected but the mesh produced no node for keeps its analytical rows.
///
/// [`ParasiticNetwork`] requires every net's nodes to occupy one contiguous
/// ascending range of `node_net`. Both inputs arrive that way and the surviving
/// net sets are disjoint, so the two-way merge reproduces it — hence a merge and
/// not a concatenation. Element order is not, so `sort_canonical` closes.
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
    // are cleared by name here; the caller's allocation survives.
    out.node_net.clear();
    out.node_layer.clear();
    out.from.clear();
    out.to.clear();
    out.value.clear();

    let (coarse_nodes, fine_nodes) = (analytical.node_count(), solved.node_count());
    let (coarse_elements, fine_elements) = (analytical.element_count(), solved.element_count());

    // Which nets the solve produced nodes for, one dense byte per net. Both
    // columns ascend, so the last row of each is its maximum.
    let highest_net = analytical
        .node_net
        .last()
        .map_or(0, |net| net.0)
        .max(solved.node_net.last().map_or(0, |net| net.0));
    let mut replaced = vec![0_u8; highest_net as usize + 1];
    for i in 0..fine_nodes {
        replaced[solved.node_net[i].0 as usize] = 1;
    }

    let mut coarse_map = vec![DROPPED_NODE; coarse_nodes];
    let mut fine_map = vec![DROPPED_NODE; fine_nodes];
    out.node_net.reserve(coarse_nodes + fine_nodes);
    out.node_layer.reserve(coarse_nodes + fine_nodes);

    let mut coarse = 0_usize;
    let mut fine = 0_usize;
    loop {
        // Skip the analytical rows of every net the solve replaced.
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
    debug_assert_eq!(
        fine, fine_nodes,
        "a field-solved node reached no merged row"
    );

    out.from.reserve(coarse_elements + fine_elements);
    out.to.reserve(coarse_elements + fine_elements);
    out.value.reserve(coarse_elements + fine_elements);

    // An analytical element survives when its nodes did. `analytical::
    // extract_into` emits nothing spanning two nets, so its endpoints agree on
    // survival — asserted, because one that spanned would be dropped silently.
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

    // Every field-solved node survived, so only the renumbering applies.
    for i in 0..fine_elements {
        let from = fine_map[solved.from[i].0 as usize];
        let to = solved.to[i].map(|node| fine_map[node.0 as usize]);
        debug_assert_ne!(
            from, DROPPED_NODE,
            "a field-solved element lost its near node"
        );
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
/// A fold rather than a counter threaded through the merge, which would be
/// checking the merge against itself.
fn replaced_node_count(analytical: &ParasiticNetwork, replaced: &[u8]) -> usize {
    let n = analytical.node_net.len();
    let mut count = 0_usize;
    for i in 0..n {
        count += usize::from(replaced[analytical.node_net[i].0 as usize]);
    }
    count
}

/// Load, extract and check in one call.
pub fn run(
    inputs: &Inputs,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<Summary, EngineError> {
    // Nothing touches `out` before the load: a run that failed to read its
    // inputs must not have left findings behind.
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
    #[error(transparent)]
    Drc(#[from] gpurify_check::drc::DrcError),
    /// The deck could not be turned into an ERC rule set.
    #[error(transparent)]
    Erc(#[from] gpurify_check::erc::ErcError),
    #[error(transparent)]
    Solve(#[from] gpurify_extract::quasistatic::solve::SolveError),
    #[error(transparent)]
    Mesh(#[from] gpurify_extract::quasistatic::mesh::MeshError),
}

/// [`merge_field_solved_into`] and [`reciprocity_refusal`] are private, so their
/// checks live beside them.
#[cfg(test)]
mod tests {
    use super::{merge_field_solved_into, reciprocity_refusal};
    use gpurify_geom::LayerId;
    use gpurify_extract::network::NodeId;
    use gpurify_extract::quasistatic::matvec::Backend;
    use gpurify_extract::quasistatic::Accuracy;
    use gpurify_extract::{Parasitic, ParasiticNetwork};
    use gpurify_check::topology::NetId;
    use gpurify_geom::Qty;

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
        analytical.push(
            NodeId(0),
            Some(NodeId(1)),
            Parasitic::Resistance(Qty::new(10.0)),
        );
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
