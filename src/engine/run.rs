//! Running the checks, and reporting honestly about which ones ran.
//!
//! Data in: [`Loaded`] + [`Extracted`] + [`RunOptions`]. Data out: [`Outputs`]
//! (violations, rule records, LVS verdict, parasitics) and a [`Summary`].

use crate::engine::pipeline::{Extracted, Inputs, Loaded};
use gpurify_check::lvs::verdict::Inconclusive;
use gpurify_check::lvs::Verdict;
use gpurify_check::report::{Outcome, RuleRun, Severity, Violations};
use gpurify_extract::ParasiticNetwork;
use gpurify_geom::{celsius, prefix, Qty, Temperature};
use gpurify_geom::{Bbox, GeometryStore, LayerId};

/// Which checks to run.
///
/// A check left out is [`StageStatus::NotSelected`], which does not fail
/// [`Summary::passed`], so a run with none selected passes having checked
/// nothing. Unknown rule kinds in the deck are refused whatever is selected.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    /// Design rules: every DRC row of the deck.
    pub drc: bool,
    /// Electrical rules: every ERC row of the deck.
    pub erc: bool,
    /// The layout-only LVS checks and, given a reference, the comparison.
    pub lvs: bool,
    /// Parasitic extraction.
    pub pex: bool,
}

impl Checks {
    /// All four, as `gpurify all` runs them.
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
    /// Which of the four checks to run.
    pub checks: Checks,
    /// LVS comparison settings. Only `max_rounds` and `param_tolerance` are
    /// read: `params` is always replaced by the names `w`, `l`, `nf` and `m`.
    pub lvs: gpurify_check::lvs::CompareOptions,
    /// Nets to field-solve for capacitance and inductance instead of the
    /// closed-form estimate. Empty means analytical extraction only.
    ///
    /// Each entry is a label text. A name no label carries refuses the PEX
    /// stage. A name on several disconnected nets solves only the lowest of
    /// them. Naming a net twice makes the solve fail with
    /// [`EngineError::Solve`].
    pub quasistatic_nets: Vec<String>,
}

/// Whether a check ran, and if not, why. `Skipped` is not a quieter `Ran`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageStatus {
    /// Requested and run. Its findings, if any, are in [`Outputs`]; an LVS
    /// mismatch still counts as run, with its discrepancies as error rows.
    Ran,
    /// Not requested.
    NotSelected,
    /// Requested, but a required input was absent: no reference netlist for
    /// LVS, or a layout with no geometry for ERC. Fails [`Summary::passed`].
    Skipped(&'static str),
    /// Requested and refused: the input is outside what this tool represents exactly.
    /// For LVS, a comparison that did not conclude; for PEX, an unknown net
    /// name, a capacitance matrix that is not reciprocal, or an inductance
    /// solve that refused. ERC refuses row by row instead (a supply grid that
    /// cannot be built or solved refuses the rows that read it), and those
    /// rows count in [`Summary::rules_skipped`]. Fails [`Summary::passed`].
    Refused(String),
}

/// Everything a run produced.
#[derive(Debug, Default)]
pub struct Outputs {
    /// DRC, ERC and LVS findings, sorted canonically.
    pub violations: Violations,
    /// One row per rule, run or not, sorted by rule id.
    pub runs: Vec<RuleRun>,
    /// The comparison's verdict. `Some` whenever LVS ran with a reference,
    /// including an inconclusive comparison; `None` otherwise.
    pub lvs: Option<Verdict>,
    /// Every series or parallel merge LVS made on either side.
    pub lvs_merges: Vec<(gpurify_check::lvs::verdict::Side, gpurify_check::lvs::Merge)>,
    /// The extracted parasitics, analytical with any field-solved nets laid
    /// over them, in canonical order. `Some` only when PEX ran; a refused
    /// PEX stage leaves `None`, not a partial network.
    pub parasitics: Option<ParasiticNetwork>,
}

/// What happened, at a glance. `0 violations` without `rules_skipped` is a false clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Whether DRC ran.
    pub drc: StageStatus,
    /// Whether ERC ran.
    pub erc: StageStatus,
    /// Whether LVS ran.
    pub lvs: StageStatus,
    /// Whether PEX ran.
    pub pex: StageStatus,
    /// Rows in [`Outputs::violations`], errors and warnings together.
    pub violations: u32,
    /// Violations of error severity, LVS discrepancies included. Any fails
    /// [`Self::passed`].
    pub errors: u32,
    /// Violations of warning severity. These do not fail [`Self::passed`].
    pub warnings: u32,
    /// Rules that ran and found nothing.
    pub rules_clean: u32,
    /// Rules that did not run. Read this before believing a clean result.
    /// Skipped and refused rules both count, and any fails [`Self::passed`].
    pub rules_skipped: u32,
}

impl Summary {
    /// The pass criterion: no errors, no skipped rule, and no selected stage
    /// skipped or refused. An LVS mismatch arrives through `errors`.
    ///
    /// Warnings do not fail it. The CLI exits `0` only when this holds.
    pub fn passed(&self) -> bool {
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

/// The temperature every ERC derating is computed at.
///
/// ponytail: 85 °C hard-coded, as nothing carries a sign-off corner; add a
/// `RunOptions` field when one is needed.
fn sign_off_temperature() -> Qty<Temperature, { prefix::BASE }> {
    celsius(85.0)
}

/// Layer names a deck may declare its die outline under, first match wins.
const DIE_LAYER_NAMES: [&str; 3] = ["prBoundary", "DIEAREA", "die"];

/// The die boundary every density divides by: the deck's outline layer if it
/// has one, else the union of every polygon's bbox (fail-open for min-density,
/// which never sweeps the margin). [`Bbox::EMPTY`] for an empty store.
pub(crate) fn design_extent(loaded: &Loaded) -> Bbox {
    let declared = DIE_LAYER_NAMES
        .iter()
        .find_map(|name| loaded.deck.layers.id(&loaded.strings, name))
        .filter(|layer| layer.idx() < loaded.store.layer_count())
        .map(|layer| union_bboxes(loaded.store.layer_bboxes(layer)))
        .filter(|outline| !outline.is_empty());
    declared.unwrap_or_else(|| design_bbox(&loaded.store))
}

fn union_bboxes(boxes: &[Bbox]) -> Bbox {
    boxes.iter().fold(Bbox::EMPTY, |acc, &b| acc.union(b))
}

fn design_bbox(store: &GeometryStore) -> Bbox {
    (0..store.layer_count()).fold(Bbox::EMPTY, |die, layer| {
        let layer = LayerId(u16::try_from(layer).expect("a LayerId is a u16"));
        die.union(union_bboxes(store.layer_bboxes(layer)))
    })
}

/// Refuse a deck row whose kind neither DRC nor ERC implements. A rule nobody
/// runs is a report that looks complete.
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

/// Run the selected checks. A deck that cannot become rule tables fails the whole
/// run: a run against a wrong deck has no verdict to report.
///
/// The checks run once each, in the order DRC, ERC, LVS, PEX. A check that
/// cannot run is reported in its [`StageStatus`], never as an empty result.
/// `loaded` must come from [`load`](crate::engine::pipeline::load), and
/// `extracted` from [`extract`](crate::engine::pipeline::extract) over it.
///
/// # Errors
///
/// - [`EngineError::Drc`]: a deck rule names a kind neither DRC nor ERC
///   knows (checked even when neither is selected), or DRC is selected and
///   its rules cannot be built.
/// - [`EngineError::Erc`]: ERC is selected and its rules cannot be built.
/// - [`EngineError::Solve`]: `quasistatic_nets` cannot be meshed, or a
///   capacitance column does not converge. A net on a layer the stack does
///   not describe fails here.
pub fn run_checks(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
) -> Result<(Outputs, Summary), EngineError> {
    // Before `options.checks` is read, so a misspelled ERC kind fails a DRC-only run.
    reject_unknown_rule_kinds(loaded)?;

    let mut out = Outputs::default();
    let drc = if options.checks.drc {
        run_drc(loaded, extracted, &mut out)?
    } else {
        StageStatus::NotSelected
    };
    let erc = if options.checks.erc {
        run_erc(loaded, extracted, &mut out)?
    } else {
        StageStatus::NotSelected
    };
    let lvs = if options.checks.lvs {
        run_lvs(loaded, extracted, options, &mut out)
    } else {
        StageStatus::NotSelected
    };
    let pex = if options.checks.pex {
        run_pex(loaded, extracted, options, &mut out)?
    } else {
        StageStatus::NotSelected
    };

    out.violations.sort_canonical();
    out.runs.sort_by_key(|run| run.rule);

    let violations =
        u32::try_from(out.violations.len()).expect("a violation table indexes rows with a u32");
    let errors = count(out.violations.severity.iter(), |&&s| s == Severity::Error);
    let rules_clean = count(out.runs.iter(), |run| {
        run.outcome == Outcome::Ran && run.violations == 0
    });
    let rules_skipped = count(out.runs.iter(), |run| run.outcome != Outcome::Ran);

    let summary = Summary {
        drc,
        erc,
        lvs,
        pex,
        violations,
        errors,
        warnings: violations - errors,
        rules_clean,
        rules_skipped,
    };
    Ok((out, summary))
}

fn count<T>(items: impl Iterator<Item = T>, keep: impl FnMut(&T) -> bool) -> u32 {
    u32::try_from(items.filter(keep).count()).expect("a table indexes rows with a u32")
}

/// Run one rule set into fresh buffers (DRC and ERC clear what they are
/// handed), then append them to `out`.
fn append_stage(out: &mut Outputs, run: impl FnOnce(&mut Violations, &mut Vec<RuleRun>)) {
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    run(&mut violations, &mut runs);
    out.violations.extend(&violations);
    out.runs.append(&mut runs);
}

fn run_drc(
    loaded: &Loaded,
    extracted: &Extracted,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    let rules = gpurify_check::drc::RuleSet::from_deck(&loaded.deck, &loaded.strings)?;
    append_stage(out, |violations, runs| {
        rules.run_with_nets(&loaded.store, Some(&extracted.nets), violations, runs);
    });
    Ok(StageStatus::Ran)
}

/// Classify nets, resolve intent, build and solve the supply grid, then run the
/// rules. A supply grid that cannot be built or solved refuses only the rows
/// that read it; `erc::check` refusing the whole stage maps to
/// [`StageStatus::Refused`].
fn run_erc(
    loaded: &Loaded,
    extracted: &Extracted,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    // Before any skip, so a missing input cannot hide a wrong deck.
    let rules = gpurify_check::erc::RuleSet::from_deck(&loaded.deck, &loaded.strings)?;

    let grid = loaded.grid;
    let die = design_extent(loaded);
    if die.is_empty() {
        return Ok(StageStatus::Skipped(
            "the layout holds no geometry, so no die boundary bounds a density",
        ));
    }

    let inputs = gpurify_check::erc::Inputs {
        design: gpurify_check::Design {
            store: &loaded.store,
            nets: &extracted.nets,
            devices: &extracted.devices,
        },
        ports: &extracted.ports,
        intent: loaded.intent.as_ref(),
        process: gpurify_check::erc::Process {
            grid,
            stack: &loaded.deck.stack,
            connectivity: &loaded.deck.connectivity,
        },
        die,
        temperature: sign_off_temperature(),
    };
    let mut result = Ok(());
    append_stage(out, |violations, runs| {
        result = gpurify_check::erc::check(&rules, inputs, violations, runs);
    });
    Ok(result.map_or_else(
        |error| StageStatus::Refused(error.to_string()),
        |()| StageStatus::Ran,
    ))
}

/// The five layout-only checks on the unreduced graph, then a flat comparison of
/// both sides reduced, on the reference's unique top cell. A verdict that did not
/// conclude is [`StageStatus::Refused`].
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

    let layout = gpurify_check::lvs::graph::from_layout(
        &extracted.nets,
        &extracted.devices,
        &extracted.ports,
        &loaded.strings,
        Some(loaded.grid),
    );
    append_stage(out, |violations, runs| {
        gpurify_check::lvs::check_layout(
            &layout,
            &extracted.nets,
            &extracted.devices,
            &extracted.ports,
            &loaded.strings,
            violations,
            runs,
        );
    });

    let verdict = match reference.top() {
        // Guessing which subcircuit was meant is the one thing a comparison must never do.
        None => Verdict::Inconclusive(Inconclusive::AmbiguousTop),
        Some(top) => {
            // The SPICE names of width, length, fingers and multiplier, as both
            // netlists intern them, so sized fingers merge like netgen's.
            let name = |n: &str| loaded.strings.get(n);
            let lvs = gpurify_check::lvs::CompareOptions {
                params: gpurify_check::lvs::ParamNames {
                    width: name("w"),
                    length: name("l"),
                    fingers: name("nf"),
                    multiplier: name("m"),
                },
                ..options.lvs
            };
            let (verdict, merges) = gpurify_check::lvs::compare_logged(
                &layout,
                &gpurify_check::lvs::graph::from_reference(reference, top),
                lvs,
            );
            out.lvs_merges = merges;
            verdict
        }
    };

    let status = match &verdict {
        Verdict::Match => StageStatus::Ran,
        // Concluded; the failure is carried by the error rows.
        Verdict::Mismatch(found) => {
            gpurify_check::lvs::record_discrepancies(found, &loaded.strings, &mut out.violations);
            StageStatus::Ran
        }
        Verdict::Inconclusive(why) => {
            StageStatus::Refused(format!("the comparison did not conclude: {why:?}"))
        }
    };
    out.lvs = Some(verdict);
    status
}

/// Analytical extraction of the whole design; with `quasistatic_nets`, those nets
/// are field-solved and overlaid on it. A non-reciprocal solve is refused.
///
/// ponytail: the solve's `CapMatrix`, `InductMatrix` and `Accuracy` are dropped,
/// as `Outputs` has no slot for them; add fields there when a caller needs them.
fn run_pex(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<StageStatus, EngineError> {
    let grid = loaded.grid;
    let mut network = ParasiticNetwork::default();
    gpurify_extract::analytical::extract_into(
        &loaded.store,
        &extracted.nets,
        &loaded.deck.connectivity,
        &loaded.deck.stack,
        grid,
        &mut network,
    );
    if !options.quasistatic_nets.is_empty() {
        let mut selected = Vec::with_capacity(options.quasistatic_nets.len());
        for name in &options.quasistatic_nets {
            // `get`, never `intern`: a name the run never saw is not a net.
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

        let mut matrix = gpurify_extract::quasistatic::CapMatrix::default();
        let mut solved = ParasiticNetwork::default();
        let accuracy = gpurify_extract::quasistatic::extract_into(
            &loaded.store,
            &extracted.nets,
            &selected,
            &loaded.deck.stack,
            grid,
            &mut matrix,
            &mut solved,
        )?;

        if let Some(refusal) = reciprocity_refusal(&accuracy) {
            return Ok(StageStatus::Refused(refusal));
        }

        let mut inductance = gpurify_extract::quasistatic::InductMatrix::default();
        if let Err(refusal) = gpurify_extract::quasistatic::extract_inductance_into(
            &loaded.store,
            &extracted.nets,
            &selected,
            &loaded.deck.stack,
            grid,
            &mut inductance,
            &mut solved,
        ) {
            return Ok(StageStatus::Refused(refusal.to_string()));
        }

        gpurify_extract::quasistatic::overlay(&mut network, &solved);
    }

    out.parasitics = Some(network);
    Ok(StageStatus::Ran)
}

/// `Some(reason)` when the matrix is not reciprocal within the solve's own
/// tolerance. A NaN or infinite asymmetry is refused too.
fn reciprocity_refusal(accuracy: &gpurify_extract::quasistatic::Accuracy) -> Option<String> {
    let refused = !accuracy.asymmetry.is_finite() || accuracy.asymmetry > accuracy.tolerance;
    refused.then(|| {
        format!(
            "the capacitance matrix is not reciprocal: asymmetry {:e} against a solve tolerance of {:e}, after {} iterations",
            accuracy.asymmetry, accuracy.tolerance, accuracy.iterations
        )
    })
}

/// Load, extract and check in one call.
///
/// Returns what was loaded and extracted alongside the results, since the
/// report writers need the string table, grid and ports.
///
/// # Errors
///
/// [`EngineError::Load`] and [`EngineError::Extract`] from the first two
/// steps, then whatever [`run_checks`] returns. An error means no verdict;
/// a check that could not run is not an error but a [`StageStatus`].
pub fn run(
    inputs: &Inputs,
    options: &RunOptions,
) -> Result<(Loaded, Extracted, Outputs, Summary), EngineError> {
    let loaded = crate::engine::pipeline::load(inputs)?;
    let extracted = crate::engine::pipeline::extract(&loaded)?;
    let (outputs, summary) = run_checks(&loaded, &extracted, options)?;
    Ok((loaded, extracted, outputs, summary))
}

/// Why a run produced no report at all. The CLI prints it and exits `1`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
    /// An input file could not be read or parsed.
    #[error(transparent)]
    Load(#[from] crate::engine::pipeline::LoadError),
    /// Nets, devices or ports could not be extracted.
    #[error(transparent)]
    Extract(#[from] crate::engine::pipeline::ExtractError),
    /// The deck's rules could not become DRC tables, or name an unknown kind.
    #[error(transparent)]
    Drc(#[from] gpurify_check::drc::DrcError),
    /// The deck's rules could not become ERC tables.
    #[error(transparent)]
    Erc(#[from] gpurify_check::erc::ErcError),
    /// A field solve for `quasistatic_nets` could not be meshed or did not converge.
    #[error(transparent)]
    Solve(#[from] gpurify_extract::quasistatic::solve::SolveError),
}

/// [`reciprocity_refusal`] is private, so its check lives beside it.
#[cfg(test)]
mod tests {
    use super::reciprocity_refusal;
    use gpurify_extract::quasistatic::Accuracy;

    fn accuracy(asymmetry: f64) -> Accuracy {
        Accuracy {
            tolerance: 1e-10,
            iterations: 7,
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
