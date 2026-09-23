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
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    pub drc: bool,
    pub erc: bool,
    pub lvs: bool,
    pub pex: bool,
}

impl Checks {
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
    /// Also solve the quasi-static nets for inductance. Off leaves output unchanged.
    pub quasistatic_inductance: bool,
}

/// Whether a check ran, and if not, why. `Skipped` is not a quieter `Ran`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageStatus {
    Ran,
    /// Not requested.
    NotSelected,
    /// Requested, but a required input was absent.
    Skipped(&'static str),
    /// Requested and refused: the input is outside what this tool represents exactly.
    Refused(String),
}

/// Everything a run produced.
#[derive(Debug, Default)]
pub struct Outputs {
    /// DRC, ERC and LVS findings, sorted canonically.
    pub violations: Violations,
    /// One row per rule, run or not, sorted by rule id.
    pub runs: Vec<RuleRun>,
    pub lvs: Option<Verdict>,
    pub parasitics: Option<ParasiticNetwork>,
}

/// What happened, at a glance. `0 violations` without `rules_skipped` is a false clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub drc: StageStatus,
    pub erc: StageStatus,
    pub lvs: StageStatus,
    pub pex: StageStatus,
    pub violations: u32,
    pub errors: u32,
    pub warnings: u32,
    /// Rules that ran and found nothing.
    pub rules_clean: u32,
    /// Rules that did not run. Read this before believing a clean result.
    pub rules_skipped: u32,
}

impl Summary {
    /// The pass criterion: no errors, no skipped rule, and no selected stage
    /// skipped or refused. An LVS mismatch arrives through `errors`.
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
fn design_extent(loaded: &Loaded) -> Bbox {
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
/// rules. A supply grid that cannot be built or solved is [`StageStatus::Refused`].
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

/// The six layout-only checks on the unreduced graph, then a flat comparison of
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
        Some(top) => gpurify_check::lvs::compare(
            &layout,
            &gpurify_check::lvs::graph::from_reference(reference, top),
            options.lvs,
        ),
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

        if options.quasistatic_inductance {
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
pub fn run(
    inputs: &Inputs,
    options: &RunOptions,
) -> Result<(Loaded, Extracted, Outputs, Summary), EngineError> {
    let loaded = crate::engine::pipeline::load(inputs)?;
    let extracted = crate::engine::pipeline::extract(&loaded)?;
    let (outputs, summary) = run_checks(&loaded, &extracted, options)?;
    Ok((loaded, extracted, outputs, summary))
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Load(#[from] crate::engine::pipeline::LoadError),
    #[error(transparent)]
    Extract(#[from] crate::engine::pipeline::ExtractError),
    #[error(transparent)]
    Drc(#[from] gpurify_check::drc::DrcError),
    #[error(transparent)]
    Erc(#[from] gpurify_check::erc::ErcError),
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
