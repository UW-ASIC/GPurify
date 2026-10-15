//! Running the checks, and reporting honestly about which ones ran.
//!
//! Data in: [`Loaded`] + [`Extracted`] + [`RunOptions`]. Data out: [`Outputs`]
//! (violations, rule records, LVS verdict, parasitics) and a [`Summary`].

use crate::engine::pipeline::{Extracted, Inputs, Loaded};
use gpurify_check::deck::DeckFn;
use gpurify_check::erc::rules::antenna::MacroPinAntenna;
use gpurify_check::lvs::verdict::Inconclusive;
use gpurify_check::lvs::Verdict;
use gpurify_check::report::{Outcome, RuleRun, Severity, Violations};
use gpurify_extract::ParasiticNetwork;
use gpurify_geom::{celsius, prefix, Qty, Temperature};
use gpurify_geom::{Bbox, LayerId};

/// Which checks to run.
///
/// A check left out is [`StageStatus::NotSelected`], which does not fail
/// [`Summary::passed`], so a run with none selected passes having checked
/// nothing. A deck whose rules do not compile was refused when it was loaded,
/// whatever is selected.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    /// Design rules: every DRC row of the deck, then its custom rules.
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
    /// Each entry is a label text. A name no label carries, or one on
    /// several disconnected nets (an open), refuses the PEX stage. A net
    /// named twice is solved once.
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
    /// For LVS, a comparison that did not conclude; for PEX, a conductor or
    /// via layer with no `pex` row
    /// ([`AnalyticalError`](gpurify_extract::analytical::AnalyticalError)), an
    /// unknown net name or one on several nets, a field solve that refused
    /// ([`SolveError`](gpurify_extract::quasistatic::solve::SolveError): a
    /// layer it cannot mesh, named as the deck names it, or a column that did
    /// not converge), a capacitance matrix that is not reciprocal, or an
    /// inductance solve that refused; for ERC, design
    /// intent on a layout that shorts two labelled nets. Otherwise ERC refuses
    /// row by row (a supply grid that
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
    /// Each instance of the reference a mismatch left with every device
    /// unpaired, the outermost such, and its device count
    /// ([`gpurify_check::lvs::unpaired_instances`]); each is also an
    /// `lvs.unpaired_instance` row.
    pub lvs_unpaired_instances: Vec<(gpurify_ingest::netlist::Placement, u32)>,
    /// The extracted parasitics, analytical with any field-solved nets laid
    /// over them, reduced to the deck's extraction type
    /// ([`gpurify_extract::reduce`]), in canonical order. `Some` only when
    /// PEX ran; a refused PEX stage leaves `None`, not a partial network.
    pub parasitics: Option<ParasiticNetwork>,
    /// The violations the deck's waivers cover (`waive <rule> <layer>`: a
    /// finding whose marker lies on a shape of that layer), moved out of
    /// [`Self::violations`], sorted canonically: reported, not counted
    /// against the run, and taken off their rule's
    /// [`RuleRun::violations`](gpurify_check::report::RuleRun::violations).
    pub waived: Violations,
    /// The same extraction at each of the deck's process corners
    /// ([`gpurify_ingest::deck::ProcessCorner`]), by the corner's name, in
    /// deck order: the same nets, nodes and kinds of element as
    /// [`Self::parasitics`], at the corner's values. Empty without corners or
    /// when PEX did not run.
    pub corners: Vec<(String, ParasiticNetwork)>,
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

/// The temperature every ERC derating is computed at: the intent's
/// `temperature_c` (this chip's junction), else the deck's `temperature`
/// statement, else 85 °C.
fn sign_off_temperature(loaded: &Loaded) -> Qty<Temperature, { prefix::BASE }> {
    loaded
        .intent
        .as_ref()
        .and_then(gpurify_ingest::DesignIntent::temperature)
        .or(loaded.deck.temperature)
        .unwrap_or_else(|| celsius(85.0))
}

/// Layer names a deck may declare its die outline under, first match wins.
const DIE_LAYER_NAMES: [&str; 3] = ["prBoundary", "DIEAREA", "die"];

/// The die boundary every density divides by: the deck's outline layer if it
/// has one, else the union of every drawn polygon's bbox (fail-open for
/// min-density, which never sweeps the margin). A derived layer is not layout,
/// so one grown past the drawing does not widen the die. [`Bbox::EMPTY`] for
/// an empty store.
pub(crate) fn design_extent(loaded: &Loaded) -> Bbox {
    let declared = DIE_LAYER_NAMES
        .iter()
        .find_map(|name| loaded.deck.layers.id(&loaded.strings, name))
        .filter(|layer| layer.idx() < loaded.store.layer_count())
        .map(|layer| union_bboxes(loaded.store.layer_bboxes(layer)))
        .filter(|outline| !outline.is_empty());
    declared.unwrap_or_else(|| drawn_bbox(loaded))
}

fn union_bboxes(boxes: &[Bbox]) -> Bbox {
    boxes.iter().fold(Bbox::EMPTY, |acc, &b| acc.union(b))
}

fn drawn_bbox(loaded: &Loaded) -> Bbox {
    (0..loaded.store.layer_count())
        .map(|layer| LayerId(u16::try_from(layer).expect("a LayerId is a u16")))
        .filter(|&layer| !loaded.deck.layers.is_derived(layer))
        .fold(Bbox::EMPTY, |die, layer| {
            die.union(union_bboxes(loaded.store.layer_bboxes(layer)))
        })
}

/// Run the selected checks over a deck whose rules are already typed:
/// [`load`](crate::engine::pipeline::load) refused a deck that could not
/// become rule tables, since a run against a wrong deck has no verdict.
///
/// The checks run once each, in the order DRC, ERC, LVS, PEX. A check that
/// cannot run is reported in its [`StageStatus`], never as an empty result.
/// A layout with a net carrying two labels, a short between named nets, gets
/// the `lvs.net_seed_conflict` row whatever was selected
/// ([`check_net_seed_conflicts`](gpurify_check::lvs::check_net_seed_conflicts)),
/// so it fails every run.
/// `loaded` must come from [`load`](crate::engine::pipeline::load), and
/// `extracted` from [`extract`](crate::engine::pipeline::extract) over it.
///
/// # Errors
///
/// None today: a check that cannot run is a [`StageStatus`], not an error.
/// The `Result` is the room a later failure of the whole run needs.
pub fn run_checks(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
) -> Result<(Outputs, Summary), EngineError> {
    let mut out = Outputs::default();
    let staged = !loaded.deck.stages.name.is_empty();
    let drc = if options.checks.drc {
        if let Some(design) = &loaded.design {
            append_stage(&mut out, |violations, runs| {
                crate::engine::integration::check(design, &loaded.strings, violations, runs);
            });
        }
        run_drc(loaded, extracted, &mut out)
    } else {
        StageStatus::NotSelected
    };
    let erc = if options.checks.erc {
        run_erc(loaded, extracted, &mut out)
    } else {
        StageStatus::NotSelected
    };
    if staged {
        hold_back_later_stages(loaded, &mut out);
    }
    let lvs = if options.checks.lvs {
        run_lvs(loaded, extracted, options, &mut out)
    } else {
        StageStatus::NotSelected
    };
    let pex = if options.checks.pex {
        run_pex(loaded, extracted, options, &mut out)
    } else {
        StageStatus::NotSelected
    };

    // A short between labelled nets fails every run, with its row: LVS's layout
    // checks record it when they run, and this does when they do not.
    let layout_checked = options.checks.lvs && loaded.reference.is_some();
    if !layout_checked && extracted.ports.shorted_net().is_some() {
        append_stage(&mut out, |violations, runs| {
            gpurify_check::lvs::check_net_seed_conflicts(
                gpurify_check::Design {
                    store: &loaded.store,
                    nets: &extracted.nets,
                    devices: &extracted.devices,
                },
                &extracted.ports,
                &loaded.strings,
                violations,
                runs,
            );
        });
    }

    apply_waivers(loaded, &mut out);
    let summary = summarize(&mut out, [drc, erc, lvs, pex]);
    Ok((out, summary))
}

/// Put `out` in canonical order and count it, with each stage's status in
/// DRC, ERC, LVS, PEX order.
pub(crate) fn summarize(out: &mut Outputs, stages: [StageStatus; 4]) -> Summary {
    out.violations.sort_canonical();
    out.waived.sort_canonical();
    out.runs.sort_by_key(|run| run.rule);

    let violations =
        u32::try_from(out.violations.len()).expect("a violation table indexes rows with a u32");
    let errors = count(out.violations.severity.iter(), |&&s| s == Severity::Error);
    let rules_clean = count(out.runs.iter(), |run| {
        run.outcome == Outcome::Ran && run.violations == 0
    });
    let rules_skipped = count(out.runs.iter(), |run| run.outcome != Outcome::Ran);

    let [drc, erc, lvs, pex] = stages;
    Summary {
        drc,
        erc,
        lvs,
        pex,
        violations,
        errors,
        warnings: violations - errors,
        rules_clean,
        rules_skipped,
    }
}

fn count<T>(items: impl Iterator<Item = T>, keep: impl FnMut(&T) -> bool) -> u32 {
    u32::try_from(items.filter(keep).count()).expect("a table indexes rows with a u32")
}

/// A staged deck ([`gpurify_ingest::deck::Stages`]): stage by stage in deck
/// order, the first stage whose DRC or ERC rules report an error is the last
/// one reported. Every rule of a later stage becomes
/// [`SkipReason::EarlierStage`](gpurify_check::report::SkipReason::EarlierStage),
/// its findings withdrawn, so the run fails and says what it did not check.
/// DRC has already stopped at its own first dirty stage ([`run_drc`]); this
/// carries an ERC rule's error to the DRC and ERC rules of later stages.
///
/// ponytail: ERC runs whole and its later stages are withdrawn, so they cost
/// their runtime; split the ERC tables by stage if that runtime matters.
fn hold_back_later_stages(loaded: &Loaded, out: &mut Outputs) {
    let stage_of = |rule| loaded.deck.stages.of(rule);
    let dirty = (0..out.violations.len())
        .filter(|&row| out.violations.severity[row] == Severity::Error)
        .filter_map(|row| stage_of(out.violations.rule[row]))
        .min();
    let Some(dirty) = dirty else {
        return;
    };
    let held = |rule| stage_of(rule).is_some_and(|stage| stage > dirty);
    let mut kept = Violations::default();
    for row in 0..out.violations.len() {
        if !held(out.violations.rule[row]) {
            kept.push(out.violations.get(row));
        }
    }
    out.violations = kept;
    for run in &mut out.runs {
        if held(run.rule) {
            run.outcome = Outcome::Skipped(gpurify_check::report::SkipReason::EarlierStage);
            run.examined = 0;
            run.violations = 0;
        }
    }
}

/// The deck's waivers (`waive <rule> <layer>`): a violation whose marker
/// lies on a shape of a layer that waives its rule, the boundary counting as
/// on it, moves from `out.violations` to `out.waived`, and its rule's
/// [`RuleRun::violations`] drops by one. The waivers are geometry in the
/// layout, the record Calibre Auto-Waivers keeps on "a specific geometry
/// layer" (Siemens' public description), so a waiver drawn in a cell waives
/// at every placement of it: hierarchy-invariant because the layout is
/// flattened with it.
///
/// ponytail: every waived rule's violation tests every shape of its waiver
/// layers; a spatial index if waiver layers grow to thousands of shapes.
fn apply_waivers(loaded: &Loaded, out: &mut Outputs) {
    let waivers = &loaded.deck.waivers;
    if waivers.is_empty() {
        return;
    }
    let store = &loaded.store;
    let covers = |layer: LayerId, at: gpurify_geom::ops::Point| {
        layer.idx() < store.layer_count()
            && store.polys_on_layer(layer).any(|row| {
                let poly = gpurify_geom::PolyId(row);
                let b = store.poly_bbox(poly);
                b.xlo <= at.x
                    && at.x <= b.xhi
                    && b.ylo <= at.y
                    && at.y <= b.yhi
                    && store.poly_contains_point(poly, at)
            })
    };
    let mut kept = Violations::default();
    for row in 0..out.violations.len() {
        let violation = out.violations.get(row);
        let waived = waivers
            .iter()
            .any(|&(rule, layer)| rule == violation.rule && covers(layer, violation.at));
        if !waived {
            kept.push(violation);
            continue;
        }
        if let Some(run) = out.runs.iter_mut().find(|run| run.rule == violation.rule) {
            run.violations = run.violations.saturating_sub(1);
        }
        out.waived.push(violation);
    }
    out.violations = kept;
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

/// Every DRC rule, the deck's custom rules after them; in a staged deck,
/// stage by stage (a custom rule in the last), and once a stage finds an
/// error the later stages' rules are not run but recorded
/// [`SkipReason::EarlierStage`](gpurify_check::report::SkipReason::EarlierStage).
fn run_drc(loaded: &Loaded, extracted: &Extracted, out: &mut Outputs) -> StageStatus {
    let deck = &loaded.deck;
    let custom = |rules: &[gpurify_check::deck::CustomRule],
                  violations: &mut Violations,
                  runs: &mut Vec<RuleRun>| {
        gpurify_check::deck::run_custom(
            rules,
            &loaded.store,
            Some(&extracted.nets),
            loaded.grid,
            &loaded.strings,
            violations,
            runs,
        );
    };
    let stages = deck.stages.name.len();
    if stages == 0 {
        append_stage(out, |violations, runs| {
            deck.drc
                .run_with_nets(&loaded.store, Some(&extracted.nets), violations, runs);
            custom(&deck.custom, violations, runs);
        });
        return StageStatus::Ran;
    }
    let mut rules = deck.drc.clone();
    let mut dirty = false;
    for stage in 0..stages {
        let here = |id| deck.stages.of(id).map(usize::from) == Some(stage);
        rules.rules = (deck.drc.rules.iter())
            .filter(|(id, _)| here(*id))
            .copied()
            .collect();
        let customs: Vec<_> = (deck.custom.iter())
            .filter(|rule| here(rule.id))
            .cloned()
            .collect();
        if dirty {
            let ids =
                (rules.rules.iter().map(|&(id, _)| id)).chain(customs.iter().map(|rule| rule.id));
            for rule in ids {
                out.runs.push(RuleRun {
                    rule,
                    outcome: Outcome::Skipped(gpurify_check::report::SkipReason::EarlierStage),
                    examined: 0,
                    violations: 0,
                });
            }
            continue;
        }
        let before = out.violations.len();
        append_stage(out, |violations, runs| {
            rules.run_with_nets(&loaded.store, Some(&extracted.nets), violations, runs);
            custom(&customs, violations, runs);
        });
        dirty = out.violations.severity[before..].contains(&Severity::Error);
    }
    StageStatus::Ran
}

/// Classify nets, resolve intent, build and solve the supply grid, then run the
/// rules. A supply grid that cannot be built or solved refuses only the rows
/// that read it; `erc::check` refusing the whole stage maps to
/// [`StageStatus::Refused`], and so does design intent on a layout with a net
/// carrying two labels.
fn run_erc(loaded: &Loaded, extracted: &Extracted, out: &mut Outputs) -> StageStatus {
    // Intent finds nets by label, and a net with two labels is two named nets
    // shorted: resolving it by one name would drop the other's supply.
    if let Some(net) = extracted
        .ports
        .shorted_net()
        .filter(|_| loaded.intent.is_some())
    {
        let names: Vec<&str> = extracted
            .ports
            .names_of(net)
            .iter()
            .map(|&name| loaded.strings.resolve(name))
            .collect();
        return StageStatus::Refused(format!(
            "one net carries the labels {}, a short between named nets, so design \
             intent cannot say which of them it is",
            names.join(", ")
        ));
    }

    let grid = loaded.grid;
    let die = design_extent(loaded);
    if die.is_empty() {
        return StageStatus::Skipped(
            "the layout holds no geometry, so no die boundary bounds a density",
        );
    }

    let pins = match antenna_pins(loaded) {
        Ok(pins) => pins,
        Err(why) => return StageStatus::Refused(why),
    };
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
        temperature: sign_off_temperature(loaded),
        antenna_pins: &pins,
    };
    let mut result = Ok(());
    append_stage(out, |violations, runs| {
        result = gpurify_check::erc::check(&loaded.deck.erc, inputs, violations, runs);
    });
    result.map_or_else(
        |error| StageStatus::Refused(error.to_string()),
        |()| StageStatus::Ran,
    )
}

/// Every placed macro pin's LEF antenna data on the deck's layers (ERC-A14,
/// [`MacroPinAntenna`]): per component pin on a DEF net whose `PIN` states
/// any, the store polygon its first shape on a deck conductor was drawn as
/// (the one on that layer with the shape's bounding box), and its values
/// with areas in square database units. Empty for a GDS layout.
///
/// # Errors
///
/// A statement on a layer the deck does not define: the value would
/// otherwise be dropped unseen.
fn antenna_pins(loaded: &Loaded) -> Result<Vec<MacroPinAntenna>, String> {
    use gpurify_ingest::lefdef::{AntennaKind, Origin};
    let Some(design) = &loaded.design else {
        return Ok(Vec::new());
    };
    let flat =
        gpurify_ingest::lefdef::flatten(&design.def, &design.lef).map_err(|why| why.to_string())?;
    #[expect(clippy::cast_precision_loss, reason = "a resolution squared, small")]
    let per_um2 = (loaded.grid.dbu_per_um() * loaded.grid.dbu_per_um()) as f64;
    let mut taken = std::collections::BTreeSet::new();
    // Per pin: its conductor, its shape's bounding box, and its values.
    let mut wanted = Vec::new();
    for flat in &flat {
        let Origin::MacroPin(component, pin) = flat.origin else {
            continue;
        };
        if flat.net.is_none() || taken.contains(&(component, pin)) {
            continue;
        }
        let model = &design.def.components[component as usize].model;
        let Some(cell) = design.lef.macros.iter().find(|m| &m.name == model) else {
            continue;
        };
        let pin_data = &cell.pins[pin as usize];
        let Some(layer) = loaded
            .deck
            .layers
            .id(&loaded.strings, &flat.shape.layer)
            .filter(|l| loaded.deck.connectivity.conductors.contains(l))
        else {
            continue;
        };
        if pin_data.antenna.is_empty() {
            continue;
        }
        let mut values = Vec::with_capacity(pin_data.antenna.len());
        for statement in &pin_data.antenna {
            let on = match &statement.layer {
                None => None,
                Some(name) => Some(loaded.deck.layers.id(&loaded.strings, name).ok_or_else(
                    || {
                        format!(
                            "LEF macro {model} pin {} states antenna data on layer {name}, \
                         which the deck does not define",
                            pin_data.name
                        )
                    },
                )?),
            };
            let ratio = matches!(
                statement.kind,
                AntennaKind::MaxAreaCar | AntennaKind::MaxSideAreaCar | AntennaKind::MaxCutCar
            );
            let value = if ratio {
                statement.value
            } else {
                statement.value * per_um2
            };
            values.push((statement.kind, on, value));
        }
        taken.insert((component, pin));
        wanted.push((layer, flat.shape.bbox(), values));
    }
    // Each pin's polygon, found by sweeping each layer's polygons over the
    // pins sorted by bounding box.
    let mut poly = vec![None; wanted.len()];
    let mut sorted: Vec<usize> = (0..wanted.len()).collect();
    sorted.sort_by_key(|&w| (wanted[w].0, wanted[w].1));
    for run in sorted.chunk_by(|&a, &b| wanted[a].0 == wanted[b].0) {
        let layer = wanted[run[0]].0;
        for row in loaded.store.polys_on_layer(layer) {
            let row = gpurify_geom::PolyId(row);
            let b = loaded.store.poly_bbox(row);
            let key = (b.xlo.raw(), b.ylo.raw(), b.xhi.raw(), b.yhi.raw());
            let from = run.partition_point(|&w| wanted[w].1 < key);
            for &w in run[from..].iter().take_while(|&&w| wanted[w].1 == key) {
                poly[w].get_or_insert(row);
            }
        }
    }
    Ok(wanted
        .into_iter()
        .zip(poly)
        .filter_map(|((_, _, values), poly)| {
            Some(MacroPinAntenna {
                poly: poly?,
                values,
            })
        })
        .collect())
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

    let mut layout = gpurify_check::lvs::graph::from_layout(
        &extracted.nets,
        &extracted.devices,
        &extracted.ports,
        &loaded.strings,
        Some(loaded.grid),
    );
    // The layout-dependent effects the deck's `lvs lde` rows ask for.
    gpurify_check::lvs::add_lde_params(
        &mut layout,
        gpurify_check::Design {
            store: &loaded.store,
            nets: &extracted.nets,
            devices: &extracted.devices,
        },
        (&loaded.deck.lvs.lde, &loaded.deck.layers),
        &loaded.strings,
        loaded.grid,
    );
    append_stage(out, |violations, runs| {
        gpurify_check::lvs::check_layout(
            &layout,
            gpurify_check::Design {
                store: &loaded.store,
                nets: &extracted.nets,
                devices: &extracted.devices,
            },
            &extracted.ports,
            (&loaded.strings, &loaded.deck.lvs),
            violations,
            runs,
        );
        gpurify_check::lvs::check_param_ranges(
            gpurify_check::Design {
                store: &loaded.store,
                nets: &extracted.nets,
                devices: &extracted.devices,
            },
            &loaded.deck.lvs.range,
            &loaded.strings,
            violations,
            runs,
        );
        gpurify_check::lvs::check_device_counts(
            gpurify_check::Design {
                store: &loaded.store,
                nets: &extracted.nets,
                devices: &extracted.devices,
            },
            &loaded.deck.lvs.count,
            &loaded.strings,
            violations,
            runs,
        );
    });

    let verdict = match reference.top() {
        // Guessing which subcircuit was meant is the one thing a comparison must never do.
        None => Verdict::Inconclusive(Inconclusive::AmbiguousTop),
        Some(top) => {
            // `compare_with` reads the deck's topology policy.
            let lvs = gpurify_check::lvs::CompareOptions {
                params: param_names(&loaded.strings),
                ..options.lvs
            };
            // Must-connect nets are one net to compare, though the layout
            // keeps the open, which `check_layout` reported.
            let joined =
                gpurify_check::lvs::join_must_connect(&layout, &loaded.deck.lvs, &loaded.strings);
            let traced = gpurify_check::lvs::compare_traced(
                &joined,
                &gpurify_check::lvs::graph::from_reference(reference, top),
                lvs,
                &loaded.deck.lvs,
            );
            out.lvs_merges = traced.merges;
            // The instances a mismatch left whole and unpaired, named by
            // the flattening's placements (catalog LVS-017).
            if let Verdict::Mismatch(found) = &traced.verdict {
                let instances = gpurify_check::lvs::unpaired_instances(
                    found,
                    &traced.reference_rows,
                    &reference.placements,
                );
                out.lvs_unpaired_instances = instances
                    .iter()
                    .map(|i| {
                        (
                            reference.placements[i.placement as usize].clone(),
                            i.devices,
                        )
                    })
                    .collect();
                gpurify_check::lvs::record_unpaired_instances(
                    &instances,
                    &loaded.strings,
                    &mut out.violations,
                );
            }
            traced.verdict
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

/// The SPICE names of width, length, fingers, multiplier, the source and
/// drain diffusions and the passive values, as both netlists intern them, so
/// sized fingers merge like netgen's. A name no netlist interned is `None`.
pub(crate) fn param_names(strings: &gpurify_ingest::StrTable) -> gpurify_check::lvs::ParamNames {
    let name = |n: &str| strings.get(n);
    gpurify_check::lvs::ParamNames {
        width: name("w"),
        length: name("l"),
        fingers: name("nf"),
        multiplier: name("m"),
        diffusion: [name("as"), name("ad"), name("ps"), name("pd")],
        values: [
            name("r"),
            name("c"),
            name("area"),
            name("perim"),
            name("ae"),
            name("pe"),
        ],
        inductance: name("ind"),
        stress: [name("sa"), name("sb")],
        gates: false,
        relaxed: false,
    }
}

/// Analytical extraction of the whole design; with `quasistatic_nets`, those nets
/// are field-solved and overlaid on it; then the network is reduced to the
/// deck's extraction type. The nominal stack gives [`Outputs::parasitics`],
/// and each of the deck's process corners its own network in
/// [`Outputs::corners`], the same nets solved the same way. Every refusal on
/// the way, a non-reciprocal solve included, is [`StageStatus::Refused`], a
/// corner's naming the corner.
///
/// ponytail: the solve's `CapMatrix`, `InductMatrix` and `Accuracy` are dropped,
/// as `Outputs` has no slot for them; add fields there when a caller needs them.
fn run_pex(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
    out: &mut Outputs,
) -> StageStatus {
    // The names are the user's input, so they are refused before any
    // extraction is attempted.
    let mut selected = Vec::with_capacity(options.quasistatic_nets.len());
    for name in &options.quasistatic_nets {
        // `get`, never `intern`: a name the run never saw is not a net.
        let pieces = loaded
            .strings
            .get(name)
            .map_or(&[][..], |id| extracted.ports.nets_of(id));
        match *pieces {
            [net] => selected.push(net),
            [] => {
                return StageStatus::Refused(format!(
                    "no extracted net is named {name}, so it cannot be field solved"
                ))
            }
            _ => {
                return StageStatus::Refused(format!(
                    "{name} labels {} disconnected nets, an open, so no one net \
                     of that name can be field solved",
                    pieces.len()
                ))
            }
        }
    }
    // A net named twice is one conductor: solved twice, it is a singular
    // system that never converges.
    selected.sort_unstable();
    selected.dedup();
    let network = match pex_network(loaded, extracted, &selected, &loaded.deck.stack) {
        Ok(network) => network,
        Err(refusal) => return StageStatus::Refused(refusal),
    };
    let mut corners = Vec::with_capacity(loaded.deck.corners.len());
    for corner in &loaded.deck.corners {
        let name = loaded.strings.resolve(corner.name).to_owned();
        match pex_network(loaded, extracted, &selected, &corner.stack) {
            Ok(network) => corners.push((name, network)),
            Err(refusal) => return StageStatus::Refused(format!("corner {name}: {refusal}")),
        }
    }
    out.parasitics = Some(network);
    out.corners = corners;
    StageStatus::Ran
}

/// One stack's network: the closed forms over every net, `selected`
/// field-solved over them, reduced to the deck's extraction type; or why it
/// was refused.
fn pex_network(
    loaded: &Loaded,
    extracted: &Extracted,
    selected: &[gpurify_check::topology::NetId],
    stack: &gpurify_ingest::deck::ProcessStack,
) -> Result<ParasiticNetwork, String> {
    let grid = loaded.grid;
    let mut network = ParasiticNetwork::default();
    gpurify_extract::analytical::extract_into(
        &loaded.store,
        &extracted.nets,
        &loaded.deck.connectivity,
        stack,
        grid,
        &mut network,
    )
    .map_err(|why| pex_refusal(loaded, why))?;
    if !selected.is_empty() {
        let mut matrix = gpurify_extract::quasistatic::CapMatrix::default();
        let mut solved = ParasiticNetwork::default();
        let accuracy = gpurify_extract::quasistatic::extract_into(
            &loaded.store,
            &extracted.nets,
            &loaded.deck.connectivity,
            selected,
            stack,
            grid,
            &mut matrix,
            &mut solved,
        )
        .map_err(|why| solve_refusal(loaded, why))?;

        if let Some(refusal) = reciprocity_refusal(&accuracy) {
            return Err(refusal);
        }

        let mut inductance = gpurify_extract::quasistatic::InductMatrix::default();
        gpurify_extract::quasistatic::extract_inductance_into(
            &loaded.store,
            &extracted.nets,
            &loaded.deck.connectivity,
            selected,
            stack,
            grid,
            &mut inductance,
            &mut solved,
        )
        .map_err(|refusal| refusal.to_string())?;

        gpurify_extract::quasistatic::overlay(&mut network, &solved);
    }

    gpurify_extract::device_region::add_into(
        &mut network,
        &extracted.devices,
        &loaded.deck.pex_models.device,
        &loaded.strings,
        grid,
    );
    let tsvs: Vec<_> = (loaded.deck.pex_models.tsv)
        .iter()
        .filter_map(|model| Some((loaded.deck.layers.id(&loaded.strings, &model.layer)?, model)))
        .collect();
    gpurify_extract::tsv::add_into(
        &mut network,
        &loaded.store,
        &extracted.nets,
        &loaded.deck.connectivity,
        &tsvs,
        grid,
    );
    if let Some(model) = &loaded.deck.pex_models.substrate {
        let ports: Vec<LayerId> = (model.ports)
            .iter()
            .filter_map(|name| loaded.deck.layers.id(&loaded.strings, name))
            .collect();
        let profile = gpurify_extract::substrate::Profile {
            // nm and Ω·cm to µm and Ω·µm.
            layers: (model.layers)
                .iter()
                .map(|&(t, rho)| (t / 1000.0, rho * 1e4))
                .collect(),
            grounded: model.grounded,
        };
        gpurify_extract::substrate::add_into(
            &mut network,
            &loaded.store,
            &extracted.nets,
            &profile,
            &ports,
            design_extent(loaded),
            grid,
        )
        .map_err(|why| format!("pex_substrate: {why}"))?;
    }
    gpurify_extract::fill::treat(&mut network, &fill_nets(loaded, extracted))
        .map_err(|why| why.to_string())?;
    gpurify_extract::reduce::reduce(&mut network, loaded.deck.extraction);
    Ok(network)
}

/// Every net drawn only on `pex_fill` layers, with its treatment: the
/// first fill layer it is on, in deck order.
fn fill_nets(
    loaded: &Loaded,
    extracted: &Extracted,
) -> std::collections::BTreeMap<gpurify_check::topology::NetId, gpurify_extract::fill::Treatment> {
    let fill: Vec<(LayerId, gpurify_extract::fill::Treatment)> = (loaded.deck.pex_models.fill)
        .iter()
        .filter_map(|(name, treatment)| {
            Some((loaded.deck.layers.id(&loaded.strings, name)?, *treatment))
        })
        .collect();
    let mut out = std::collections::BTreeMap::new();
    if fill.is_empty() {
        return out;
    }
    for net in 0..extracted.nets.net_count() {
        let net = gpurify_check::topology::NetId(u32::try_from(net).expect("a NetId"));
        let polys = extracted.nets.polys_of(net);
        let treatment = |poly: &gpurify_geom::PolyId| {
            let layer = loaded.store.poly_layer(*poly);
            fill.iter().find(|(on, _)| *on == layer).map(|&(_, t)| t)
        };
        if !polys.is_empty() && polys.iter().all(|p| treatment(p).is_some()) {
            let first = fill
                .iter()
                .find(|(on, _)| polys.iter().any(|p| loaded.store.poly_layer(*p) == *on))
                .map(|&(_, t)| t)
                .expect("every poly is on a fill layer");
            out.insert(net, first);
        }
    }
    out
}

/// A layer as the deck names it; the id for a layer past the deck's table.
pub(crate) fn layer_name(loaded: &Loaded, layer: LayerId) -> String {
    if layer.idx() < loaded.deck.layers.len() {
        loaded
            .strings
            .resolve(loaded.deck.layers.name(layer))
            .to_owned()
    } else {
        format!("{layer:?}")
    }
}

/// Why the closed forms refused, naming the deck layer.
pub(crate) fn pex_refusal(
    loaded: &Loaded,
    why: gpurify_extract::analytical::AnalyticalError,
) -> String {
    format!("layer {}: {why}", layer_name(loaded, why.layer()))
}

/// Why a field solve produced no capacitance, naming the deck layer a mesh
/// refusal is about.
pub(crate) fn solve_refusal(
    loaded: &Loaded,
    why: gpurify_extract::quasistatic::solve::SolveError,
) -> String {
    match why {
        gpurify_extract::quasistatic::solve::SolveError::Mesh(mesh) => match mesh.layer() {
            Some(layer) => format!("layer {}: {mesh}", layer_name(loaded, layer)),
            None => format!("field solve: {mesh}"),
        },
        _ => format!("field solve: {why}"),
    }
}

/// `Some(reason)` when the matrix is not reciprocal within what its solve
/// allows: its own tolerance with a symmetric operator, the discretisation's
/// with dielectric interfaces. A NaN or infinite asymmetry is refused too.
fn reciprocity_refusal(accuracy: &gpurify_extract::quasistatic::Accuracy) -> Option<String> {
    let refused = !accuracy.asymmetry.is_finite() || accuracy.asymmetry > accuracy.reciprocity;
    refused.then(|| {
        format!(
            "the capacitance matrix is not reciprocal: asymmetry {:e} against the {:e} its solve allows, after {} iterations",
            accuracy.asymmetry, accuracy.reciprocity, accuracy.iterations
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
    run_with(inputs, options, &[])
}

/// [`run`], with the decks a binary carries by name: `inputs.deck` naming one
/// of `decks` builds it ([`load_with`](crate::engine::pipeline::load_with)).
///
/// # Errors
///
/// As [`run`].
pub fn run_with(
    inputs: &Inputs,
    options: &RunOptions,
    decks: &[(&str, DeckFn)],
) -> Result<(Loaded, Extracted, Outputs, Summary), EngineError> {
    let loaded = crate::engine::pipeline::load_with(inputs, decks)?;
    let extracted = crate::engine::pipeline::extract(&loaded)?;
    let (outputs, summary) = run_checks(&loaded, &extracted, options)?;
    Ok((loaded, extracted, outputs, summary))
}

/// Why a run produced no report at all. The CLI prints it and exits `1`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
    /// An input file could not be read or parsed, or the deck did not
    /// compile.
    #[error(transparent)]
    Load(#[from] crate::engine::pipeline::LoadError),
    /// Nets, devices or ports could not be extracted.
    #[error(transparent)]
    Extract(#[from] crate::engine::pipeline::ExtractError),
    /// `xor`: the second layout's database unit is not the first's, so their
    /// coordinates do not compare.
    #[error(
        "the layouts are on different grids, {first} and {second} database units per \
         micrometre, so they cannot be compared"
    )]
    GridMismatch {
        /// The first layout's database units per micrometre.
        first: i64,
        /// The second layout's.
        second: i64,
    },
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
            reciprocity: 1e-10,
        }
    }

    /// The three answers that are not "reciprocal", and the one that is. The
    /// non-finite pair is the whole reason this is not a `>` comparison.
    ///
    /// Oracle: `reciprocity_refusal`'s doc: refused when the asymmetry exceeds
    /// the solve's own tolerance (1e-10 here) or is not finite, so 1e-11 and
    /// 0 pass and 1e-9, infinity and NaN are refused.
    #[test]
    fn a_matrix_that_is_not_reciprocal_is_refused_and_a_non_finite_one_too() {
        assert!(reciprocity_refusal(&accuracy(1e-11)).is_none());
        assert!(reciprocity_refusal(&accuracy(0.0)).is_none());
        assert!(reciprocity_refusal(&accuracy(1e-9)).is_some());
        assert!(reciprocity_refusal(&accuracy(f64::INFINITY)).is_some());
        assert!(reciprocity_refusal(&accuracy(f64::NAN)).is_some());
    }
}
