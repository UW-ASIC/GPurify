//! The fixture corpus, read as data and driven through the ordinary pipeline.
//!
//! `tests/fixtures/` came from the tree that was deleted at the start of this
//! rewrite, and it is split in two on purpose. The 161 GDSII files are *data* —
//! real layout, drawn with deliberate defects, and geometry cannot be wrong
//! about itself. `manifest.json` is the old implementation's *output*, and
//! `CLAUDE.md` is explicit that the old tree is not an oracle. So nothing here
//! reads the manifest. It reads `expectations.json`, whose every number was
//! re-derived from the geometry plus the rule's frozen doc comment and only
//! then compared with the old answer.
//!
//! # The oracle
//!
//! **Construct-from-answer, at corpus scale.** Each cell was drawn to carry one
//! stated defect at one stated place; `expectations.json` says what that defect
//! measures and where, derived from the shapes rather than observed from a run.
//!
//! # Why `examined` is asserted on every case
//!
//! 45 of the 94 DRC cases expect zero violations, and in the old suite an empty
//! violation table was also what a rule that never executed produced — the two
//! were indistinguishable, so 45 cases certified nothing. [`RuleRun`] carries
//! `outcome` and `examined`, so this harness asserts *the rule ran and looked at
//! something* alongside the count. That single addition is what converts those
//! 45 into real cases.
//!
//! Nine cases have `examined == 0` for a correct reason — the rule defines its
//! examined population as the pairs it had jurisdiction over (pairs with a wide
//! member, pairs straddling an end of line) and the cell was built so that
//! population is empty. `expectations.json` records their floor as `0` rather
//! than pretending, and the message below says so when it fires.
//!
//! # `tests/fixtures/klayout/drc_oracle.rb`
//!
//! An external-oracle script for KLayout, which is not installed here. Nothing
//! in this file runs it or depends on it.

use gpurify::core::view::{validate_layer_into, ValidatedLayer, ValidityError};
use gpurify::engine::pipeline::{extract_into, load_into, Extracted, Inputs, Loaded};
use gpurify::engine::run::{run_checks, Checks, Outputs, RunOptions};
use gpurify::ingest::layout::UnknownLayers;
use gpurify::pex::Parasitic;
use gpurify::report::{Measurement, Outcome, RuleRun, SkipReason};
use gpurify::units::Grid;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The grid the whole corpus is drawn against: 1 dbu = 1 nm.
///
/// Stated by `expectations.json`'s `grid_dbu_per_um`, and every `at` coordinate
/// in that file is a dbu on it. Loading at any other resolution reinterprets
/// every limit in `params.json`.
const DBU_PER_UM: i64 = 1000;

/// Femtofarads to attofarads. `Parasitic::GroundCap` fixes its prefix at femto
/// and `expectations.json` states capacitance in aF, so the conversion is
/// written once here rather than at each of the eleven comparison sites.
const AF_PER_FF: f64 = 1000.0;

// ---------------------------------------------------------------------------
// The corpus, as it sits on disk.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Corpus {
    pub drc: Domain<GeometryCase>,
    pub erc: Domain<GeometryCase>,
    pub lvs: Domain<LvsCase>,
    pub pex: Domain<PexCase>,
}

#[derive(Debug, Deserialize)]
pub struct Domain<C> {
    pub cases: Vec<C>,
}

/// A DRC or ERC case: one rule, one cell, a count and a set of findings.
///
/// One struct for both domains because the two emit the same shape — a rule
/// fired, on a layer, at a coordinate, measuring something — which is why
/// `report` gives them one table. The only difference is the field naming the
/// rule, and `serde`'s `alias` absorbs it.
#[derive(Debug, Deserialize)]
pub struct GeometryCase {
    pub id: String,
    pub cell: String,
    pub domain: String,
    #[serde(alias = "check")]
    pub rule: String,
    pub expect_violations: usize,
    pub expect_outcome: String,
    pub examined_min: u64,
    pub violations: Vec<ExpectedViolation>,
    /// The only claims derivable for this case. A field absent from it was not
    /// derivable and must not be checked.
    #[serde(rename = "assert")]
    pub asserts: Vec<String>,
    pub strength: String,
    pub dispute: Option<String>,
    pub known_defect: Option<String>,
    pub expect_validity_error: Option<ExpectedValidity>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedViolation {
    pub measured: ExpectedMeasurement,
    /// `[x, y]` in dbu.
    pub at: [i64; 2],
    pub layer: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedMeasurement {
    pub kind: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedValidity {
    pub variant: String,
    pub layer: String,
}

#[derive(Debug, Deserialize)]
pub struct LvsCase {
    pub id: String,
    pub cell: String,
    pub expect_match: bool,
    pub expect_devices: usize,
    pub expect_nets: usize,
    #[serde(rename = "assert")]
    pub asserts: Vec<String>,
    pub blocked_by: Vec<String>,
    pub strength: String,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PexCase {
    pub id: String,
    pub cell: String,
    pub kind: String,
    pub expect_value: Option<f64>,
    pub unit: Option<String>,
    pub tol: f64,
    pub expect_mismatch: bool,
    pub seam: String,
    pub provenance: String,
    #[serde(rename = "assert")]
    pub asserts: Vec<String>,
    pub strength: String,
    pub dispute: Option<String>,
    pub expect_per_net: Option<std::collections::BTreeMap<String, PerNet>>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PerNet {
    pub r_ohm: f64,
    pub ground_cap_af: f64,
}

/// Read `expectations.json`.
///
/// Panics rather than returning an error: a corpus that will not parse is not a
/// test failure to be collected alongside the others, it is the harness having
/// nothing to say.
pub fn load_corpus() -> Corpus {
    let path = fixtures().join("expectations.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{}: {why}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|why| panic!("{}: {why}", path.display()))
}

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// ---------------------------------------------------------------------------
// Driving one case through the pipeline.
// ---------------------------------------------------------------------------

/// One case's inputs, read from disk by the ordinary reader and parser.
///
/// The GDS goes through `ingest::layout::gds` and the deck through
/// `ingest::deck::parse_deck`, because a harness that built a `GeometryStore`
/// itself could not catch a reader that produces the wrong one — which is half
/// of what this corpus is for.
pub struct CaseRun {
    pub loaded: Loaded,
    pub extracted: Extracted,
    pub outputs: Outputs,
}

/// Load, extract and check one fixture cell against `params.json`.
///
/// The layout path is `<domain>/<id>.gds`: the corpus names its files by case
/// id, and several ids share a cell.
///
/// [`UnknownLayers::Drop`] rather than `Reject`, and the difference is visible:
/// `LVS_LVT_*` and `LVS_HVT_*` draw GDSII layers 12 and 13, which `params.json`
/// does not declare at all (finding F6 in `expectations.json`). Rejecting would
/// stop those four cases at load and replace the finding they carry with an I/O
/// error. Dropping is fail-open, so it is a deliberate choice made here, in the
/// harness, and not a default inherited from [`Inputs`].
pub fn run_case(domain: &str, id: &str, checks: Checks) -> Result<CaseRun, String> {
    let inputs = Inputs {
        layout: fixtures().join(domain).join(format!("{id}.gds")),
        deck: fixtures().join("params.json"),
        grid: Some(Grid::new(DBU_PER_UM).expect("a thousand dbu per micrometre is a grid")),
        reference: None,
        intent: None,
        unknown_layers: UnknownLayers::Drop,
    };

    let mut loaded = Loaded::default();
    load_into(&inputs, &mut loaded).map_err(|why| format!("load failed: {why}"))?;

    let mut extracted = Extracted::default();
    extract_into(&loaded, &mut extracted).map_err(|why| format!("extraction failed: {why}"))?;

    let options = RunOptions {
        checks,
        lvs: gpurify::lvs::CompareOptions::default(),
        // Empty, so `run_pex` takes the analytical path. Naming a net here
        // would field-solve it, which is a different extraction and a different
        // set of expected numbers.
        quasistatic_nets: Vec::new(),
        threads: Some(1),
    };

    let mut outputs = Outputs::default();
    run_checks(&loaded, &extracted, &options, &mut outputs)
        .map_err(|why| format!("run failed: {why}"))?;

    Ok(CaseRun { loaded, extracted, outputs })
}

/// The deck rule id a case's `rule`/`check` name refers to.
///
/// `expectations.json` names the rule *kind*; `params.json` names each row with
/// a deck id like `met1.min_width`, and a `RuleRun` reports against that id. The
/// two are not the same string and the mapping is not always one to one — the
/// deck declares two `density` rows and two `min_enclosure` rows — so it is
/// written out rather than inferred.
///
/// `None` means the case names no deck rule at all: `layer_validity` is a claim
/// about polygon validation, not a rule kind in either `KINDS`, and those cases
/// assert a [`ValidityError`] instead.
fn deck_rule_of(case: &GeometryCase) -> Option<&'static str> {
    // The `min_enclosure` split is the one place the case id is load-bearing:
    // `params.json` declares the kind twice, once for met1-over-met2 and once
    // for nwell-over-diff, and both rows run on a `DRC_WE_*` cell. The corpus
    // note on each of those three cases says "select the nwell.diff row".
    if case.id.starts_with("DRC_WE_") {
        return Some("nwell.diff.min_enclosure");
    }
    Some(match case.rule.as_str() {
        "min_width" => "met1.min_width",
        "max_width" => "met1.max_width",
        "min_edge_length" => "met1.min_edge_length",
        "notch" => "met1.notch",
        "min_spacing" => "met1.min_spacing",
        "min_spacing_diff" => "met1.met2.min_spacing",
        "eol_spacing" => "met1.eol_spacing",
        "prl_spacing" => "met1.prl_spacing",
        "corner_to_corner" => "met1.corner_to_corner",
        "wide_dependent_spacing" => "met1.wide_dependent_spacing",
        "min_area" => "met1.min_area",
        "min_enclosed_area" => "met1.min_enclosed_area",
        "cheesing" => "met1.cheesing",
        "min_density" => "met1.min_density",
        "max_density" => "met1.max_density",
        "min_enclosure" => "met1.met2.min_enclosure",
        "asymmetric_enclosure" => "met1.via1.asymmetric_enclosure",
        "min_extension" => "poly.diff.min_extension",
        "overlap" => "met1.met2.overlap",
        "max_distance_to_tap" => "diff.li.max_distance_to_tap",
        "off_grid" => "off_grid",
        "angle" => "angle",
        "redundant_via" => "via1.redundant_via",
        "via_array_spacing" => "via1.via_array_spacing",
        "multi_patterning" => "met1.multi_patterning",
        // The antenna family moved to `erc` wholesale — `drc::ruleset::KINDS`
        // no longer carries it — so these two DRC-named cases are checked
        // against the ERC rows that own them now.
        "antenna" => "poly.met1.antenna",
        "antenna_car" | "antenna_electrical" => "poly.antenna_electrical",
        "em_current_density" => "em_current_density",
        "esd_missing" => "esd_topological",
        "floating_gate" => "floating_gate",
        "floating_well" => "nwell.floating_well",
        "hv_domain_crossing" => "hv_domain",
        "missing_tie" => "diff.li.missing_tie",
        "multiple_drivers" => "multiple_drivers",
        "p2p_resistance" => "p2p_resistance",
        "soft_connection" => "nwell.soft_connection",
        "supply_short" => "supply_short",
        "tie_high_low" => "tie_high_low",
        "unconnected_pin" => "met1.unconnected_pin",
        "layer_validity" => return None,
        other => panic!("case {} names rule {other}, which maps to no deck row", case.id),
    })
}

// ---------------------------------------------------------------------------
// Checking one case.
// ---------------------------------------------------------------------------

/// Every way case `id` disagreed with what the geometry says it must produce.
///
/// A `Vec` rather than an assertion per claim, so one wrong count does not hide
/// the coordinate that is also wrong, and so the rest of the domain still runs.
pub fn check_geometry_case(case: &GeometryCase) -> Vec<String> {
    let mut failed = Vec::new();
    let context = context_of(case);

    // A validity case names no rule: `polygon_validity` is not a kind in either
    // `KINDS`, so the manifest stating it as a violation count is stating
    // something that cannot be counted. What is checkable is the refusal itself.
    let Some(deck_rule) = deck_rule_of(case) else {
        return check_validity_case(case, &context);
    };

    // DRC and ERC both, whichever domain directory the cell sits in: three of
    // the DRC-named cases are antenna cases, and `erc` owns that family now.
    let checks = Checks { drc: true, erc: true, lvs: false, pex: false };
    let run = match run_case(&case.domain, &case.id, checks) {
        Ok(run) => run,
        Err(why) => {
            failed.push(format!(
                "{}: cell {} did not reach the checks at all — {why}{context}",
                case.id, case.cell
            ));
            return failed;
        }
    };

    let Some(rule) = run.loaded.strings.get(deck_rule) else {
        failed.push(format!(
            "{}: the deck never interned a rule named {deck_rule}, so nothing in \
             params.json configures the {} this case is about{context}",
            case.id, case.rule
        ));
        return failed;
    };

    let record = run.outputs.runs.iter().find(|run| run.rule == rule).copied();
    let Some(record) = record else {
        failed.push(format!(
            "{}: rule {deck_rule} recorded no RuleRun on cell {}. A rule that \
             never executed and a rule that found nothing produce the same empty \
             violation table, which is the ambiguity this corpus exists to \
             close{context}",
            case.id, case.cell
        ));
        return failed;
    };

    if case.asserts.iter().any(|claim| claim == "outcome") {
        let expected = parse_outcome(&case.expect_outcome);
        if record.outcome != expected {
            failed.push(format!(
                "{}: rule {deck_rule} on cell {} recorded {:?}; the geometry says \
                 it must record {:?}{context}",
                case.id, case.cell, record.outcome, expected
            ));
        }
    }

    if case.asserts.iter().any(|claim| claim == "examined_min") {
        failed.extend(check_examined(case, deck_rule, record, &context));
    }

    let mut found: Vec<_> = (0..run.outputs.violations.len())
        .map(|row| run.outputs.violations.get(row))
        .filter(|violation| violation.rule == rule)
        .collect();
    // Ascending by report point, the same order `expectations.json` lists its
    // findings in. `Violations::sort_canonical` already orders by `at.y` then
    // `at.x`, so this only re-establishes it after the filter and makes the
    // pairing below positional rather than a search.
    found.sort_by_key(|violation| (violation.at.y.raw(), violation.at.x.raw()));

    if case.asserts.iter().any(|claim| claim == "violation_count")
        && found.len() != case.expect_violations
    {
        failed.push(format!(
            "{}: rule {deck_rule} on cell {} found {} violations; the geometry \
             says {}{}{context}",
            case.id,
            case.cell,
            found.len(),
            case.expect_violations,
            if found.is_empty() {
                " — and an empty table is also what a rule that never looked produces"
            } else {
                ""
            }
        ));
        // The per-violation comparison below is positional, so a count that is
        // already wrong would report the same disagreement several times over.
        return failed;
    }

    let wants_measured = case.asserts.iter().any(|claim| claim == "measured");
    let wants_at = case.asserts.iter().any(|claim| claim == "at");
    let wants_layer = case.asserts.iter().any(|claim| claim == "layer");
    if !(wants_measured || wants_at || wants_layer) {
        return failed;
    }

    let mut expected: Vec<&ExpectedViolation> = case.violations.iter().collect();
    expected.sort_by_key(|violation| (violation.at[1], violation.at[0]));

    for (nth, (want, got)) in expected.iter().zip(found.iter()).enumerate() {
        if wants_at && (got.at.x.raw(), got.at.y.raw()) != (want.at[0], want.at[1]) {
            failed.push(format!(
                "{}: violation {nth} of rule {deck_rule} on cell {} is reported at \
                 ({}, {}) dbu; the geometry puts it at ({}, {}). A rule flagging \
                 the wrong shape passes a count{context}",
                case.id,
                case.cell,
                got.at.x.raw(),
                got.at.y.raw(),
                want.at[0],
                want.at[1]
            ));
        }
        if wants_measured && !measurement_matches(got.measured, &want.measured) {
            failed.push(format!(
                "{}: violation {nth} of rule {deck_rule} on cell {} measures {}; \
                 the geometry measures {} {}{context}",
                case.id, case.cell, got.measured, want.measured.value, want.measured.kind
            ));
        }
        if wants_layer {
            if let Some(name) = want.layer.as_deref() {
                let want_layer = run.loaded.deck.layers.id(&run.loaded.strings, name);
                if want_layer != Some(got.layer) {
                    failed.push(format!(
                        "{}: violation {nth} of rule {deck_rule} on cell {} is \
                         reported on {:?}; the geometry puts it on layer \
                         {name}{context}",
                        case.id, case.cell, got.layer
                    ));
                }
            }
        }
    }

    failed
}

/// The rule ran and looked at something.
///
/// Split out because it is the assertion this whole layer was revived for, and
/// because its failure message has to distinguish three states a bare count
/// cannot: never ran, ran over an empty jurisdiction, ran over the wrong
/// population.
fn check_examined(
    case: &GeometryCase,
    deck_rule: &str,
    record: RuleRun,
    context: &str,
) -> Vec<String> {
    if record.examined >= case.examined_min {
        return Vec::new();
    }
    vec![if case.examined_min == 0 {
        // Unreachable while `examined` is a `u64`, and written anyway: the day
        // the floor stops being zero for a case, this branch is what says the
        // corpus moved rather than the code.
        format!(
            "{}: rule {deck_rule} examined {} on cell {}, below a floor of \
             0{context}",
            case.id, record.examined, case.cell
        )
    } else {
        format!(
            "{}: rule {deck_rule} examined {} shapes on cell {}, and the geometry \
             puts at least {} in its jurisdiction. A clean result from a rule that \
             examined nothing is not a clean design, it is a rule that did not \
             run{context}",
            case.id, record.examined, case.cell, case.examined_min
        )
    }]
}

/// A case whose claim is that the tool refuses the geometry.
///
/// `polygon_validity` is not a rule kind, so there is no count to compare and no
/// `RuleRun` to read. The checkable claim is the one `validate_layer_into`
/// makes: which polygon, and which way it is unrepresentable.
fn check_validity_case(case: &GeometryCase, context: &str) -> Vec<String> {
    let Some(want) = case.expect_validity_error.as_ref() else {
        return vec![format!(
            "{}: names no deck rule and states no expected ValidityError, so there \
             is nothing here to check{context}",
            case.id
        )];
    };

    let inputs = Inputs {
        layout: fixtures().join(&case.domain).join(format!("{}.gds", case.id)),
        deck: fixtures().join("params.json"),
        grid: Some(Grid::new(DBU_PER_UM).expect("a thousand dbu per micrometre is a grid")),
        reference: None,
        intent: None,
        unknown_layers: UnknownLayers::Drop,
    };
    let mut loaded = Loaded::default();
    if let Err(why) = load_into(&inputs, &mut loaded) {
        return vec![format!("{}: cell {} did not load — {why}{context}", case.id, case.cell)];
    }

    let Some(layer) = loaded.deck.layers.id(&loaded.strings, &want.layer) else {
        return vec![format!(
            "{}: params.json declares no layer named {}{context}",
            case.id, want.layer
        )];
    };

    let mut validated = ValidatedLayer::default();
    match validate_layer_into(&loaded.store, layer, &mut validated) {
        Err(error) if validity_variant(error) == want.variant => Vec::new(),
        Err(error) => vec![format!(
            "{}: cell {} refuses as {}; the geometry says it must refuse as {}. \
             Both fail closed, so this is a disagreement about *why* rather than a \
             safety hole{context}",
            case.id,
            case.cell,
            validity_variant(error),
            want.variant
        )],
        Ok(()) => vec![format!(
            "{}: cell {} validated cleanly on layer {}; the geometry is {} and the \
             tool must refuse it rather than check it{context}",
            case.id, case.cell, want.layer, want.variant
        )],
    }
}

fn validity_variant(error: ValidityError) -> &'static str {
    match error {
        ValidityError::Degenerate(_) => "Degenerate",
        ValidityError::SelfIntersecting(_) => "SelfIntersecting",
        ValidityError::OrphanHole(_) => "OrphanHole",
        ValidityError::NotRectilinear(_) => "NotRectilinear",
    }
}

fn parse_outcome(text: &str) -> Outcome {
    match text {
        "Ran" => Outcome::Ran,
        "Refused" => Outcome::Refused,
        "Skipped(NoDesignIntent)" => Outcome::Skipped(SkipReason::NoDesignIntent),
        "Skipped(NotInDeck)" => Outcome::Skipped(SkipReason::NotInDeck),
        "Skipped(EmptyLayer)" => Outcome::Skipped(SkipReason::EmptyLayer),
        other => panic!("expectations.json states an outcome {other} that report has no variant for"),
    }
}

/// A reported measurement against the derived one, dimension included.
///
/// A mismatched dimension is a failure rather than a panic: `Measurement`
/// refuses to compare a resistance with a spacing, and a rule reporting the
/// wrong dimension is exactly the kind of finding this corpus should surface
/// rather than abort on.
fn measurement_matches(got: Measurement, want: &ExpectedMeasurement) -> bool {
    match (got, want.kind.as_str()) {
        (Measurement::Length(value), "Length") => want.value.as_i64() == Some(value.raw()),
        (Measurement::Area(value), "Area") => {
            want.value.as_i64().map(i128::from) == Some(value.raw())
        }
        (Measurement::Count(value), "Count") => want.value.as_u64() == Some(u64::from(value)),
        (Measurement::Ratio(value), "Ratio") => want
            .value
            .as_f64()
            .is_some_and(|expected| (value - expected).abs() <= 1e-9 * expected.abs().max(1.0)),
        _ => false,
    }
}

/// What `expectations.json` already knows about a case that is expected to
/// disagree, appended to every message the case produces.
///
/// A reader of CI output should not have to open the corpus to find out that a
/// failure is a filed defect with a named fix site rather than a surprise.
fn context_of(case: &GeometryCase) -> String {
    let mut context = format!(" [strength: {}", case.strength);
    if let Some(dispute) = &case.dispute {
        context.push_str(&format!(", dispute: {dispute}"));
    }
    if let Some(defect) = &case.known_defect {
        context.push_str(&format!(", known defect: {defect}"));
    }
    context.push(']');
    if let Some(note) = &case.note {
        context.push_str(&format!("\n    derivation: {note}"));
    }
    context
}

// ---------------------------------------------------------------------------
// LVS.
// ---------------------------------------------------------------------------

/// Every way an LVS case's *layout side* disagreed with the geometry.
///
/// `expect_match` is not checked and cannot be: the corpus ships no reference
/// netlist file. The reference netlists exist only inside `manifest.json`, which
/// is the old implementation's record and is not read here, and findings F1–F6
/// in `expectations.json` say the comparison could not reach a verdict even with
/// one — no cell draws a `licon`, no pmos is recognised, and source and drain
/// collapse onto one net.
///
/// What *is* derivable from the geometry alone is how many devices and how many
/// nets the cell extracts to, and those two are where F1, F2 and F3 show
/// themselves. The comparison would only report the same three findings one
/// stage later.
pub fn check_lvs_case(case: &LvsCase) -> Vec<String> {
    let mut failed = Vec::new();
    let blocked = format!(
        " [strength: {}, expect_match: {} — not asserted, see this test's doc \
         comment; blocked by {}]",
        case.strength,
        case.expect_match,
        case.blocked_by.join(", ")
    );

    let checks = Checks { drc: false, erc: false, lvs: false, pex: false };
    let run = match run_case("lvs", &case.id, checks) {
        Ok(run) => run,
        Err(why) => {
            failed.push(format!("{}: cell {} did not extract — {why}{blocked}", case.id, case.cell));
            return failed;
        }
    };

    if case.asserts.iter().any(|claim| claim == "device_count") {
        let got = run.extracted.devices.len();
        if got != case.expect_devices {
            failed.push(format!(
                "{}: cell {} extracts {got} devices; the geometry draws {}{blocked}\n    \
                 derivation: {}",
                case.id,
                case.cell,
                case.expect_devices,
                case.note.as_deref().unwrap_or("(none recorded)")
            ));
        }
    }

    if case.asserts.iter().any(|claim| claim == "net_count") {
        let got = run.extracted.nets.net_count();
        if got != case.expect_nets {
            failed.push(format!(
                "{}: cell {} extracts {got} nets; the geometry draws {}. A net count \
                 above the derived one is conductors that should have been joined and \
                 were not{blocked}",
                case.id, case.cell, case.expect_nets
            ));
        }
    }

    failed
}

// ---------------------------------------------------------------------------
// PEX.
// ---------------------------------------------------------------------------

/// The parasitic totals one cell extracts to, folded by kind.
///
/// `ParasiticNetwork::net_capacitance` sums ground and coupling together and
/// there is nothing for resistance at all (finding F13), so a test asking for
/// "the area capacitance of this cell" folds the public element columns itself.
/// That is what this is.
pub struct Totals {
    pub resistance_ohm: f64,
    pub ground_cap_af: f64,
    pub coupling_cap_af: f64,
}

pub fn totals_of(run: &CaseRun) -> Totals {
    let mut totals = Totals { resistance_ohm: 0.0, ground_cap_af: 0.0, coupling_cap_af: 0.0 };
    let Some(network) = run.outputs.parasitics.as_ref() else {
        return totals;
    };
    for &value in &network.value {
        match value {
            Parasitic::Resistance(ohm) => totals.resistance_ohm += ohm.raw(),
            Parasitic::GroundCap(ff) => totals.ground_cap_af += ff.raw() * AF_PER_FF,
            Parasitic::CouplingCap(ff) => totals.coupling_cap_af += ff.raw() * AF_PER_FF,
            Parasitic::Inductance(_) => {}
        }
    }
    totals
}

/// The measured value for a case's `kind`, or `None` if the kind names
/// something this fold does not produce.
fn value_of(kind: &str, totals: &Totals) -> Option<f64> {
    Some(match kind {
        "resistance" | "resistance_met2" | "via_resistance" => totals.resistance_ohm,
        "area_cap" => totals.ground_cap_af,
        "coupling_cap" | "coupling_cap_met2" | "interlayer_cap" => totals.coupling_cap_af,
        _ => return None,
    })
}

/// Every way a PEX case disagreed with its closed form.
///
/// The three `underivable` coupling cases are not checked here — `ProcessStack`
/// has no lateral coefficient column (F12), so no absolute number is derivable
/// from the deck at all. What is derivable about them is a relation between
/// them, which `check_coupling_laws` states.
pub fn check_pex_case(case: &PexCase) -> Vec<String> {
    let mut failed = Vec::new();
    let context = format!(
        " [strength: {}, seam: {}{}]",
        case.strength,
        case.seam,
        case.dispute.as_ref().map_or(String::new(), |d| format!(", dispute: {d}"))
    );

    if case.provenance == "underivable" {
        // Says so rather than pretending. The claims that *are* derivable about
        // these three are relations, and they are asserted in
        // `check_coupling_laws`.
        return failed;
    }

    let checks = Checks { drc: false, erc: false, lvs: false, pex: true };
    let run = match run_case("pex", &case.id, checks) {
        Ok(run) => run,
        Err(why) => {
            failed.push(format!(
                "{}: cell {} did not extract — {why}{context}",
                case.id, case.cell
            ));
            return failed;
        }
    };
    let totals = totals_of(&run);

    if let Some(per_net) = case.expect_per_net.as_ref() {
        failed.extend(check_per_net(case, &run, per_net, &context));
        return failed;
    }

    let Some(want) = case.expect_value else {
        return failed;
    };
    let Some(got) = value_of(&case.kind, &totals) else {
        failed.push(format!(
            "{}: kind {} names no element this fold produces{context}",
            case.id, case.kind
        ));
        return failed;
    };

    let agrees = (got - want).abs() <= case.tol;
    if case.expect_mismatch && case.asserts.iter().any(|claim| claim == "mismatch") {
        if agrees {
            failed.push(format!(
                "{}: cell {} extracts {got} {}, which is the value a *correct* cell \
                 would give. This fixture is drawn wrong on purpose and the \
                 extraction must not reproduce {want}{context}",
                case.id,
                case.cell,
                case.unit.as_deref().unwrap_or("")
            ));
        } else if got == 0.0 && want != 0.0 {
            // The same fail-open shape `examined > 0` closes on the DRC side.
            // "The extraction did not produce the correct number" is satisfied
            // by an extraction that produced nothing at all, so a negative case
            // over an empty network certifies exactly as much as a clean
            // violation table from a rule that never ran.
            failed.push(format!(
                "{}: cell {} extracts nothing at all, so 'the value must differ from \
                 {want} {}' is met by an absence rather than by a measurement. The \
                 negative case is vacuous until something is extracted{context}",
                case.id,
                case.cell,
                case.unit.as_deref().unwrap_or("")
            ));
        }
    } else if case.asserts.iter().any(|claim| claim == "value") && !agrees {
        failed.push(format!(
            "{}: cell {} extracts {got} {}; the closed form gives {want} (tolerance \
             {}){context}\n    derivation: {}",
            case.id,
            case.cell,
            case.unit.as_deref().unwrap_or(""),
            case.tol,
            case.note.as_deref().unwrap_or("(none recorded)")
        ));
    }

    failed
}

fn check_per_net(
    case: &PexCase,
    run: &CaseRun,
    per_net: &std::collections::BTreeMap<String, PerNet>,
    context: &str,
) -> Vec<String> {
    let mut failed = Vec::new();
    let Some(network) = run.outputs.parasitics.as_ref() else {
        failed.push(format!("{}: cell {} extracted no network at all{context}", case.id, case.cell));
        return failed;
    };

    for (name, want) in per_net {
        let net: u32 = name.parse().expect("a per-net key is a NetId");
        let mut resistance = 0.0;
        let mut ground = 0.0;
        for row in 0..network.value.len() {
            let owner = network.node_net.get(network.from[row].0 as usize).copied();
            if owner.map(|id| id.0) != Some(net) {
                continue;
            }
            match network.value[row] {
                Parasitic::Resistance(ohm) => resistance += ohm.raw(),
                Parasitic::GroundCap(ff) => ground += ff.raw() * AF_PER_FF,
                Parasitic::CouplingCap(_) | Parasitic::Inductance(_) => {}
            }
        }

        let r_agrees = (resistance - want.r_ohm).abs() <= case.tol;
        let c_agrees = (ground - want.ground_cap_af).abs() <= case.tol;
        if case.expect_mismatch {
            if r_agrees && c_agrees {
                failed.push(format!(
                    "{}: net {net} of cell {} extracts {resistance} ohm and {ground} \
                     aF, the values a correct cell gives; this fixture is drawn wrong \
                     on purpose{context}",
                    case.id, case.cell
                ));
            } else if resistance == 0.0 && ground == 0.0 {
                // As above: a negative claim met by an empty network is the
                // fail-open shape, not a result.
                failed.push(format!(
                    "{}: net {net} of cell {} extracts nothing, so 'these values must \
                     differ from {} ohm / {} aF' is met by an absence{context}",
                    case.id, case.cell, want.r_ohm, want.ground_cap_af
                ));
            }
        } else {
            if !r_agrees {
                failed.push(format!(
                    "{}: net {net} of cell {} extracts {resistance} ohm; the closed \
                     form gives {}{context}",
                    case.id, case.cell, want.r_ohm
                ));
            }
            if !c_agrees {
                failed.push(format!(
                    "{}: net {net} of cell {} extracts {ground} aF of ground \
                     capacitance; the closed form gives {}{context}",
                    case.id, case.cell, want.ground_cap_af
                ));
            }
        }
    }

    failed
}

/// The two claims the corpus *can* make about lateral coupling.
///
/// `StackJson` carries no lateral coefficient (F12), so no absolute coupling
/// value is derivable from the deck — but two relations are, and they are exact:
///
///  - **1/S.** `PEX_S100`, `PEX_CC` and `PEX_S400` are the same two bars at
///    100, 200 and 400 nm, so `C·S` is the same number for all three.
///  - **Rotation invariance.** `PEX_VERT` is `PEX_CC` rotated a quarter turn and
///    `PEX_M2C` is it moved to met2 at the same thickness and `k`, so all three
///    must couple identically. The manifest gives `PEX_MET2_COUPLING` 200 aF and
///    `PEX_COUPLING_C` 160, which no physics permits of the same geometry.
pub fn check_coupling_laws() -> Vec<String> {
    let mut failed = Vec::new();
    let coupling = |id: &str| -> f64 {
        run_case("pex", id, Checks { drc: false, erc: false, lvs: false, pex: true })
            .map(|run| totals_of(&run).coupling_cap_af)
            .unwrap_or(f64::NAN)
    };

    let at_100 = coupling("PEX_SPACING_100");
    let at_200 = coupling("PEX_COUPLING_C");
    let at_400 = coupling("PEX_SPACING_400");
    let rotated = coupling("PEX_VERT_COUPLING");

    if !(at_100 > 0.0 && at_200 > 0.0 && at_400 > 0.0) {
        failed.push(format!(
            "the three lateral-coupling cells extract {at_100}, {at_200} and {at_400} \
             aF at 100, 200 and 400 nm. With no coupling extracted there is no 1/S \
             law to check, and every coupling case in this corpus passes on an \
             absence [finding F11: analytical::extract_into emits no coupling at all]"
        ));
        return failed;
    }

    for (near, far, ratio) in [(at_100, at_200, 2.0), (at_200, at_400, 2.0)] {
        let implied = near / far;
        if (implied - ratio).abs() > 0.02 * ratio {
            failed.push(format!(
                "lateral coupling scales as {implied:.4} when the gap doubles; \
                 parallel plates give exactly {ratio}. C·S is the invariant here and \
                 it is the only exact claim the deck permits about coupling"
            ));
        }
    }

    if (at_200 - rotated).abs() > 1e-6 * at_200.max(1.0) {
        failed.push(format!(
            "PEX_CC couples at {at_200} aF and PEX_VERT — the same two bars rotated a \
             quarter turn, same thickness, same k — at {rotated}. Coupling is a \
             function of the gap and the facing area, not of the axis"
        ));
    }

    failed
}

/// Turn a domain's collected failures into one assertion.
///
/// One `#[test]` per domain rather than one per case, so a single wrong count
/// does not stop the other 93 from running, and the panic message names every
/// case that disagreed instead of the first.
pub fn report(domain: &str, cases: usize, failed: &[String]) {
    assert!(
        failed.is_empty(),
        "{} disagreements across {cases} {domain} cases: the geometry says one thing \
         and the run says another.\n\nEvery expectation below was derived from the shapes and \
         the rule's frozen doc comment, never from a run. A disagreement is \
         therefore a finding on one side or the other — read the derivation in the \
         message, and see `known_defects` and `blocking_findings` in \
         `tests/fixtures/expectations.json` for the ones already filed.\n\n{}\n",
        failed.len(),
        failed.join("\n\n")
    );
}
