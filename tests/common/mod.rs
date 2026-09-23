//! Fixtures for the end-to-end suite: a deck and a layout written to disk and
//! run through the ordinary reader, and the fixture corpus read as data and
//! driven through the same pipeline.
//!
//! Corpus: every expected number comes from `expectations.json`, derived from
//! the geometry; `manifest.json` supplies only each case's source cell. Every
//! case asserts `RuleRun::examined` beside the count, since an empty violation
//! table is also what a rule that never ran produces.

mod gen_fixtures;

use gpurify::check::lvs;
use gpurify::check::report::{Measurement, Outcome, RuleRun, SkipReason, Violation, Violations};
use gpurify::engine::pipeline::{extract, load, Extracted, Inputs, LoadError, Loaded};
use gpurify::engine::run::{run_checks, Checks, EngineError, Outputs, RunOptions, Summary};
use gpurify::extract::Parasitic;
use gpurify::geom::view::{validate_layer_into, ValidatedLayer, ValidityError};
use gpurify::geom::{Dbu, Grid};
use gpurify::geom::{GeometryStore, LayerId, PolyId};
use gpurify::ingest::layout::UnknownLayers;
use gpurify::{export, ingest};
use gpurify_ingest::StrId;
use gpurify_testgen::LayoutBuilder;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// Database units per micrometre for every fixture here: a 1 nm grid.
pub const DBU_PER_UM: i64 = 1000;

/// The only layer any fixture draws on, and its GDSII stream pair.
const MET1: (u16, u16) = (10, 0);

/// The rule under test, and its limit in physical nanometres.
const RULE: &str = "narrow_metal";
const LIMIT_NM: i64 = 300;

/// The width the violating fixture draws, in physical nanometres. Below
/// `LIMIT_NM`, so `min_width` must find it; the clean fixture widens this one
/// shape and changes nothing else.
const NARROW_NM: i64 = 200;
const WIDE_NM: i64 = 400;

/// How far the drawn rectangle runs along its other axis. Long enough that the
/// narrow span is unambiguously the measured one.
const RUN_NM: i64 = 2_000;

/// Where the fixture puts the shape's centre, which is where `min_width` is
/// documented to report.
const CENTRE_NM: (i64, i64) = (5_000, 5_000);

/// A prepared run: files on disk, and the parameters the assertions need.
pub struct Run {
    pub dir: PathBuf,
    pub inputs: Inputs,
    pub grid: Grid,
    pub strings: ingest::StrTable,
    pub checks: Checks,

    /// The layer the deliberate violation sits on.
    pub met1: gpurify::geom::LayerId,
    /// Where the violation is, in database units.
    pub violation_at: gpurify::geom::ops::Point,
    /// The width the fixture actually drew.
    pub actual_width: Dbu,
    pub actual_width_nm: i64,
    /// The limit the deck states.
    pub limit: Dbu,
    /// The extreme coordinate used by the domain-edge fixture.
    pub extreme: Dbu,
}

impl Run {
    /// A layout carrying exactly one minimum-width violation, at a coordinate
    /// this fixture chose.
    pub fn with_min_width_violation() -> Self {
        build("narrow", &min_width_deck(LIMIT_NM), NARROW_NM)
    }

    /// The same layout with the narrow shape widened past the limit.
    pub fn clean() -> Self {
        build("clean", &min_width_deck(LIMIT_NM), WIDE_NM)
    }

    /// [`clean`](Self::clean), plus one intent-gated ERC rule the deck actually
    /// asks for, and `erc` selected so it is dispatched.
    pub fn clean_with_gated_rule() -> Self {
        let mut run = build(
            "clean-gated",
            &min_width_and_ir_drop_deck(LIMIT_NM),
            WIDE_NM,
        );
        run.checks.erc = true;
        run
    }

    /// A deck stating a limit that is not a whole number of grid units.
    pub fn with_off_grid_limit() -> Self {
        // A 1 nm grid divides every whole nanometre exactly, so the limit has
        // to be fractional to be off it. Written as `0.5` rather than as a
        // sub-nanometre integer because the schema's `nm` value is a number,
        // not an integer, and a rounding parser would accept this one silently.
        build(
            "off-grid",
            &deck_with_rule(
                r#""kind": "min_width", "layers": ["met1"], "params": { "limit": { "nm": 300.5 } }"#,
            ),
            WIDE_NM,
        )
    }

    /// Geometry at `±i32::MAX`, the widest coordinate a GDSII file can carry.
    pub fn at_domain_edge() -> Self {
        let extreme = i64::from(i32::MAX);
        let mut run = build_with("domain-edge", &min_width_deck(LIMIT_NM), |layout, met1| {
            layout.rect(met1, -extreme, -extreme, extreme, extreme);
        });
        run.extreme = Dbu::new_unchecked(extreme);
        run
    }

    /// Drop the reference netlist, so LVS has nothing to compare against.
    #[must_use]
    pub fn without_reference(mut self) -> Self {
        self.inputs.reference = None;
        self
    }

    /// Drop the design intent, so the six intent-gated ERC rules cannot run.
    #[must_use]
    pub fn without_intent(mut self) -> Self {
        self.inputs.intent = None;
        self
    }

    /// Read every input from disk.
    pub fn load(&self) -> Result<Loaded, LoadError> {
        load(&self.inputs)
    }

    /// Load, extract and check.
    pub fn execute(&self) -> Result<(Outputs, Summary), EngineError> {
        let loaded = self.load()?;
        let extracted = extract(&loaded)?;
        let options = RunOptions {
            checks: self.checks,
            lvs: lvs::CompareOptions::default(),
            quasistatic_nets: Vec::new(),
            quasistatic_inductance: false,
            threads: Some(1),
        };
        run_checks(&loaded, &extracted, &options)
    }

    /// Every rule id the deck declares.
    pub fn deck_rule_ids(&self) -> Vec<StrId> {
        let loaded = self
            .load()
            .expect("a fixture whose rules are being listed loads");
        loaded.deck.rules.spec.iter().map(|spec| spec.id).collect()
    }
}

impl Drop for Run {
    /// Remove the temporary directory.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The deck every well-formed fixture uses: one layer, one `min_width` rule.
fn min_width_deck(limit_nm: i64) -> String {
    deck_with_rule(&format!(
        r#""kind": "min_width", "layers": ["met1"], "params": {{ "limit": {{ "nm": {limit_nm} }} }}"#
    ))
}

/// The `min_width` deck plus one `ir_drop` row — one rule from each domain —
/// and the `pex` stack ERC needs before it will dispatch a rule at all.
fn min_width_and_ir_drop_deck(limit_nm: i64) -> String {
    format!(
        r#"{{
  "layers": {{ "met1": [{}, {}] }},
  "rules": {{
    "{RULE}": {{ "kind": "min_width", "layers": ["met1"], "params": {{ "limit": {{ "nm": {limit_nm} }} }} }},
    "supply_ir_drop": {{ "kind": "ir_drop", "layers": [], "params": {{}} }}
  }},
  "connectivity": {{ "conductors": ["met1"], "intra_layer_touch": true, "vias": [] }},
  "pex": {{ "met1": {{ "thickness_nm": 200, "height_nm": 100,
                       "sheet_res_ohm_sq": 0.08, "area_cap_af_um2": 40,
                       "fringe_cap_af_um": 20, "dielectric_k": 3.9 }} }}
}}"#,
        MET1.0, MET1.1
    )
}

/// The deck with its one rule's body substituted, so a malformed fixture
/// differs from the good one in exactly the bytes under test.
fn deck_with_rule(body: &str) -> String {
    format!(
        r#"{{
  "layers": {{ "met1": [{}, {}] }},
  "rules": {{ "{RULE}": {{ {body} }} }},
  "connectivity": {{ "conductors": ["met1"], "intra_layer_touch": true, "vias": [] }}
}}"#,
        MET1.0, MET1.1
    )
}

/// Build a fixture drawing one rectangle `width_nm` across.
fn build(tag: &str, deck: &str, width_nm: i64) -> Run {
    let half_w = width_nm / 2;
    let half_r = RUN_NM / 2;
    let (cx, cy) = CENTRE_NM;
    let mut run = build_with(tag, deck, |layout, met1| {
        layout.rect(met1, cx - half_w, cy - half_r, cx + half_w, cy + half_r);
    });
    run.actual_width = Dbu::new_unchecked(width_nm);
    run.actual_width_nm = width_nm;
    run
}

/// Write a deck and a layout to a fresh directory, and describe the run over
/// them.
fn build_with(tag: &str, deck_source: &str, draw: impl FnOnce(&mut LayoutBuilder, LayerId)) -> Run {
    let dir = scratch_dir(tag);
    let grid = Grid::new(DBU_PER_UM).expect("a thousand database units per micrometre is a grid");

    let deck_path = dir.join("deck.json");
    std::fs::write(&deck_path, deck_source).expect("the scratch directory is writable");

    // Parsed with a throwaway string table: this one exists only to reach
    // `layers`, and the ids the *run* reports against come from its own load
    // below. A malformed deck has no layer table at all, which is why the
    // layout is written on a default `LayerTable` in that case — those
    // fixtures are read by `load`, which never reaches the layout.
    let mut scratch_strings = ingest::StrTable::default();
    let parsed = ingest::deck::parse_deck(deck_source, grid, &mut scratch_strings).ok();
    let met1 = parsed
        .as_ref()
        .and_then(|deck| deck.layers.id(&scratch_strings, "met1"))
        .unwrap_or(LayerId(0));

    let mut layout = LayoutBuilder::new(1);
    draw(&mut layout, met1);
    let (store, _ids) = layout.finish();

    let layout_path = dir.join("layout.gds");
    if let Some(deck) = &parsed {
        let mut bytes = Vec::new();
        export::gds::write_store(&store, &deck.layers, "TOP", &mut bytes)
            .expect("a fixture emits geometry this writer accepts");
        std::fs::write(&layout_path, &bytes).expect("the scratch directory is writable");
    }

    let inputs = Inputs {
        layout: layout_path,
        deck: deck_path,
        grid: Some(grid),
        // No reference netlist and no design intent exist yet, so `Inputs`
        // starts without them and `without_reference` / `without_intent` are
        // idempotent. See `docs/NEED_TESTING.md`: writing either one needs a
        // deck holding rules of both domains, which cannot currently be parsed.
        reference: None,
        intent: None,
        ..Inputs::default()
    };

    // The run's own string table, from a real load, so a `StrId` in a violation
    // and a `StrId` this fixture resolves are the same id space. A separately
    // interned table would agree by luck and stop agreeing the day the parser
    // interns one extra name.
    let strings = load(&inputs)
        .map(|loaded| loaded.strings)
        .unwrap_or_default();

    Run {
        dir,
        inputs,
        grid,
        strings,
        // ERC is off for the reason the module doc gives: one domain per deck.
        // PEX is off because no fixture declares a process stack, and a
        // parasitic extracted against absent coefficients is a number nothing
        // measured.
        checks: Checks {
            drc: true,
            erc: false,
            lvs: true,
            pex: false,
        },
        met1,
        violation_at: gpurify_testgen::point(CENTRE_NM.0, CENTRE_NM.1),
        actual_width: Dbu::new_unchecked(0),
        actual_width_nm: 0,
        limit: Dbu::new_unchecked(LIMIT_NM),
        extreme: Dbu::new_unchecked(0),
    }
}

/// A directory no other fixture in this process will touch.
fn scratch_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("gpurify-e2e-{}-{tag}-{serial}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory can be created");
    dir
}

/// The single violation in a table that must contain exactly one.
pub fn only_violation(violations: &Violations) -> Violation {
    assert_eq!(
        violations.len(),
        1,
        "this fixture places exactly one violation; finding {} means the \
         fixture is wrong or a second rule fired",
        violations.len()
    );
    violations.get(0)
}

/// The run record for one rule, by name.
pub fn rule_run(runs: &[RuleRun], strings: &ingest::StrTable, name: &str) -> RuleRun {
    let id = strings
        .get(name)
        .unwrap_or_else(|| panic!("no rule named {name} was interned by this run"));
    let mut found = runs.iter().filter(|run| run.rule == id);
    let first = *found
        .next()
        .unwrap_or_else(|| panic!("rule {name} produced no run record"));
    assert!(
        found.next().is_none(),
        "rule {name} produced more than one run record"
    );
    first
}

/// Read a store back from GDS bytes held in memory.
pub fn load_bytes(
    bytes: &[u8],
    deck: &ingest::Deck,
) -> Result<ingest::layout::Layout, ingest::layout::LayoutError> {
    ingest::layout::gds::read(bytes, deck, ingest::layout::UnknownLayers::Reject)
}

/// Two stores hold the same geometry.
pub fn assert_stores_equal(left: &GeometryStore, right: &GeometryStore) {
    assert_eq!(left.layer_count(), right.layer_count(), "layer table width");
    assert_eq!(left.poly_count(), right.poly_count(), "polygon count");

    for layer in 0..left.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("a LayerId is a u16"));
        assert_eq!(
            left.polys_on_layer(layer),
            right.polys_on_layer(layer),
            "layer {layer:?} groups a different row range after the round trip"
        );
    }

    for row in 0..left.poly_count() {
        let poly = PolyId(u32::try_from(row).expect("a PolyId is a u32"));
        assert_eq!(
            left.poly_layer(poly),
            right.poly_layer(poly),
            "polygon {row} changed layer"
        );
        let (lx, ly) = left.poly_verts(poly);
        let (rx, ry) = right.poly_verts(poly);
        assert_eq!(lx, rx, "polygon {row} x column");
        assert_eq!(ly, ry, "polygon {row} y column");
        assert_eq!(
            left.poly_bbox(poly),
            right.poly_bbox(poly),
            "polygon {row} bbox"
        );
    }
}

/// Every coordinate at `±MAX_ABS_DBU` came back unchanged.
pub fn assert_extremes_preserved(store: &GeometryStore, extreme: Dbu) {
    let mut saw_low = false;
    let mut saw_high = false;

    for row in 0..store.poly_count() {
        let poly = PolyId(u32::try_from(row).expect("a PolyId is a u32"));
        let (xs, ys) = store.poly_verts(poly);
        for &coord in xs.iter().chain(ys) {
            assert!(
                coord.raw().unsigned_abs() <= extreme.raw().unsigned_abs(),
                "a coordinate of {} came back outside the ±{} the fixture drew; \
                 the file round trip moved geometry",
                coord.raw(),
                extreme.raw()
            );
            saw_low |= coord.raw() == -extreme.raw();
            saw_high |= coord.raw() == extreme.raw();
        }
    }

    assert!(
        saw_low && saw_high,
        "the fixture drew ±{} and the store came back without one of them; a \
         silently truncated coordinate reads as a smaller, legal shape",
        extreme.raw()
    );
}

/// A measurement as a reader sees it.
pub fn render(measured: Measurement, grid: Grid) -> String {
    match measured {
        Measurement::Length(value) => format!("{}", grid.to_length(value)),
        other => format!("{other}"),
    }
}

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
pub fn load_corpus() -> Corpus {
    let path = fixtures().join("expectations.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|why| panic!("{}: {why}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|why| panic!("{}: {why}", path.display()))
}

pub use gen_fixtures::fixtures;

// ---------------------------------------------------------------------------
// Driving one case through the pipeline.
// ---------------------------------------------------------------------------

/// The inputs for one corpus case: its own GDS, the shared deck, the corpus grid.
fn case_inputs(
    domain: &str,
    id: &str,
    intent: Option<PathBuf>,
    reference: Option<PathBuf>,
) -> Inputs {
    Inputs {
        layout: fixtures().join(domain).join(format!("{id}.gds")),
        deck: fixtures().join("params.json"),
        grid: Some(Grid::new(DBU_PER_UM).expect("a thousand dbu per micrometre is a grid")),
        reference,
        intent,
        unknown_layers: UnknownLayers::Drop,
    }
}

/// One case's inputs, read from disk by the ordinary reader and parser.
pub struct CaseRun {
    pub loaded: Loaded,
    pub extracted: Extracted,
    pub outputs: Outputs,
}

/// Load, extract and check one fixture cell against `params.json`.
pub fn run_case(domain: &str, id: &str, checks: Checks) -> Result<CaseRun, String> {
    run_case_inputs(case_inputs(domain, id, None, None), checks)
}

/// The same case with a reference netlist beside it, so the LVS stage compares
/// rather than skipping.
pub fn run_case_with_reference(
    domain: &str,
    id: &str,
    checks: Checks,
    reference: &str,
) -> Result<CaseRun, String> {
    let path = fixtures().join(reference);
    run_case_inputs(case_inputs(domain, id, None, Some(path)), checks)
}

/// The same case with a design intent file written beside it.
pub fn run_case_with_intent(
    domain: &str,
    id: &str,
    checks: Checks,
    intent_source: &str,
) -> Result<CaseRun, String> {
    let dir = scratch_dir(id);
    let path = dir.join("intent.json");
    std::fs::write(&path, intent_source).expect("the scratch directory is writable");
    let run = run_case_inputs(case_inputs(domain, id, Some(path), None), checks);
    // Best-effort, and silent for the reason `Run::drop` gives: a failure to
    // clean up must not turn a passing test red or mask a failing one.
    let _ = std::fs::remove_dir_all(&dir);
    run
}

/// Load, extract and check whatever inputs were assembled.
fn run_case_inputs(inputs: Inputs, checks: Checks) -> Result<CaseRun, String> {
    let loaded = load(&inputs).map_err(|why| format!("load failed: {why}"))?;
    let extracted = extract(&loaded).map_err(|why| format!("extraction failed: {why}"))?;

    let options = RunOptions {
        checks,
        lvs: gpurify::check::lvs::CompareOptions::default(),
        // Empty, so `run_pex` takes the analytical path. Naming a net here
        // would field-solve it, which is a different extraction and a different
        // set of expected numbers.
        quasistatic_nets: Vec::new(),
        quasistatic_inductance: false,
        threads: Some(1),
    };

    let (outputs, _) =
        run_checks(&loaded, &extracted, &options).map_err(|why| format!("run failed: {why}"))?;

    Ok(CaseRun {
        loaded,
        extracted,
        outputs,
    })
}

/// One case run through the **field solve** rather than the closed form.
pub fn run_case_field_solved(domain: &str, id: &str) -> Result<CaseRun, String> {
    let inputs = case_inputs(domain, id, None, None);

    let loaded = load(&inputs).map_err(|why| format!("load failed: {why}"))?;
    let extracted = extract(&loaded).map_err(|why| format!("extraction failed: {why}"))?;

    // Every net that carries a name. Ascending by `NetId`, so the selection is
    // a function of the geometry and not of the order a table happened to be
    // built in.
    let named: Vec<String> = (0..extracted.nets.net_count())
        .filter_map(|net| {
            extracted.ports.name_of(gpurify::check::topology::NetId(
                u32::try_from(net).expect("a NetId is a u32"),
            ))
        })
        .map(|name| loaded.strings.resolve(name).to_owned())
        .collect();
    if named.is_empty() {
        return Err(format!(
            "cell {id} has no labelled net, so there is nothing to field solve — \
             a field solve selects by name"
        ));
    }

    let options = RunOptions {
        checks: Checks {
            drc: false,
            erc: false,
            lvs: false,
            pex: true,
        },
        lvs: gpurify::check::lvs::CompareOptions::default(),
        quasistatic_nets: named,
        quasistatic_inductance: false,
        threads: Some(1),
    };

    let (outputs, _) =
        run_checks(&loaded, &extracted, &options).map_err(|why| format!("run failed: {why}"))?;

    Ok(CaseRun {
        loaded,
        extracted,
        outputs,
    })
}

/// The coupling capacitance a field solve found in one cell, in attofarads.
pub fn field_solved_coupling_af(domain: &str, id: &str) -> Result<f64, String> {
    let run = run_case_field_solved(domain, id)?;
    let network = run
        .outputs
        .parasitics
        .as_ref()
        .ok_or_else(|| format!("cell {id} field solved to no network at all"))?;
    let mut femtofarads = 0.0;
    for value in &network.value {
        if let gpurify::extract::Parasitic::CouplingCap(coupling) = value {
            femtofarads += coupling.raw();
        }
    }
    Ok(femtofarads * AF_PER_FF)
}

/// The deck rule id a case's `rule`/`check` name refers to.
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
        "density_cmp" => "met1.density_cmp",
        "electromigration" => "met1.electromigration",
        "em_current_density" => "em_current_density",
        "esd_latchup" => "esd_latchup",
        "esd_missing" => "esd_topological",
        "floating_gate" => "floating_gate",
        "floating_well" => "nwell.floating_well",
        "hv_domain_crossing" => "hv_domain",
        "ir_drop" => "ir_drop",
        "missing_tie" => "diff.li.missing_tie",
        "multiple_drivers" => "multiple_drivers",
        "p2p_resistance" => "p2p_resistance",
        "reliability" => "bti",
        "soft_connection" => "nwell.soft_connection",
        "supply_short" => "supply_short",
        "tie_high_low" => "tie_high_low",
        "unconnected_pin" => "met1.unconnected_pin",
        "layer_validity" => return None,
        other => panic!(
            "case {} names rule {other}, which maps to no deck row",
            case.id
        ),
    })
}

// ---------------------------------------------------------------------------
// Checking one case.
// ---------------------------------------------------------------------------

/// Every way case `id` disagreed with what the geometry says it must produce.
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
    let checks = Checks {
        drc: true,
        erc: true,
        lvs: false,
        pex: false,
    };
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

    let record = run
        .outputs
        .runs
        .iter()
        .find(|run| run.rule == rule)
        .copied();
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
fn check_validity_case(case: &GeometryCase, context: &str) -> Vec<String> {
    let Some(want) = case.expect_validity_error.as_ref() else {
        return vec![format!(
            "{}: names no deck rule and states no expected ValidityError, so there \
             is nothing here to check{context}",
            case.id
        )];
    };

    let inputs = case_inputs(&case.domain, &case.id, None, None);
    let loaded = match load(&inputs) {
        Ok(loaded) => loaded,
        Err(why) => {
            return vec![format!(
                "{}: cell {} did not load — {why}{context}",
                case.id, case.cell
            )]
        }
    };

    let Some(layer) = loaded.deck.layers.id(&loaded.strings, &want.layer) else {
        return vec![format!(
            "{}: params.json declares no layer named {}{context}",
            case.id, want.layer
        )];
    };

    let mut validated = ValidatedLayer::default();
    match validate_layer_into(&loaded.store, layer, &mut validated) {
        // `Valid` is the claim that the geometry is representable, which is as
        // checkable as any refusal and is the whole point of a fixture drawn to
        // be legal. Without it a case could only ever assert that the tool says
        // no, and a reader that refused everything would pass every one.
        Ok(()) if want.variant == VALID => Vec::new(),
        Ok(()) => vec![format!(
            "{}: cell {} validated cleanly on layer {}; the geometry is {} and the \
             tool must refuse it rather than check it{context}",
            case.id, case.cell, want.layer, want.variant
        )],
        Err(error) if want.variant == VALID => vec![format!(
            "{}: cell {} refuses as {} on layer {}; the geometry is representable \
             and the tool must check it rather than refuse it{context}",
            case.id,
            case.cell,
            validity_variant(error),
            want.layer
        )],
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
    }
}

/// The `expect_validity_error.variant` that claims a layer validates.
const VALID: &str = "Valid";

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
        other => {
            panic!("expectations.json states an outcome {other} that report has no variant for")
        }
    }
}

/// A reported measurement against the derived one, dimension included.
fn measurement_matches(got: Measurement, want: &ExpectedMeasurement) -> bool {
    /// One relative tolerance for every floating-point dimension.
    fn near(value: f64, want: &ExpectedMeasurement) -> bool {
        want.value
            .as_f64()
            .is_some_and(|expected| (value - expected).abs() <= 1e-9 * expected.abs().max(1.0))
    }

    match (got, want.kind.as_str()) {
        (Measurement::Length(value), "Length") => want.value.as_i64() == Some(value.raw()),
        (Measurement::Area(value), "Area") => {
            want.value.as_i64().map(i128::from) == Some(value.raw())
        }
        (Measurement::Count(value), "Count") => want.value.as_u64() == Some(u64::from(value)),
        (Measurement::Ratio(value), "Ratio") => near(value, want),
        // Millivolts, microamps and ohms — the prefix is the one the
        // `Measurement` variant carries, so `expectations.json` states the
        // number in the unit the report prints.
        (Measurement::Voltage(value), "Voltage") => near(value.raw(), want),
        (Measurement::Current(value), "Current") => near(value.raw(), want),
        (Measurement::Resistance(value), "Resistance") => near(value.raw(), want),
        _ => false,
    }
}

/// What `expectations.json` already knows about a case that is expected to
/// disagree, appended to every message the case produces.
fn context_of(case: &GeometryCase) -> String {
    use std::fmt::Write as _;
    let mut context = format!(" [strength: {}", case.strength);
    if let Some(dispute) = &case.dispute {
        let _ = write!(context, ", dispute: {dispute}");
    }
    if let Some(defect) = &case.known_defect {
        let _ = write!(context, ", known defect: {defect}");
    }
    context.push(']');
    if let Some(note) = &case.note {
        let _ = write!(context, "\n    derivation: {note}");
    }
    context
}

// ---------------------------------------------------------------------------
// LVS.
// ---------------------------------------------------------------------------

/// Every way an LVS case's *layout side* disagreed with the geometry.
pub fn check_lvs_case(case: &LvsCase) -> Vec<String> {
    let mut failed = Vec::new();
    let blocked = format!(
        " [strength: {}, expect_match: {} — not asserted, see this test's doc \
         comment; blocked by {}]",
        case.strength,
        case.expect_match,
        case.blocked_by.join(", ")
    );

    let checks = Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: false,
    };
    let run = match run_case("lvs", &case.id, checks) {
        Ok(run) => run,
        Err(why) => {
            failed.push(format!(
                "{}: cell {} did not extract — {why}{blocked}",
                case.id, case.cell
            ));
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
pub struct Totals {
    pub resistance_ohm: f64,
    pub ground_cap_af: f64,
    pub coupling_cap_af: f64,
}

/// `only: Some(layer)` folds the elements that leave a node on that layer and
/// nothing else.
pub fn totals_of(run: &CaseRun, only: Option<gpurify::geom::LayerId>) -> Totals {
    let mut totals = Totals {
        resistance_ohm: 0.0,
        ground_cap_af: 0.0,
        coupling_cap_af: 0.0,
    };
    let Some(network) = run.outputs.parasitics.as_ref() else {
        return totals;
    };
    for (row, &value) in network.value.iter().enumerate() {
        // The element's layer is its near node's. A coupling capacitance runs
        // between two layers and is attributed to the lower net's, which is the
        // side `analytical` emits it from.
        let layer = network.node_layer[network.from[row].0 as usize];
        if only.is_some_and(|want| want != layer) {
            continue;
        }
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
        "resistance" | "resistance_met1" | "resistance_met2" | "via_resistance" => {
            totals.resistance_ohm
        }
        "area_cap" => totals.ground_cap_af,
        "coupling_cap" | "coupling_cap_met2" | "interlayer_cap" => totals.coupling_cap_af,
        _ => return None,
    })
}

/// Every way a PEX case disagreed with its closed form.
pub fn check_pex_case(case: &PexCase) -> Vec<String> {
    let mut failed = Vec::new();
    let context = format!(
        " [strength: {}, seam: {}{}]",
        case.strength,
        case.seam,
        case.dispute
            .as_ref()
            .map_or(String::new(), |d| format!(", dispute: {d}"))
    );

    if case.provenance == "underivable" {
        // Says so rather than pretending. The claims that *are* derivable about
        // these three are relations, and they are asserted in
        // `check_coupling_laws`.
        return failed;
    }

    let checks = Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: true,
    };
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
    // A kind ending in a conductor name scopes the fold to that conductor;
    // every other kind is the whole cell. `PEX_DIFF` is met1 *and* met2 in one
    // cell and its two cases derive 1.0 ohm and 0.8 ohm separately, so a
    // whole-cell fold answers 1.8 to both and agrees with neither — which is a
    // question the harness asked wrong, not an extraction defect.
    //
    // Resolved through the run's own `LayerTable`, so the corpus does not encode
    // the deck's layer ordering a second time.
    let scope = match case.kind.rsplit_once('_') {
        Some((_, conductor @ ("met1" | "met2"))) => {
            match run.loaded.deck.layers.id(&run.loaded.strings, conductor) {
                Some(layer) => Some(layer),
                None => {
                    failed.push(format!(
                        "{}: kind {} names {conductor} and the deck defines no such \
                         layer{context}",
                        case.id, case.kind
                    ));
                    return failed;
                }
            }
        }
        _ => None,
    };
    let totals = totals_of(&run, scope);

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
        failed.push(format!(
            "{}: cell {} extracted no network at all{context}",
            case.id, case.cell
        ));
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
pub fn check_coupling_laws() -> Vec<String> {
    let mut failed = Vec::new();
    let coupling = |id: &str| -> f64 {
        run_case(
            "pex",
            id,
            Checks {
                drc: false,
                erc: false,
                lvs: false,
                pex: true,
            },
        )
        .map_or(f64::NAN, |run| totals_of(&run, None).coupling_cap_af)
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
pub fn report_domain(domain: &str, cases: usize, failed: &[String]) {
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
