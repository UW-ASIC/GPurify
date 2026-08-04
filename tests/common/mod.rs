//! Fixtures for the end-to-end suite: a deck on disk, a layout on disk, and a
//! run over both.
//!
//! Everything here builds *files*, not in-memory structures. That is the whole
//! point of this suite — a per-crate test hands `topology` a `GeometryStore` it
//! built itself, so it can never catch a reader that produces the wrong store.
//! These tests start where a user starts.
//!
//! The deck is written as JSON against the schema documented on
//! `ingest::deck::parse_deck`, so this suite also pins that schema: if the
//! parser and the documentation disagree, these fail.
//!
//! # One domain per deck, except where a fixture needs both
//!
//! Most decks below hold DRC rules only and [`Run::checks`] leaves `erc` off,
//! because one rule is what makes a malformed fixture differ from the good one
//! in exactly the bytes under test.
//!
//! That used to be forced rather than chosen: `drc::RuleSet::from_deck` and
//! `erc::RuleSet::from_deck` both read the one `RuleTable` and each rejected the
//! other's rows as an unknown kind, so a deck holding both could not be run at
//! all. That is now fixed — each domain skips kinds outside its own `KINDS`, and
//! `engine::run::reject_unknown_rule_kinds` refuses a kind in neither, so the
//! fail-closed refusal moved up rather than disappearing.
//! [`Run::clean_with_gated_rule`] is the one fixture that exercises both.

use gpurify::core::{GeometryStore, LayerId, PolyId};
use gpurify::engine::pipeline::{extract_into, load_into, Extracted, Inputs, LoadError, Loaded};
use gpurify::engine::run::{run_checks, Checks, EngineError, Outputs, RunOptions, Summary};
use gpurify::report::{Measurement, RuleRun, Violation, Violations};
use gpurify::units::{Dbu, Grid};
use gpurify::{export, ingest, lvs};
use gpurify_ingest::StrId;
use gpurify_testgen::LayoutBuilder;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// Database units per micrometre for every fixture here: a 1 nm grid.
///
/// Stated once because half the assertions convert against it, and a second
/// copy would eventually disagree with this one.
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
    pub met1: gpurify::core::LayerId,
    /// Where the violation is, in database units.
    pub violation_at: gpurify::core::ops::Point,
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
    ///
    /// One violation, not several: an assertion that has to pick a row out of a
    /// list is an assertion about ordering as well as about the rule, and those
    /// deserve separate tests.
    pub fn with_min_width_violation() -> Self {
        build("narrow", &min_width_deck(LIMIT_NM), NARROW_NM)
    }

    /// The same layout with the narrow shape widened past the limit.
    ///
    /// Derived from the violating fixture rather than written independently, so
    /// the two differ in exactly one dimension of one shape and a failure
    /// cannot be blamed on anything else.
    pub fn clean() -> Self {
        build("clean", &min_width_deck(LIMIT_NM), WIDE_NM)
    }

    /// [`clean`](Self::clean), plus one intent-gated ERC rule the deck actually
    /// asks for, and `erc` selected so it is dispatched.
    ///
    /// Pair with [`without_intent`](Self::without_intent). A rule the deck never
    /// named is never dispatched and records no [`RuleRun`], which reads exactly
    /// like a rule that ran clean — so a fixture asserting a rule was *skipped*
    /// has to configure one first.
    ///
    /// `ir_drop` is the cheapest of the intent-gated ERC rules to state: zero
    /// layers, no parameters (`erc::ruleset` line 619). Nothing about the skip
    /// path is specific to it.
    pub fn clean_with_gated_rule() -> Self {
        let mut run = build("clean-gated", &min_width_and_ir_drop_deck(LIMIT_NM), WIDE_NM);
        run.checks.erc = true;
        run
    }


    /// A deck naming a rule kind that is in neither `drc::ruleset::KINDS` nor
    /// `erc::ruleset::KINDS`.
    pub fn with_unknown_rule_kind() -> Self {
        // `parse_deck` interns the kind verbatim and does not know the
        // vocabulary, so this must be refused where the vocabulary lives.
        build("unknown-kind", &deck_with_rule(r#""kind": "min_widht", "layers": ["met1"], "params": { "limit": { "nm": 300 } }"#), WIDE_NM)
    }

    /// A deck stating a limit that is not a whole number of grid units.
    pub fn with_off_grid_limit() -> Self {
        // A 1 nm grid divides every whole nanometre exactly, so the limit has
        // to be fractional to be off it. Written as `0.5` rather than as a
        // sub-nanometre integer because the schema's `nm` value is a number,
        // not an integer, and a rounding parser would accept this one silently.
        build("off-grid", &deck_with_rule(r#""kind": "min_width", "layers": ["met1"], "params": { "limit": { "nm": 300.5 } }"#), WIDE_NM)
    }

    /// Geometry at `±MAX_ABS_DBU`, the edge of the representable domain.
    ///
    /// Except that it is not `MAX_ABS_DBU`, and the difference is the test.
    /// GDSII holds a coordinate in a signed 32-bit field, and
    /// `export::gds::write_store` refuses anything wider rather than truncating
    /// it — so the edge reachable *through a file* is `i32::MAX`, not `2^40`.
    /// Writing this fixture at `MAX_ABS_DBU` would assert on geometry no GDSII
    /// file can carry, which is a claim about the format rather than about this
    /// pipeline.
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

    #[must_use]
    pub fn selecting(mut self, checks: Checks) -> Self {
        self.checks = checks;
        self
    }

    /// Read every input from disk. The first half of the pipeline.
    pub fn load(&self) -> Result<Loaded, LoadError> {
        let mut loaded = Loaded::default();
        load_into(&self.inputs, &mut loaded)?;
        Ok(loaded)
    }

    /// Load, extract and check. The whole pipeline, at one thread.
    pub fn execute(&self) -> Result<Outputs, EngineError> {
        self.execute_with_threads(1)
    }

    /// The whole pipeline at a stated thread count.
    ///
    /// The count affects speed only. If it affects output, that is the bug the
    /// determinism gate exists to find, so it is a parameter here rather than a
    /// global.
    pub fn execute_with_threads(&self, threads: usize) -> Result<Outputs, EngineError> {
        let loaded = self.load()?;
        let mut extracted = Extracted::default();
        extract_into(&loaded, &mut extracted)?;

        let mut outputs = Outputs::default();
        run_checks(&loaded, &extracted, &self.options(threads), &mut outputs)?;
        Ok(outputs)
    }

    /// The summary of a completed run.
    ///
    /// Re-runs the pipeline rather than reading `outputs`. The four
    /// `StageStatus` fields are not in `Outputs` at all — `run_checks` returns
    /// them and `execute` drops them — so there is nothing here to reconstruct
    /// them from, and inventing a status is exactly the false-clean this suite
    /// is written against. Re-running is sound *because* of the gate one test
    /// up: the pipeline is deterministic, so the second run's summary is the
    /// first's.
    pub fn summary(&self, outputs: &Outputs) -> Summary {
        let loaded = self.load().expect("the fixture loaded once already");
        let mut extracted = Extracted::default();
        extract_into(&loaded, &mut extracted).expect("the fixture extracted once already");

        let mut again = Outputs::default();
        let summary = run_checks(&loaded, &extracted, &self.options(1), &mut again)
            .expect("the fixture ran once already");
        assert_eq!(
            again.violations.len(),
            outputs.violations.len(),
            "the re-run this summary comes from disagrees with the run it is \
             being asked about; the pipeline is not deterministic and every \
             assertion below it is meaningless"
        );
        summary
    }

    fn options(&self, threads: usize) -> RunOptions {
        RunOptions {
            checks: self.checks,
            lvs: lvs::CompareOptions::default(),
            quasistatic_nets: Vec::new(),
            threads: Some(threads),
        }
    }

    /// Serialise a run's outputs the way the CLI's `--format json` would.
    ///
    /// The header carries a `None` timestamp, so every byte of the result is a
    /// function of the inputs. That is what makes byte-comparison meaningful:
    /// with a real timestamp the comparison would be trivially false and the
    /// gate would have to be weakened to compensate.
    pub fn serialise(&self, outputs: &Outputs, out: &mut String) -> Result<(), export::WriteError> {
        let header = export::Header {
            tool_version: "test",
            deck_path: "deck.json".to_owned(),
            layout_path: "layout.gds".to_owned(),
            timestamp: None,
        };
        export::json::write_report(
            &export::json::Report {
                header: &header,
                violations: &outputs.violations,
                runs: &outputs.runs,
                strings: &self.strings,
                grid: self.grid,
            },
            out,
        )
    }

    /// Every rule id the deck declares.
    pub fn deck_rule_ids(&self) -> Vec<StrId> {
        let loaded = self.load().expect("a fixture whose rules are being listed loads");
        loaded.deck.rules.spec.iter().map(|spec| spec.id).collect()
    }
}

impl Drop for Run {
    /// Remove the temporary directory.
    ///
    /// Best-effort and deliberately silent: a failure to clean up must not turn
    /// a passing test red, and must not mask the real failure of a failing one.
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
///
/// Kept separate from [`deck_with_rule`] so the single-rule invariant every other
/// fixture relies on is untouched: only this one pays for the extra rows.
///
/// The `pex` section is not decoration. Without a sheet resistance for `met1`,
/// `erc::power::extract_nets_into` refuses with "layer LayerId(0) carries current
/// but the process stack gives it no sheet resistance", `run_erc` returns
/// `StageStatus::Refused`, and **no rule records a `RuleRun` at all** — so a
/// fixture meant to show rules being *skipped* shows nothing being skipped. The
/// numbers below are ordinary metal-1 values; nothing asserts on them, they only
/// have to let the stage start.
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
///
/// The deck is parsed here before the layout is written, because the GDSII
/// writer needs the deck's `LayerTable` to turn a `LayerId` back into a stream
/// pair — the fixture cannot emit a file the run could not read back.
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
    let mut loaded = Loaded::default();
    let strings = if load_into(&inputs, &mut loaded).is_ok() {
        loaded.strings
    } else {
        ingest::StrTable::default()
    };

    Run {
        dir,
        inputs,
        grid,
        strings,
        // ERC is off for the reason the module doc gives: one domain per deck.
        // PEX is off because no fixture declares a process stack, and a
        // parasitic extracted against absent coefficients is a number nothing
        // measured.
        checks: Checks { drc: true, erc: false, lvs: true, pex: false },
        met1,
        violation_at: gpurify_testgen::point(CENTRE_NM.0, CENTRE_NM.1),
        actual_width: Dbu::new_unchecked(0),
        actual_width_nm: 0,
        limit: Dbu::new_unchecked(LIMIT_NM),
        extreme: Dbu::new_unchecked(0),
    }
}

/// A directory no other fixture in this process will touch.
///
/// Tests run concurrently in one process, so the process id alone is not
/// enough — two fixtures built at once would write each other's deck.
fn scratch_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "gpurify-e2e-{}-{tag}-{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory can be created");
    dir
}

/// The single violation in a table that must contain exactly one.
///
/// Asserting the count here rather than in each test means a fixture that
/// silently produces two violations fails with "expected 1, found 2" instead of
/// with a confusing mismatch on whichever row happened to sort first.
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
pub fn load_bytes(bytes: &[u8], deck: &ingest::Deck) -> Result<ingest::layout::Layout, ingest::layout::LayoutError> {
    ingest::layout::gds::read(bytes, deck, ingest::layout::UnknownLayers::Reject)
}

/// Two stores hold the same geometry.
///
/// Compared column by column rather than with `assert_eq!` because
/// `GeometryStore` has no `PartialEq` — recorded in `docs/SIGNATURE_DEFECTS.md`.
/// Compares layer grouping too, since the round trip has to preserve the CSR
/// layout invariant and not merely the coordinates.
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
        assert_eq!(left.poly_bbox(poly), right.poly_bbox(poly), "polygon {row} bbox");
    }
}

/// Every coordinate at `±MAX_ABS_DBU` came back unchanged.
///
/// Two halves, and the second is the one that catches a truncation: the extreme
/// has to be *present*, and nothing may be outside it. A reader that wrapped
/// `i32::MAX` to a negative would satisfy neither.
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
///
/// The same conversion the text report applies, and deliberately not a second
/// spelling of it: a length is physical against the run's grid, and everything
/// else prints its own labelled unit because `units` has no `Dbu`-area-to-
/// physical conversion to apply.
pub fn render(measured: Measurement, grid: Grid) -> String {
    match measured {
        Measurement::Length(value) => format!("{}", grid.to_length(value)),
        other => format!("{other}"),
    }
}
