//! The rule set: every kind's table, the deck builder, and the dispatcher.
//!
//! This is the file the dispatcher pattern is *for*. A deck's rules arrive as a
//! flat [`RuleTable`] of [`RuleSpec`] rows whose kind is an interned string;
//! [`RuleSet::from_deck`] matches that string once per rule and files the row
//! into the table for its kind. After that the kind is gone — it is encoded in
//! *which table the row is in*, and the transform over that table needs no tag,
//! no vtable and no match.
//!
//! Everything downstream is therefore uniform: [`RuleSet::run`] is a fixed list
//! of calls, one per table, each a straight-line loop over rows that all take
//! the same parameters. The cost of a rule kind is paid once at load; the run
//! pays nothing for kinds the deck does not use, because their tables are
//! empty and their transforms are never called.
//!
//! [`RuleTable`]: gpurify_ingest::deck::RuleTable
//! [`RuleSpec`]: gpurify_ingest::deck::RuleSpec

use crate::rules::antenna::{AntennaCarTable, AntennaTable};
use crate::rules::area::{CheesingTable, DensityTable, MinAreaTable, MinEnclosedAreaTable};
use crate::rules::grid::{AngleTable, OffGridTable};
use crate::rules::overlay::{
    AsymmetricEnclosureTable, MaxDistanceToTapTable, MinEnclosureTable, MinExtensionTable,
    OverlapTable,
};
use crate::rules::patterning::MultiPatterningTable;
use crate::rules::spacing::{
    CornerToCornerTable, EolSpacingTable, MinSpacingDiffTable, MinSpacingTable, PrlSpacingTable,
    WideDependentSpacingTable,
};
use crate::rules::via::{RedundantViaTable, ViaArraySpacingTable};
use crate::rules::width::{MaxWidthTable, MinEdgeLengthTable, MinWidthTable, NotchTable};
use crate::{Design, DrcError, Scratch};
use gpurify_ingest::deck::Deck;
use gpurify_ingest::StrTable;
use gpurify_report::{RuleRun, Violations};

/// Every DRC rule the deck configures, filed by kind.
///
/// **Five questions.** In: a [`Deck`] and the run's [`StrTable`]. Out: itself,
/// twenty-six `SoA` tables. How many: exactly one per run. Access pattern: each
/// table is read once, front to back, by its own transform — so the twenty-six
/// fields are never read together and there is nothing to gain from packing
/// them. Lifetime: the whole run, built once, never mutated. Parallelisable:
/// the tables are independent of one another; see [`Scratch`]'s ponytail note
/// for why the dispatcher does not yet exploit that.
///
/// Twenty-six distinct field types rather than one `Vec<Rule>` with a kind tag.
/// That is the whole architecture in one struct: passing a [`MinWidthTable`] to
/// [`check_notch`](crate::rules::width::check_notch) does not compile, so the
/// dispatcher below cannot be wired up wrong in a way that produces plausible
/// output. A tag-and-match design would compile and would report the wrong
/// rule id on every violation.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub min_width: MinWidthTable,
    pub max_width: MaxWidthTable,
    pub min_edge_length: MinEdgeLengthTable,
    pub notch: NotchTable,

    pub min_spacing: MinSpacingTable,
    pub min_spacing_diff: MinSpacingDiffTable,
    pub eol_spacing: EolSpacingTable,
    pub prl_spacing: PrlSpacingTable,
    pub corner_to_corner: CornerToCornerTable,
    pub wide_dependent_spacing: WideDependentSpacingTable,

    pub min_area: MinAreaTable,
    pub min_enclosed_area: MinEnclosedAreaTable,
    pub cheesing: CheesingTable,
    pub density: DensityTable,

    pub min_enclosure: MinEnclosureTable,
    pub asymmetric_enclosure: AsymmetricEnclosureTable,
    pub min_extension: MinExtensionTable,
    pub overlap: OverlapTable,
    pub max_distance_to_tap: MaxDistanceToTapTable,

    pub off_grid: OffGridTable,
    pub angle: AngleTable,

    pub antenna: AntennaTable,
    pub antenna_car: AntennaCarTable,

    pub redundant_via: RedundantViaTable,
    pub via_array_spacing: ViaArraySpacingTable,

    pub multi_patterning: MultiPatterningTable,
}

impl RuleSet {
    /// File every rule in the deck into the table for its kind.
    ///
    /// **Transform, dispatcher — and the only place in this crate that branches
    /// on a rule kind.** One match per
    /// [`RuleSpec`](gpurify_ingest::deck::RuleSpec), at load, over an interned
    /// [`StrId`](gpurify_ingest::StrId): the kind names are looked up in
    /// `strings` once each up front, so the match is on `u32` equality and not
    /// on text.
    ///
    /// `strings` is borrowed, not mutated. A kind or parameter name the table
    /// does not already contain cannot name anything the deck defined, so
    /// `StrTable::get` is the right call and interning here would grow the
    /// table with names that are by definition unused.
    ///
    /// # Fail closed
    ///
    /// Rejects rather than skips, in every case: an unknown kind, a missing or
    /// mistyped parameter, the wrong number of layers, a non-positive limit, a
    /// duplicate rule id. A deck with one rule this crate silently ignored
    /// produces a report that looks complete and is not, which is the failure
    /// mode the whole tree is built against. Partial construction is not
    /// offered, because a partially-loaded deck has no meaningful verdict.
    ///
    /// The layer resolution and grid conversion are already done — `ingest`
    /// produced [`ParamValue::Length`](gpurify_ingest::deck::ParamValue::Length)
    /// in [`Dbu`](gpurify_units::Dbu) against the run's grid, or refused the
    /// deck. Nothing here parses text or touches a grid.
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, DrcError> {
        todo!()
    }

    /// How many rule rows the set holds, across every table.
    ///
    /// The number [`RuleSet::run`] will produce [`RuleRun`] rows for, so a
    /// caller can assert the run accounted for every rule it loaded. That
    /// equality is the crate's top-level invariant and this is what makes it
    /// checkable without reaching into twenty-six fields.
    pub fn rule_count(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    /// Run every configured rule.
    ///
    /// **Transform, dispatcher.** One call per non-empty table, in the fixed
    /// order the fields are declared in. `out` and `runs` are cleared here —
    /// the one place they are, since the transforms themselves append — and
    /// `runs` gains exactly [`RuleSet::rule_count`] rows.
    ///
    /// # Ordering
    ///
    /// The dispatch order is fixed but is *not* the output order. Violations
    /// are canonically sorted afterwards by
    /// [`Violations::sort_canonical`](gpurify_report::Violations::sort_canonical),
    /// which is what makes the report independent of this order and therefore
    /// of any future decision to run the tables in parallel. `runs` is left in
    /// dispatch order, which is deterministic for a given [`RuleSet`] because
    /// the tables are built in deck order.
    ///
    /// # Infallible on purpose
    ///
    /// There is no `Result`. Geometry a rule cannot handle is that rule's
    /// [`Outcome::Refused`](gpurify_report::Outcome::Refused) row, not the
    /// run's failure: one unrepresentable polygon on one layer must not
    /// suppress the verdict of the other twenty-five rules. Everything that
    /// *could* fail the whole run already failed in
    /// [`RuleSet::from_deck`].
    pub fn run(
        &self,
        design: Design<'_>,
        scratch: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        todo!()
    }
}

/// The rule-dispatch adapter test.
///
/// `docs/TESTING.md` names rule dispatch as a seam that needs one: "clean"
/// meaning *this rule ran and examined N shapes* is not observable in the
/// violation table, and in this crate the observation is the [`RuleRun`] row. So
/// the property under test is the one a missing line in the dispatcher breaks
/// and nothing else in the suite catches — **every table holding a row produces
/// exactly one run row attributable to it**. A rule kind wired up nowhere is
/// silent, and silence is what a clean design looks like.
///
/// These are unit tests rather than integration tests because the fixture below
/// is the dispatcher's own inventory: it has to name all twenty-six fields, and
/// it belongs beside the struct it enumerates so the compiler points here when a
/// twenty-seventh arrives.
#[cfg(test)]
mod tests {
    use super::RuleSet;
    use crate::rules::grid::Direction;
    use crate::{Design, Scratch};
    use gpurify_core::{GeometryStore, LayerId};
    use gpurify_derived::Evaluator;
    use gpurify_ingest::StrId;
    use gpurify_report::{LimitSense, Outcome, RuleRun, SkipReason, Violations};
    use gpurify_testgen::dbu;
    use gpurify_testgen::shapes::{area, hole, rect, LayoutBuilder};
    use gpurify_topology::{DeviceTable, NetTable};

    const A: LayerId = LayerId(0);
    const B: LayerId = LayerId(1);

    /// One rule id per table, in the order the fields are declared, so a failure
    /// names the kind rather than a number.
    const KINDS: [&str; 26] = [
        "min_width",
        "max_width",
        "min_edge_length",
        "notch",
        "min_spacing",
        "min_spacing_diff",
        "eol_spacing",
        "prl_spacing",
        "corner_to_corner",
        "wide_dependent_spacing",
        "min_area",
        "min_enclosed_area",
        "cheesing",
        "density",
        "min_enclosure",
        "asymmetric_enclosure",
        "min_extension",
        "overlap",
        "max_distance_to_tap",
        "off_grid",
        "angle",
        "antenna",
        "antenna_car",
        "redundant_via",
        "via_array_spacing",
        "multi_patterning",
    ];

    fn id(kind: &str) -> StrId {
        let index = KINDS
            .iter()
            .position(|&name| name == kind)
            .expect("every rule id in this module names a kind");
        StrId(u32::try_from(index).expect("twenty-six kinds"))
    }

    /// Geometry chosen so no rule has an empty population to look at.
    ///
    /// Two facing stripes give the spacing family its pairs and the overlay
    /// family its hosts; a short-ended pair gives the end-of-line rule an edge
    /// that qualifies; a diagonally offset pair gives corner-to-corner its only
    /// legal input; and the ring gives the enclosed-area rule a hole, which is
    /// the one population a layer of simple shapes does not contain.
    fn populated_design() -> GeometryStore {
        let mut layout = LayoutBuilder::new(2);
        layout.rect(A, 0, 0, 200, 1_000);
        layout.rect(A, 300, 0, 500, 1_000);
        layout.rect(A, 600, 0, 800, 200);
        layout.rect(A, 600, 300, 800, 500);
        layout.rect(A, 2_000, 2_000, 2_100, 2_100);
        layout.rect(A, 2_200, 2_200, 2_300, 2_300);
        layout.shape(A, &rect(5_000, 5_000, 5_400, 5_400));
        layout.shape(A, &hole(5_100, 5_100, 5_300, 5_300));
        layout.rect(B, -100, -100, 600, 1_100);
        layout.rect(B, 3_000, 3_000, 3_100, 3_100);
        let (store, _ids) = layout.finish();
        store
    }

    /// One row in every one of the twenty-six tables, each with a distinct id.
    ///
    /// The limits are deliberately loose: what is under test here is dispatch,
    /// not measurement, and every measurement has its own test in `tests/`.
    #[allow(
        clippy::too_many_lines,
        reason = "one statement group per rule kind; splitting it would hide the \
                  fact that this fixture is an exhaustive inventory of RuleSet's \
                  fields, which is the only reason it exists"
    )]
    fn full_deck() -> RuleSet {
        let mut set = RuleSet::default();

        set.min_width.rule.push(id("min_width"));
        set.min_width.layer.push(A);
        set.min_width.limit.push(dbu(1));

        set.max_width.rule.push(id("max_width"));
        set.max_width.layer.push(A);
        set.max_width.limit.push(dbu(1_000_000));

        set.min_edge_length.rule.push(id("min_edge_length"));
        set.min_edge_length.layer.push(A);
        set.min_edge_length.limit.push(dbu(1));

        set.notch.rule.push(id("notch"));
        set.notch.layer.push(A);
        set.notch.limit.push(dbu(1));

        set.min_spacing.rule.push(id("min_spacing"));
        set.min_spacing.layer.push(A);
        set.min_spacing.limit.push(dbu(100));

        set.min_spacing_diff.rule.push(id("min_spacing_diff"));
        set.min_spacing_diff.a.push(A);
        set.min_spacing_diff.b.push(B);
        set.min_spacing_diff.limit.push(dbu(100));

        set.eol_spacing.rule.push(id("eol_spacing"));
        set.eol_spacing.layer.push(A);
        set.eol_spacing.eol_width.push(dbu(300));
        set.eol_spacing.limit.push(dbu(100));

        set.prl_spacing.rule.push(id("prl_spacing"));
        set.prl_spacing.layer.push(A);
        set.prl_spacing.prl_threshold.push(dbu(1));
        set.prl_spacing.limit.push(dbu(100));

        set.corner_to_corner.rule.push(id("corner_to_corner"));
        set.corner_to_corner.layer.push(A);
        set.corner_to_corner.limit.push(dbu(200));

        set.wide_dependent_spacing
            .rule
            .push(id("wide_dependent_spacing"));
        set.wide_dependent_spacing.layer.push(A);
        set.wide_dependent_spacing.width_threshold.push(dbu(1));
        set.wide_dependent_spacing.limit.push(dbu(100));

        set.min_area.rule.push(id("min_area"));
        set.min_area.layer.push(A);
        set.min_area.limit.push(area(1));

        set.min_enclosed_area.rule.push(id("min_enclosed_area"));
        set.min_enclosed_area.layer.push(A);
        set.min_enclosed_area.limit.push(area(1));

        set.cheesing.rule.push(id("cheesing"));
        set.cheesing.layer.push(A);
        set.cheesing.max_unslotted.push(area(1_000_000_000));

        set.density.rule.push(id("density"));
        set.density.layer.push(A);
        set.density.window.push(dbu(1_000));
        set.density.step.push(dbu(500));
        set.density.limit.push(1.0);
        set.density.sense.push(LimitSense::Maximum);

        set.min_enclosure.rule.push(id("min_enclosure"));
        set.min_enclosure.outer.push(B);
        set.min_enclosure.inner.push(A);
        set.min_enclosure.limit.push(dbu(1));

        set.asymmetric_enclosure
            .rule
            .push(id("asymmetric_enclosure"));
        set.asymmetric_enclosure.outer.push(B);
        set.asymmetric_enclosure.inner.push(A);
        set.asymmetric_enclosure.min_one_side.push(dbu(1));

        set.min_extension.rule.push(id("min_extension"));
        set.min_extension.layer.push(A);
        set.min_extension.reference.push(B);
        set.min_extension.limit.push(dbu(1));

        set.overlap.rule.push(id("overlap"));
        set.overlap.a.push(A);
        set.overlap.b.push(B);
        set.overlap.limit.push(dbu(1));

        set.max_distance_to_tap.rule.push(id("max_distance_to_tap"));
        set.max_distance_to_tap.well.push(A);
        set.max_distance_to_tap.tap.push(B);
        set.max_distance_to_tap.limit.push(dbu(1_000_000));

        set.off_grid.rule.push(id("off_grid"));
        set.off_grid.pitch.push(dbu(1));

        set.angle.rule.push(id("angle"));
        set.angle.allowed_start.push(0);
        set.angle.allowed_len.push(2);
        set.angle.allowed.push(Direction { dx: 1, dy: 0 });
        set.angle.allowed.push(Direction { dx: 0, dy: 1 });

        set.antenna.rule.push(id("antenna"));
        set.antenna.layer.push(B);
        set.antenna.ratio.push(50.0);
        set.antenna.diode.push(None);

        set.antenna_car.rule.push(id("antenna_car"));
        set.antenna_car.stack_start.push(0);
        set.antenna_car.stack_len.push(1);
        set.antenna_car.stack.push(B);
        set.antenna_car.ratio.push(50.0);
        set.antenna_car.diode.push(None);

        set.redundant_via.rule.push(id("redundant_via"));
        set.redundant_via.layer.push(A);
        set.redundant_via.min_count.push(1);
        set.redundant_via.within.push(dbu(200));

        set.via_array_spacing.rule.push(id("via_array_spacing"));
        set.via_array_spacing.layer.push(A);
        set.via_array_spacing.array_threshold.push(0);
        set.via_array_spacing.limit.push(dbu(200));

        set.multi_patterning.rule.push(id("multi_patterning"));
        set.multi_patterning.layer.push(A);
        set.multi_patterning.colors.push(3);
        set.multi_patterning.color_spacing.push(dbu(100));

        set
    }

    struct Fixture {
        store: GeometryStore,
        derived: Evaluator,
        nets: NetTable,
        devices: DeviceTable,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                store: populated_design(),
                derived: Evaluator::default(),
                nets: NetTable::default(),
                devices: DeviceTable::default(),
            }
        }

        fn design(&self) -> Design<'_> {
            Design {
                store: &self.store,
                derived: &self.derived,
                nets: &self.nets,
                devices: &self.devices,
            }
        }
    }

    /// Oracle: construct-from-answer. The deck was built with exactly one row in
    /// each of the twenty-six tables, so the run must produce twenty-six run
    /// rows, one per id, with nothing repeated and nothing missing. A rule kind
    /// the dispatcher forgets to call produces no row and no violation, which
    /// is indistinguishable from a clean design in every other test in this
    /// crate.
    #[test]
    fn every_configured_rule_produces_exactly_one_attributable_run_row() {
        let fixture = Fixture::new();
        let set = full_deck();
        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = Vec::new();

        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        assert_eq!(set.rule_count(), KINDS.len());
        assert_eq!(
            runs.len(),
            set.rule_count(),
            "the run must account for every rule it loaded"
        );

        let mut seen: Vec<u32> = runs.iter().map(|run| run.rule.0).collect();
        seen.sort_unstable();
        let expected: Vec<u32> =
            (0..u32::try_from(KINDS.len()).expect("twenty-six kinds")).collect();
        assert_eq!(
            seen, expected,
            "every table with a row must be dispatched exactly once"
        );
    }

    /// Oracle: construct-from-answer. The geometry above was chosen so every
    /// geometric rule has a nonzero population — polygons, pairs, holes, edges,
    /// vertices, windows — so each must report `Ran` over a nonzero `examined`.
    /// A rule whose layer lookup returned the wrong range reports `Ran` with
    /// zero, which is the shape of a false-clean result and is what this
    /// assertion exists to reject.
    ///
    /// The two antenna rules are the exception and are asserted separately: they
    /// refer collected charge to a gate, the design has no recognised devices,
    /// and a ratio with no denominator is `Skipped` rather than clean.
    #[test]
    fn every_geometric_rule_ran_over_a_population_it_could_measure() {
        let fixture = Fixture::new();
        let set = full_deck();
        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = Vec::new();

        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        for (index, kind) in KINDS.iter().enumerate() {
            let wanted = StrId(u32::try_from(index).expect("twenty-six kinds"));
            let run = runs
                .iter()
                .find(|run| run.rule == wanted)
                .unwrap_or_else(|| panic!("{kind} produced no run row"));

            if *kind == "antenna" || *kind == "antenna_car" {
                assert_eq!(
                    run.outcome,
                    Outcome::Skipped(SkipReason::EmptyLayer),
                    "{kind} has no gate to refer a ratio to and must say so"
                );
            } else {
                assert_eq!(run.outcome, Outcome::Ran, "{kind} did not run");
                assert!(
                    run.examined > 0,
                    "{kind} ran but examined nothing, so nothing about it was exercised"
                );
            }
        }
    }

    /// Oracle: construct-from-answer. `run` owns the clearing of both output
    /// containers — the transforms themselves only append — so rows left over
    /// from an earlier run must not survive into this one. A run that appended
    /// instead would report the previous design's violations against this
    /// design's rules.
    #[test]
    fn a_run_clears_the_outputs_it_was_handed() {
        let fixture = Fixture::new();
        let set = full_deck();
        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = vec![RuleRun {
            rule: StrId(9_999),
            outcome: Outcome::Refused,
            examined: 5,
            violations: 3,
        }];
        out.rule.push(StrId(9_999));

        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        assert_eq!(runs.len(), set.rule_count());
        assert!(
            runs.iter().all(|run| run.rule != StrId(9_999)),
            "a stale run row survived into a new run"
        );
        assert!(
            out.rule.iter().all(|&rule| rule != StrId(9_999)),
            "a stale violation survived into a new run"
        );
    }

    /// Oracle: construct-from-answer. An empty set holds no rules and produces
    /// no run rows — which is the one case where an empty `runs` is correct, and
    /// is why `rule_count` is the number every other assertion compares against
    /// rather than a constant.
    #[test]
    fn an_empty_rule_set_holds_nothing_and_dispatches_nothing() {
        let fixture = Fixture::new();
        let set = RuleSet::default();
        assert!(set.is_empty());
        assert_eq!(set.rule_count(), 0);

        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = Vec::new();
        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        assert!(runs.is_empty());
        assert!(out.rule.is_empty());
    }

    /// Oracle: construct-from-answer. `rule_count` sums across every table, so
    /// adding a second row to one table moves it by one and `is_empty` stops
    /// being true the moment any table holds anything.
    #[test]
    fn the_rule_count_is_the_sum_across_every_table() {
        let mut set = RuleSet::default();
        assert!(set.is_empty());

        set.min_width.rule.push(StrId(0));
        set.min_width.layer.push(A);
        set.min_width.limit.push(dbu(10));
        assert!(!set.is_empty());
        assert_eq!(set.rule_count(), 1);

        set.off_grid.rule.push(StrId(1));
        set.off_grid.pitch.push(dbu(5));
        assert_eq!(set.rule_count(), 2);

        set.min_width.rule.push(StrId(2));
        set.min_width.layer.push(B);
        set.min_width.limit.push(dbu(20));
        assert_eq!(set.rule_count(), 3);
    }
}
