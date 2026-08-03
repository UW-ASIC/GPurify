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
