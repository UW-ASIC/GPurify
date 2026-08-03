//! The twenty-six rule kinds, grouped by what they measure.
//!
//! One file per family, because a family shares its geometry primitive: the
//! width rules all scan inside one polygon, the spacing rules all start from a
//! candidate-pair prune, the overlay rules all relate an inner shape to an
//! outer one. Grouping by primitive is what lets the four width rules be four
//! reductions over one scan instead of four scans.
//!
//! # Every table has the same shape
//!
//! **Five questions**, answered once for all twenty-six. In: [`RuleSpec`] rows
//! from the deck, already layer-resolved and grid-converted by `ingest`. Out:
//! one `SoA` table of exactly the parameters that kind takes, nothing widened
//! to a common shape. How many: tens of rows per table, hundreds per deck —
//! *cold*, read once each at the top of a transform and hoisted as uniforms
//! over a loop with millions of iterations. Access pattern: a single forward
//! scan, all columns of a row read together at the top of that row's work.
//! Lifetime: the whole run, built once from the deck and never mutated.
//! Parallelisable: rows of one table are independent of each other; see the
//! ponytail note on [`Scratch`](crate::Scratch) for why they are not run that
//! way yet.
//!
//! Rows are `SoA` rather than `AoS` for one reason that is not performance:
//! [`RuleSet::rule_count`](crate::RuleSet::rule_count) and the dispatcher want
//! to ask "is this table empty" without knowing the row type, and the columns
//! keep the limit types honest — a `Vec<Dbu>` beside a `Vec<DbuArea>` cannot be
//! transposed by accident the way two `i64` struct fields can.
//!
//! # Every transform has the same shape
//!
//! ```ignore
//! pub fn check_<kind>(
//!     design: Design<'_>,
//!     table: &<Kind>Table,
//!     scratch: &mut Scratch,
//!     out: &mut Violations,
//!     runs: &mut Vec<RuleRun>,
//! )
//! ```
//!
//! - **`out` and `runs` are appended to, not cleared.** They are the gatherer's
//!   containers, shared by all twenty-six transforms;
//!   [`RuleSet::run`](crate::RuleSet::run) clears them once at the top of a run.
//!   Every *scratch* buffer is cleared and refilled, which is the `_into`
//!   discipline the conventions ask for — the outputs are the one place it
//!   would be wrong.
//! - **One [`RuleRun`] per table row, always**, pushed through
//!   `record_run`. Not per violation, not per layer, and
//!   never omitted because nothing was found.
//! - **`examined` counts the primitive the rule actually looked at**, named in
//!   each transform's doc: polygons for the shape rules, candidate pairs for
//!   the spacing rules, vertices for [`grid::check_off_grid`], gates for the
//!   antenna rules. It is a claim a test can check, so it has to mean something
//!   specific.
//! - **Nothing allocates per row.** Every buffer a row needs lives in
//!   [`Scratch`](crate::Scratch) and is cleared, not reallocated.
//!
//! # Refusal is a result
//!
//! Validation of a layer can fail — [`ValidityError::NotRectilinear`] is the
//! common one, since this tool represents rectilinear geometry exactly and
//! refuses to approximate anything else. A rule whose layer fails to validate
//! records [`Outcome::Refused`] for that row and the run continues to the next
//! rule. It never records `Ran` with zero violations, and it never aborts the
//! whole run: one bad polygon on one layer must not suppress the verdict of
//! every other rule in the deck.
//!
//! [`RuleSpec`]: gpurify_ingest::deck::RuleSpec
//! [`ValidityError::NotRectilinear`]: gpurify_core::view::ValidityError::NotRectilinear
//! [`Outcome::Refused`]: gpurify_report::Outcome::Refused
//! [`RuleRun`]: gpurify_report::RuleRun

pub mod antenna;
pub mod area;
pub mod grid;
pub mod overlay;
pub mod patterning;
pub mod spacing;
pub mod via;
pub mod width;
