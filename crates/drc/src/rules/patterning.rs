//! Multi-patterning: can this layer be split across the masks the process has?
//!
//! Below the single-exposure pitch a layer is printed by two or three masks,
//! and two shapes closer than `color_spacing` cannot be on the same one. So the
//! question is graph colouring: nodes are shapes, edges are too-close pairs,
//! colours are masks. A layer that cannot be coloured cannot be manufactured,
//! and no amount of moving one shape fixes it — the designer has to break an
//! odd cycle.
//!
//! # The only search in the crate, and the only one that can give up
//!
//! Every other rule is a measurement. This one is NP-hard, so it runs a bounded
//! search and can exhaust its budget without an answer. That makes the failure
//! mode different in kind, and it is the reason [`Coloring`] has three variants
//! rather than being a `bool`:
//!
//! - [`Coloring::Complete`] — an assignment exists and is in `out`.
//! - [`Coloring::Infeasible`] — proved: no assignment exists. A real violation.
//! - [`Coloring::Exhausted`] — the budget ran out. **Not** a violation and
//!   **not** clean. It becomes `Outcome::Refused` on the rule's [`RuleRun`],
//!   because a checker that reports "colourable" after giving up is worse than
//!   one that reports nothing.
//!
//! Collapsing `Exhausted` into either of the other two is the single defect
//! this module exists to avoid, and it is why the outcome is a sum type instead
//! of an empty violation list.

use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// Backtracking budget, in search steps.
///
/// ponytail: one fixed budget for every layer, tuned so a full-reticle metal
/// layer of ordinary structure finishes well inside it. Upgrade to a budget
/// scaled by node count, or to a proper odd-cycle detector that answers
/// two-colourability in linear time without search, if the scale corpus starts
/// producing `Exhausted`. The signature does not change either way: the budget
/// is not a parameter because a deck has no business tuning it, and a caller
/// that could raise it would be tempted to raise it until the answer came out
/// clean.
pub const COLOR_SEARCH_BUDGET: u32 = 1 << 20;

/// Multi-patterning colourability.
#[derive(Debug, Default)]
pub struct MultiPatterningTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Masks available. Two or three in practice; `u8` because a process with
    /// 256 masks for one layer does not exist.
    pub colors: Vec<u8>,
    /// Two shapes closer than this cannot share a mask. Also the radius the
    /// candidate prune is built at, so narrowing it drops conflict edges and
    /// makes an uncolourable layer look colourable — fail-open, and the reason
    /// the prune's inclusivity matters here as much as in the spacing family.
    pub color_spacing: Vec<Dbu>,
}

impl MultiPatterningTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// How a colouring attempt ended.
///
/// A sum type rather than `Option<Vec<u8>>`, because "no assignment exists" and
/// "we did not find one" are different claims and only the first is a defect in
/// the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coloring {
    /// Every node has a colour, in `out`.
    Complete,
    /// Proved uncolourable within the budget.
    ///
    /// `node` is the lowest-indexed node the search could not place — lowest,
    /// not "the last one tried", so the reported coordinate is a function of
    /// the graph and not of the search's path through it. Determinism is a
    /// gate, and a search reporting wherever it happened to stop would not
    /// survive it.
    Infeasible { node: u32 },
    /// The budget ran out with no answer either way. Fail closed.
    Exhausted,
}

/// Colour a conflict graph with at most `colors` colours.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled to
/// `node_count` entries on [`Coloring::Complete`] and left empty otherwise —
/// a partial colouring is not a result anyone can use, and leaving one in the
/// buffer invites a caller to read it.
///
/// `conflicts` is a flat pair list over `0 .. node_count`, the same shape
/// `core::connectivity::components_into` takes. An edge naming a node at or
/// beyond `node_count` is a caller bug and is asserted, not ignored: ignoring
/// it drops a constraint and makes an uncolourable graph look fine.
///
/// DSATUR ordering with backtracking, tie-broken by node index so the result is
/// canonical. Separate from [`check_multi_patterning`] because it is exactly
/// the shape that earns a definitive test: a graph built *from* a known
/// colouring is colourable by construction, and an odd cycle is uncolourable in
/// two by construction — both are construct-from-answer oracles needing no
/// geometry at all.
pub fn color_into(
    node_count: u32,
    conflicts: &[(u32, u32)],
    colors: u8,
    out: &mut Vec<u8>,
) -> Coloring {
    todo!()
}

/// Check every multi-patterning rule.
///
/// **Transform.** Builds the conflict graph from the candidate pairs at
/// `color_spacing`, confirms each pair exactly, then hands it to
/// [`color_into`].
///
/// One violation per uncolourable layer, at the shape named by
/// [`Coloring::Infeasible`] — one, not one per shape, because the defect is the
/// cycle rather than any member of it, and reporting every node of a
/// thousand-shape component buries the fix.
///
/// `examined` counts shapes on the layer. A budget exhaustion records
/// `Outcome::Refused` for the row with the same `examined` count, so a report
/// can tell "checked 40 000 shapes, colourable" from "gave up after 40 000
/// shapes" — which the violation table alone cannot.
pub fn check_multi_patterning(
    design: Design<'_>,
    table: &MultiPatterningTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
