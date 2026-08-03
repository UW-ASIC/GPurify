//! Bounding-box prefiltering for boolean operands.
//!
//! Structurally identical to the candidate-pair prune in `core::index`: reject
//! cheaply, then compute exactly. And it has the same silent failure mode — a
//! wrongly rejected pair produces a shorter, perfectly well-formed operand list
//! and a quietly wrong answer, because nothing downstream ever looks at the
//! pair again.
//!
//! So it carries the same kind of test adapter, for the same reason: the
//! property that matters is *no rejected pair would have contributed to the
//! result*, and that is not observable in the output.
//!
//! This code is new. It has no history of being right, which is the argument
//! for instrumenting it from the start rather than after it burns someone.

use gpurify_core::observe::{NoObserve, Observer};
use gpurify_core::{GeometryStore, PolyId, ValidatedLayer};

/// What crossing the prefilter seam did.
pub trait ObservePrefilter: Observer {
    /// A pair was kept for exact evaluation.
    fn kept(&mut self, a: PolyId, b: PolyId);
    /// A pair was rejected on bounding boxes alone. The one that matters.
    fn rejected(&mut self, a: PolyId, b: PolyId);
}

impl ObservePrefilter for NoObserve {
    fn kept(&mut self, a: PolyId, b: PolyId) {}
    fn rejected(&mut self, a: PolyId, b: PolyId) {}
}

/// Which operand pairs can possibly interact.
///
/// **Transform, gatherer.** Caller owns `out`, cleared and refilled, emitted in
/// ascending order so the result is deterministic regardless of index layout.
///
/// A superset: a surviving pair may still contribute nothing. A pair absent
/// from here is never evaluated by anyone.
pub fn candidates_into(
    store: &GeometryStore,
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    candidates_observed(store, a, b, out, &mut NoObserve);
}

/// [`candidates_into`] with the seam exposed.
///
/// Private, so the observer does not widen this module's interface and adapter
/// tests are unit tests here. Same trade as `core::observe` records.
fn candidates_observed<O: ObservePrefilter>(
    store: &GeometryStore,
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    todo!()
}
