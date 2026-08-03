//! Test-adapter machinery: the gate constant and the null adapter.
//!
//! Some behaviour is not visible in a return value. A spatial prune that
//! wrongly rejects a pair returns a *shorter, still perfectly valid* list; a
//! rule that never fires returns the same empty report as a rule that ran and
//! found nothing. Testing those requires observing the seam, not the result.
//!
//! # The rule
//!
//! An adapter is acceptable only if the production build provably pays nothing
//! for it. Not "cheap" — **absent**. That rests on three things together:
//!
//! 1. The gate is an associated `const`, so `if O::ENABLED` folds at
//!    monomorphisation and the disabled arm is never codegenned.
//! 2. [`NoObserve`] is zero-sized with empty method bodies, so `&mut NoObserve`
//!    is a dangling-but-valid pointer that no instruction dereferences.
//! 3. The generic sits on a *private* entry point. The public interface takes
//!    no observer, so the seam does not widen the module's interface and
//!    adapter tests live inside the crate.
//!
//! Point 3 is why the adapter tests are unit tests. That is a deliberate
//! trade: a smaller public interface, at the cost of the tests not being able
//! to live in `tests/`.
//!
//! # Proving it
//!
//! Points 1 and 2 are claims about codegen, and claims about codegen are
//! checked by reading codegen. For the two hot seams — candidate-pair
//! generation and the derived-layer prefilter — the check is a disassembly
//! comparison of the `bench` profile against a build with the seam removed by
//! `cfg`; identical instruction sequence or it does not merge. For the wider
//! seams the check is a benchmark within noise on the scale corpus.
//!
//! The failure mode being checked for is *not* a leftover call. It is the
//! observer parameter blocking inlining or defeating vectorisation of the loop
//! it threads through, which is invisible to a symbol check and cheap to miss.

/// Base of every seam trait. Carries only the gate.
///
/// Seam-specific traits (`ObservePairs`, and the ones `derived`, `drc` and the
/// allocation counters define) require this, so `O::ENABLED` is available
/// wherever an observer is threaded.
pub trait Observer {
    /// `false` in every production build. The one constant the optimiser needs
    /// in order to delete the seam.
    const ENABLED: bool;
}

/// The null adapter: zero-sized, does nothing, is the only observer a
/// production build instantiates.
///
/// Each seam trait is implemented for this type at the seam's own definition
/// site, which is legal under the orphan rule because the seam trait is local
/// there.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserve;

impl Observer for NoObserve {
    const ENABLED: bool = false;
}

// The zero-sized guarantee, checked at compile time rather than asserted in
// prose. Not a test — a test would be Phase 3, and this is a property of the
// type declaration itself.
const _: () = assert!(std::mem::size_of::<NoObserve>() == 0);
const _: () = assert!(!NoObserve::ENABLED);
