//! Test-adapter machinery: the gate constant and the null adapter.

/// Base of every seam trait. Carries only the gate.
pub trait Observer {
    /// `false` in every production build; folds at monomorphisation so the
    /// disabled arm is never codegenned.
    const ENABLED: bool;
}

/// The null adapter: zero-sized, does nothing, is the only observer a
/// production build instantiates.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserve;

impl Observer for NoObserve {
    const ENABLED: bool = false;
}

const _: () = assert!(std::mem::size_of::<NoObserve>() == 0);
const _: () = assert!(!NoObserve::ENABLED);
