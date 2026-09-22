//! Base of the test-seam traits in other crates; `NoObserve` is the production adapter.

/// `ENABLED` is `false` for [`NoObserve`], so the disabled arm folds away.
pub trait Observer {
    const ENABLED: bool;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserve;

impl Observer for NoObserve {
    const ENABLED: bool = false;
}
