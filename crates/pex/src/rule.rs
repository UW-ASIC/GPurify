//! The one rule abstraction the analytical extractors implement.
//!
//! A rule is a pure function from its context to a list of findings; the engine
//! runs every rule and sums the findings. `backend` is passed through for
//! parity with the other engines but the analytical path is exact on CPU: it
//! never consults a GPU prefilter (the old session/arena model is gone).

use rayon::prelude::*;

use crate::backend::Backend;

/// One extraction rule over an engine-specific context.
pub trait Rule<Ctx: ?Sized>: Send + Sync {
    /// What one hit looks like: here, a [`crate::Attributed`] parasitic.
    type Finding;
    /// Stable rule identifier for reports and deduplication.
    fn id(&self) -> &str;
    /// Run the rule. Exact by contract; `backend` only enables pruning.
    fn check(&self, ctx: &Ctx, backend: Backend) -> Vec<Self::Finding>;
}

/// Run every rule against the context in parallel and sum the findings.
/// Ordering across rules follows the rules slice (rayon preserves it).
pub fn run_rules<Ctx, F, R>(rules: &[Box<R>], ctx: &Ctx, backend: Backend) -> Vec<F>
where
    Ctx: Sync,
    F: Send,
    R: Rule<Ctx, Finding = F> + ?Sized,
{
    rules
        .par_iter()
        .flat_map_iter(|rule| rule.check(ctx, backend))
        .collect()
}
