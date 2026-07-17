//! PEX — parasitic extraction, unified.
//!
//! Two extraction paths behind one API, selected by [`Accuracy`]:
//!   * [`Accuracy::Analytical`] — fast formula-based (pattern, 2.5D) extraction
//!     over the 2-D [`GeometryStore`] + process-stack [`Deck`]. No field solver.
//!   * [`Accuracy::Quasistatic`] — heavier, more accurate 3-D BEM field solver
//!     (FastCap/FastHenry-class) in [`quasistatic`]. Standalone numerics; the
//!     layout→3D bridge is staged (see [`bridge`]).
//!
//! Default is [`Accuracy::Quasistatic`] (LVS extraction defaults to it). Until the
//! layout bridge lands the quasistatic path falls back to analytical, once,
//! audibly — never silently wrong.

// Re-exports so both the ported analytical modules and downstream callers keep
// resolving `crate::geometry`, `crate::params`, `crate::backend`.
pub use gdsverify_backend as backend;
pub use gdsverify_core::geometry;
pub use gdsverify_core::params;

pub mod rule;

pub mod analytical;
pub mod bridge;
pub mod quasistatic;

// The analytical crate's public surface, re-exported at the crate root: lvs/erc
// consume these, and the ported rule files reference them as `crate::…`.
pub use analytical::{
    build_pex_graph, run_pex, run_pex_backend, run_pex_by_net, run_pex_by_net_checked,
    run_pex_multi_corner, Attributed, BoxedRule, NetParasitics, Parasitic, PexCtx, PexError,
    PexReport, NM_PER_UM,
};
pub use analytical::{device_parasitics, dspf, graph, inductance, process_stack, reduce, rules, spef};

/// Which extraction engine runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Accuracy {
    /// Fast, formula-based analytical extraction.
    Analytical,
    /// Heavier, more accurate quasistatic BEM field solver.
    #[default]
    Quasistatic,
}

/// Per-net PEX with an explicit [`Accuracy`] choice.
///
/// For [`Accuracy::Quasistatic`] this attempts the 3-D field-solver bridge and,
/// while that bridge is still staged, falls back to the analytical path (logged
/// once). [`run_pex_by_net`] / [`run_pex_by_net_checked`] default to
/// [`Accuracy::Quasistatic`] via this entry point.
pub fn run_pex_by_net_with_accuracy(
    store: &geometry::GeometryStore,
    deck: &params::Deck,
    net_of_poly: &[u32],
    accuracy: Accuracy,
) -> std::collections::HashMap<u32, NetParasitics> {
    if accuracy == Accuracy::Quasistatic
        && bridge::extract_quasistatic(store, deck, net_of_poly).is_none()
    {
        // ponytail: layout→3D bridge not built; the analytical path is the only
        // real extractor today, so the report is always None → fall through.
        bridge::warn_fallback_once();
    }
    run_pex_by_net(store, deck, net_of_poly)
}
