//! PEX — parasitic extraction, unified.
//!
//! Two extraction paths behind one API, selected by [`Accuracy`]:
//!   * [`Accuracy::Analytical`] — fast formula-based (pattern, 2.5D) extraction
//!     over the 2-D [`GeometryStore`] + process-stack [`Deck`]. No field solver.
//!   * [`Accuracy::Quasistatic`] — heavier 3-D BEM/FastHenry-class extraction in
//!     [`quasistatic`], reached through the layout/process-stack [`bridge`].
//!
//! [`run_pex_by_net`] follows `Deck::pex_method`; the explicit
//! [`run_pex_by_net_with_accuracy`] entry point overrides the deck. The checked
//! variants fail closed if the field bridge cannot represent an input, while
//! compatibility variants fall back to analytical extraction once, audibly.

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
    build_pex_graph, run_pex, run_pex_backend, run_pex_by_net as run_pex_by_net_analytical,
    run_pex_by_net_checked as run_pex_by_net_analytical_checked, run_pex_multi_corner, Attributed,
    BoxedRule, NetParasitics, Parasitic, PexCtx, PexError, PexReport, NM_PER_UM,
};
pub use analytical::{
    device_parasitics, dspf, graph, inductance, process_stack, reduce, rules, spef,
};

/// Which extraction engine runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Accuracy {
    /// Fast, formula-based analytical extraction.
    Analytical,
    /// Heavier, more accurate quasistatic BEM field solver.
    #[default]
    Quasistatic,
}

/// Per-net PEX selected by `deck.pex_method`.
///
/// This is the drop-in compatibility entry point. A field-solver failure is
/// logged once and falls back to analytical extraction. Signoff callers that
/// must not accept a fallback should use [`run_pex_by_net_checked`].
#[must_use]
pub fn run_pex_by_net(
    store: &geometry::GeometryStore,
    deck: &params::Deck,
    net_of_poly: &[u32],
) -> std::collections::HashMap<u32, NetParasitics> {
    let accuracy = match deck.pex_method {
        params::PexMethod::Analytical => Accuracy::Analytical,
        params::PexMethod::FieldSolver => Accuracy::Quasistatic,
    };
    run_pex_by_net_with_accuracy(store, deck, net_of_poly, accuracy)
}

/// Fail-closed per-net PEX selected by `deck.pex_method`.
pub fn run_pex_by_net_checked(
    store: &geometry::GeometryStore,
    deck: &params::Deck,
    net_of_poly: &[u32],
) -> Result<std::collections::HashMap<u32, NetParasitics>, PexError> {
    let accuracy = match deck.pex_method {
        params::PexMethod::Analytical => Accuracy::Analytical,
        params::PexMethod::FieldSolver => Accuracy::Quasistatic,
    };
    run_pex_by_net_with_accuracy_checked(store, deck, net_of_poly, accuracy)
}

/// Per-net PEX with an explicit [`Accuracy`] choice.
///
/// This preserves the historical numeric return type. Use
/// [`run_pex_by_net_with_accuracy_checked`] to reject rather than accept an
/// analytical compatibility fallback.
#[must_use]
pub fn run_pex_by_net_with_accuracy(
    store: &geometry::GeometryStore,
    deck: &params::Deck,
    net_of_poly: &[u32],
    accuracy: Accuracy,
) -> std::collections::HashMap<u32, NetParasitics> {
    match accuracy {
        Accuracy::Analytical => run_pex_by_net_analytical(store, deck, net_of_poly),
        Accuracy::Quasistatic => match bridge::extract_quasistatic(store, deck, net_of_poly) {
            Ok(extracted) => extracted,
            Err(error) => {
                bridge::warn_fallback_once(&error);
                run_pex_by_net_analytical(store, deck, net_of_poly)
            }
        },
    }
}

/// Fail-closed per-net PEX with an explicit [`Accuracy`] choice.
pub fn run_pex_by_net_with_accuracy_checked(
    store: &geometry::GeometryStore,
    deck: &params::Deck,
    net_of_poly: &[u32],
    accuracy: Accuracy,
) -> Result<std::collections::HashMap<u32, NetParasitics>, PexError> {
    match accuracy {
        Accuracy::Analytical => run_pex_by_net_analytical_checked(store, deck, net_of_poly),
        Accuracy::Quasistatic => bridge::extract_quasistatic(store, deck, net_of_poly).map_err(
            |error| {
                let polygon = match &error {
                    bridge::BridgeError::UnsupportedGeometry { polygon, .. } => *polygon,
                    _ => u32::MAX,
                };
                PexError::UnsupportedGeometry(vec![Parasitic::ExtractionDiagnostic {
                    layer: "<quasistatic-bridge>".into(),
                    polygon,
                    model: "quasistatic".into(),
                    message: error.to_string(),
                }])
            },
        ),
    }
}
