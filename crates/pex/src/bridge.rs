//! Staged bridge: layout + process stack → 3-D BEM for the quasistatic solver.
//!
//! The [`quasistatic`](crate::quasistatic) solver is standalone numerics over
//! 3-D panels/filaments, not layout. Turning a 2-D [`GeometryStore`] plus a
//! process-stack [`Deck`] into those panels — extruding each rect by its layer
//! thickness/z — is new work that is not built yet. Rather than fabricate
//! solver results, [`extract_quasistatic`] returns `None` so the dispatcher
//! falls back to the analytical path, audibly and once.

use std::sync::Once;

use crate::geometry::GeometryStore;
use crate::params::Deck;
use crate::PexReport;

/// Extract parasitics with the quasistatic field solver.
///
/// Returns `None` until the layout→3D bridge is built.
#[allow(unused_variables)]
#[must_use]
pub fn extract_quasistatic(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> Option<PexReport> {
    // TODO(bridge): extrude layout+stack to 3D BEM panels
    //   1. ProcessStack::from_deck(deck) → per-layer thickness + z.
    //   2. per conductor poly: extrude its rect(s) to a box, mesh faces into
    //      quasistatic::cap panels (and filaments for henry).
    //   3. group panels by net_of_poly, solve cap/henry, map back to Parasitic.
    None
}

static FALLBACK_WARN: Once = Once::new();

/// Log the quasistatic→analytical fallback exactly once per process.
pub fn warn_fallback_once() {
    FALLBACK_WARN.call_once(|| {
        eprintln!("pex: quasistatic layout bridge not yet built; falling back to analytical");
    });
}
