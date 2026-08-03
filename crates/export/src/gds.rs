//! GDSII writer.
//!
//! Two uses, and the second is why it matters more than it looks.
//!
//! The obvious one is writing marker layers: a violation's geometry as shapes a
//! layout viewer can display over the design.
//!
//! The other is that it closes the round trip. `parse → write → parse` being
//! the identity on the store is one of the strongest laws available to test
//! `ingest` with, and it needs a writer to state. That law does not depend on
//! either implementation being right in any absolute sense — which is exactly
//! the property this project's oracles are chosen for.

use crate::WriteError;
use gpurify_core::{GeometryStore, LayerId};
use gpurify_ingest::deck::LayerTable;
use gpurify_report::Violations;

/// Write a store as a flat GDSII library.
///
/// **Transform.** Caller owns `out`, appended to.
///
/// Flat: the store has no hierarchy left, having been flattened at ingest, so
/// this writes one cell. Round-tripping therefore returns the flattened store,
/// not the original file — which is the identity the law actually claims, and
/// stating it precisely is what stops the test being wrong about what it proves.
///
/// Emits polygons in store order, which is grouped by layer and canonical.
pub fn write_store(
    store: &GeometryStore,
    layers: &LayerTable,
    cell_name: &str,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    todo!()
}

/// Write violation markers as geometry.
///
/// One shape per violation on a per-rule marker layer, so a viewer can toggle
/// rules independently. Marker layer numbers come from the caller rather than
/// being invented here, because they have to agree with whatever the viewer is
/// configured to show.
pub fn write_markers(
    violations: &Violations,
    store: &GeometryStore,
    marker_layer: LayerId,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    todo!()
}
