//! Cold per-polygon data: where a shape came from.
//!
//! Keyed by the same [`PolyId`] as `core`'s `GeometryStore`, in a separate
//! table because no geometric transform reads any of it. Splitting it out is
//! what keeps `core` free of strings, maps and serde.
//!
//! It is read exactly twice: once when a report names the cell a violation is
//! in, and once when LVS binds a net label. Everything here is therefore
//! `StrId` and index ranges — the old `Vec<Vec<String>>` per polygon was 48
//! bytes of `Vec` header per shape before a single character existed.

use crate::intern::StrId;
use gpurify_core::PolyId;

/// A root-to-instance hierarchy path, as a range into a shared component list.
///
/// Paths are deeply shared — every shape under one instance has the same path —
/// so they are deduplicated and referenced by id, not stored per polygon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PathId(pub u32);

/// Deduplicated hierarchy paths.
#[derive(Debug, Default)]
pub struct PathTable {
    /// Interned path components, concatenated.
    components: Vec<StrId>,
    /// `components[span[i].0 .. span[i].1]` is path `i`.
    span: Vec<(u32, u32)>,
}

impl PathTable {
    /// Intern a path, deduplicating against paths already present.
    pub fn intern(&mut self, components: &[StrId]) -> PathId {
        todo!()
    }

    /// The components of a path, root first.
    pub fn get(&self, id: PathId) -> &[StrId] {
        todo!()
    }

    /// The empty path, used by directly constructed geometry that came from no
    /// instance. Always id 0, so it costs nothing to store.
    pub const ROOT: PathId = PathId(0);
}

/// Per-polygon provenance, one row per row of the `GeometryStore`.
///
/// **Five questions.** In: annotations from a layout reader. Out: the same,
/// permuted into store order. How many: one row per polygon. Access pattern:
/// random single-row reads when a report is written, never a scan — which is
/// why this is a separate table and not columns in the store. Lifetime: the
/// whole run. Parallelisable: read-only after ingest.
#[derive(Debug, Default)]
pub struct Provenance {
    /// Which instance path each polygon came from.
    poly_path: Vec<PathId>,
    /// `props[prop_start[i] .. prop_start[i + 1]]` are polygon `i`'s stream
    /// properties. CSR, so a polygon with no properties costs one `u32`.
    prop_start: Vec<u32>,
    props: Vec<(i16, StrId)>,
    /// Net label attached to a polygon, if any. `None` is the common case, so
    /// this is a sparse pair list rather than a column of `Option`.
    labelled: Vec<(PolyId, StrId)>,
    paths: PathTable,
}

impl Provenance {
    /// Append a row. Must be called exactly once per polygon, in the order the
    /// polygons were pushed to the builder.
    pub fn push(&mut self, path: PathId, props: &[(i16, StrId)]) {
        todo!()
    }

    /// Attach a net label to a polygon. Sparse; most polygons have none.
    pub fn label(&mut self, poly: PolyId, name: StrId) {
        todo!()
    }

    /// Reorder into store row order.
    ///
    /// **The invariant this whole module hangs on.** `permutation[new] == old`,
    /// as returned by `GeometryStoreBuilder::finish`. Called exactly once, by
    /// [`crate::layout::read_layout`]. Getting it wrong reports every violation
    /// against the wrong cell — plausible output, entirely wrong.
    pub fn permute(&mut self, permutation: &[u32]) {
        todo!()
    }

    pub fn path_of(&self, poly: PolyId) -> PathId {
        todo!()
    }

    pub fn props_of(&self, poly: PolyId) -> &[(i16, StrId)] {
        todo!()
    }

    /// Every labelled polygon, ascending by [`PolyId`].
    ///
    /// Ordered so `topology`'s label binding is deterministic without sorting.
    pub fn labels(&self) -> &[(PolyId, StrId)] {
        todo!()
    }

    pub fn paths(&self) -> &PathTable {
        todo!()
    }
}
