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

/// The permutation, checked on the column it was written for.
///
/// A unit test rather than an integration test because a non-root [`PathId`]
/// cannot be made from outside this crate: [`PathTable::intern`] needs a `&mut`
/// and [`Provenance::paths`] hands out a shared reference only, so every
/// externally built row sits at [`PathTable::ROOT`] and the hierarchy path —
/// the exact column whose mispermutation names the wrong cell — is unreachable.
/// The gap is recorded in `docs/NEED_TESTING.md`; the signature stays as it is.
#[cfg(test)]
mod tests {
    use super::Provenance;
    use crate::intern::StrTable;
    use gpurify_core::PolyId;

    /// Oracle: construct-from-answer. Each row is pushed under a path that
    /// names it, and the permutation is stated by the test rather than taken
    /// from a store, so the expected path of every row after the reorder is
    /// known before `permute` runs. The permutation moves every row, which is
    /// what stops a `permute` that does nothing from passing.
    #[test]
    fn permute_moves_each_hierarchy_path_onto_the_row_its_polygon_became() {
        let mut strings = StrTable::default();
        let mut provenance = Provenance::default();

        // `permutation[new] == old`, and no row stays where it was.
        let permutation = [3u32, 0, 4, 1, 2];
        let mut pushed = Vec::with_capacity(permutation.len());
        for row in 0..permutation.len() {
            let cell = strings.intern(&format!("cell_{row}"));
            let instance = strings.intern(&format!("inst_{row}"));
            let path = provenance.paths.intern(&[cell, instance]);
            provenance.push(path, &[]);
            pushed.push((path, [cell, instance]));
        }
        assert!(
            permutation
                .iter()
                .enumerate()
                .all(|(new, &old)| u32::try_from(new).expect("five rows") != old),
            "the permutation leaves a row in place, so this test would be weaker \
             than it claims"
        );

        provenance.permute(&permutation);

        for (new, &old) in permutation.iter().enumerate() {
            let poly = PolyId(u32::try_from(new).expect("five rows"));
            let (expected, components) = pushed[old as usize];
            assert_eq!(
                provenance.path_of(poly),
                expected,
                "{poly:?} came from arrival row {old} and must carry its path"
            );
            assert_eq!(
                provenance.paths().get(provenance.path_of(poly)),
                components,
                "{poly:?} resolves to the wrong cell, which is what a report \
                 would print beside every violation on it"
            );
        }
    }

    /// Oracle: law. The identity permutation is a no-op. Worth stating on its
    /// own because it is what a single-layer layout produces, and a `permute`
    /// that reversed or rotated its input would still pass a test that only
    /// counted rows.
    #[test]
    fn the_identity_permutation_leaves_every_row_where_it_is() {
        let mut strings = StrTable::default();
        let mut provenance = Provenance::default();
        let mut pushed = Vec::with_capacity(4);
        for row in 0..4u32 {
            let cell = strings.intern(&format!("cell_{row}"));
            let path = provenance.paths.intern(&[cell]);
            provenance.push(path, &[]);
            pushed.push(path);
        }

        provenance.permute(&[0, 1, 2, 3]);

        for (row, &path) in pushed.iter().enumerate() {
            assert_eq!(
                provenance.path_of(PolyId(u32::try_from(row).expect("four rows"))),
                path
            );
        }
    }
}
