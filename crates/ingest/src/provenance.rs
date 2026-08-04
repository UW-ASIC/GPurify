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
    /// Ids sorted by their path's components. The binary-search index.
    ///
    /// The same field, for the same reason, as [`crate::intern::StrTable`]'s:
    /// dedup has to be exact and its iteration order has to be identical on
    /// every machine, which is what rules out a hash map. Sorted lexicographic
    /// by component id, so [`Self::ROOT`] — the empty path — is always row 0 of
    /// this index as well as row 0 of `span`.
    sorted: Vec<PathId>,
}

impl PathTable {
    /// Intern a path, deduplicating against paths already present.
    pub fn intern(&mut self, components: &[StrId]) -> PathId {
        // `ROOT` is documented as always id 0, and `Default` cannot seed it, so
        // row 0 materialises here. A non-empty path interned into a fresh table
        // would otherwise take the id every root-level polygon carries.
        if self.span.is_empty() {
            self.span.push((0, 0));
            self.sorted.push(Self::ROOT);
        }
        debug_assert_eq!(
            self.span.len(),
            self.sorted.len(),
            "the binary-search index holds a different number of paths than the table"
        );

        // Dedup by binary search over `sorted`, O(log paths · depth) per
        // intern. A flattening reader interns one path per instance and then
        // once more per shape under it, so this is on the per-shape path.
        //
        // The scrutinee is bound first so the shared borrow of `self` taken by
        // the comparator ends before the `&mut self` work below.
        let found = self
            .sorted
            .binary_search_by(|&id| self.get(id).cmp(components));
        let pos = match found {
            Ok(pos) => return self.sorted[pos],
            Err(pos) => pos,
        };

        let start = crate::narrow(self.components.len());
        self.components.extend_from_slice(components);
        let end = crate::narrow(self.components.len());
        let id = PathId(crate::narrow(self.span.len()));
        self.span.push((start, end));
        // O(paths) memmove of `u32`s per *distinct* path, the same shape and
        // ceiling `StrTable::intern` accepts. Repeat interns — the common case,
        // one per shape — do not reach here at all.
        self.sorted.insert(pos, id);

        debug_assert!(
            !components.is_empty(),
            "the empty path must have deduplicated onto the seeded root row"
        );
        debug_assert_ne!(
            id,
            Self::ROOT,
            "a real path took the id reserved for the root"
        );
        debug_assert_eq!(
            self.get(id),
            components,
            "the path just interned reads back as another"
        );
        debug_assert_eq!(
            self.span.len(),
            self.sorted.len(),
            "the binary-search index holds a different number of paths than the table"
        );
        // Ascending is maintained inductively, so only the new row's two
        // neighbours need checking. An index that fell out of order does not
        // panic, it silently stops finding duplicates — every shape under one
        // instance would then get its own path row.
        debug_assert!(
            pos == 0 || self.get(self.sorted[pos - 1]) < components,
            "the path index is out of order below the row just inserted"
        );
        debug_assert!(
            pos + 1 == self.sorted.len() || self.get(self.sorted[pos + 1]) > components,
            "the path index is out of order above the row just inserted"
        );
        id
    }

    /// The components of a path, root first.
    pub fn get(&self, id: PathId) -> &[StrId] {
        // The root path exists before anything is interned; `intern` is what
        // materialises row 0. Any other id against an empty table is a path
        // from a different `PathTable`, which fails closed on the assert.
        if self.span.is_empty() {
            assert_eq!(id, Self::ROOT, "path id does not name a row of this table");
            return &[];
        }
        let (start, end) = self.span[id.0 as usize];
        &self.components[start as usize..end as usize]
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
        // CSR carries one more offset than it has rows. `Default` cannot seed
        // it, so the leading zero goes down with the first row.
        if self.prop_start.is_empty() {
            self.prop_start.push(0);
        }
        self.poly_path.push(path);
        self.props.extend_from_slice(props);
        self.prop_start
            .push(crate::narrow(self.props.len()));

        debug_assert_eq!(
            self.prop_start.len(),
            self.poly_path.len() + 1,
            "the property column desynchronised from the row count"
        );
    }

    /// Attach a net label to a polygon. Sparse; most polygons have none.
    pub fn label(&mut self, poly: PolyId, name: StrId) {
        // Sorted on insert because ascending order is `labels`'s interface, not
        // an optimisation: it hands out a shared slice, `topology::port` binds
        // against it without sorting, and `engine::pipeline` asserts over it —
        // all three on a table that may never be permuted. Deferring the sort
        // to `permute` would leave that slice in reader-encounter order, which
        // is the nondeterministic binding this column exists to prevent.
        //
        // The O(labels) memmove is what that slice costs, and only for input
        // that arrives out of order: a reader emitting text records in
        // ascending `PolyId` lands at `at == self.labelled.len()` every time,
        // where `Vec::insert` is a push.
        let at = self
            .labelled
            .partition_point(|&(labelled, _)| labelled <= poly);
        self.labelled.insert(at, (poly, name));

        // Ascending is maintained inductively, so only the new row's two
        // neighbours need checking — a full scan here would be quadratic.
        debug_assert!(
            at == 0 || self.labelled[at - 1].0 <= poly,
            "the label column is what `topology` binds without sorting"
        );
        debug_assert!(
            at + 1 == self.labelled.len() || poly <= self.labelled[at + 1].0,
            "the label column is what `topology` binds without sorting"
        );
    }

    /// Reorder into store row order.
    ///
    /// **The invariant this whole module hangs on.** `permutation[new] == old`,
    /// as returned by `GeometryStoreBuilder::finish`. Called exactly once, by
    /// [`crate::layout::read_layout`]. Getting it wrong reports every violation
    /// against the wrong cell — plausible output, entirely wrong.
    pub fn permute(&mut self, permutation: &[u32]) {
        let rows = permutation.len();
        debug_assert_eq!(
            self.poly_path.len(),
            rows,
            "the permutation and the provenance table disagree on the row count"
        );
        debug_assert!(
            permutation.iter().all(|&old| (old as usize) < rows),
            "the permutation names an arrival row that was never pushed"
        );
        // In range is not enough: `[0, 0, 2]` passes the check above, and it
        // duplicates one row's provenance over another's while leaving
        // `inverse` holding a zero for the row it dropped. Every violation on
        // the dropped row would then be reported against whichever cell sits at
        // arrival row 0 — plausible output, entirely wrong, which is the
        // failure this whole module is written around.
        debug_assert!(
            {
                let mut seen = vec![false; rows];
                permutation
                    .iter()
                    .all(|&old| !core::mem::replace(&mut seen[old as usize], true))
            },
            "the permutation names one arrival row twice, so another row's \
             provenance was dropped"
        );

        // The hierarchy path is one row in, one row out: a gather, whose
        // data-dependent load is an address rather than a branch. The row count
        // was asserted equal to `rows` on entry, so the reserve covers the whole
        // output and the push never reallocates.
        let mut poly_path = Vec::with_capacity(rows);
        for &old in permutation {
            poly_path.push(self.poly_path[old as usize]);
        }
        debug_assert_eq!(poly_path.len(), rows, "the gather dropped a row");

        // The property column is CSR, so this is a segmented gather: the row is
        // a range rather than a value, and the destination offset of row N is
        // the running total through row N-1. That chain is what keeps it scalar;
        // there is nothing here to run wide.
        let mut props = Vec::with_capacity(self.props.len());
        let mut prop_start = Vec::with_capacity(rows + 1);
        prop_start.push(0);
        for &old in permutation {
            props.extend_from_slice(crate::csr(&self.prop_start, &self.props, old as usize));
            prop_start.push(crate::narrow(props.len()));
        }

        // Labels were attached against arrival ids, so they move by the inverse.
        if !self.labelled.is_empty() {
            debug_assert!(
                {
                    // A strict left fold with `&`, not `all`: no short circuit,
                    // so the cost is flat in the number of labels and the loop
                    // carries no data-dependent branch.
                    let mut ok = true;
                    for i in 0..self.labelled.len() {
                        ok &= self.labelled[i].0.idx() < rows;
                    }
                    ok
                },
                "a label names an arrival row this permutation does not cover"
            );

            // Inverting a permutation is a scatter: the output index is the
            // data, which is unvectorisable without lane-conflict detection.
            let mut inverse = vec![0u32; rows];
            for (new, &old) in permutation.iter().enumerate() {
                inverse[old as usize] = crate::narrow(new);
            }
            // Elementwise in place; the assert above proves every load into
            // `inverse` is in range.
            for row in &mut self.labelled {
                row.0 = PolyId(inverse[row.0.idx()]);
            }
            self.labelled.sort_unstable();

            debug_assert!(
                self.labelled.windows(2).all(|w| w[0].0 <= w[1].0),
                "the remapped label column is not ascending, which is the one \
                 thing `labels` promises `topology` about it"
            );
        }

        self.poly_path = poly_path;
        self.props = props;
        self.prop_start = prop_start;

        debug_assert_eq!(
            self.poly_path.len(),
            rows,
            "the reorder changed the row count"
        );
        debug_assert_eq!(
            self.prop_start.len(),
            rows + 1,
            "CSR carries one more offset than it has rows"
        );
        debug_assert_eq!(
            self.prop_start.last().copied().unwrap_or(0) as usize,
            self.props.len(),
            "the reorder dropped or duplicated stream properties"
        );
    }

    pub fn path_of(&self, poly: PolyId) -> PathId {
        debug_assert!(
            poly.idx() < self.poly_path.len(),
            "{poly:?} is past the {} provenance rows, so this table was not \
             permuted alongside the store it is keyed by",
            self.poly_path.len()
        );
        self.poly_path[poly.idx()]
    }

    pub fn props_of(&self, poly: PolyId) -> &[(i16, StrId)] {
        crate::csr(&self.prop_start, &self.props, poly.idx())
    }

    /// Every labelled polygon, ascending by [`PolyId`].
    ///
    /// Ordered so `topology`'s label binding is deterministic without sorting.
    pub fn labels(&self) -> &[(PolyId, StrId)] {
        &self.labelled
    }

    pub fn paths(&self) -> &PathTable {
        &self.paths
    }

    /// Intern a hierarchy path into this table's own [`PathTable`], returning
    /// the id [`Self::push`] takes.
    ///
    /// Added in the Testing-Phase. [`PathTable::intern`] needs `&mut` and
    /// [`Self::paths`] hands out a shared reference, so no caller outside this
    /// crate could make a [`PathId`] other than [`PathTable::ROOT`] — the
    /// hierarchy-path column, the one whose mispermutation names the wrong cell
    /// in every violation under an instance, was unreachable from an
    /// integration test and so was `topology`'s label binding against a
    /// labelled instance.
    ///
    /// A method rather than a `paths_mut`: this is the only mutation a caller
    /// needs, and handing out `&mut PathTable` would also hand out the ability
    /// to intern paths no polygon references.
    pub fn intern_path(&mut self, components: &[StrId]) -> PathId {
        self.paths.intern(components)
    }
}

/// The permutation, checked on the column it was written for.
///
/// A unit test because it was written when a non-root [`PathId`] could not be
/// made from outside this crate: [`PathTable::intern`] needs a `&mut` and
/// [`Provenance::paths`] hands out a shared reference only, so every externally
/// built row sat at [`PathTable::ROOT`] and the hierarchy path — the exact
/// column whose mispermutation names the wrong cell — was unreachable.
/// [`Provenance::intern_path`] closed that in the Testing-Phase; these tests
/// stay here, and an integration test may now cover the same ground.
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
