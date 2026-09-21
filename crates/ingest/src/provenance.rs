//! Cold per-polygon data: where a shape came from, keyed by the same [`PolyId`]
//! as `core`'s `GeometryStore`.

use gpurify_geom::StrId;
use gpurify_geom::{ops::Point, GeometryStore, LayerId, PolyId};

/// One `TEXT` as the layout stated it. A GDS `TEXT` carries no polygon, so
/// binding is a separate later pass: [`Provenance::resolve_labels`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacedLabel {
    /// The label's single `XY` point, in the root frame.
    pub at: Point,
    /// The layer the `TEXT` was drawn on, mapped through the deck.
    pub layer: LayerId,
    /// The `STRING` record's contents, interned.
    pub name: StrId,
}

/// Why a placed label could not be bound to a polygon. A label the deck claims
/// that lands on no shape is a fault, not a no-op: dropping it leaves a net with
/// its geometry and without its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error(
        "a net label on layer {layer:?} at ({x}, {y}) lies on no shape of the conductor it names"
    )]
    Unplaced { layer: LayerId, x: i64, y: i64 },
}

/// A root-to-instance hierarchy path, deduplicated and referenced by id.
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
    /// Ids sorted lexicographic by component id — the binary-search index — so
    /// [`Self::ROOT`] is row 0 of this index as well as of `span`.
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
        // neighbours need checking. An index out of order does not panic, it
        // stops finding duplicates.
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
    /// Labels the reader placed but nothing has bound yet. Not keyed by
    /// [`PolyId`], so [`Self::permute`] leaves it alone.
    placed: Vec<PlacedLabel>,
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
        self.prop_start.push(crate::narrow(self.props.len()));

        debug_assert_eq!(
            self.prop_start.len(),
            self.poly_path.len() + 1,
            "the property column desynchronised from the row count"
        );
    }

    /// Attach a net label to a polygon. Sparse; most polygons have none.
    pub fn label(&mut self, poly: PolyId, name: StrId) {
        // Sorted on insert because ascending order is `labels`'s interface:
        // `topology::port` binds against it without sorting, on a table that may
        // never be permuted, so deferring the sort to `permute` would leave it
        // in nondeterministic reader-encounter order.
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

    /// Reorder into store row order: `permutation[new] == old`, as returned by
    /// `GeometryStoreBuilder::finish`. Called exactly once, by
    /// [`crate::layout::read_layout`].
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
        // In range is not enough: `[0, 0, 2]` passes the check above while
        // duplicating one row's provenance over another's.
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

        let mut poly_path = Vec::with_capacity(rows);
        for &old in permutation {
            poly_path.push(self.poly_path[old as usize]);
        }
        debug_assert_eq!(poly_path.len(), rows, "the gather dropped a row");

        // The property column is CSR, so this is a segmented gather.
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
                    let mut ok = true;
                    for i in 0..self.labelled.len() {
                        ok &= self.labelled[i].0.idx() < rows;
                    }
                    ok
                },
                "a label names an arrival row this permutation does not cover"
            );

            let mut inverse = vec![0u32; rows];
            for (new, &old) in permutation.iter().enumerate() {
                inverse[old as usize] = crate::narrow(new);
            }
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

    /// How many polygons this table describes. Must equal
    /// `GeometryStore::poly_count`.
    pub fn len(&self) -> usize {
        // The CSR carries one offset more than it has rows, once seeded at all —
        // the first `push` seeds it, and a `permute` of nothing does not unseed.
        debug_assert!(
            self.prop_start.is_empty() || self.prop_start.len() == self.poly_path.len() + 1,
            "the property column desynchronised from the row count"
        );
        self.poly_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    /// Record a `TEXT` where the layout drew it, bound to nothing. The point is
    /// already in the root frame.
    pub fn place_label(&mut self, at: Point, layer: LayerId, name: StrId) {
        self.placed.push(PlacedLabel { at, layer, name });
    }

    /// Every label the layout declared, in file order, bound or not.
    pub fn placed_labels(&self) -> &[PlacedLabel] {
        &self.placed
    }

    /// Bind each placed label to the polygon it sits on.
    ///
    /// Must run after `read_layout` has flattened and permuted: a label's point
    /// is in the root frame only after flattening, and its [`PolyId`] is a store
    /// row only after the layer sort. Which text names which conductor comes
    /// from `Connectivity::label_layer`; a text on an unpaired layer is
    /// documentation. The boundary counts as inside, lowest matching row wins.
    ///
    /// # Errors
    ///
    /// [`LabelError::Unplaced`] for a claimed label on no shape. Fail closed:
    /// the alternative is a net that quietly loses its name.
    pub fn resolve_labels(
        &mut self,
        store: &GeometryStore,
        connectivity: &crate::deck::Connectivity,
    ) -> Result<(), LabelError> {
        debug_assert_eq!(
            connectivity.label_layer.len(),
            connectivity.label_names.len(),
            "the deck's label pairing columns arrive parallel"
        );

        for index in 0..self.placed.len() {
            let label = self.placed[index];
            let mut bound = None;

            // ponytail: linear scan of the paired layer per label, bbox-pruned.
            // The ceiling is labels × polygons-on-that-layer, and the upgrade
            // path is a point query on `core::index::SpatialIndex` — which does
            // not have one today, only the pairwise `candidate_pairs_into`, so
            // taking it is a new interface in `core` rather than a call. A real
            // design labels ports and rails, hundreds of texts against millions
            // of shapes, and the prune below is what keeps that a scan of a
            // `Bbox` column rather than of vertex rings.
            for row in 0..connectivity.label_layer.len() {
                if connectivity.label_layer[row] != label.layer {
                    continue;
                }
                let conductor = connectivity.label_names[row];
                for poly in store.polys_on_layer(conductor) {
                    let poly = PolyId(poly);
                    // A point outside a shape's box is outside the shape.
                    let box_of = store.poly_bbox(poly);
                    let inside_box = (label.at.x.raw() >= box_of.xlo.raw())
                        & (label.at.x.raw() <= box_of.xhi.raw())
                        & (label.at.y.raw() >= box_of.ylo.raw())
                        & (label.at.y.raw() <= box_of.yhi.raw());
                    if inside_box && store.poly_contains_point(poly, label.at) {
                        bound = Some(poly);
                        break;
                    }
                }
                if bound.is_some() {
                    break;
                }
            }

            // A text on an unpaired layer is not claimed and not a fault; a
            // claimed one that landed nowhere is.
            let claimed = connectivity.label_layer.contains(&label.layer);
            match bound {
                Some(poly) => self.label(poly, label.name),
                None if claimed => {
                    return Err(LabelError::Unplaced {
                        layer: label.layer,
                        x: label.at.x.raw(),
                        y: label.at.y.raw(),
                    })
                }
                None => {}
            }
        }

        debug_assert!(
            self.labelled.windows(2).all(|w| w[0].0 <= w[1].0),
            "the label column is what `topology` binds without sorting"
        );
        Ok(())
    }

    pub fn paths(&self) -> &PathTable {
        &self.paths
    }

    /// Intern a hierarchy path into this table's own [`PathTable`], returning
    /// the id [`Self::push`] takes.
    pub fn intern_path(&mut self, components: &[StrId]) -> PathId {
        self.paths.intern(components)
    }
}

#[cfg(test)]
mod tests {
    use super::Provenance;
    use gpurify_geom::PolyId;
    use gpurify_geom::StrTable;

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

    /// The identity permutation is a no-op.
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
