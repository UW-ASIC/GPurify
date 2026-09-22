//! Net labels: `TEXT` points as the layout placed them, and the polygons they bind to.
//!
//! Data in: [`PlacedLabel`]s in the root frame, a finished `GeometryStore`, the deck's label pairing.
//! Data out: `(PolyId, StrId)` rows ascending by `PolyId`.

use gpurify_geom::StrId;
use gpurify_geom::{ops::Point, GeometryStore, LayerId, PolyId};

/// One `TEXT` as the layout stated it, point already in the root frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacedLabel {
    pub at: Point,
    /// The layer the `TEXT` was drawn on, mapped through the deck.
    pub layer: LayerId,
    pub name: StrId,
}

/// A label the deck claims that lands on no shape: failing closed keeps a net from losing its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error(
        "a net label on layer {layer:?} at ({x}, {y}) lies on no shape of the conductor it names"
    )]
    Unplaced { layer: LayerId, x: i64, y: i64 },
}

/// Placed labels, and the ones bound to a polygon.
#[derive(Debug, Default)]
pub struct Provenance {
    /// Ascending by `PolyId`, arrival order kept among equal ids.
    labelled: Vec<(PolyId, StrId)>,
    pub(crate) placed: Vec<PlacedLabel>,
}

impl Provenance {
    /// Attach a net label to a polygon, keeping [`Self::labels`] ascending.
    pub fn label(&mut self, poly: PolyId, name: StrId) {
        let at = self
            .labelled
            .partition_point(|&(labelled, _)| labelled <= poly);
        self.labelled.insert(at, (poly, name));
    }

    /// Every labelled polygon, ascending by [`PolyId`]; `topology` binds against it without sorting.
    pub fn labels(&self) -> &[(PolyId, StrId)] {
        &self.labelled
    }

    /// Record a `TEXT` where the layout drew it, bound to nothing yet.
    pub fn place_label(&mut self, at: Point, layer: LayerId, name: StrId) {
        self.placed.push(PlacedLabel { at, layer, name });
    }

    /// Bind each placed label to the polygon it sits on. Run after the store is finished.
    ///
    /// The boundary counts as inside; the first pairing row, then the lowest `PolyId`, wins.
    /// A text on a layer no pairing row names binds nothing.
    ///
    /// # Errors
    ///
    /// [`LabelError::Unplaced`] for a claimed label on no shape.
    pub fn resolve_labels(
        &mut self,
        store: &GeometryStore,
        connectivity: &crate::deck::Connectivity,
    ) -> Result<(), LabelError> {
        for index in 0..self.placed.len() {
            let label = self.placed[index];
            let mut bound = None;

            // ponytail: labels × polygons-on-layer scan, bbox-pruned; a point query on the spatial index is the upgrade.
            'rows: for row in 0..connectivity.label_layer.len() {
                if connectivity.label_layer[row] != label.layer {
                    continue;
                }
                for poly in store.polys_on_layer(connectivity.label_names[row]) {
                    let poly = PolyId(poly);
                    let box_of = store.poly_bbox(poly);
                    let inside_box = (label.at.x.raw() >= box_of.xlo.raw())
                        & (label.at.x.raw() <= box_of.xhi.raw())
                        & (label.at.y.raw() >= box_of.ylo.raw())
                        & (label.at.y.raw() <= box_of.yhi.raw());
                    if inside_box && store.poly_contains_point(poly, label.at) {
                        bound = Some(poly);
                        break 'rows;
                    }
                }
            }

            match bound {
                Some(poly) => self.label(poly, label.name),
                None if connectivity.label_layer.contains(&label.layer) => {
                    return Err(LabelError::Unplaced {
                        layer: label.layer,
                        x: label.at.x.raw(),
                        y: label.at.y.raw(),
                    })
                }
                None => {}
            }
        }
        Ok(())
    }
}
