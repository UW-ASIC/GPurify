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
        let mut bound: Vec<Option<PolyId>> = vec![None; self.placed.len()];
        let mut pending = Vec::new();
        for (&text, &conductor) in connectivity
            .label_layer
            .iter()
            .zip(&connectivity.label_names)
        {
            // An earlier row's binding stands.
            pending.clear();
            pending.extend(
                (0..self.placed.len())
                    .filter(|&i| bound[i].is_none() && self.placed[i].layer == text),
            );
            bind_on_layer(store, conductor, &self.placed, &mut pending, &mut bound);
        }

        for (label, poly) in self.placed.iter().zip(bound) {
            match poly {
                Some(poly) => self.labelled.push((poly, label.name)),
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
        // Stable: equal ids keep arrival order, as `label` would have.
        self.labelled.sort_by_key(|&(poly, _)| poly);
        Ok(())
    }
}

/// For each label in `pending`, the lowest-id polygon on `layer` holding it on
/// material, or `None`. A sweep in x: labels in x order, polygons entering by
/// `xlo` and leaving past `xhi`, so each label tests only the boxes spanning its x.
fn bind_on_layer(
    store: &GeometryStore,
    layer: LayerId,
    placed: &[PlacedLabel],
    pending: &mut [usize],
    bound: &mut [Option<PolyId>],
) {
    let first = store.polys_on_layer(layer).start;
    let boxes = store.layer_bboxes(layer);
    let mut by_xlo: Vec<u32> = (0..crate::narrow(boxes.len())).collect();
    by_xlo.sort_unstable_by_key(|&i| boxes[i as usize].xlo);
    pending.sort_unstable_by_key(|&i| placed[i].at.x);

    let (mut entered, mut active, mut hits) = (0, Vec::new(), Vec::new());
    for &label in pending.iter() {
        let p = placed[label].at;
        while let Some(&i) = by_xlo
            .get(entered)
            .filter(|&&i| boxes[i as usize].xlo <= p.x)
        {
            active.push(i);
            entered += 1;
        }
        active.retain(|&i| boxes[i as usize].xhi >= p.x);

        hits.clear();
        hits.extend(active.iter().filter_map(|&i| {
            let b = boxes[i as usize];
            let poly = PolyId(first + i);
            (b.ylo <= p.y && p.y <= b.yhi && store.poly_contains_point(poly, p)).then_some(poly)
        }));
        hits.sort_unstable();
        bound[label] = hits
            .iter()
            .copied()
            .find(|&poly| !in_hole_of(store, poly, p, &hits));
    }
}

/// Whether `p` sits in a hole of `poly` rather than on its material: a hole row
/// is never a label target, and neither is an outer holding a smaller hole row
/// that holds `p` strictly. `hits` is every row on the layer containing `p`, so
/// every candidate hole. A point on a hole's edge is material.
fn in_hole_of(store: &GeometryStore, poly: PolyId, p: Point, hits: &[PolyId]) -> bool {
    use gpurify_geom::ops::{area2, winding_of, Winding};
    let (xs, ys) = store.poly_verts(poly);
    if winding_of(xs, ys) == Some(Winding::Clockwise) {
        return true;
    }
    let outer_area = area2(xs, ys).raw().abs();
    hits.iter().any(|&hole| {
        let (hx, hy) = store.poly_verts(hole);
        winding_of(hx, hy) == Some(Winding::Clockwise)
            && area2(hx, hy).raw().abs() < outer_area
            && store.poly_contains_point(poly, Point { x: hx[0], y: hy[0] })
            && !on_ring(hx, hy, p)
    })
}

/// Whether `p` lies on an edge of the ring.
fn on_ring(xs: &[gpurify_geom::Dbu], ys: &[gpurify_geom::Dbu], p: Point) -> bool {
    let n = xs.len();
    (0..n).any(|i| {
        let j = if i + 1 == n { 0 } else { i + 1 };
        let (ax, ay, bx, by) = (xs[i].raw(), ys[i].raw(), xs[j].raw(), ys[j].raw());
        let (px, py) = (p.x.raw(), p.y.raw());
        let cross =
            i128::from(bx - ax) * i128::from(py - ay) - i128::from(by - ay) * i128::from(px - ax);
        cross == 0 && px >= ax.min(bx) && px <= ax.max(bx) && py >= ay.min(by) && py <= ay.max(by)
    })
}
