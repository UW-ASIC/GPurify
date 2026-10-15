//! Net labels: `TEXT` points as the layout placed them, and the polygons they bind to.
//!
//! Data in: [`PlacedLabel`]s in the root frame, a finished `GeometryStore`, the deck's label pairing.
//! Data out: `(PolyId, StrId)` rows ascending by `PolyId`.

use gpurify_geom::StrId;
use gpurify_geom::{ops::Point, Bbox, GeometryStore, LayerId, PolyId};

/// One `TEXT` as the layout stated it, point already in the root frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacedLabel {
    /// Where the text's anchor point lands in the root cell, in database units.
    pub at: Point,
    /// The layer the `TEXT` was drawn on, mapped through the deck.
    pub layer: LayerId,
    /// The text's string, interned: a net name when the layer is a label layer.
    pub name: StrId,
}

/// One placement of a cell the deck's `lvs blackbox` names, in the root
/// frame ([`gds::Library::black_boxes`](crate::layout::gds::Library::black_boxes)):
/// LVS compares it by its pins alone (catalog LVS-033).
#[derive(Debug, Clone, PartialEq)]
pub struct BlackBox {
    /// The placed cell's name.
    pub cell: StrId,
    /// The extent of every shape placed under it, on any layer: a device
    /// inside it is the box's own and is left out of the comparison.
    pub extent: Bbox,
    /// The cell's own `TEXT`s, placed: its pins, each naming the subcircuit
    /// port it is.
    pub pins: Vec<PlacedLabel>,
}

/// A label the deck claims that lands on no shape: failing closed keeps a net from losing its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    /// A `TEXT` on a deck label layer lies on no shape of any conductor its
    /// label rows name, holes counting as no shape.
    #[error(
        "a net label on layer {layer:?} at ({x}, {y}) lies on no shape of the conductor it names"
    )]
    Unplaced {
        /// The label layer the text was drawn on.
        layer: LayerId,
        /// The text's x, in database units of the root frame.
        x: i64,
        /// The text's y, in database units of the root frame.
        y: i64,
    },
}

/// Placed labels, and the ones bound to a polygon.
///
/// Filled in two steps: [`gds::Library::flatten`](crate::layout::gds::Library::flatten)
/// places every `TEXT`, then [`Self::resolve_labels`] binds the ones on label
/// layers to the store rows under them.
#[derive(Debug, Default)]
pub struct Provenance {
    /// Ascending by `PolyId`, arrival order kept among equal ids.
    labelled: Vec<(PolyId, StrId)>,
    /// The rows [`Self::label`] attached, in arrival order: what a
    /// [`Self::resolve_labels`] call keeps when it rebinds.
    attached: Vec<(PolyId, StrId)>,
    pub(crate) placed: Vec<PlacedLabel>,
    /// The black boxes, as [`Self::set_black_boxes`] gave them.
    boxes: Vec<BlackBox>,
    /// `(box, polygon, name)` for each box pin on a label layer, bound by
    /// [`Self::resolve_labels`], ascending by box.
    box_pins: Vec<(u32, PolyId, StrId)>,
}

impl Provenance {
    /// Attaches a net label to a polygon, keeping [`Self::labels`] ascending;
    /// after any existing labels of the same polygon. `O(n)` per call.
    pub fn label(&mut self, poly: PolyId, name: StrId) {
        let at = self
            .labelled
            .partition_point(|&(labelled, _)| labelled <= poly);
        self.labelled.insert(at, (poly, name));
        self.attached.push((poly, name));
    }

    /// Every labelled polygon, ascending by [`PolyId`]; `topology` binds against it without sorting.
    pub fn labels(&self) -> &[(PolyId, StrId)] {
        &self.labelled
    }

    /// Every `TEXT` as placed, in arrival order, bound or not.
    pub fn placed(&self) -> &[PlacedLabel] {
        &self.placed
    }

    /// The black boxes [`Self::set_black_boxes`] recorded, in its order.
    pub fn black_boxes(&self) -> &[BlackBox] {
        &self.boxes
    }

    /// Every black-box pin [`Self::resolve_labels`] bound: `(box, polygon,
    /// name)`, the box an index into [`Self::black_boxes`], ascending by
    /// box. A pin on a layer no label row names is documentation and binds
    /// nothing.
    pub fn black_box_pins(&self) -> &[(u32, PolyId, StrId)] {
        &self.box_pins
    }

    /// Records the layout's black boxes, whose pins the next
    /// [`Self::resolve_labels`] binds. Their pins never name a net: a
    /// sub-cell's text is no port.
    pub fn set_black_boxes(&mut self, boxes: Vec<BlackBox>) {
        self.boxes = boxes;
        self.box_pins.clear();
    }

    /// Record a `TEXT` where the layout drew it, bound to nothing yet.
    pub fn place_label(&mut self, at: Point, layer: LayerId, name: StrId) {
        self.placed.push(PlacedLabel { at, layer, name });
    }

    /// Binds each placed label to the polygon it sits on. Run after the store
    /// is finished and its derived layers appended. Each call rebinds from
    /// scratch: what an earlier call bound is replaced, never duplicated, and
    /// what [`Self::label`] attached is kept. One sweep in x per label row:
    /// each text tests only the shapes whose box spans its x.
    ///
    /// The boundary counts as inside; the first pairing row, then the lowest `PolyId`, wins.
    /// A text on a layer no pairing row names binds nothing. Black-box pins
    /// ([`Self::set_black_boxes`]) are bound the same way, apart.
    ///
    /// # Errors
    ///
    /// [`LabelError::Unplaced`] for a claimed label, or a black-box pin on a
    /// label layer, on no shape.
    pub fn resolve_labels(
        &mut self,
        store: &GeometryStore,
        connectivity: &crate::deck::Connectivity,
    ) -> Result<(), LabelError> {
        let bound = bind_all(store, connectivity, &self.placed);
        self.labelled.clone_from(&self.attached);
        for (label, poly) in self.placed.iter().zip(bound) {
            if let Some(poly) = claimed(label, poly, connectivity)? {
                self.labelled.push((poly, label.name));
            }
        }
        // Stable: equal ids keep arrival order, as `label` would have.
        self.labelled.sort_by_key(|&(poly, _)| poly);

        let pins: Vec<(u32, PlacedLabel)> = (0..)
            .zip(&self.boxes)
            .flat_map(|(at, black_box)| black_box.pins.iter().map(move |&pin| (at, pin)))
            .collect();
        let labels: Vec<PlacedLabel> = pins.iter().map(|&(_, pin)| pin).collect();
        let bound = bind_all(store, connectivity, &labels);
        self.box_pins.clear();
        for (&(at, pin), poly) in pins.iter().zip(bound) {
            if let Some(poly) = claimed(&pin, poly, connectivity)? {
                self.box_pins.push((at, poly, pin.name));
            }
        }
        Ok(())
    }
}

/// The polygon each of `placed` binds to, by the first label row naming
/// its layer that finds a shape under it, or `None`.
fn bind_all(
    store: &GeometryStore,
    connectivity: &crate::deck::Connectivity,
    placed: &[PlacedLabel],
) -> Vec<Option<PolyId>> {
    let mut bound: Vec<Option<PolyId>> = vec![None; placed.len()];
    let mut pending = Vec::new();
    for (&text, &conductor) in connectivity
        .label_layer
        .iter()
        .zip(&connectivity.label_names)
    {
        // An earlier row's binding stands.
        pending.clear();
        pending
            .extend((0..placed.len()).filter(|&i| bound[i].is_none() && placed[i].layer == text));
        bind_on_layer(store, conductor, placed, &mut pending, &mut bound);
    }
    bound
}

/// `poly`, the binding of `label`; an error when `label` is on a label
/// layer and bound nothing, `None` when it is on no label layer.
fn claimed(
    label: &PlacedLabel,
    poly: Option<PolyId>,
    connectivity: &crate::deck::Connectivity,
) -> Result<Option<PolyId>, LabelError> {
    match poly {
        Some(poly) => Ok(Some(poly)),
        None if connectivity.label_layer.contains(&label.layer) => Err(LabelError::Unplaced {
            layer: label.layer,
            x: label.at.x.raw(),
            y: label.at.y.raw(),
        }),
        None => Ok(None),
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
