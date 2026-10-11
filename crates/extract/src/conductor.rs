//! A net's conductors: on each layer, the union of the net's drawn polygons,
//! one region per connected piece, each cut into disjoint rectangles.
//!
//! Data in: one net's polygons. Data out: [`Regions`], ascending by layer.
//! The closed forms and the inductance filaments read regions, not drawn
//! polygons, so a wire is the same conductor however it was drawn: pieces
//! that abut share no edge, and pieces that overlap count the overlap once
//! (testing-plan F44, F45). Two pieces that meet only at a corner are one
//! region, as [`merge_into`] joins them (the corner model of
//! [`gpurify_geom::boolean::union_into`]).

use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::derive::merge_into;
use gpurify_geom::rects::{covered_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, GeometryStoreBuilder, LayerId, RingRef};

/// Regions as columns, in the order they were pushed.
#[derive(Debug, Default)]
pub(crate) struct Regions {
    /// The net of each region.
    pub(crate) net: Vec<NetId>,
    /// The layer of each region.
    pub(crate) layer: Vec<LayerId>,
    /// Each region's area.
    pub(crate) area: Vec<DbuArea>,
    /// Each region's perimeter, its holes' included.
    pub(crate) perimeter: Vec<Dbu>,
    /// Region `r` owns `rects[rect_start[r] .. rect_start[r + 1]]`.
    rect_start: Vec<u32>,
    /// Every region's disjoint rectangles, as [`decompose_into`] cuts them:
    /// vertical slabs, ascending in x, each slab's rectangles ascending in y.
    pub(crate) rects: Vec<Bbox>,
    scratch: Scratch,
}

#[derive(Debug, Default)]
struct Scratch {
    drawn: ValidatedLayer,
    merged: ValidatedLayer,
    cut: Vec<Bbox>,
    cut_start: Vec<u32>,
}

impl Regions {
    /// The number of regions.
    pub(crate) fn len(&self) -> usize {
        self.net.len()
    }

    /// Where region `region`'s rectangles sit in [`Self::rects`].
    pub(crate) fn rect_range(&self, region: usize) -> std::ops::Range<usize> {
        self.rect_start[region] as usize..self.rect_start[region + 1] as usize
    }

    /// Region `region`'s rectangles.
    pub(crate) fn rects_of(&self, region: usize) -> &[Bbox] {
        &self.rects[self.rect_range(region)]
    }

    /// Appends `net`'s regions on every layer `keep` accepts, ascending by
    /// layer, each layer's in the order the merge gives them.
    ///
    /// # Errors
    ///
    /// The layer whose shapes of this net do not validate as simple
    /// rectilinear rings, so they cannot be merged exactly. Regions pushed
    /// before it stay.
    pub(crate) fn push_net(
        &mut self,
        store: &GeometryStore,
        nets: &NetTable,
        net: NetId,
        keep: impl Fn(LayerId) -> bool,
    ) -> Result<(), LayerId> {
        if self.rect_start.is_empty() {
            self.rect_start.push(0);
        }
        // A net's polygons ascend by row, and rows are grouped by layer.
        let polys = nets.polys_of(net);
        for group in polys.chunk_by(|&a, &b| store.poly_layer(a) == store.poly_layer(b)) {
            let layer = store.poly_layer(group[0]);
            if !keep(layer) {
                continue;
            }
            let mut builder = GeometryStoreBuilder::with_capacity(group.len(), 0);
            for &poly in group {
                let (xs, ys) = store.poly_verts(poly);
                builder.push(LayerId(0), xs, ys);
            }
            let (drawn, _) = builder.finish(1);
            let scratch = &mut self.scratch;
            validate_layer_into(&drawn, LayerId(0), &mut scratch.drawn).map_err(|_| layer)?;
            // One polygon (holes bound to it) is already its own union.
            let shape = if scratch.drawn.len() > 1 {
                merge_into(&scratch.drawn, &mut scratch.merged).map_err(|_| layer)?;
                &scratch.merged
            } else {
                &scratch.drawn
            };
            decompose_into(shape, &mut scratch.cut, &mut scratch.cut_start);
            for piece in 0..shape.len() {
                let rects = &scratch.cut
                    [scratch.cut_start[piece] as usize..scratch.cut_start[piece + 1] as usize];
                let index = u32::try_from(piece).expect("a polygon index is a u32");
                let perimeter = shape.poly_rings(index).map(ring_length).sum();
                self.net.push(net);
                self.layer.push(layer);
                self.area.push(covered_area(rects));
                self.perimeter.push(Dbu::new_unchecked(perimeter));
                self.rects.extend_from_slice(rects);
                self.rect_start
                    .push(u32::try_from(self.rects.len()).expect("a rectangle count is a u32"));
            }
        }
        Ok(())
    }
}

/// A rectilinear ring's length, its closing edge included.
fn ring_length(ring: RingRef<'_>) -> i64 {
    let (xs, ys) = ring.coords();
    let n = xs.len();
    (0..n)
        .map(|i| {
            let j = (i + 1) % n;
            (xs[j].raw() - xs[i].raw()).abs() + (ys[j].raw() - ys[i].raw()).abs()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::Regions;
    use gpurify_check::topology::net::extract_nets_into;
    use gpurify_check::topology::{NetId, NetTable};
    use gpurify_geom::{Bbox, Dbu, GeometryStoreBuilder, LayerId};
    use gpurify_ingest::deck::Connectivity;

    fn regions_of(rects: &[(i64, i64, i64, i64)]) -> Regions {
        let d = Dbu::new_unchecked;
        let mut builder = GeometryStoreBuilder::default();
        for &(xlo, ylo, xhi, yhi) in rects {
            builder.push(
                LayerId(0),
                &[d(xlo), d(xhi), d(xhi), d(xlo)],
                &[d(ylo), d(ylo), d(yhi), d(yhi)],
            );
        }
        let (store, _) = builder.finish(1);
        let connectivity = Connectivity {
            conductors: vec![LayerId(0)],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&store, &connectivity, &mut nets);
        let mut out = Regions::default();
        for net in 0..nets.net_count() {
            let net = NetId(u32::try_from(net).expect("small"));
            out.push_net(&store, &nets, net, |_| true)
                .expect("rectilinear");
        }
        out
    }

    /// Oracle: definition. A 12 x 1 bar drawn as three abutting pieces, and
    /// an L drawn as two bars that overlap at the corner, are each one
    /// region with the outline's own area and perimeter: 12 and 26 for the
    /// bar; `20 + 12 - 1 = 31` and `2 (20 + 12) = 64` for the L.
    #[test]
    fn pieces_of_one_conductor_are_one_region_with_the_outlines_measures() {
        let bar = regions_of(&[(0, 0, 4, 1), (4, 0, 8, 1), (8, 0, 12, 1)]);
        assert_eq!(bar.len(), 1);
        assert_eq!(bar.area[0].raw(), 12);
        assert_eq!(bar.perimeter[0].raw(), 26);
        let d = Dbu::new_unchecked;
        assert_eq!(
            bar.rects_of(0),
            [Bbox {
                xlo: d(0),
                ylo: d(0),
                xhi: d(12),
                yhi: d(1)
            }]
        );

        let l = regions_of(&[(0, 0, 20, 1), (19, 0, 20, 12)]);
        assert_eq!(l.len(), 1);
        assert_eq!(l.area[0].raw(), 31);
        assert_eq!(l.perimeter[0].raw(), 64);
    }

    /// Oracle: definition (the corner model: material meeting at a corner is
    /// joined). Two 4 x 1 bars meeting only at a corner are one net and one
    /// region, whose area is both bars', 8, and whose outline walks round
    /// both, `2 (4 + 1) + 2 (4 + 1) = 20`.
    #[test]
    fn a_corner_touch_is_one_region_of_one_net() {
        let regions = regions_of(&[(0, 0, 4, 1), (4, 1, 8, 2)]);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions.area[0].raw(), 8);
        assert_eq!(regions.perimeter[0].raw(), 20);
    }
}
