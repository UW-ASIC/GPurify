//! A net's conductors: on each layer, the union of the net's drawn polygons,
//! one region per piece that current can cross, each cut into disjoint
//! rectangles.
//!
//! Data in: one net's polygons. Data out: [`Regions`], ascending by layer.
//! The closed forms and the inductance filaments read regions, not drawn
//! polygons, so a wire is the same conductor however it was drawn: pieces
//! that abut share no edge, and pieces that overlap count the overlap once
//! (testing-plan F44, F45). A region is edge-connected: [`merge_into`] joins
//! two pieces that meet only at a corner into one polygon (the corner model
//! of [`gpurify_geom::boolean::union_into`]), but a corner is a neck of zero
//! width that carries no current, so the merged polygon is split there into
//! its pieces that share an edge of positive length (testing-plan F76).

use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::derive::merge_into;
use gpurify_geom::rects::{covered_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, GeometryStoreBuilder, LayerId};

/// Regions as columns, in the order they were pushed.
#[derive(Debug, Default)]
pub(crate) struct Regions {
    /// The net of each region.
    pub(crate) net: Vec<NetId>,
    /// The layer of each region.
    pub(crate) layer: Vec<LayerId>,
    /// Each region's area.
    pub(crate) area: Vec<DbuArea>,
    /// Each region's perimeter, its holes' included; a corner it touches
    /// another region at adds nothing.
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
    piece: Pieces,
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
    /// layer, each layer's in the order the merge gives them; a merged
    /// polygon split at a corner gives its pieces in the order of their first
    /// rectangles, each keeping its rectangles' order.
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
            for polygon in 0..shape.len() {
                let rects = &scratch.cut
                    [scratch.cut_start[polygon] as usize..scratch.cut_start[polygon + 1] as usize];
                scratch.piece.split(rects);
                for (piece, &shared) in scratch.piece.shared.iter().enumerate() {
                    let mut perimeter = -2 * shared;
                    let first = self.rects.len();
                    for (&rect, &of) in rects.iter().zip(&scratch.piece.label) {
                        if of as usize == piece {
                            perimeter += 2 * (rect.width().raw() + rect.height().raw());
                            self.rects.push(rect);
                        }
                    }
                    self.net.push(net);
                    self.layer.push(layer);
                    self.area.push(covered_area(&self.rects[first..]));
                    self.perimeter.push(Dbu::new_unchecked(perimeter));
                    self.rect_start
                        .push(u32::try_from(self.rects.len()).expect("a rectangle count is a u32"));
                }
            }
        }
        Ok(())
    }
}

/// One merged polygon's rectangles split into the pieces that share an edge
/// of positive length: the polygon less the corners it touches itself at.
#[derive(Debug, Default)]
struct Pieces {
    /// The piece of each rectangle, numbered in order of first rectangle.
    label: Vec<u32>,
    /// Per piece, the length of the edges its rectangles share, which its
    /// perimeter does not count.
    shared: Vec<i64>,
    /// Union-find parents, by rectangle.
    parent: Vec<u32>,
    /// `(rectangle, length)` of every shared edge.
    edge: Vec<(u32, i64)>,
}

impl Pieces {
    /// Splits `rects`, as [`decompose_into`] cuts one polygon: vertical slabs
    /// ascending in x, each slab's rectangles ascending in y and disjoint. So
    /// two rectangles share an edge only stacked in one slab or side by side
    /// in two slabs that abut, and a sweep finds every such pair.
    fn split(&mut self, rects: &[Bbox]) {
        let n = u32::try_from(rects.len()).expect("a rectangle count is a u32");
        self.parent.clear();
        self.parent.extend(0..n);
        self.edge.clear();
        let slab_of = |r: &Bbox| (r.xlo, r.xhi);
        let mut slab = 0;
        while slab < rects.len() {
            let end = slab + rects[slab..].partition_point(|r| slab_of(r) == slab_of(&rects[slab]));
            for k in slab + 1..end {
                if rects[k - 1].yhi == rects[k].ylo {
                    self.join(k - 1, k, rects[k].width().raw());
                }
            }
            // The next slab, if it abuts this one: walk both columns up.
            // (An empty tail never calls the predicate, so `rects[end]` is
            // read only when it exists.)
            let next = end + rects[end..].partition_point(|r| slab_of(r) == slab_of(&rects[end]));
            if next > end && rects[end].xlo == rects[slab].xhi {
                let (mut i, mut j) = (slab, end);
                while i < end && j < next {
                    let overlap = rects[i].yhi.raw().min(rects[j].yhi.raw())
                        - rects[i].ylo.raw().max(rects[j].ylo.raw());
                    if overlap > 0 {
                        self.join(i, j, overlap);
                    }
                    if rects[i].yhi <= rects[j].yhi {
                        i += 1;
                    } else {
                        j += 1;
                    }
                }
            }
            slab = end;
        }
        self.label.clear();
        self.shared.clear();
        let mut piece_of_root = vec![u32::MAX; rects.len()];
        for k in 0..rects.len() {
            let root = self.root(k) as usize;
            if piece_of_root[root] == u32::MAX {
                piece_of_root[root] =
                    u32::try_from(self.shared.len()).expect("a piece count is a u32");
                self.shared.push(0);
            }
            self.label.push(piece_of_root[root]);
        }
        for &(k, length) in &self.edge {
            self.shared[self.label[k as usize] as usize] += length;
        }
    }

    fn root(&mut self, mut k: usize) -> u32 {
        while self.parent[k] as usize != k {
            let up = self.parent[k] as usize;
            self.parent[k] = self.parent[up];
            k = up;
        }
        u32::try_from(k).expect("a rectangle index is a u32")
    }

    fn join(&mut self, a: usize, b: usize, length: i64) {
        let (ra, rb) = (self.root(a), self.root(b));
        self.parent[ra.max(rb) as usize] = ra.min(rb);
        self.edge.push((
            u32::try_from(a).expect("a rectangle index is a u32"),
            length,
        ));
    }
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

    /// Oracle: definition (F76: a corner is a neck of zero width, which
    /// carries no current). Two 4 x 1 bars meeting only at a corner are one
    /// net, which the merge makes one polygon, but two regions: each its own
    /// bar, area 4 and perimeter `2 (4 + 1) = 10`, in the order of their first
    /// rectangles. Read as one region they were the rectangle of area 8 and
    /// perimeter 20, `(5 + √17) / (5 − √17)`, about 10.4 squares through a point.
    #[test]
    fn a_corner_touch_is_two_regions_of_one_net() {
        let regions = regions_of(&[(0, 0, 4, 1), (4, 1, 8, 2)]);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions.net[0], regions.net[1]);
        let d = Dbu::new_unchecked;
        for (region, (xlo, ylo)) in [(0, 0), (4, 1)].into_iter().enumerate() {
            assert_eq!(regions.area[region].raw(), 4);
            assert_eq!(regions.perimeter[region].raw(), 10);
            assert_eq!(
                regions.rects_of(region),
                [Bbox {
                    xlo: d(xlo),
                    ylo: d(ylo),
                    xhi: d(xlo + 4),
                    yhi: d(ylo + 1)
                }]
            );
        }
    }

    /// Oracle: definition. A figure that touches itself at a corner but is
    /// edge-connected throughout stays one region: the cells `###`, `#.#`,
    /// `.##` (top row first) are seven unit squares joined by six shared
    /// edges, so area 7 and perimeter `7 * 4 - 2 * 6 = 16`, the outer
    /// outline's 12 plus the enclosed cell's 4.
    #[test]
    fn a_figure_touching_itself_at_a_corner_is_one_region() {
        let regions = regions_of(&[(0, 2, 3, 3), (0, 1, 1, 2), (2, 0, 3, 2), (1, 0, 2, 1)]);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions.area[0].raw(), 7);
        assert_eq!(regions.perimeter[0].raw(), 16);
    }
}
