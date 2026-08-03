//! Net extraction: which shapes are electrically the same conductor.
//!
//! Two shapes join if they are on the same conductor layer and touch, or if a
//! via cut on the right layer overlaps both. That is the whole rule; everything
//! else is finding the pairs efficiently, which is `core::index`'s job, and
//! labelling the components, which is `core::connectivity`'s.

use gpurify_core::connectivity::ComponentLabel;
use gpurify_core::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::Connectivity;

/// Identifies one electrical net.
///
/// Derived from a [`ComponentLabel`], which is the minimum polygon index in the
/// component — so net ids are canonical: the same layout gives the same ids on
/// every run and every machine, regardless of thread count. The determinism
/// gate rests on that, and so does any test comparing extracted nets by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NetId(pub u32);

/// Which net each polygon belongs to.
///
/// **Five questions.** In: a store and the deck's connectivity rules. Out: one
/// [`NetId`] per polygon, plus the reverse index. How many: one row per
/// polygon, millions. Access pattern: `poly_net` is read randomly by rules
/// asking "same net?"; `net_polys` is scanned per net by resistance and
/// antenna rules — so both directions exist, and the reverse one is CSR.
/// Lifetime: whole run. Parallelisable: pair-finding is; the union-find is not,
/// which is why it is a separate sequential pass over a precomputed edge list.
#[derive(Debug, Default)]
pub struct NetTable {
    /// Net of each polygon, indexed by [`PolyId`].
    poly_net: Vec<NetId>,
    /// `polys[net_start[n] .. net_start[n + 1]]` are net `n`'s polygons,
    /// ascending. CSR, not a `Vec<Vec<PolyId>>`.
    net_start: Vec<u32>,
    polys: Vec<PolyId>,
    /// Scratch, kept so a second extraction reuses the allocation.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
}

impl NetTable {
    pub fn net_count(&self) -> usize {
        todo!()
    }

    pub fn net_of(&self, poly: PolyId) -> NetId {
        todo!()
    }

    /// The polygons on one net, ascending by [`PolyId`].
    pub fn polys_of(&self, net: NetId) -> &[PolyId] {
        todo!()
    }

    /// Whether two polygons are the same net. The question most rules ask.
    pub fn same_net(&self, a: PolyId, b: PolyId) -> bool {
        todo!()
    }
}

/// Extract nets from geometry.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled; its internal
/// scratch survives, so extracting twice allocates once.
///
/// Two passes, deliberately. The first builds the edge list — intra-layer
/// touching and via-mediated joins — and is a pure function of the geometry,
/// so it parallelises by layer. The second runs the union-find, which is
/// inherently sequential. Fusing them would make the whole thing sequential for
/// no gain; this is the "take two passes instead" case the kernel rule names.
pub fn extract_nets_into(
    store: &GeometryStore,
    connectivity: &Connectivity,
    out: &mut NetTable,
) {
    todo!()
}

/// Edges from shapes touching on one conductor layer.
///
/// **Transform, gatherer.** Separate and public because it is independently
/// testable: a table of touching and non-touching configurations, with the
/// answer known by construction.
pub fn intra_layer_edges_into(
    store: &GeometryStore,
    layer: LayerId,
    out: &mut Vec<(u32, u32)>,
) {
    todo!()
}

/// Edges from a via cut overlapping shapes on the two layers it joins.
///
/// A cut overlapping only one of the two is not an error — a stacked via array
/// produces those — but it contributes no edge.
pub fn via_edges_into(
    store: &GeometryStore,
    cut: LayerId,
    connects: (LayerId, LayerId),
    out: &mut Vec<(u32, u32)>,
) {
    todo!()
}
