//! Geometry at any size whose net partition and per-layer area are known by
//! construction, so one corpus serves both the benchmark and the assertion.
//!
//! A comb per net — a rail, `fingers` stubs and a cut per stub — with nets in
//! disjoint y bands and blocks in disjoint regions, so no two nets touch.
//! Blocks are placed by recursively quartering a region with the gap scaled by
//! level, which gives the corpus more than one spatial scale.

use gpurify_core::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::Connectivity;

use crate::shapes::{Handle, Ids, LayoutBuilder};
use crate::Rng;

/// How big a corpus to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleSpec {
    /// Fixes the whole corpus. Two runs at one seed are byte-identical.
    pub seed: u64,
    /// Total polygons, rounded down to what a whole comb expresses.
    pub polygons: u32,
    /// Electrically distinct nets. Each becomes one comb.
    pub nets: u32,
    /// Levels of block nesting. One or more.
    pub hierarchy_depth: u8,
}

/// Which layer is which in a corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleLayers {
    /// Rails.
    pub lower: LayerId,
    /// Fingers.
    pub upper: LayerId,
    /// Cuts joining the two.
    pub cut: LayerId,
}

impl ScaleLayers {
    /// The layer table this corpus needs.
    pub const COUNT: usize = 3;
    const LOWER: LayerId = LayerId(0);
    const UPPER: LayerId = LayerId(1);
    const CUT: LayerId = LayerId(2);
}

/// A corpus and everything known about it without running anything.
#[derive(Debug)]
pub struct ScaleCorpus {
    pub store: GeometryStore,
    pub ids: Ids,
    pub layers: ScaleLayers,
    pub connectivity: Connectivity,
    /// `expected_net_polys[n]` is every conductor polygon on net `n`,
    /// ascending. Cuts are not conductors and are not listed.
    pub expected_net_polys: Vec<Vec<PolyId>>,
    /// Covered area per layer, indexed by `LayerId`. Exact: shapes on one
    /// layer never overlap.
    pub layer_area: [i128; ScaleLayers::COUNT],
    /// Polygons actually emitted.
    pub polygons: u32,
    /// Fingers per net.
    pub fingers: u32,
    /// Leaf blocks the nets were spread over.
    pub blocks: u32,
    /// Side of the square region the whole corpus occupies.
    pub extent: i64,
}

/// Rail height, in database units.
const RAIL_HEIGHT: i64 = 200;
/// Distance between the bottoms of adjacent rails. Exceeds `RAIL_HEIGHT` plus
/// the finger height, so nothing in one band reaches the next.
const BAND_PITCH: i64 = 1_000;
/// Finger width and the distance between finger left edges.
const FINGER_WIDTH: i64 = 120;
const FINGER_PITCH: i64 = 400;
/// How far a finger reaches above its rail. Must leave clearance to the band
/// above: `RAIL_HEIGHT + FINGER_HEIGHT` is 800 against a 1000 pitch.
const FINGER_HEIGHT: i64 = 600;
/// Cut side, small enough to sit inside the rail-and-finger overlap.
const CUT_SIZE: i64 = 80;
/// Gap between adjacent leaf blocks at the innermost level.
const BLOCK_GAP: i64 = 4_000;

/// Build the corpus.
#[must_use]
pub fn scale_corpus(spec: ScaleSpec) -> ScaleCorpus {
    assert!(spec.nets > 0, "a corpus needs at least one net");
    assert!(spec.hierarchy_depth > 0, "hierarchy depth starts at one");
    assert!(
        spec.polygons >= 3 * spec.nets,
        "{} polygons cannot express {} nets: a comb is a rail, a finger and a cut",
        spec.polygons,
        spec.nets
    );

    // A comb is 1 + 2 * fingers polygons; round down and report what was
    // emitted rather than silently missing the request.
    let fingers = (spec.polygons / spec.nets - 1) / 2;
    let mut rng = Rng::new(spec.seed);

    // Leaves are `4^(depth-1)`. Computed here rather than read off
    // `origins.len()` because the band stack is sized before `tile` runs.
    let blocks = 4u32.pow(u32::from(spec.hierarchy_depth) - 1);
    let bands = spec.nets.div_ceil(blocks);

    // The block side must cover the taller axis: the rail with its fingers
    // horizontally, and the whole `ceil(nets / blocks)`-band stack vertically.
    // Sizing on the horizontal need alone lets a tall stack overrun into the
    // block above, where a cut bridges two combs and two nets extract as one.
    let block_side = i64::from(fingers + 1) * FINGER_PITCH;
    let block_side = block_side.max(i64::from(bands) * BAND_PITCH);
    let (extent, origins) = tile(spec.hierarchy_depth, block_side, BLOCK_GAP);
    debug_assert_eq!(origins.len(), blocks as usize, "one origin per leaf block");

    // Round-robin then shuffle, so a net's index says nothing about where it
    // is and adjacency in the store cannot be relied on.
    let mut block_of_net: Vec<u32> = (0..spec.nets).map(|n| n % blocks).collect();
    rng.shuffle(&mut block_of_net);

    let mut layout = LayoutBuilder::new(ScaleLayers::COUNT);
    let mut net_handles: Vec<Vec<Handle>> = Vec::with_capacity(spec.nets as usize);
    let mut layer_area = [0i128; ScaleLayers::COUNT];
    let mut band_in_block = vec![0i64; blocks as usize];

    for &block in &block_of_net {
        let (bx, by) = origins[block as usize];
        let band = band_in_block[block as usize];
        band_in_block[block as usize] += 1;
        let y = by + band * BAND_PITCH;

        let rail_width = i64::from(fingers) * FINGER_PITCH + FINGER_WIDTH;
        let mut handles = vec![layout.rect(
            ScaleLayers::LOWER,
            bx,
            y,
            bx + rail_width,
            y + RAIL_HEIGHT,
        )];
        layer_area[ScaleLayers::LOWER.idx()] += i128::from(rail_width) * i128::from(RAIL_HEIGHT);

        for finger in 0..fingers {
            let x = bx + i64::from(finger) * FINGER_PITCH;
            handles.push(layout.rect(
                ScaleLayers::UPPER,
                x,
                y,
                x + FINGER_WIDTH,
                y + FINGER_HEIGHT,
            ));
            layer_area[ScaleLayers::UPPER.idx()] +=
                i128::from(FINGER_WIDTH) * i128::from(FINGER_HEIGHT);

            let cx = x + FINGER_WIDTH / 2 - CUT_SIZE / 2;
            let cy = y + RAIL_HEIGHT / 2 - CUT_SIZE / 2;
            layout.rect(
                ScaleLayers::CUT,
                cx,
                cy,
                cx + CUT_SIZE,
                cy + CUT_SIZE,
            );
            layer_area[ScaleLayers::CUT.idx()] += i128::from(CUT_SIZE) * i128::from(CUT_SIZE);
        }
        net_handles.push(handles);
    }

    let polygons = layout.len();
    let (store, ids) = layout.finish();
    let expected_net_polys = net_handles.iter().map(|h| ids.sorted(h)).collect();

    ScaleCorpus {
        store,
        ids,
        layers: ScaleLayers {
            lower: ScaleLayers::LOWER,
            upper: ScaleLayers::UPPER,
            cut: ScaleLayers::CUT,
        },
        connectivity: Connectivity {
            conductors: vec![ScaleLayers::LOWER, ScaleLayers::UPPER],
            via_cut: vec![ScaleLayers::CUT],
            via_connects: vec![(ScaleLayers::LOWER, ScaleLayers::UPPER)],
            // Off deliberately: every join here is via-mediated.
            intra_layer_touch: false,
            ..Connectivity::default()
        },
        expected_net_polys,
        layer_area,
        polygons,
        fingers,
        blocks,
        extent,
    }
}

/// Recursively quarter a region, returning its side and every leaf origin.
///
/// The gap at each level is `pad * level`, which is what spreads the corpus
/// over more than one spatial scale.
fn tile(depth: u8, leaf: i64, pad: i64) -> (i64, Vec<(i64, i64)>) {
    if depth <= 1 {
        return (leaf, vec![(0, 0)]);
    }
    let (inner, origins) = tile(depth - 1, leaf, pad);
    let step = inner + pad * i64::from(depth);
    let mut out = Vec::with_capacity(origins.len() * 4);
    for quadrant_y in 0..2 {
        for quadrant_x in 0..2 {
            for &(x, y) in &origins {
                out.push((x + quadrant_x * step, y + quadrant_y * step));
            }
        }
    }
    (inner + step, out)
}

#[cfg(test)]
mod tests {
    use super::tile;

    /// Quartering `d` times gives `4^(d-1)` leaves.
    #[test]
    fn tiling_depth_gives_four_to_the_power_of_its_levels() {
        for depth in 1..=5u8 {
            let (_, origins) = tile(depth, 1_000, 100);
            assert_eq!(origins.len(), 4usize.pow(u32::from(depth) - 1));
        }
    }

    /// Leaf origins are distinct and every leaf lies inside the reported
    /// extent.
    #[test]
    fn leaves_are_distinct_and_inside_the_reported_extent() {
        let leaf = 1_000;
        let (extent, origins) = tile(4, leaf, 100);
        let mut sorted = origins.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), origins.len(), "two leaves share an origin");
        for &(x, y) in &origins {
            assert!(x >= 0 && y >= 0, "leaf at ({x}, {y}) is outside the region");
            assert!(
                x + leaf <= extent && y + leaf <= extent,
                "leaf at ({x}, {y}) runs past the extent of {extent}"
            );
        }
    }

    /// Two leaves never overlap, whatever the depth — the property the per-net
    /// partition rests on.
    #[test]
    fn no_two_leaves_overlap() {
        let leaf = 500;
        let (_, origins) = tile(3, leaf, 80);
        for (i, &(x0, y0)) in origins.iter().enumerate() {
            for &(x1, y1) in &origins[i + 1..] {
                let clear = (x1 - x0).abs() >= leaf || (y1 - y0).abs() >= leaf;
                assert!(clear, "leaves at ({x0}, {y0}) and ({x1}, {y1}) overlap");
            }
        }
    }
}
