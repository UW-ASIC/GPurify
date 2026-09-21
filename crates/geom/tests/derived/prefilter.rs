//! Moved out of `prefilter.rs`: the fixtures come from `gpurify-testgen`,
//! which depends on this crate, so they cannot be a unit test.

//! The completeness property, asserted at the observer seam against
//! exhaustive pairing of extents the test itself chose.

use gpurify_geom::prefilter::{candidates_observed, ObservePrefilter};
use gpurify_geom::observe::Observer;
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_testgen::shapes::{Handle, Ids, LayoutBuilder};
use gpurify_testgen::Rng;

const OPERAND_A: LayerId = LayerId(0);
const OPERAND_B: LayerId = LayerId(1);
const LAYER_COUNT: usize = 2;

/// An inclusive bounding box, as the test wrote it.
type Extent = [i64; 4];

/// Records both halves of the seam, in the order they were reported.
#[derive(Debug, Default)]
struct Record {
    kept: Vec<(PolyId, PolyId)>,
    rejected: Vec<(PolyId, PolyId)>,
}

impl Observer for Record {
    const ENABLED: bool = true;
}

impl ObservePrefilter for Record {
    fn kept(&mut self, a: PolyId, b: PolyId) {
        self.kept.push((a, b));
    }
    fn rejected(&mut self, a: PolyId, b: PolyId) {
        self.rejected.push((a, b));
    }
}

/// Do two boxes share at least one point? Inclusive: touching counts, which
/// is the direction that fails closed — a shared edge merges under a union.
fn overlaps(p: Extent, q: Extent) -> bool {
    p[0] <= q[2] && q[0] <= p[2] && p[1] <= q[3] && q[1] <= p[3]
}

/// Rectangles whose extents the caller keeps, so the expected answer never
/// comes from a second reading of the store.
fn push_rects(layout: &mut LayoutBuilder, layer: LayerId, boxes: &[Extent]) -> Vec<Handle> {
    boxes
        .iter()
        .map(|&[xlo, ylo, xhi, yhi]| layout.rect(layer, xlo, ylo, xhi, yhi))
        .collect()
}

/// Pseudo-random rectangles in a window small enough that both overlapping
/// and disjoint pairs are common.
fn random_extents(rng: &mut Rng, count: usize, window: i64, max_side: i64) -> Vec<Extent> {
    (0..count)
        .map(|_| {
            let xlo = rng.range(-window, window);
            let ylo = rng.range(-window, window);
            [
                xlo,
                ylo,
                xlo + rng.range(1, max_side + 1),
                ylo + rng.range(1, max_side + 1),
            ]
        })
        .collect()
}

/// Extents indexed by the store row each rectangle became.
fn by_poly_id(ids: &Ids, groups: &[(&[Handle], &[Extent])], total: usize) -> Vec<Extent> {
    let mut table = vec![[0i64; 4]; total];
    for (handles, boxes) in groups {
        for (&handle, &extent) in handles.iter().zip(*boxes) {
            table[ids.of(handle).idx()] = extent;
        }
    }
    table
}

/// Validate both layers of a store into fresh buffers.
fn validated(store: &GeometryStore) -> (ValidatedLayer, ValidatedLayer) {
    let mut a = ValidatedLayer::default();
    let mut b = ValidatedLayer::default();
    validate_layer_into(store, OPERAND_A, &mut a).expect("rectangles are valid geometry");
    validate_layer_into(store, OPERAND_B, &mut b).expect("rectangles are valid geometry");
    (a, b)
}

/// No rejected pair overlaps is the correctness claim; every overlapping
/// pair surviving stops a prune from emitting nothing.
#[test]
fn no_rejected_pair_could_have_contributed_to_the_exact_result() {
    for seed in [1u64, 2, 3, 5, 8] {
        let mut rng = Rng::new(seed);
        let a_boxes = random_extents(&mut rng, 8, 300, 180);
        let b_boxes = random_extents(&mut rng, 7, 300, 180);

        let mut layout = LayoutBuilder::new(LAYER_COUNT);
        let a_handles = push_rects(&mut layout, OPERAND_A, &a_boxes);
        let b_handles = push_rects(&mut layout, OPERAND_B, &b_boxes);
        let total = layout.len() as usize;
        let (store, ids) = layout.finish();
        let extent = by_poly_id(
            &ids,
            &[(&a_handles, &a_boxes), (&b_handles, &b_boxes)],
            total,
        );

        let (a, b) = validated(&store);
        let mut out = Vec::new();
        let mut seam = Record::default();
        candidates_observed(&store, &a, &b, &mut out, &mut seam);

        for (&handle_a, &box_a) in a_handles.iter().zip(&a_boxes) {
            for (&handle_b, &box_b) in b_handles.iter().zip(&b_boxes) {
                if !overlaps(box_a, box_b) {
                    continue;
                }
                let pair = (ids.of(handle_a), ids.of(handle_b));
                assert!(
                    out.contains(&pair),
                    "seed {seed}: {pair:?} has overlapping boxes {box_a:?} and {box_b:?} \
                     but was not offered for exact evaluation"
                );
            }
        }

        for &(left, right) in &seam.rejected {
            assert!(
                !overlaps(extent[left.idx()], extent[right.idx()]),
                "seed {seed}: ({left:?}, {right:?}) was rejected on boxes \
                 {:?} and {:?}, which do share a point",
                extent[left.idx()],
                extent[right.idx()]
            );
        }

        // "Reject nothing" is a legal superset and passes every assertion
        // above, so count the disjoint pairs the test built itself.
        let disjoint = a_boxes
            .iter()
            .flat_map(|&box_a| b_boxes.iter().map(move |&box_b| (box_a, box_b)))
            .filter(|&(box_a, box_b)| !overlaps(box_a, box_b))
            .count();
        assert!(
            disjoint > 0 && !seam.rejected.is_empty(),
            "seed {seed}: {disjoint} of the cross pairs are disjoint and the \
             prefilter rejected none of them, so it examined nothing"
        );
    }
}

/// The kept half of the seam must agree with what the caller is handed, or
/// the rejected half proves nothing about the output.
#[test]
fn the_pairs_reported_kept_are_exactly_the_pairs_emitted() {
    let mut rng = Rng::new(13);
    let a_boxes = random_extents(&mut rng, 6, 240, 160);
    let b_boxes = random_extents(&mut rng, 6, 240, 160);

    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    push_rects(&mut layout, OPERAND_A, &a_boxes);
    push_rects(&mut layout, OPERAND_B, &b_boxes);
    let (store, _) = layout.finish();

    let (a, b) = validated(&store);
    let mut out = vec![(PolyId(u32::MAX), PolyId(u32::MAX))];
    let mut seam = Record::default();
    candidates_observed(&store, &a, &b, &mut out, &mut seam);

    assert_eq!(
        out, seam.kept,
        "the pairs the caller receives and the pairs the seam reports kept differ"
    );
    assert!(
        out.windows(2).all(|pair| pair[0] < pair[1]),
        "candidates must be emitted in ascending order and without repeats: {out:?}"
    );
    for pair in &seam.rejected {
        assert!(
            !out.contains(pair),
            "{pair:?} was reported both kept and rejected"
        );
    }
}

/// Two rectangles sharing exactly one edge interact — their union is a
/// single polygon — and a strict overlap test would drop the pair with
/// nothing downstream to notice.
#[test]
fn two_operands_touching_along_an_edge_are_kept() {
    let a_boxes: Vec<Extent> = vec![[0, 0, 100, 100]];
    let b_boxes: Vec<Extent> = vec![[100, 0, 200, 100], [500, 500, 600, 600]];

    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    let a_handles = push_rects(&mut layout, OPERAND_A, &a_boxes);
    let b_handles = push_rects(&mut layout, OPERAND_B, &b_boxes);
    let (store, ids) = layout.finish();

    let (a, b) = validated(&store);
    let mut out = Vec::new();
    let mut seam = Record::default();
    candidates_observed(&store, &a, &b, &mut out, &mut seam);

    let touching = (ids.of(a_handles[0]), ids.of(b_handles[0]));
    assert!(
        out.contains(&touching),
        "{touching:?} share the line x = 100 and merge under a union, but the \
         prune dropped the pair; emitted {out:?}"
    );
    assert!(
        seam.kept.contains(&touching),
        "{touching:?} reached the caller without being reported at the seam, \
         so the seam does not describe what the prune did"
    );
    assert!(
        !seam.rejected.contains(&touching),
        "{touching:?} was reported rejected as well as kept"
    );

    // The other half of the fixture: keep-everything is legal under the
    // superset clause, so a pair four hundred units apart must be rejected.
    let distant = (ids.of(a_handles[0]), ids.of(b_handles[1]));
    assert!(
        seam.rejected.contains(&distant) && !out.contains(&distant),
        "{distant:?} span [0, 100] and [500, 600] in both axes and cannot \
         interact, but the prune offered the pair for exact evaluation"
    );
}

/// The same operands produce the same list, and a reused output buffer is
/// cleared rather than appended to.
#[test]
fn the_same_operands_produce_the_same_candidate_list_twice() {
    let mut rng = Rng::new(21);
    let a_boxes = random_extents(&mut rng, 9, 260, 150);
    let b_boxes = random_extents(&mut rng, 9, 260, 150);

    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    push_rects(&mut layout, OPERAND_A, &a_boxes);
    push_rects(&mut layout, OPERAND_B, &b_boxes);
    let (store, _) = layout.finish();

    let (a, b) = validated(&store);
    let mut first = Vec::new();
    gpurify_geom::prefilter::candidates_into(&store, &a, &b, &mut first);
    let mut second = first.clone();
    gpurify_geom::prefilter::candidates_into(&store, &a, &b, &mut second);

    assert_eq!(
        first, second,
        "two runs over the same operands disagreed, or the output buffer was \
         appended to rather than cleared"
    );
}
