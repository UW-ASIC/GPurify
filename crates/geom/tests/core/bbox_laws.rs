//! Laws and closed forms for [`Bbox`].
//!
//! This is the file the crate's own doc comment points at: making
//! [`Bbox::overlaps`] strict on one axis produced zero failures across the
//! previous suite. The touching cases below are written out on both axes and at
//! the corner for exactly that reason, and the inclusive boundary of
//! [`Bbox::within`] is checked on the passing side *and* one database unit past
//! it, because only the second direction can fail.

use gpurify_geom::Bbox;
use gpurify_testgen::shapes::dbu;
use gpurify_testgen::Rng;
use gpurify_geom::{DbuArea, MAX_ABS_DBU};

fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
    Bbox {
        xlo: dbu(xlo),
        ylo: dbu(ylo),
        xhi: dbu(xhi),
        yhi: dbu(yhi),
    }
}

/// Arbitrary non-empty boxes, seeded so a failure is reproducible from the
/// seed printed beside it. Laws hold over these because they hold over
/// everything; that is what makes them laws rather than fixtures.
fn arbitrary_boxes(seed: u64, count: usize) -> Vec<Bbox> {
    let mut rng = Rng::new(seed);
    (0..count)
        .map(|_| {
            let (x0, x1) = (rng.range(-10_000, 10_000), rng.range(-10_000, 10_000));
            let (y0, y1) = (rng.range(-10_000, 10_000), rng.range(-10_000, 10_000));
            bbox(x0.min(x1), y0.min(y1), x0.max(x1), y0.max(y1))
        })
        .collect()
}

/// Oracle: law. The identity element of a fold is a property of the operation,
/// so it must hold against every box rather than against a chosen one. The
/// `Default` half matters because `Bbox::default()` is what a caller gets from
/// a `vec![Bbox::default(); n]` seed.
#[test]
fn empty_is_the_identity_of_union() {
    assert_eq!(Bbox::default(), Bbox::EMPTY);
    assert!(Bbox::EMPTY.is_empty());
    for b in arbitrary_boxes(1, 256) {
        assert_eq!(Bbox::EMPTY.union(b), b, "EMPTY on the left of {b:?}");
        assert_eq!(b.union(Bbox::EMPTY), b, "EMPTY on the right of {b:?}");
    }
    assert_eq!(Bbox::EMPTY.union(Bbox::EMPTY), Bbox::EMPTY);
}

/// Oracle: law. Union is a join: commutative, associative, idempotent, and
/// monotone. An implementation that mixed up a `min` and a `max` on one axis
/// breaks commutativity or containment here whichever way it leans.
#[test]
fn union_is_a_commutative_associative_idempotent_join() {
    let boxes = arbitrary_boxes(2, 64);
    for (i, &a) in boxes.iter().enumerate() {
        assert_eq!(a.union(a), a, "self-union of {a:?}");
        for &b in &boxes[i + 1..] {
            let ab = a.union(b);
            assert_eq!(ab, b.union(a), "union of {a:?} and {b:?} does not commute");
            assert!(ab.contains(a) && ab.contains(b), "{ab:?} loses an operand");
            for &c in &boxes[..4] {
                assert_eq!(ab.union(c), a.union(b.union(c)), "union is not associative");
            }
        }
    }
}

/// Oracle: closed form. `EMPTY` is built from `±MAX_ABS_DBU`, and its doc
/// comment claims that dominates the coordinate domain *with equality*. A
/// sentinel one unit inside the domain would silently drop the extreme point,
/// and nothing else in the tree would notice.
#[test]
fn a_point_on_the_coordinate_domain_edge_folds_exactly() {
    let top = Bbox::EMPTY.include(dbu(MAX_ABS_DBU), dbu(MAX_ABS_DBU));
    assert_eq!(top, Bbox::point(dbu(MAX_ABS_DBU), dbu(MAX_ABS_DBU)));
    assert!(!top.is_empty());

    let whole = top.include(dbu(-MAX_ABS_DBU), dbu(-MAX_ABS_DBU));
    assert_eq!(
        whole,
        bbox(-MAX_ABS_DBU, -MAX_ABS_DBU, MAX_ABS_DBU, MAX_ABS_DBU)
    );

    // The bound exists so this product fits `i128`: (2 * 2^40)^2 = 2^82.
    let side = 2 * i128::from(MAX_ABS_DBU);
    assert_eq!(whole.area(), DbuArea::new(side * side));
}

/// Oracle: law. `include` is `union` against a degenerate box, so folding a run
/// of points one at a time must agree with unioning their singleton boxes — and
/// with [`Bbox::of_points`], which is the vectorised form of the same fold.
#[test]
fn include_folds_a_run_of_points_the_same_way_of_points_does() {
    let mut rng = Rng::new(3);
    for run in 1..=40usize {
        let xs: Vec<_> = (0..run).map(|_| dbu(rng.range(-5_000, 5_000))).collect();
        let ys: Vec<_> = (0..run).map(|_| dbu(rng.range(-5_000, 5_000))).collect();

        let mut folded = Bbox::EMPTY;
        for (&x, &y) in xs.iter().zip(&ys) {
            folded = folded.include(x, y);
            assert_eq!(folded, folded.union(Bbox::point(x, y)));
        }
        assert_eq!(Bbox::of_points(&xs, &ys), folded, "run of {run} points");
    }
}

/// Oracle: law. Emptiness is `lo > hi`, which is a strictly different claim
/// from zero area: a point and a segment are both zero-area and both contain
/// points, and conflating the two drops legitimately degenerate derived shapes.
#[test]
fn a_point_and_a_segment_are_zero_area_but_not_empty() {
    let point = Bbox::point(dbu(7), dbu(-3));
    assert!(!point.is_empty());
    assert_eq!(point.area(), DbuArea::new(0));
    assert_eq!(point.width(), dbu(0));
    assert_eq!(point.height(), dbu(0));

    let horizontal = bbox(0, 5, 10, 5);
    let vertical = bbox(5, 0, 5, 10);
    for degenerate in [horizontal, vertical] {
        assert!(!degenerate.is_empty(), "{degenerate:?} contains points");
        assert_eq!(degenerate.area(), DbuArea::new(0));
    }
    assert_eq!(horizontal.width(), dbu(10));
    assert_eq!(horizontal.height(), dbu(0));
    assert_eq!(vertical.width(), dbu(0));
    assert_eq!(vertical.height(), dbu(10));

    assert!(Bbox::EMPTY.is_empty());
    // Empty on one axis only is still empty; the predicate is a disjunction.
    assert!(bbox(10, 0, 0, 10).is_empty());
    assert!(bbox(0, 10, 10, 0).is_empty());
}

/// Oracle: construct-from-answer. Two boxes sharing only an edge share a line
/// of points, so they overlap. This is the exact mutation that survived the
/// whole previous suite, which is why every edge and the corner are written out
/// rather than sampled: a strict implementation passes the interior cases.
#[test]
fn boxes_sharing_only_an_edge_or_a_corner_overlap() {
    let a = bbox(0, 0, 10, 10);
    assert!(a.overlaps(bbox(10, 0, 20, 10)), "right edge");
    assert!(a.overlaps(bbox(-10, 0, 0, 10)), "left edge");
    assert!(a.overlaps(bbox(0, 10, 10, 20)), "top edge");
    assert!(a.overlaps(bbox(0, -10, 10, 0)), "bottom edge");
    assert!(a.overlaps(bbox(10, 10, 20, 20)), "top-right corner");
    assert!(a.overlaps(bbox(-10, -10, 0, 0)), "bottom-left corner");

    // One database unit further out on either axis and they genuinely miss.
    assert!(!a.overlaps(bbox(11, 0, 20, 10)), "one unit clear on x");
    assert!(!a.overlaps(bbox(0, 11, 10, 20)), "one unit clear on y");
    assert!(!a.overlaps(bbox(11, 11, 20, 20)), "one unit clear on both");

    assert!(!a.overlaps(Bbox::EMPTY), "nothing overlaps the empty box");
    assert!(!Bbox::EMPTY.overlaps(a));
}

/// Oracle: construct-from-answer. `within` is the spacing-rule prune, and the
/// only failure that matters is rejecting a pair at exactly the limit. Both
/// axes, both sides of the boundary, plus the claim that distance zero is
/// [`Bbox::overlaps`].
#[test]
fn within_is_inclusive_at_exactly_the_stated_distance() {
    let a = bbox(0, 0, 10, 10);

    // A five-unit gap on x: edges at 10 and 15.
    let right = bbox(15, 0, 25, 10);
    assert!(a.within(right, dbu(5)), "a gap of five is within five");
    assert!(!a.within(right, dbu(4)), "a gap of five is not within four");

    // The same gap on y.
    let above = bbox(0, 15, 10, 25);
    assert!(above.within(a, dbu(5)), "and the predicate is symmetric");
    assert!(!a.within(above, dbu(4)));

    // Diagonal separation is per-axis, not Euclidean: both axes must be within.
    let diagonal = bbox(15, 15, 25, 25);
    assert!(a.within(diagonal, dbu(5)));
    assert!(!a.within(diagonal, dbu(4)));

    // Distance zero is exactly the touch-or-overlap predicate.
    assert!(a.within(bbox(10, 0, 20, 10), dbu(0)));
    assert!(!a.within(bbox(11, 0, 20, 10), dbu(0)));
}

/// Oracle: law. `within` is monotone in its distance and agrees with
/// `overlaps` at zero, for any pair. A prune that computed the gap on the wrong
/// pair of edges breaks monotonicity long before it breaks a fixture.
#[test]
fn within_is_monotone_in_distance_and_agrees_with_overlaps_at_zero() {
    let boxes = arbitrary_boxes(4, 48);
    for (i, &a) in boxes.iter().enumerate() {
        for &b in &boxes[i + 1..] {
            assert_eq!(
                a.within(b, dbu(0)),
                a.overlaps(b),
                "within(0) must be overlaps for {a:?} and {b:?}"
            );
            let mut previous = a.within(b, dbu(0));
            for distance in 1..64i64 {
                let now = a.within(b, dbu(distance));
                assert!(
                    now || !previous,
                    "within went false at {distance} after being true for {a:?} and {b:?}"
                );
                assert_eq!(now, b.within(a, dbu(distance)), "within is symmetric");
                previous = now;
            }
        }
    }
}

/// Oracle: law. Three predicates describe the same relation from three angles,
/// so they must agree on every input: an intersection exists precisely when the
/// boxes overlap, it is contained in both, and containment implies the
/// intersection is the contained box.
#[test]
fn overlaps_contains_and_intersection_agree_on_every_pair() {
    let boxes = arbitrary_boxes(5, 96);
    for (i, &a) in boxes.iter().enumerate() {
        assert!(a.contains(a), "{a:?} does not contain itself");
        assert_eq!(a.intersection(a), Some(a));
        for &b in &boxes[i + 1..] {
            let meet = a.intersection(b);
            assert_eq!(meet.is_some(), a.overlaps(b), "{a:?} against {b:?}");
            assert_eq!(meet, b.intersection(a), "intersection does not commute");
            if let Some(meet) = meet {
                assert!(!meet.is_empty(), "an existing intersection has points");
                assert!(a.contains(meet) && b.contains(meet), "meet escapes {a:?}");
                assert!(a.union(b).contains(meet));
            }
            if a.contains(b) {
                assert_eq!(a.intersection(b), Some(b));
                assert!(a.overlaps(b));
                assert_eq!(a.union(b), a);
            }
        }
    }
}

/// Oracle: closed form. Width, height and area of an inclusive box are
/// differences of its own bounds, and area is the product taken in `i128`
/// because the `i64` product would wrap at the coordinate domain's edge.
#[test]
fn width_height_and_area_are_the_closed_form_of_the_bounds() {
    for &(xlo, ylo, xhi, yhi) in &[
        (0i64, 0i64, 10i64, 5i64),
        (-40, -40, -10, -30),
        (-1_000_000, 7, 1_000_000, 9),
        (3, 3, 3, 3),
    ] {
        let b = bbox(xlo, ylo, xhi, yhi);
        assert_eq!(b.width(), dbu(xhi - xlo));
        assert_eq!(b.height(), dbu(yhi - ylo));
        assert_eq!(
            b.area(),
            DbuArea::new(i128::from(xhi - xlo) * i128::from(yhi - ylo))
        );
    }
}

/// Oracle: law. A bounding box is defined by its extremes, so translating every
/// input translates the box and leaves its area alone. Coordinate-independence
/// is the law no implementation can dodge by special-casing.
#[test]
fn of_points_is_translation_equivariant_and_area_preserving() {
    let mut rng = Rng::new(6);
    for _ in 0..64 {
        let run = 3 + usize::try_from(rng.below(24)).expect("a small draw fits a usize");
        let xs: Vec<i64> = (0..run).map(|_| rng.range(-100_000, 100_000)).collect();
        let ys: Vec<i64> = (0..run).map(|_| rng.range(-100_000, 100_000)).collect();
        let (dx, dy) = (rng.range(-500_000, 500_000), rng.range(-500_000, 500_000));

        let here = Bbox::of_points(
            &xs.iter().copied().map(dbu).collect::<Vec<_>>(),
            &ys.iter().copied().map(dbu).collect::<Vec<_>>(),
        );
        let there = Bbox::of_points(
            &xs.iter().map(|&x| dbu(x + dx)).collect::<Vec<_>>(),
            &ys.iter().map(|&y| dbu(y + dy)).collect::<Vec<_>>(),
        );

        assert_eq!(there.area(), here.area(), "translation changed the area");
        assert_eq!(there.width(), here.width());
        assert_eq!(there.height(), here.height());
        assert_eq!(
            there,
            Bbox {
                xlo: here.xlo + dbu(dx),
                ylo: here.ylo + dbu(dy),
                xhi: here.xhi + dbu(dx),
                yhi: here.yhi + dbu(dy),
            }
        );
    }
}

/// Oracle: law. One output row per polygon, each a function of its own vertex
/// range and nothing else — which is what makes the transform a kernel. Running
/// it against the ranges in a different order must therefore give the same rows
/// permuted, and each row must equal [`Bbox::of_points`] over that range alone.
#[test]
fn of_polys_into_gives_one_row_per_range_independent_of_its_neighbours() {
    let mut rng = Rng::new(8);
    let (mut xs, mut ys, mut starts, mut lens) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..50 {
        let run = 3 + u32::try_from(rng.below(10)).expect("a small draw fits a u32");
        starts.push(u32::try_from(xs.len()).expect("the run fits a u32"));
        lens.push(run);
        for _ in 0..run {
            xs.push(dbu(rng.range(-9_000, 9_000)));
            ys.push(dbu(rng.range(-9_000, 9_000)));
        }
    }

    // Pre-fill with a value the transform must overwrite, not merge into.
    let mut out = vec![bbox(-1, -1, 1, 1); 3];
    Bbox::of_polys_into(&xs, &ys, &starts, &lens, &mut out);
    assert_eq!(
        out.len(),
        starts.len(),
        "one row per polygon, buffer cleared"
    );

    for (row, (&start, &len)) in out.iter().zip(starts.iter().zip(&lens)) {
        let (from, to) = (start as usize, (start + len) as usize);
        assert_eq!(*row, Bbox::of_points(&xs[from..to], &ys[from..to]));
    }

    // The same call twice into a dirty buffer is the determinism gate for this
    // transform: nothing here reads what a previous run left behind.
    let mut again = vec![Bbox::EMPTY; 500];
    Bbox::of_polys_into(&xs, &ys, &starts, &lens, &mut again);
    assert_eq!(again, out);
}

/// Oracle: construct-from-answer, on the sentinel rather than on a shape. An
/// empty box contains no points, so it covers no area, and the only right
/// answer is zero on every empty box there is.
///
/// Asserted here because the guard inside [`Bbox::area`] is one `max` per axis
/// and the only other thing holding it is a `debug_assert` — absent from
/// exactly the build where the two unclamped answers do damage. Both are worse
/// than a wrong number. `EMPTY` inverts *both* spans, and two negatives
/// multiply back to `+2^82`, bit-identical to a box spanning the whole
/// coordinate domain: the sentinel comes back wearing the largest real area
/// there is, and a `min_area` rule passes it. A box empty on one axis only
/// inverts one span and comes out **negative**, subtracting real area from any
/// density that sums these.
#[test]
fn every_empty_box_covers_no_area_in_both_profiles() {
    assert_eq!(
        Bbox::EMPTY.area(),
        DbuArea::new(0),
        "the sentinel reported the area of the whole coordinate domain"
    );

    // Empty on one axis only, in both orders, and at the domain edges — the
    // cases that come out negative rather than enormous.
    let x_only = bbox(10, 0, -10, 20);
    let y_only = bbox(0, 10, 20, -10);
    let edge = Bbox::EMPTY.include(dbu(MAX_ABS_DBU), dbu(MAX_ABS_DBU));
    for empty in [x_only, y_only] {
        assert!(empty.is_empty(), "{empty:?} is the case under test");
        assert_eq!(
            empty.area(),
            DbuArea::new(0),
            "{empty:?} reported a negative area"
        );
    }

    // One point folded into the sentinel is a point, not an empty box — the
    // fold has to leave the sentinel behind, or every `of_points` result of a
    // single vertex inherits it.
    assert!(!edge.is_empty());
    assert_eq!(edge.area(), DbuArea::new(0));
}
