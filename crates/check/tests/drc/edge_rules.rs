//! Edge-layer kinds (`drc::rules::edge`): `edge_min_length`, `edge_spacing`,
//! `edge_width`, `edge_facing_space` and `edge_enclosure`, over segments
//! written by hand with their shape on the left. Each case states every
//! finding (measured value and marker) and the rule's `examined`, so a pair
//! dropped from or added to the scan shows as well as a wrong measurement.

use crate::common::RULE;
use gpurify_check::drc::{Rule, RuleSet};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_geom::ops::{Point, Seg};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_testgen::dbu;
use gpurify_testgen::shapes::LayoutBuilder;

const E: LayerId = LayerId(0);
const F: LayerId = LayerId(1);
const OUTER: LayerId = LayerId(2);

fn seg(ax: i64, ay: i64, bx: i64, by: i64) -> Seg {
    Seg {
        a: Point {
            x: dbu(ax),
            y: dbu(ay),
        },
        b: Point {
            x: dbu(bx),
            y: dbu(by),
        },
    }
}

/// A store with edge layers `E` and `F` and rectangles on `OUTER`.
fn store(e: &[Seg], f: &[Seg], outer: &[[i64; 4]]) -> GeometryStore {
    let mut builder = LayoutBuilder::new(3);
    for &[xlo, ylo, xhi, yhi] in outer {
        builder.rect(OUTER, xlo, ylo, xhi, yhi);
    }
    let mut store = builder.finish().0;
    store.append_edges(E, e);
    store.append_edges(F, f);
    store
}

/// Every finding as `(measured length, (x, y))`, sorted, and the rule's row.
fn run(store: &GeometryStore, rule: Rule) -> (Vec<(i64, (i64, i64))>, RuleRun) {
    let set = RuleSet {
        rules: vec![(RULE, rule)],
        ..RuleSet::default()
    };
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    set.run(store, &mut out, &mut runs);
    let mut found: Vec<_> = (0..out.len())
        .map(|i| {
            let v = out.get(i);
            let Measurement::Length(m) = v.measured else {
                panic!("an edge rule measures a length: {v:?}");
            };
            assert_eq!(v.rule, RULE);
            (m.raw(), (v.at.x.raw(), v.at.y.raw()))
        })
        .collect();
    found.sort_unstable();
    (found, runs[0])
}

/// The segments under a quarter turn `(x, y) -> (-y, x)`, `k` times.
fn turned(segs: &[Seg], k: u8) -> Vec<Seg> {
    let turn = |p: Point| {
        let (mut x, mut y) = (p.x.raw(), p.y.raw());
        for _ in 0..k {
            (x, y) = (-y, x);
        }
        Point {
            x: dbu(x),
            y: dbu(y),
        }
    };
    segs.iter()
        .map(|s| Seg {
            a: turn(s.a),
            b: turn(s.b),
        })
        .collect()
}

/// Oracle: the definition, lengths by construction. A 40 and a 39 edge are
/// under 41 and reported at their midpoints, floored ((261 + 300) / 2 =
/// 280); a 41 edge, at the limit, is legal, whichever way the edges run.
/// `examined` counts every edge. A diagonal edge is refused, not measured.
#[test]
fn edge_min_length_reports_each_edge_under_the_limit_at_its_midpoint() {
    let edges = [
        seg(0, 0, 40, 0),
        seg(100, 0, 100, 41),
        seg(300, 10, 261, 10),
        seg(500, 141, 500, 100),
    ];
    let rule = Rule::EdgeMinLength {
        layer: E,
        limit: dbu(41),
    };
    let (found, row) = run(&store(&edges, &[], &[]), rule);
    assert_eq!(found, [(39, (280, 10)), (40, (20, 0))]);
    assert_eq!(
        (row.outcome, row.examined, row.violations),
        (Outcome::Ran, 4, 2)
    );

    let (found, row) = run(&store(&[seg(0, 0, 30, 30)], &[], &[]), rule);
    assert!(found.is_empty());
    assert_eq!(row.outcome, Outcome::Refused);
}

/// Pairs of `edge_spacing` cases, each group 1000 or more from the next, at
/// `limit` 100:
/// - two parallel edges 99 apart: one finding of 99 at the middle of the gap
///   between their boxes, (100, 49) (99 / 2 floored);
/// - two parallel edges exactly 100 apart: legal, and not within reach
///   either (reach is strictly closer than the limit on both axes);
/// - two collinear edges 50 apart end to end: 50, Euclidean, at (2125, 0);
/// - two parallel edges 60 along and 80 across, 100 apart: legal but within
///   reach on both axes, so measured;
/// - the same 60 along and 79 across, sqrt(9841) = 99.2: reported as 99, at
///   ((4160 + 4100) / 2, 79 / 2) = (4130, 39);
/// - a perpendicular edge 50 from a horizontal one: not measured;
/// - two collinear edges that touch: measured, and touching is no spacing;
/// - a 1000 long edge first in the table and, after it, a 100 long edge
///   50 above its middle: 50 at (550, 7025).
///
/// Oracle: the definition (`Rule::EdgeSpacing`), every distance by
/// construction; `examined` is the six parallel pairs within reach.
fn spacing_cases() -> (Vec<Seg>, Vec<(i64, (i64, i64))>, u64) {
    let edges = vec![
        seg(0, 0, 200, 0),
        seg(200, 99, 0, 99),
        seg(1000, 0, 1200, 0),
        seg(1200, 100, 1000, 100),
        seg(2000, 0, 2100, 0),
        seg(2150, 0, 2250, 0),
        seg(3000, 0, 3100, 0),
        seg(3160, 80, 3260, 80),
        seg(4000, 0, 4100, 0),
        seg(4160, 79, 4260, 79),
        seg(5000, 0, 5100, 0),
        seg(5150, 10, 5150, 110),
        seg(6000, 0, 6100, 0),
        seg(6100, 0, 6200, 0),
        seg(500, 7050, 600, 7050),
        seg(0, 7000, 1000, 7000),
    ];
    let found = vec![
        (50, (550, 7025)),
        (50, (2125, 0)),
        (99, (100, 49)),
        (99, (4130, 39)),
    ];
    (edges, found, 6)
}

/// Oracle: the definition, each case of [`spacing_cases`] by construction.
#[test]
fn edge_spacing_measures_parallel_pairs_end_to_end_and_across() {
    let (edges, want, examined) = spacing_cases();
    let rule = Rule::EdgeSpacing {
        a: E,
        b: None,
        limit: dbu(100),
    };
    let (found, row) = run(&store(&edges, &[], &[]), rule);
    assert_eq!(found, want);
    assert_eq!((row.outcome, row.examined), (Outcome::Ran, examined));
}

/// Oracle: rotation invariance of a Euclidean spacing. Under each quarter
/// turn the measured values and the pairs examined are the same (markers
/// move, and a floored midpoint need not commute, so only values compare).
#[test]
fn edge_spacing_is_the_same_under_every_quarter_turn() {
    let (edges, want, examined) = spacing_cases();
    let mut want: Vec<i64> = want.iter().map(|w| w.0).collect();
    want.sort_unstable();
    for k in 1..4 {
        let rule = Rule::EdgeSpacing {
            a: E,
            b: None,
            limit: dbu(100),
        };
        let (found, row) = run(&store(&turned(&edges, k), &[], &[]), rule);
        let mut got: Vec<i64> = found.iter().map(|f| f.0).collect();
        got.sort_unstable();
        assert_eq!(got, want, "turned {k} times");
        assert_eq!(row.examined, examined, "turned {k} times");
    }
}

/// Oracle: the definition with a second layer. Each edge of `E` is paired
/// with each edge of `F`, never with another edge of `E`: the two `E` edges
/// 10 apart are not a finding; the first `F` edge is 99 above the first `E`
/// edge (at (100, 49)) and 89 above the second (at (100, 54)); the other is
/// 60 past the third's end (at (1030, 0)). `examined` is those three
/// parallel `E`-`F` pairs within reach.
#[test]
fn edge_spacing_between_two_layers_pairs_only_across() {
    let e = [seg(0, 0, 200, 0), seg(200, 10, 0, 10), seg(800, 0, 1000, 0)];
    let f = [seg(0, 99, 200, 99), seg(1060, 0, 1100, 0)];
    let rule = Rule::EdgeSpacing {
        a: E,
        b: Some(F),
        limit: dbu(100),
    };
    let (found, row) = run(&store(&e, &f, &[]), rule);
    assert_eq!(found, [(60, (1030, 0)), (89, (100, 54)), (99, (100, 49))]);
    assert_eq!(row.examined, 3);
}

/// The two sides of a rectangle `w` wide from x = `x0`, 1000 high, as a
/// counter-clockwise ring runs them: left down, right up.
fn sides(x0: i64, w: i64) -> [Seg; 2] {
    [seg(x0, 1000, x0, 0), seg(x0 + w, 0, x0 + w, 1000)]
}

/// Oracle: the definition (`Rule::EdgeWidth`, back to back; `Rule::
/// EdgeFacingSpace`, face to face), widths and gaps by construction:
/// - a rectangle 149 wide: its sides are back to back 149 apart, a width
///   finding at (74, 500) (149 / 2 floored) and no spacing;
/// - one 150 wide: legal;
/// - two rectangles 200 wide, 100 apart: the facing sides are face to face, a
///   spacing finding of 100 at (2450, 500) and no width; each one's own
///   sides are 200 apart, out of reach;
/// - every parallel pair within reach (closer than 150) is examined by both
///   rules, whatever its sides: the 149 pair and the 100 pair;
/// - a quarter turn gives the same values: the edges are horizontal then.
#[test]
fn edge_width_and_facing_space_tell_the_sides_apart() {
    let mut edges = Vec::new();
    edges.extend(sides(0, 149));
    edges.extend(sides(1000, 150));
    edges.extend(sides(2200, 200));
    edges.extend(sides(2500, 200));
    for k in 0..4 {
        let edges = turned(&edges, k);
        let width = Rule::EdgeWidth {
            layer: E,
            limit: dbu(150),
        };
        let space = Rule::EdgeFacingSpace {
            layer: E,
            limit: dbu(150),
            prl: dbu(0),
        };
        let (w, wrow) = run(&store(&edges, &[], &[]), width);
        let (s, srow) = run(&store(&edges, &[], &[]), space);
        assert_eq!(
            w.iter().map(|f| f.0).collect::<Vec<_>>(),
            [149],
            "turned {k}"
        );
        assert_eq!(
            s.iter().map(|f| f.0).collect::<Vec<_>>(),
            [100],
            "turned {k}"
        );
        assert_eq!((wrow.examined, srow.examined), (2, 2), "turned {k}");
        if k == 0 {
            assert_eq!(w, [(149, (74, 500))]);
            assert_eq!(s, [(100, (2450, 500))]);
        }
    }
}

/// Oracle: the definition of `prl` in `Rule::EdgeFacingSpace`: a pair is
/// judged only when its projections overlap by more than `prl`. Two facing
/// edges 40 apart overlapping by 50 are exempt at `prl: 50` (and not
/// examined), and judged at an overlap of 51; at `prl: 0` a pair whose
/// projections meet only at a point (overlap 0) is examined but has no gap
/// straight across, so it is no finding.
#[test]
fn edge_facing_space_judges_only_runs_longer_than_prl() {
    // Face to face: the left edge runs up (its shape on its left, away from
    // the right edge), the right edge runs down (its shape on its right).
    let pair = |overlap: i64| {
        [
            seg(0, 0, 0, 1000),
            seg(40, 1000 + 1000 - overlap, 40, 1000 - overlap),
        ]
    };
    for (overlap, judged) in [(50, false), (51, true)] {
        let rule = Rule::EdgeFacingSpace {
            layer: E,
            limit: dbu(100),
            prl: dbu(50),
        };
        let (found, row) = run(&store(&pair(overlap), &[], &[]), rule);
        let mid = (1000 + 1000 - overlap) / 2;
        let want: Vec<(i64, (i64, i64))> = if judged {
            vec![(40, (20, mid))]
        } else {
            vec![]
        };
        assert_eq!(found, want, "overlap {overlap}");
        assert_eq!(row.examined, u64::from(judged), "overlap {overlap}");
    }
    let rule = Rule::EdgeFacingSpace {
        layer: E,
        limit: dbu(100),
        prl: dbu(0),
    };
    let (found, row) = run(&store(&pair(0), &[], &[]), rule);
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(row.examined, 1);
}

/// Oracle: the definition (`Rule::EdgeEnclosure`), depths by construction.
/// A 1000 square's four sides (counter-clockwise, so the outside of each is
/// away from the square) inside an `OUTER` rectangle 200 out on the left,
/// 124 below, 125 right and 60 above, at `limit` 125: the bottom (124) and
/// top (60) are reported at their midpoints with the covered depth, the
/// right side (exactly 125) and left side (200, capped at the limit) are
/// legal. `examined` counts the four edges.
#[test]
fn edge_enclosure_measures_how_deep_each_side_is_covered() {
    let square = [
        seg(0, 0, 1000, 0),
        seg(1000, 0, 1000, 1000),
        seg(1000, 1000, 0, 1000),
        seg(0, 1000, 0, 0),
    ];
    for k in 0..4 {
        let rule = Rule::EdgeEnclosure {
            edges: E,
            outer: OUTER,
            limit: dbu(125),
        };
        // The margins turn around the square: each side meets each margin.
        let margins = [124, 125, 60, 200];
        let m = |side: u8| margins[usize::from((side + 4 - k) % 4)];
        let outer = [-m(3), -m(0), 1000 + m(1), 1000 + m(2)];
        let (found, row) = run(&store(&square, &[], &[outer]), rule);
        let mut want = Vec::new();
        for (side, at) in [
            (0u8, (500, 0)),
            (1, (1000, 500)),
            (2, (500, 1000)),
            (3, (0, 500)),
        ] {
            if m(side) < 125 {
                want.push((m(side), at));
            }
        }
        want.sort_unstable();
        assert_eq!(found, want, "turned {k}");
        assert_eq!(row.examined, 4);
    }
}

/// Oracle: the definition, "covered without a gap". The bottom edge of a
/// square, 1000 long, under three `OUTER` cases at `limit` 125:
/// - a band 0 to 30 deep and another 50 to 200 deep: covered to 30;
/// - full depth under x 0 to 400 and 600 to 1000 but only 60 under 400 to
///   600: covered to 60, the shallowest slice across the whole edge;
/// - full depth under only half the edge: covered to 0.
#[test]
fn edge_enclosure_stops_at_the_first_gap_across_the_whole_edge() {
    let bottom = [seg(0, 0, 1000, 0)];
    let rule = Rule::EdgeEnclosure {
        edges: E,
        outer: OUTER,
        limit: dbu(125),
    };
    let cases: [(&[[i64; 4]], i64); 3] = [
        (&[[-10, -30, 1010, 0], [-10, -200, 1010, -50]], 30),
        (
            &[
                [-10, -200, 400, 0],
                [600, -200, 1010, 0],
                [400, -60, 600, 0],
            ],
            60,
        ),
        (&[[-10, -200, 500, 0]], 0),
    ];
    for (outer, depth) in cases {
        let (found, _) = run(&store(&bottom, &[], outer), rule);
        assert_eq!(found, [(depth, (500, 0))], "{outer:?}");
    }
}
