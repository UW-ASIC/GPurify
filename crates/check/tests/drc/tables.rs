//! The tables a rule set carries beside its rules, and what they answer:
//! each `is_valid` against the conditions its struct states, one condition
//! broken at a time from a valid table and each boundary value on both
//! sides, and the band lookups (`CutAreaBands::limit`, `CoverBands::need`,
//! `Pattern::anchor`) and `Rule::required_spacing` at their edges.

use gpurify_check::drc::ruleset::{
    ClassTable, CoverBands, CutAreaBands, CutClassTable, DefectSizes, Pattern, Rule, SpacingQuery,
    SpacingTable, SpanTable,
};
use gpurify_geom::{Bbox, DbuArea, LayerId};
use gpurify_testgen::dbu;

fn area(v: i128) -> DbuArea {
    DbuArea::new(v)
}

/// Oracle: `CutAreaBands`' rustdoc: "at least 1, rising strictly" starts,
/// one change per band, "0 or more" changes; and `limit` takes the last
/// band whose start the count reaches. The valid base `[1, 4] -> [10000,
/// 40000]` is broken one condition at a time; 0 and 1 are the first
/// start's two sides, -1 and 0 the change's, equal starts the rise's.
/// Counts 0 to 5 read: none below 1, 10000 from 1 to 3, 40000 from 4.
#[test]
fn cut_area_bands_hold_their_stated_shape_and_pick_the_last_band_reached() {
    let bands = |cuts: &[u32], change: &[i128]| CutAreaBands {
        cuts: cuts.to_vec(),
        change: change.iter().map(|&c| area(c)).collect(),
    };
    assert!(bands(&[1, 4], &[10_000, 40_000]).is_valid());
    assert!(
        bands(&[1, 4], &[0, 0]).is_valid(),
        "a change of 0 is allowed"
    );
    for (broken, why) in [
        (bands(&[], &[]), "no band"),
        (bands(&[0, 4], &[10_000, 40_000]), "a start below 1"),
        (bands(&[1, 4], &[10_000]), "a band without a change"),
        (
            bands(&[1, 1], &[10_000, 40_000]),
            "starts not rising strictly",
        ),
        (bands(&[4, 1], &[10_000, 40_000]), "starts falling"),
        (bands(&[1, 4], &[-1, 40_000]), "a negative change"),
        (bands(&[1, 4], &[10_000, -1]), "a negative last change"),
    ] {
        assert!(!broken.is_valid(), "{why}");
    }
    let table = bands(&[1, 4], &[10_000, 40_000]);
    let limits: Vec<Option<DbuArea>> = (0..=5).map(|n| table.limit(n)).collect();
    assert_eq!(
        limits,
        [
            None,
            Some(area(10_000)),
            Some(area(10_000)),
            Some(area(10_000)),
            Some(area(40_000)),
            Some(area(40_000)),
        ]
    );
}

/// Oracle: `DefectSizes`' rustdoc: radii "positive and rising strictly",
/// "one weight per radius, from 0 to 1". Broken one condition at a time;
/// radius 0 against 1, weights -0.1 and 1.1 against 0 and 1.
#[test]
fn defect_sizes_hold_their_stated_shape() {
    let sizes = |radius: &[i64], weight: &[f64]| DefectSizes {
        radius: radius.iter().map(|&r| dbu(r)).collect(),
        weight: weight.to_vec(),
    };
    assert!(sizes(&[1, 20], &[0.0, 1.0]).is_valid());
    for (broken, why) in [
        (sizes(&[], &[]), "no size"),
        (sizes(&[0, 20], &[0.5, 0.5]), "a radius of 0"),
        (sizes(&[10, 20], &[0.5]), "a radius without a weight"),
        (sizes(&[20, 20], &[0.5, 0.5]), "radii not rising strictly"),
        (sizes(&[20, 10], &[0.5, 0.5]), "radii falling"),
        (sizes(&[10, 20], &[-0.1, 0.5]), "a weight below 0"),
        (sizes(&[10, 20], &[0.5, 1.1]), "a weight above 1"),
    ] {
        assert!(!broken.is_valid(), "{why}");
    }
}

/// Oracle: `CoverBands`' rustdoc: fractions in `0..=1`, one density per
/// band, starts rising strictly; `need` takes the last band whose start
/// the coverage reaches, at the start itself only when `inclusive`. Bands
/// from 25 %, 50 % and 100 % asking 25 %, 50 % and 75 %: 20 % is below
/// every band; exactly 50 % is the 50 % band inclusive and the 25 % band
/// exclusive; exactly 25 % exclusive is below every band; full cover is
/// the last band inclusive and the middle one exclusive.
#[test]
fn cover_bands_hold_their_stated_shape_and_read_a_start_as_written() {
    let bands = |cover: &[f64], density: &[f64], inclusive: bool| CoverBands {
        cover: cover.to_vec(),
        density: density.to_vec(),
        inclusive,
    };
    let (cover, density) = ([0.25, 0.5, 1.0], [0.25, 0.5, 0.75]);
    assert!(bands(&cover, &density, true).is_valid());
    assert!(
        bands(&[0.0, 1.0], &[0.0, 1.0], false).is_valid(),
        "the ends of 0..=1"
    );
    for (broken, why) in [
        (bands(&[], &[], true), "no band"),
        (
            bands(&[0.25, 0.5], &[0.25], true),
            "a band without a density",
        ),
        (bands(&[-0.01, 0.5], &[0.25, 0.5], true), "a start below 0"),
        (bands(&[0.25, 1.01], &[0.25, 0.5], true), "a start above 1"),
        (
            bands(&[0.25, 0.5], &[-0.01, 0.5], true),
            "a density below 0",
        ),
        (
            bands(&[0.25, 0.5], &[0.25, 1.01], true),
            "a density above 1",
        ),
        (
            bands(&[0.5, 0.5], &[0.25, 0.5], true),
            "starts not rising strictly",
        ),
    ] {
        assert!(!broken.is_valid(), "{why}");
    }
    let inclusive = bands(&cover, &density, true);
    let exclusive = bands(&cover, &density, false);
    for (coverage, wanted_inclusive, wanted_exclusive) in [
        (0.2, None, None),
        (0.25, Some(0.25), None),
        (0.3, Some(0.25), Some(0.25)),
        (0.5, Some(0.5), Some(0.25)),
        (0.6, Some(0.5), Some(0.5)),
        (1.0, Some(0.75), Some(0.5)),
    ] {
        assert_eq!(
            inclusive.need(coverage),
            wanted_inclusive,
            "{coverage} inclusive"
        );
        assert_eq!(
            exclusive.need(coverage),
            wanted_exclusive,
            "{coverage} exclusive"
        );
    }
}

/// Oracle: `SpanTable`'s rustdoc: both lists "positive and rising
/// strictly". Broken in either list: empty, a first length of 0 (1 is
/// valid), equal neighbours, falling neighbours.
#[test]
fn span_tables_hold_both_lists_to_positive_strict_rises() {
    let table = |x: &[i64], y: &[i64]| SpanTable {
        x: x.iter().map(|&v| dbu(v)).collect(),
        y: y.iter().map(|&v| dbu(v)).collect(),
        x_except: None,
        y_except: None,
    };
    assert!(table(&[1, 200], &[120]).is_valid());
    for (x, y, why) in [
        (&[][..], &[120][..], "x empty"),
        (&[60, 200], &[], "y empty"),
        (&[0, 200], &[120], "x starting at 0"),
        (&[60, 200], &[0], "y starting at 0"),
        (&[200, 200], &[120], "x not rising strictly"),
        (&[60, 200], &[120, 60], "y falling"),
    ] {
        assert!(!table(x, y).is_valid(), "{why}");
    }
}

/// Oracle: `SpacingTable`'s rustdoc: run lengths and widths "start at 0
/// and strictly rise", `width.len()` rows of `prl.len()` positive cells
/// that "never fall along a row or column". A 2 x 2 base `[[10, 20], [30,
/// 40]]`, and equal cells everywhere (never falling, so valid), broken one
/// condition at a time.
#[test]
fn spacing_tables_are_complete_and_never_fall() {
    let table = |prl: &[i64], width: &[i64], space: &[i64]| SpacingTable {
        prl: prl.iter().map(|&v| dbu(v)).collect(),
        width: width.iter().map(|&v| dbu(v)).collect(),
        space: space.iter().map(|&v| dbu(v)).collect(),
    };
    assert!(table(&[0, 100], &[0, 200], &[10, 20, 30, 40]).is_valid());
    assert!(table(&[0, 100], &[0, 200], &[10, 10, 10, 10]).is_valid());
    for (prl, width, space, why) in [
        (
            &[1, 100][..],
            &[0, 200][..],
            &[10, 20, 30, 40][..],
            "runs not from 0",
        ),
        (&[0, 100], &[1, 200], &[10, 20, 30, 40], "widths not from 0"),
        (&[0, 0], &[0, 200], &[10, 20, 30, 40], "runs not rising"),
        (&[0, 100], &[0, 0], &[10, 20, 30, 40], "widths not rising"),
        (&[0, 100], &[0, 200], &[10, 20, 30], "a cell missing"),
        (&[0, 100], &[0, 200], &[0, 20, 30, 40], "a cell of 0"),
        (&[0, 100], &[0, 200], &[20, 10, 30, 40], "a row falling"),
        (&[0, 100], &[0, 200], &[30, 40, 10, 20], "a column falling"),
        (
            &[0, 100],
            &[0, 200],
            &[10, 40, 30, 35],
            "the last column falling",
        ),
    ] {
        assert!(!table(prl, width, space).is_valid(), "{why}");
    }
}

/// Oracle: `CutClassTable`'s rustdoc: classes with a positive short side
/// no longer than the long one, distinct, `2n` x `2n` positive cells,
/// symmetric. The two-class base (170 x 170 and 190 x 2000) and a square
/// class (short equal to long, valid) broken one condition at a time.
#[test]
fn cut_class_tables_are_complete_symmetric_and_distinct() {
    let cells = [
        [170, 170, 510, 510],
        [170, 170, 510, 510],
        [510, 510, 350, 510],
        [510, 510, 510, 510],
    ];
    let table = |short: &[i64], long: &[i64], space: Vec<i64>| CutClassTable {
        short: short.iter().map(|&v| dbu(v)).collect(),
        long: long.iter().map(|&v| dbu(v)).collect(),
        space: space.into_iter().map(dbu).collect(),
    };
    let flat = || cells.iter().flatten().copied().collect::<Vec<_>>();
    assert!(table(&[170, 190], &[170, 2000], flat()).is_valid());
    let mut asymmetric = flat();
    asymmetric[1] = 200;
    let mut zero = flat();
    zero[5] = 0;
    for (broken, why) in [
        (table(&[], &[], vec![]), "no class"),
        (
            table(&[170, 190], &[170], flat()),
            "a class without a long side",
        ),
        (table(&[0, 190], &[170, 2000], flat()), "a short side of 0"),
        (
            table(&[171, 190], &[170, 2000], flat()),
            "short longer than long",
        ),
        (table(&[170, 170], &[170, 170], flat()), "two classes alike"),
        (
            table(&[170, 190], &[170, 2000], flat()[..15].to_vec()),
            "a cell missing",
        ),
        (table(&[170, 190], &[170, 2000], zero), "a cell of 0"),
        (
            table(&[170, 190], &[170, 2000], asymmetric),
            "not symmetric",
        ),
    ] {
        assert!(!broken.is_valid(), "{why}");
    }
}

/// Oracle: `ClassTable`'s rustdoc. A tip table: no runs, classes from 0
/// rising strictly, square, symmetric, positive. A two-width table: one
/// run per class, the first none, runs 0 or more and never falling,
/// classes from 0 never falling, cells never falling along a row. Each
/// base broken one condition at a time; equal classes separate the two
/// (strict for tips, allowed for widths).
#[test]
fn class_tables_hold_what_each_kind_reads() {
    let table = |class: &[i64], prl: &[Option<i64>], space: &[i64]| ClassTable {
        class: class.iter().map(|&v| dbu(v)).collect(),
        prl: prl.iter().map(|run| run.map(dbu)).collect(),
        space: space.iter().map(|&v| dbu(v)).collect(),
    };
    assert!(table(&[0, 100], &[], &[10, 20, 20, 30]).is_valid_tips());
    for (broken, why) in [
        (table(&[0, 100], &[None, None], &[10, 20, 20, 30]), "runs"),
        (
            table(&[1, 100], &[], &[10, 20, 20, 30]),
            "classes not from 0",
        ),
        (
            table(&[0, 0], &[], &[10, 20, 20, 30]),
            "classes not rising strictly",
        ),
        (table(&[0, 100], &[], &[10, 20, 20]), "a cell missing"),
        (table(&[0, 100], &[], &[10, 0, 0, 30]), "a cell of 0"),
        (table(&[0, 100], &[], &[10, 20, 25, 30]), "not symmetric"),
    ] {
        assert!(!broken.is_valid_tips(), "tips: {why}");
    }
    let runs = [None, Some(50), Some(50)];
    let cells = [10, 20, 30, 20, 20, 30, 30, 30, 40];
    assert!(table(&[0, 100, 100], &runs, &cells).is_valid_two_widths());
    assert!(
        table(&[0, 100], &[None, Some(0)], &[10, 10, 10, 10]).is_valid_two_widths(),
        "a run of 0 and equal cells"
    );
    for (class, prl, space, why) in [
        (
            &[0, 100, 100][..],
            &[None, Some(50)][..],
            &cells[..],
            "a class without a run",
        ),
        (
            &[0, 100, 100],
            &[Some(0), Some(50), Some(50)],
            &cells,
            "a first run stated",
        ),
        (
            &[0, 100, 100],
            &[None, Some(-1), Some(50)],
            &cells,
            "a negative run",
        ),
        (
            &[0, 100, 100],
            &[None, Some(50), Some(40)],
            &cells,
            "runs falling",
        ),
        (&[0, 100, 50], &runs, &cells, "widths falling"),
        (
            &[0, 100, 100],
            &runs,
            &[10, 20, 30, 20, 20, 30, 30, 30],
            "a cell missing",
        ),
        (
            &[0, 100, 100],
            &runs,
            &[30, 20, 10, 20, 20, 30, 10, 30, 40],
            "a row falling",
        ),
        (
            &[0, 100, 100],
            &runs,
            &[10, 20, 30, 20, 40, 30, 30, 30, 40],
            "a middle row falling",
        ),
        (
            &[0, 100, 100],
            &runs,
            &[10, 20, 30, 15, 20, 30, 30, 30, 40],
            "not symmetric",
        ),
    ] {
        assert!(
            !table(class, prl, space).is_valid_two_widths(),
            "two widths: {why}"
        );
    }
}

/// An L of 100-wide arms in a 300 window: `[0, 300] x [0, 100]` and `[0,
/// 100] x [100, 300]`.
fn ell(ignore: &[[i64; 4]]) -> Pattern {
    let b = |[xlo, ylo, xhi, yhi]: [i64; 4]| Bbox {
        xlo: dbu(xlo),
        ylo: dbu(ylo),
        xhi: dbu(xhi),
        yhi: dbu(yhi),
    };
    Pattern {
        window: (dbu(300), dbu(300)),
        shapes: vec![b([0, 0, 300, 100]), b([0, 100, 100, 300])],
        ignore: ignore.iter().map(|&r| b(r)).collect(),
    }
}

/// Oracle: `Pattern`'s rustdoc. The merged L's corners are (0, 0), (300,
/// 0), (300, 100), (100, 100), (100, 300) and (0, 300); only (100, 100)
/// lies strictly inside the window, so it is the anchor. A don't-care box
/// covering it, or whose edge or corner passes through it ("their edges
/// included"), leaves no anchor; one starting a unit past it does not.
#[test]
fn a_pattern_anchors_on_its_least_free_inner_corner() {
    assert_eq!(ell(&[]).anchor(), Some((100, 100)));
    assert_eq!(ell(&[[150, 150, 300, 300]]).anchor(), Some((100, 100)));
    assert_eq!(ell(&[[101, 101, 300, 300]]).anchor(), Some((100, 100)));
    assert_eq!(ell(&[[50, 50, 150, 150]]).anchor(), None);
    assert_eq!(ell(&[[100, 100, 200, 200]]).anchor(), None);
    assert_eq!(ell(&[[0, 0, 100, 100]]).anchor(), None);
    assert_eq!(ell(&[[0, 100, 100, 200]]).anchor(), None);
    // Two shapes side by side, (100, 0) shared: the merged bar's corners
    // all lie on the window's edge, so there is no anchor.
    let mut bar = ell(&[]);
    bar.shapes = vec![
        Bbox {
            xlo: dbu(0),
            ylo: dbu(0),
            xhi: dbu(100),
            yhi: dbu(300),
        },
        Bbox {
            xlo: dbu(100),
            ylo: dbu(0),
            xhi: dbu(300),
            yhi: dbu(300),
        },
    ];
    assert_eq!(bar.anchor(), None);
}

/// Oracle: `Pattern::is_valid`'s rustdoc: a positive window, every shape
/// and don't-care box a rectangle with positive sides inside it, at least
/// one shape, and an anchor. The L is valid; a shape or box touching the
/// window's far edge is still inside; each other case breaks one
/// condition.
#[test]
fn a_pattern_is_valid_only_inside_a_positive_window_with_an_anchor() {
    assert!(ell(&[]).is_valid());
    assert!(ell(&[[200, 200, 300, 300]]).is_valid());
    let with = |edit: &dyn Fn(&mut Pattern)| {
        let mut p = ell(&[]);
        edit(&mut p);
        p
    };
    let cases: [(Pattern, &str); 12] = [
        (with(&|p| p.window.0 = dbu(0)), "a window 0 wide"),
        (with(&|p| p.window.1 = dbu(0)), "a window 0 high"),
        (
            with(&|p| p.window.0 = dbu(299)),
            "a shape past the window's right",
        ),
        (
            with(&|p| p.window.1 = dbu(299)),
            "a shape past the window's top",
        ),
        (with(&|p| p.shapes.clear()), "no shape"),
        (
            with(&|p| p.shapes[0].xlo = dbu(-1)),
            "a shape left of the window",
        ),
        (
            with(&|p| p.shapes[0].ylo = dbu(-1)),
            "a shape below the window",
        ),
        (with(&|p| p.shapes[1].xhi = dbu(0)), "a shape with no width"),
        (
            with(&|p| p.shapes[0].yhi = dbu(0)),
            "a shape with no height",
        ),
        (
            ell(&[[250, 250, 301, 300]]),
            "a don't-care box past the window",
        ),
        (
            ell(&[[250, 250, 250, 300]]),
            "a don't-care box with no width",
        ),
        (ell(&[[90, 90, 110, 110]]), "no anchor"),
    ];
    for (pattern, why) in cases {
        assert!(!pattern.is_valid(), "{why}");
    }
}

/// Oracle: `Rule::required_spacing`'s rustdoc: a rule answers only for
/// its own layer, a wide rule only for a pair whose wider width reaches the
/// threshold (`is_wide`: at it counts), a run rule only for a run reaching
/// its threshold, an end-of-line rule only for a facing edge strictly
/// shorter than its width, a table its largest applicable row. Each case
/// is read at the threshold and one unit short of it, and on the other
/// layer.
#[test]
fn required_spacing_answers_for_its_own_layer_at_its_thresholds() {
    let (a, b) = (LayerId(0), LayerId(1));
    let q = |width: i64, run: i64, eol: Option<i64>| SpacingQuery {
        width_a: dbu(100),
        width_b: dbu(width),
        run_length: dbu(run),
        end_of_line: eol.map(dbu),
    };
    let wide = Rule::WideDependentSpacing {
        layer: a,
        width_threshold: dbu(3000),
        limit: dbu(400),
    };
    let attached = Rule::AttachedWideSpacing {
        layer: a,
        width_threshold: dbu(3000),
        attached: dbu(500),
        limit: dbu(450),
    };
    let prl = Rule::PrlSpacing {
        layer: a,
        prl_threshold: dbu(1000),
        limit: dbu(300),
    };
    let eol = Rule::EolSpacing {
        layer: a,
        eol_width: dbu(200),
        limit: dbu(250),
    };
    let min = Rule::MinSpacing {
        layer: a,
        limit: dbu(140),
    };
    let table = Rule::SpacingTable { layer: a, table: 0 };
    let tables = [SpacingTable {
        prl: vec![dbu(0), dbu(1000)],
        width: vec![dbu(0), dbu(2999)],
        space: [140, 200, 300, 500].into_iter().map(dbu).collect(),
    }];
    let at = |rule: &Rule, layer: LayerId, query: SpacingQuery| {
        rule.required_spacing(layer, &tables, &query)
    };
    for rule in [&wide, &attached, &prl, &eol, &min, &table] {
        assert_eq!(
            at(rule, b, q(3000, 1000, Some(10))),
            None,
            "{rule:?} on another layer"
        );
    }
    assert_eq!(at(&min, a, q(100, 0, None)), Some(dbu(140)));
    assert_eq!(at(&wide, a, q(3000, 0, None)), Some(dbu(400)));
    assert_eq!(at(&wide, a, q(2999, 0, None)), None);
    assert_eq!(at(&attached, a, q(3000, 0, None)), Some(dbu(450)));
    assert_eq!(at(&attached, a, q(2999, 0, None)), None);
    assert_eq!(at(&prl, a, q(100, 1000, None)), Some(dbu(300)));
    assert_eq!(at(&prl, a, q(100, 999, None)), None);
    assert_eq!(at(&eol, a, q(100, 0, Some(199))), Some(dbu(250)));
    assert_eq!(at(&eol, a, q(100, 0, Some(200))), None);
    assert_eq!(at(&eol, a, q(100, 0, None)), None);
    // Row 1 holds widths past 2999 (a 3000 square fits), column 1 runs past
    // 1000.
    assert_eq!(at(&table, a, q(100, 1000, None)), Some(dbu(140)));
    assert_eq!(at(&table, a, q(100, 1001, None)), Some(dbu(200)));
    assert_eq!(at(&table, a, q(3000, 1000, None)), Some(dbu(300)));
    assert_eq!(at(&table, a, q(3000, 1001, None)), Some(dbu(500)));
    assert_eq!(at(&table, a, q(2999, 1001, None)), Some(dbu(200)));
}

/// Oracle: `Rule::validate`'s rustdoc and each variant's: a via
/// redundancy's `space` is "0 or more"; a DFM score's recommended value
/// lies above its required one (refused with their difference); a keep-out
/// zone's class is oblong (its long side past its short one, refused with
/// the difference), its `to` class positive, its zone reaches 0 or more.
/// Each value is read at the line and one unit past it.
#[test]
fn validate_holds_each_value_to_its_stated_range() {
    let refuse = |limit: i64| gpurify_check::drc::DrcError::NonPositiveLimit {
        rule: "r".to_owned(),
        limit,
    };
    let check = |rule: Rule| rule.validate("r", &[]);
    let (a, b, c) = (LayerId(0), LayerId(1), LayerId(2));
    let redundancy = |space: i64| Rule::ViaRedundancy {
        cut: a,
        lower: b,
        upper: c,
        pitch: dbu(200),
        space: dbu(space),
        limit: 0.5,
    };
    assert_eq!(check(redundancy(0)), Ok(()));
    assert_eq!(check(redundancy(-1)), Err(refuse(-1)));
    let dfm = |required: i64, recommended: i64| Rule::DfmScore {
        check: gpurify_check::drc::ruleset::DfmCheck::Space,
        layer: a,
        outer: None,
        required: dbu(required),
        recommended: dbu(recommended),
        rate: 0.5,
        limit: 0.9,
    };
    assert_eq!(check(dfm(100, 101)), Ok(()));
    assert_eq!(check(dfm(100, 100)), Err(refuse(0)));
    assert_eq!(check(dfm(100, 99)), Err(refuse(-1)));
    let zone = |class: (i64, i64), to: Option<(i64, i64)>, end: (i64, i64), side: (i64, i64)| {
        Rule::KeepOutZone {
            layer: a,
            class: (dbu(class.0), dbu(class.1)),
            to: to.map(|(s, l)| (dbu(s), dbu(l))),
            end: (dbu(end.0), dbu(end.1)),
            side: (dbu(side.0), dbu(side.1)),
        }
    };
    assert_eq!(
        check(zone((100, 101), Some((1, 1)), (0, 0), (0, 0))),
        Ok(())
    );
    assert_eq!(
        check(zone((100, 100), None, (10, 80), (50, 20))),
        Err(refuse(0))
    );
    assert_eq!(
        check(zone((100, 99), None, (10, 80), (50, 20))),
        Err(refuse(-1))
    );
    assert_eq!(
        check(zone((0, 300), None, (10, 80), (50, 20))),
        Err(refuse(0))
    );
    assert_eq!(
        check(zone((100, 300), Some((0, 100)), (10, 80), (50, 20))),
        Err(refuse(0))
    );
    for (end, side, bad) in [
        ((-1, 80), (50, 20), -1),
        ((10, -2), (50, 20), -2),
        ((10, 80), (-3, 20), -3),
        ((10, 80), (50, -4), -4),
    ] {
        assert_eq!(check(zone((100, 300), None, end, side)), Err(refuse(bad)));
    }
}
