//! `from_layout`'s measured parameters on devices drawn by hand: every value
//! is a length or area read off the drawing, in SI, and the derived `r`, `c`
//! and `ind` follow from the deck's coefficients by their laws.

use gpurify_check::lvs::graph::{from_layout, Graph};
use gpurify_check::lvs::{check_device_counts, check_param_ranges, intern_rule_ids};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_check::topology::device::recognise_into;
use gpurify_check::topology::{extract_nets_into, DeviceTable, NetTable, PortTable};
use gpurify_check::Design;
use gpurify_geom::ops::Point;
use gpurify_geom::{Dbu, DbuArea, GeometryStore, Grid, LayerId, PolyId};
use gpurify_ingest::deck::{parse_deck, DeviceKind, LvsCount, LvsLimit, LvsRange};
use gpurify_ingest::StrTable;
use gpurify_testgen::LayoutBuilder;

const DECK: &str = "grid 1nm
layer gate = gds(1, 0)
layer poly = gds(2, 0)
layer sd = gds(3, 0)
layer pina = gds(4, 0)
layer pinb = gds(5, 0)
layer pinc = gds(6, 0)
layer resm = gds(7, 0)
layer capm = gds(8, 0)
layer bjtm = gds(9, 0)
layer indm = gds(10, 0)
connect conductors [poly, sd, pina, pinb, pinc]
connect touch_within_layer
device mos gate model \"nmos\" terminals [poly, sd, sd]
device resistor resm model \"rpoly\" terminals [pina, pina] sheet 100ohm
device capacitor capm model \"cmim\" terminals [pina, pinb] area_cap 1fF/um2 fringe_cap 100aF/um
device bjt bjtm model \"npn\" terminals [pina, pinb, pinc]
device inductor indm model \"spiral\" terminals [pina, pina] inductance 2nH
";

/// Every name `from_layout` can write.
const NAMES: [&str; 14] = [
    "w", "l", "area", "perim", "nf", "as", "ad", "ps", "pd", "ae", "pe", "r", "c", "ind",
];

/// The layout: two nmos sharing their middle diffusion, and one each of
/// resistor, capacitor, bipolar and inductor, each marker 800 x 400 over
/// 400 nm pads 800 apart (the bipolar's three pads under a 1600 marker).
fn drawn() -> Vec<(&'static str, [i64; 4])> {
    let mut shapes = vec![
        // nmos: gates x 500..650 and 1150..1300, diffusions 0..500,
        // 650..1150 (shared) and 1300..1800, all 1000 high.
        ("gate", [500, 0, 650, 1000]),
        ("gate", [1150, 0, 1300, 1000]),
        ("poly", [500, -200, 650, 1200]),
        ("poly", [1150, -200, 1300, 1200]),
        ("sd", [0, 0, 500, 1000]),
        ("sd", [650, 0, 1150, 1000]),
        ("sd", [1300, 0, 1800, 1000]),
    ];
    // Passives in rows below, each pad 400 square.
    for (y, marker, pads) in [
        (-2000, "resm", &["pina", "pina"][..]),
        (-4000, "capm", &["pina", "pinb"][..]),
        (-6000, "bjtm", &["pina", "pinb", "pinc"][..]),
        (-8000, "indm", &["pina", "pina"][..]),
    ] {
        let mut right = 0;
        for (k, &pad) in pads.iter().enumerate() {
            let x = 800 * i64::try_from(k).expect("small");
            shapes.push((pad, [x, y, x + 400, y + 400]));
            right = x;
        }
        shapes.push((marker, [200, y, right + 200, y + 400]));
    }
    shapes
}

/// [`drawn`], extracted and recognised under [`DECK`], with `names`
/// interned before the deck.
fn extract(names: &[&str]) -> (GeometryStore, NetTable, DeviceTable, StrTable) {
    let mut strings = StrTable::default();
    for name in names {
        strings.intern(name);
    }
    let deck = parse_deck(DECK, Grid::new(1000).expect("1 nm"), &mut strings).expect("parses");
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for (layer, [xlo, ylo, xhi, yhi]) in drawn() {
        let id = deck.layers.id(&strings, layer).expect("a deck layer");
        layout.rect(id, xlo, ylo, xhi, yhi);
    }
    let (store, _) = layout.finish();
    let mut nets = NetTable::default();
    extract_nets_into(&store, &deck.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    recognise_into(&store, &nets, &deck.devices, &mut devices);
    (store, nets, devices, strings)
}

/// `from_layout` of [`drawn`] on a 1 nm grid, or with no grid.
fn graph(grid: Option<Grid>) -> (Graph, StrTable) {
    let (_, nets, devices, strings) = extract(&NAMES);
    let graph = from_layout(&nets, &devices, &PortTable::default(), &strings, grid);
    (graph, strings)
}

/// One device's parameters by name, sorted by name then value.
fn params(graph: &Graph, strings: &StrTable, device: u32) -> Vec<(String, f64)> {
    let mut out: Vec<(String, f64)> = graph
        .params_of(device)
        .iter()
        .map(|&(name, value)| (strings.resolve(name).to_owned(), value))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
    out
}

fn assert_close(got: &[(String, f64)], want: &[(&str, f64)], what: &str) {
    let mut want: Vec<(&str, f64)> = want.to_vec();
    want.sort_by(|a, b| a.0.cmp(b.0).then(a.1.total_cmp(&b.1)));
    assert_eq!(
        got.iter().map(|p| p.0.as_str()).collect::<Vec<_>>(),
        want.iter().map(|p| p.0).collect::<Vec<_>>(),
        "{what}: names"
    );
    for ((name, value), (_, expected)) in got.iter().zip(&want) {
        assert!(
            (value - expected).abs() <= 1e-9 * expected.abs(),
            "{what}: {name} = {value:e}, want {expected:e}"
        );
    }
}

/// Oracle: hand-derived from `from_layout`'s rustdoc and the drawing, in
/// SI at 1e-9 m per unit:
/// - each nmos: `w` 1000 nm, `l` 150 nm, `nf` 1, its gate's `area` 1.5e-13
///   m² and `perim` 2.3e-6 m; the outer diffusion 500 x 1000 (5e-13 m²,
///   3e-6 m) whole, the shared middle one halved (2.5e-13 m², 1.5e-6 m),
///   one as the source and one as the drain;
/// - the resistor: its body along its pads, `l` 800 nm, `w` 400 nm, `area`
///   3.2e-13, `perim` 2.4e-6, and `r` = 100 Ω/□ x 800 / 400 = 200 Ω;
/// - the capacitor: `area` and `perim` as the resistor's, and `c` = 1
///   fF/µm² x 0.32 µm² + 0.1 fF/µm x 2.4 µm = 0.56 fF;
/// - the bipolar: its marker 1600 x 400 (6.4e-13 m², 4e-6 m), its emitter
///   the middle pad, `ae` 1.6e-13 m², `pe` 1.6e-6 m;
/// - the inductor: the marker's `area` and `perim`, and `ind` 2 nH.
#[test]
fn measured_parameters_are_the_drawing_in_si_and_the_values_follow_their_laws() {
    let (graph, strings) = graph(Some(Grid::new(1000).expect("1 nm")));
    let kinds: Vec<DeviceKind> = graph.device_kind.clone();
    let of = |kind: DeviceKind| {
        (0..graph.device_count())
            .filter(|&d| kinds[d] == kind)
            .map(|d| u32::try_from(d).expect("small"))
            .collect::<Vec<u32>>()
    };
    let mos = of(DeviceKind::Mos);
    assert_eq!(mos.len(), 2);
    for &d in &mos {
        let got = params(&graph, &strings, d);
        let mut want = vec![
            ("w", 1e-6),
            ("l", 150e-9),
            ("nf", 1.0),
            ("area", 1.5e-13),
            ("perim", 2.3e-6),
        ];
        // One end whole, the shared end halved; which is the source does
        // not matter here, so both orders are accepted.
        let whole = (5e-13, 3e-6);
        let half = (2.5e-13, 1.5e-6);
        let source_whole = got
            .iter()
            .any(|p| p.0 == "as" && (p.1 - whole.0).abs() < 1e-20);
        let (s, dr) = if source_whole {
            (whole, half)
        } else {
            (half, whole)
        };
        want.extend([("as", s.0), ("ps", s.1), ("ad", dr.0), ("pd", dr.1)]);
        assert_close(&got, &want, &format!("nmos {d}"));
    }
    let one = |kind| {
        let rows = of(kind);
        assert_eq!(rows.len(), 1, "{kind:?}");
        params(&graph, &strings, rows[0])
    };
    assert_close(
        &one(DeviceKind::Resistor),
        &[
            ("w", 400e-9),
            ("l", 800e-9),
            ("area", 3.2e-13),
            ("perim", 2.4e-6),
            ("r", 200.0),
        ],
        "resistor",
    );
    assert_close(
        &one(DeviceKind::Capacitor),
        &[("area", 3.2e-13), ("perim", 2.4e-6), ("c", 5.6e-16)],
        "capacitor",
    );
    assert_close(
        &one(DeviceKind::Bjt),
        &[
            ("area", 6.4e-13),
            ("perim", 4e-6),
            ("ae", 1.6e-13),
            ("pe", 1.6e-6),
        ],
        "bipolar",
    );
    assert_close(
        &one(DeviceKind::Inductor),
        &[("area", 3.2e-13), ("perim", 2.4e-6), ("ind", 2e-9)],
        "inductor",
    );
}

/// Oracle: `from_layout`'s rustdoc: with no grid a length or area has no
/// unit and is omitted, and so are `r` and `c`, which follow from them; a
/// count (`nf`) and the inductance, which is no measure, stay. With no
/// name interned nothing is written at all.
#[test]
fn without_a_grid_only_counts_and_stated_values_are_written() {
    let (graph, strings) = graph(None);
    for d in 0..graph.device_count() {
        let d = u32::try_from(d).expect("small");
        let got = params(&graph, &strings, d);
        let want: &[(&str, f64)] = match graph.device_kind[d as usize] {
            DeviceKind::Mos => &[("nf", 1.0)],
            DeviceKind::Inductor => &[("ind", 2e-9)],
            _ => &[],
        };
        assert_close(&got, want, &format!("device {d}"));
    }

    let (_, nets, devices, strings) = extract(&[]);
    let graph = from_layout(
        &nets,
        &devices,
        &PortTable::default(),
        &strings,
        Some(Grid::new(1000).expect("1 nm")),
    );
    assert_eq!(graph.device_count(), 6);
    assert!(graph.param.is_empty(), "{:?}", graph.param);
}

/// Each row a run wrote: `(measured, limit, shape, at, layer)`.
type Rows = Vec<(Measurement, Measurement, PolyId, Point, LayerId)>;

fn row_list(out: &Violations) -> Rows {
    (0..out.len())
        .map(|i| {
            (
                out.measured[i],
                out.limit[i],
                out.shape_a[i],
                out.at[i],
                out.layer[i],
            )
        })
        .collect()
}

/// A bound row as written: `(model, param, min, max)`.
type RangeRow<'a> = (&'a str, &'a str, Option<LvsLimit>, Option<LvsLimit>);

/// `check_param_ranges` over [`drawn`]: its run, its rows, and the store and
/// devices it ran over.
fn ranges(rows: &[RangeRow<'_>]) -> (Option<RuleRun>, Rows, (GeometryStore, DeviceTable)) {
    let (store, nets, devices, mut strings) = extract(&[]);
    intern_rule_ids(&mut strings);
    let rows: Vec<LvsRange> = rows
        .iter()
        .map(|&(model, param, min, max)| LvsRange {
            model: strings.intern(model),
            param: strings.intern(param),
            min,
            max,
        })
        .collect();
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    check_param_ranges(
        Design {
            store: &store,
            nets: &nets,
            devices: &devices,
        },
        &rows,
        &strings,
        &mut out,
        &mut runs,
    );
    assert!(runs.len() <= 1);
    (runs.pop(), row_list(&out), (store, devices))
}

/// Where a row on `marker` must be: its first vertex, on its layer.
fn on(store: &GeometryStore, marker: PolyId) -> (Point, LayerId) {
    let (xs, ys) = store.poly_verts(marker);
    (Point { x: xs[0], y: ys[0] }, store.poly_layer(marker))
}

fn length(v: i64) -> LvsLimit {
    LvsLimit::Length(Dbu::new_unchecked(v))
}

fn area(v: i128) -> Option<LvsLimit> {
    Some(LvsLimit::Area(DbuArea::new(v)))
}

/// Oracle: `check_param_ranges`' rustdoc ("a value at a bound is legal")
/// against the drawing: each nmos is 1000 wide, so a `w` range of exactly
/// [1000, 1000] passes both and one unit inside either end fails both,
/// measured 1000 against the bound, on each gate's first vertex; two rows
/// over two transistors examine four pairs; a range with no bound
/// examines and finds nothing.
#[test]
fn a_length_at_its_bound_passes_and_one_unit_past_fails() {
    let (run, rows, _) = ranges(&[("nmos", "w", Some(length(1000)), Some(length(1000)))]);
    let run = run.expect("a row");
    assert_eq!(
        (run.outcome, run.examined, run.violations),
        (Outcome::Ran, 2, 0)
    );
    assert!(rows.is_empty());

    for (min, max, limit) in [(1001, 2000, 1001), (0, 999, 999)] {
        let (run, rows, (store, devices)) = ranges(&[
            ("nmos", "w", Some(length(min)), Some(length(max))),
            ("nmos", "l", None, None),
        ]);
        let run = run.expect("a row");
        assert_eq!(
            (run.outcome, run.examined, run.violations),
            (Outcome::Ran, 4, 2)
        );
        let want: Rows = (0..devices.len())
            .filter(|&d| devices.kind[d] == DeviceKind::Mos)
            .map(|d| {
                let marker = devices.marker[d];
                let (at, layer) = on(&store, marker);
                (
                    Measurement::Length(Dbu::new_unchecked(1000)),
                    Measurement::Length(Dbu::new_unchecked(limit)),
                    marker,
                    at,
                    layer,
                )
            })
            .collect();
        assert_eq!(rows, want, "w in [{min}, {max}]");
    }
}

/// Oracle: the rustdoc's share rule, hand-derived. Each nmos has one end
/// to itself (500 x 1000 = 500000 nm²) and shares the middle one with the
/// other (a share of 250000). A maximum of 250000 on both `as` and `ad`
/// fails each whole end only, reported as the ratio 500000 against
/// 250000; at 249999 the shared ends fail too, as the ratio 250000. Which
/// end is the source does not matter: `as` and `ad` together hold one of
/// each per transistor.
#[test]
fn a_shared_diffusion_is_held_to_its_bound_by_its_share() {
    for (max, mut want) in [
        (250_000, vec![500_000.0, 500_000.0]),
        (249_999, vec![250_000.0, 250_000.0, 500_000.0, 500_000.0]),
    ] {
        let (run, rows, _) = ranges(&[
            ("nmos", "as", None, area(max)),
            ("nmos", "ad", None, area(max)),
        ]);
        let run = run.expect("a row");
        assert_eq!((run.outcome, run.examined), (Outcome::Ran, 4));
        #[expect(clippy::cast_precision_loss, reason = "small")]
        let bound = max as f64;
        let mut got: Vec<f64> = rows
            .iter()
            .map(|r| match (r.0, r.1) {
                (Measurement::Ratio(m), Measurement::Ratio(l)) => {
                    assert!((l - bound).abs() < 1e-9, "{l} against {max}");
                    m
                }
                other => panic!("a share is a ratio: {other:?}"),
            })
            .collect();
        got.sort_by(f64::total_cmp);
        want.sort_by(f64::total_cmp);
        assert_eq!(got, want, "max {max}");
    }
}

/// Oracle: the rustdoc, hand-derived: the resistor's marker is 800 x 400,
/// 320000 nm², an area compared exactly (319999 fails, 320000 passes);
/// each nmos is one finger, a count (`nf` at least 2 fails both, measured
/// 1 against 2); a bound of another kind than its parameter (a `w`
/// against an area) or a parameter not measured on the model (`ae` on a
/// transistor) refuses the run, keeping its other rows.
#[test]
fn areas_and_counts_compare_exactly_and_what_cannot_be_compared_refuses() {
    let (run, rows, _) = ranges(&[("rpoly", "area", None, area(320_000))]);
    assert_eq!(
        run.map(|r| (r.outcome, r.violations)),
        Some((Outcome::Ran, 0))
    );
    assert!(rows.is_empty());
    let (_, rows, _) = ranges(&[("rpoly", "area", None, area(319_999))]);
    assert_eq!(
        rows.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>(),
        [(
            Measurement::Area(DbuArea::new(320_000)),
            Measurement::Area(DbuArea::new(319_999))
        )]
    );
    let (_, rows, _) = ranges(&[("nmos", "nf", Some(LvsLimit::Count(2)), None)]);
    assert_eq!(
        rows.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>(),
        [(Measurement::Count(1), Measurement::Count(2)); 2]
    );
    let (_, rows, _) = ranges(&[(
        "nmos",
        "nf",
        Some(LvsLimit::Count(1)),
        Some(LvsLimit::Count(1)),
    )]);
    assert!(rows.is_empty());

    for (param, bound) in [("w", area(1)), ("ae", area(1))] {
        let (run, rows, _) = ranges(&[
            ("nmos", param, None, bound),
            ("nmos", "w", None, Some(length(999))),
        ]);
        let run = run.expect("a row");
        assert_eq!(
            (run.outcome, run.violations),
            (Outcome::Refused, 2),
            "{param}"
        );
        assert_eq!(rows.len(), 2, "{param}: the other rows kept");
    }
    let (run, rows, _) = ranges(&[]);
    assert!(run.is_none() && rows.is_empty(), "no range, no row");
}

/// Oracle: `check_device_counts`' rustdoc, hand-derived: two nmos against
/// a maximum of 1 is one row on the second (the `max + 1`-th), measured 2
/// against 1; against a minimum of 3, one row on the first, 2 against 3;
/// a model with no device under a minimum of 1 is a row with no shape,
/// at the origin, 0 against 1; at the bounds nothing. One examined per row.
#[test]
fn device_counts_are_held_to_their_bounds() {
    let (store, nets, devices, mut strings) = extract(&[]);
    intern_rule_ids(&mut strings);
    let nmos = strings.intern("nmos");
    let pmos = strings.intern("pmos");
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let count = |model, min, max| LvsCount { model, min, max };
    let run = |rows: &[LvsCount]| {
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        check_device_counts(design, rows, &strings, &mut out, &mut runs);
        (runs, row_list(&out))
    };
    let (runs, rows) = run(&[count(nmos, Some(2), Some(2))]);
    assert_eq!((runs.len(), runs[0].examined, rows.len()), (1, 1, 0));

    let mos: Vec<PolyId> = (0..devices.len())
        .filter(|&d| devices.model[d] == nmos)
        .map(|d| devices.marker[d])
        .collect();
    let (runs, rows) = run(&[count(nmos, Some(3), Some(1)), count(pmos, Some(1), None)]);
    assert_eq!((runs[0].examined, runs[0].violations), (2, 3));
    let (second, layer) = on(&store, mos[1]);
    let (first, _) = on(&store, mos[0]);
    let nowhere = Point {
        x: Dbu::new_unchecked(0),
        y: Dbu::new_unchecked(0),
    };
    assert_eq!(
        rows,
        [
            (
                Measurement::Count(2),
                Measurement::Count(1),
                mos[1],
                second,
                layer
            ),
            (
                Measurement::Count(2),
                Measurement::Count(3),
                mos[0],
                first,
                layer
            ),
            (
                Measurement::Count(0),
                Measurement::Count(1),
                PolyId(u32::MAX),
                nowhere,
                LayerId(u16::MAX)
            ),
        ]
    );
    let (runs, _) = run(&[]);
    assert!(runs.is_empty());
}
