//! `add_lde_params` (LVS-074) on one transistor drawn by hand: `SA`/`SB`
//! from BSIM4's effective-distance law and `SCA`/`SCB`/`SCC` from Silvaco's
//! closed forms, written out again here apart from `lvs::lde::wpe`.

use gpurify_check::lvs::add_lde_params;
use gpurify_check::lvs::graph::{from_layout, Graph};
use gpurify_check::topology::device::recognise_into;
use gpurify_check::topology::{extract_nets_into, DeviceTable, NetTable, PortTable};
use gpurify_check::Design;
use gpurify_geom::Grid;
use gpurify_ingest::deck::{parse_deck, Deck};
use gpurify_ingest::{StrId, StrTable};
use gpurify_testgen::LayoutBuilder;

/// One `nmos` and one `pmos` recogniser over drawn layers, an `lvs lde` row
/// for `nmos` with `max` and, when `well`, the well layer at `SCREF` 1000 nm.
fn deck(max: i64, well: bool, strings: &mut StrTable) -> Deck {
    let well = if well { " well wellm scref 1000nm" } else { "" };
    let text = format!(
        "grid 1nm
layer diff = gds(1, 0)
layer poly = gds(2, 0)
layer gate = gds(3, 0)
layer sd = gds(4, 0)
layer wellm = gds(5, 0)
layer pgate = gds(6, 0)
connect conductors [sd, poly]
connect touch_within_layer
device mos gate model \"nmos\" terminals [poly, sd, sd]
device mos pgate model \"pmos\" terminals [poly, sd, sd]
lvs lde \"nmos\" od diff max {max}nm{well}
"
    );
    parse_deck(&text, Grid::new(1000).expect("1 nm"), strings).expect("the deck parses")
}

/// A rectangle `[xlo, ylo, xhi, yhi]` on a named layer.
type Shape = (&'static str, [i64; 4]);

/// One of four placements of the square: identity, the transpose (the
/// channel then runs along y), the mirror in y, and a quarter turn.
#[derive(Clone, Copy, Debug)]
enum Place {
    Identity,
    Transpose,
    Mirror,
    Turn,
}

impl Place {
    const ALL: [Place; 4] = [
        Place::Identity,
        Place::Transpose,
        Place::Mirror,
        Place::Turn,
    ];

    fn rect(self, [xlo, ylo, xhi, yhi]: [i64; 4]) -> [i64; 4] {
        let map = |x: i64, y: i64| match self {
            Place::Identity => (x, y),
            Place::Transpose => (y, x),
            Place::Mirror => (-x, y),
            Place::Turn => (-y, x),
        };
        let (a, b) = (map(xlo, ylo), map(xhi, yhi));
        [a.0.min(b.0), a.1.min(b.1), a.0.max(b.0), a.1.max(b.1)]
    }
}

/// The parameters `add_lde_params` gives the first device, after the ones
/// `from_layout` measured, with `names` interned as a reference would.
fn lde_of(
    shapes: &[Shape],
    place: Place,
    (max, well): (i64, bool),
    names: &[&str],
) -> (Vec<(String, f64)>, usize) {
    let mut strings = StrTable::default();
    // The device's own `w` and `l`, which `from_layout` measures and the
    // LDE parameters follow.
    for name in ["w", "l"].iter().chain(names) {
        strings.intern(name);
    }
    let deck = deck(max, well, &mut strings);
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for &(layer, rect) in shapes {
        let id = deck.layers.id(&strings, layer).expect("a deck layer");
        let [xlo, ylo, xhi, yhi] = place.rect(rect);
        layout.rect(id, xlo, ylo, xhi, yhi);
    }
    let (store, _) = layout.finish();
    let mut nets = NetTable::default();
    extract_nets_into(&store, &deck.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    recognise_into(&store, &nets, &deck.devices, &mut devices);
    let ports = PortTable::default();
    let grid = Grid::new(1000).expect("1 nm");
    let mut graph: Graph = from_layout(&nets, &devices, &ports, &strings, Some(grid));
    assert_eq!(graph.device_count(), 1, "the fixture draws one transistor");
    let before = graph.params_of(0).len();
    add_lde_params(
        &mut graph,
        Design {
            store: &store,
            nets: &nets,
            devices: &devices,
        },
        (&deck.lvs.lde, &deck.layers),
        &strings,
        grid,
    );
    assert_eq!(graph.device_param_start.len(), 2);
    let params = graph.params_of(0);
    assert_eq!(
        params.len(),
        graph.param.len(),
        "one device holds every row"
    );
    let resolve = |id: StrId| strings.resolve(id).to_owned();
    let own: Vec<(String, f64)> = params[..before]
        .iter()
        .map(|&(name, value)| (resolve(name), value))
        .collect();
    assert_params(
        &own,
        &[("w", 1e-6), ("l", 150e-9)],
        "the device's own, first",
    );
    (
        params[before..]
            .iter()
            .map(|&(name, value)| (resolve(name), value))
            .collect(),
        before,
    )
}

/// Silvaco's `SCA`, `SCB`, `SCC` from `[SC1, SC2, SC3, SC4]`, `w`, `l`,
/// `scref`, in metres, as the application note writes them.
fn silvaco_wpe(sc: [f64; 4], w: f64, l: f64, scref: f64) -> [f64; 3] {
    let sca = scref * scref / (w * l)
        * (w * (1.0 / sc[0] - 1.0 / (sc[0] + l))
            + l * (1.0 / sc[1] - 1.0 / (sc[1] + w))
            + w * (1.0 / sc[2] - 1.0 / (sc[2] + l))
            + l * (1.0 / sc[3] - 1.0 / (sc[3] + w)));
    let one = |n: f64, s: f64, e: f64| {
        1.0 / (e * scref)
            * (scref / n * s * (-n * s / scref).exp()
                + scref * scref / (n * n) * (-n * s / scref).exp()
                - scref / n * (s + e) * (-n * (s + e) / scref).exp()
                - scref * scref / (n * n) * (-n * (s + e) / scref).exp())
    };
    let integral =
        |n: f64| one(n, sc[1], w) + one(n, sc[3], w) + one(n, sc[0], l) + one(n, sc[2], l);
    [sca, integral(10.0), integral(20.0)]
}

/// The transistor: OD `x` 0..1150 by `y` 0..1000 with an OD strip `x`
/// -300..0 by `y` 0..500 abutting its source side, the gate `x` 500..650
/// (`L` 150, `W` 1000), poly across it, and the two diffusions beside it.
fn transistor() -> Vec<Shape> {
    vec![
        ("diff", [0, 0, 1150, 1000]),
        ("diff", [-300, 0, 0, 500]),
        ("gate", [500, 0, 650, 1000]),
        ("poly", [500, -200, 650, 1200]),
        ("sd", [0, 0, 500, 1000]),
        ("sd", [650, 0, 1150, 1000]),
    ]
}

const NAMES: [&str; 5] = ["sa", "sb", "sca", "scb", "scc"];

fn assert_params(got: &[(String, f64)], want: &[(&str, f64)], case: &str) {
    assert_eq!(
        got.iter().map(|p| p.0.as_str()).collect::<Vec<_>>(),
        want.iter().map(|p| p.0).collect::<Vec<_>>(),
        "{case}: the names, in order"
    );
    for ((name, value), (_, expected)) in got.iter().zip(want) {
        assert!(
            (value - expected).abs() <= 1e-9 * expected.abs(),
            "{case}: {name} = {value:e}, want {expected:e}"
        );
    }
}

/// `sa`, `sb` of [`transistor`] with `max`: the drain side sees 500 nm over
/// the whole width; the source side sees 800 nm (to the strip's far edge)
/// over the lower half and 500 nm over the upper, each capped at `max`, and
/// BSIM4's effective distance is `1 / Σ (wᵢ/W) / (dᵢ + L/2) − L/2`.
fn stress_pair(max: f64) -> (f64, f64) {
    let half = 75.0;
    let source = 1.0 / (0.5 / (800f64.min(max) + half) + 0.5 / (500f64.min(max) + half)) - half;
    let drain = 500f64.min(max);
    (source.min(drain) * 1e-9, source.max(drain) * 1e-9)
}

/// Oracle: BSIM4's law, hand-evaluated ([`stress_pair`]): `sa` 500 nm and
/// `sb` `1/(0.5/875 + 0.5/575) − 75` = 619.0 nm, smaller first, in metres,
/// after the device's own `w` and `l`. With the source strip read as a
/// separate OD (the merge of abutting spans dropped) `sb` would be 500; a
/// wrong strip weight, side, or halving of `L` moves it. The same under the
/// transpose, the mirror and a quarter turn: the channel then runs along y
/// or the sides swap, and the pair is sorted.
#[test]
fn sa_and_sb_are_bsim4_s_effective_distances_in_every_placement() {
    let (sa, sb) = stress_pair(f64::INFINITY);
    for place in Place::ALL {
        let (got, before) = lde_of(&transistor(), place, (5000, false), &NAMES);
        assert_eq!(before, 2, "{place:?}: from_layout's w and l come first");
        assert_params(&got, &[("sa", sa), ("sb", sb)], &format!("{place:?}"));
    }
}

/// Oracle: the cap, hand-evaluated. With `max` 700 nm the source side's
/// 800 nm strip reads 700, so `sb` is `1/(0.5/775 + 0.5/575) − 75`, and `sa`
/// stays 500; with `max` 400 every distance reads 400, so both are 400.
#[test]
fn every_distance_is_capped_at_the_row_s_max() {
    for max in [700, 400] {
        #[expect(clippy::cast_precision_loss, reason = "small")]
        let (sa, sb) = stress_pair(max as f64);
        let (got, _) = lde_of(&transistor(), Place::Identity, (max, false), &NAMES);
        assert_params(&got, &[("sa", sa), ("sb", sb)], &format!("max {max}"));
    }
}

/// Oracle: Silvaco's closed forms ([`silvaco_wpe`]) over distances read off
/// the drawing. A well `x` -1500..2650 by `y` -2000..4000 puts the gate's
/// source end (`x` 500) 2000 nm from its left edge (`SC1`), its bottom
/// (`y` 0) 2000 from the bottom (`SC2`), its drain end (650) 2000 from the
/// right (`SC3`) and its top (1000) 3000 from the top (`SC4`); `W` 1000,
/// `L` 150, `SCREF` 1000 nm. `SCA` is symmetric in `SC1`/`SC3` and in
/// `SC2`/`SC4`, so every placement agrees.
#[test]
fn an_enclosing_well_gives_silvaco_s_integrals_in_every_placement() {
    let (sa, sb) = stress_pair(f64::INFINITY);
    let [sca, scb, scc] = silvaco_wpe(
        [2000e-9, 2000e-9, 2000e-9, 3000e-9],
        1000e-9,
        150e-9,
        1000e-9,
    );
    let mut shapes = transistor();
    shapes.push(("wellm", [-1500, -2000, 2650, 4000]));
    for place in Place::ALL {
        let (got, _) = lde_of(&shapes, place, (5000, true), &NAMES);
        assert_params(
            &got,
            &[
                ("sa", sa),
                ("sb", sb),
                ("sca", sca),
                ("scb", scb),
                ("scc", scc),
            ],
            &format!("{place:?}"),
        );
    }
}

/// Oracle: the median rule, hand-evaluated. A well to the right only, its
/// left edge at `x` 1000 for `y` below 300 and at 1500 above: the drain end
/// (650) sees 350 nm over a 300 strip of the gate's width and 850 over a
/// 700 strip, so the width-weighted median is 850; the other three edges
/// see no well edge outward and read `max`, 5000. Every placement agrees.
#[test]
fn a_stepped_well_edge_reads_the_width_weighted_median() {
    let (sa, sb) = stress_pair(f64::INFINITY);
    let [sca, scb, scc] = silvaco_wpe(
        [5000e-9, 5000e-9, 850e-9, 5000e-9],
        1000e-9,
        150e-9,
        1000e-9,
    );
    let mut shapes = transistor();
    shapes.push(("wellm", [1000, -3000, 3000, 300]));
    shapes.push(("wellm", [1500, 300, 3000, 4000]));
    for place in Place::ALL {
        let (got, _) = lde_of(&shapes, place, (5000, true), &NAMES);
        assert_params(
            &got,
            &[
                ("sa", sa),
                ("sb", sb),
                ("sca", sca),
                ("scb", scb),
                ("scc", scc),
            ],
            &format!("{place:?}"),
        );
    }
}

/// Oracle: the median rule's other side. The well's step is at `y` 700
/// instead: 350 nm over 700 of the width and 850 over 300, so the median is
/// 350 (half the width is covered at the first distance).
#[test]
fn a_well_edge_near_over_most_of_the_width_reads_the_near_distance() {
    let [sca, scb, scc] = silvaco_wpe(
        [5000e-9, 5000e-9, 350e-9, 5000e-9],
        1000e-9,
        150e-9,
        1000e-9,
    );
    let mut shapes = transistor();
    shapes.push(("wellm", [1000, -3000, 3000, 700]));
    shapes.push(("wellm", [1500, 700, 3000, 4000]));
    let (got, _) = lde_of(&shapes, Place::Identity, (5000, true), &NAMES);
    assert_params(
        &got[2..],
        &[("sca", sca), ("scb", scb), ("scc", scc)],
        "step at 700",
    );
}

/// Oracle: the median rule at its boundary and the "outward" rule, hand
/// evaluated. A step at `y` 500 splits the width in halves, 350 and 850:
/// half the width is covered at 350, so the (lower) weighted median is
/// 350. A well whose edge lies on the gate's drain edge (`x` 650) is not
/// outward of it: the drain end reads the well's far edge, 2350 away.
#[test]
fn the_median_takes_the_lower_half_and_an_edge_on_the_gate_is_not_outward() {
    let mut halves = transistor();
    halves.push(("wellm", [1000, -3000, 3000, 500]));
    halves.push(("wellm", [1500, 500, 3000, 4000]));
    let mut flush = transistor();
    flush.push(("wellm", [650, -3000, 3000, 4000]));
    for (shapes, sc3) in [(halves, 350e-9), (flush, 2350e-9)] {
        let [sca, scb, scc] =
            silvaco_wpe([5000e-9, 5000e-9, sc3, 5000e-9], 1000e-9, 150e-9, 1000e-9);
        let (got, _) = lde_of(&shapes, Place::Identity, (5000, true), &NAMES);
        assert_params(
            &got[2..],
            &[("sca", sca), ("scb", scb), ("scc", scc)],
            &format!("SC3 {sc3:e}"),
        );
    }
}

/// Oracle: the module's contract. Only interned names are written (a
/// reference that never states `sb` gets no `sb`), none at all when no name
/// is interned, and nothing for a gate that is not one rectangle inside one
/// stretch of OD.
#[test]
fn only_measurable_gates_and_interned_names_get_parameters() {
    let (sa, _) = stress_pair(f64::INFINITY);
    let (got, _) = lde_of(&transistor(), Place::Identity, (5000, false), &["sa"]);
    assert_params(&got, &[("sa", sa)], "sa alone");
    let (got, _) = lde_of(&transistor(), Place::Identity, (5000, false), &[]);
    assert!(got.is_empty(), "no name interned: {got:?}");

    // The OD stops at the gate's drain edge: it runs past the gate on one
    // side only, so no channel direction.
    let mut short = transistor();
    short[0] = ("diff", [0, 0, 650, 1000]);
    let (got, _) = lde_of(&short, Place::Identity, (5000, false), &NAMES);
    assert!(got.is_empty(), "OD on one side only: {got:?}");

    // An OD as wide as the gate and running past it both ways is a cross:
    // no single axis.
    let mut cross = transistor();
    cross.push(("diff", [500, -500, 650, 1500]));
    let (got, _) = lde_of(&cross, Place::Identity, (5000, false), &NAMES);
    assert!(got.is_empty(), "OD on both axes: {got:?}");
}

/// Oracle: the row names its model. A `pmos` drawn the same way is not the
/// row's `nmos`, and gets nothing.
#[test]
fn a_transistor_of_another_model_gets_nothing() {
    let shapes: Vec<Shape> = transistor()
        .into_iter()
        .map(|(layer, rect)| (if layer == "gate" { "pgate" } else { layer }, rect))
        .collect();
    let (got, before) = lde_of(&shapes, Place::Identity, (5000, true), &NAMES);
    assert_eq!(before, 2);
    assert!(got.is_empty(), "{got:?}");
}
