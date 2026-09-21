//! Metamorphic laws over the whole of extraction.
//!
//! Oracle throughout: **law**. Every test here transforms one hand-placed
//! layout and asserts that the extraction changes in the one way the transform
//! licenses and in no other. That is the oracle `topology` is shortest of — the
//! rest of `tests/` is construct-from-answer over `layout_from_netlist`, which
//! can only say "this generator and this extractor agree", and cannot say
//! anything at all about geometry the generator never emits.
//!
//! The transform is applied **at the store level**, never by re-ingesting a
//! transformed layout file. A mirrored `SREF` drags in the flattener's
//! `at.flip` ring reversal and `derived::validate_layer_into`'s winding-derived
//! hole bit, neither of which is part of any claim below: the subject is
//! `extract_nets_into` and `recognise_into` over a store, and nothing else.
//!
//! `port::bind_ports_into` is deliberately out of scope. It reads
//! `provenance.labels()`, a `Vec<(PolyId, StrId)>` carrying no coordinate, so
//! every geometric law is trivially true of it and asserting one would be
//! coverage theatre.

use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_geom::Evaluator;
use gpurify_ingest::deck::{Connectivity, DeviceKind, DeviceRecognition};
use gpurify_ingest::StrTable;
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_check::topology::device::{recognise_into, DeviceMeasure, DeviceParam};
use gpurify_check::topology::{extract_nets_into, DeviceId, DeviceTable, NetId, NetTable, TerminalRole};
use gpurify_geom::{Dbu, DbuArea};

// The layer table. Five conductors, one cut, one marker — the marker is
// deliberately *not* a conductor, which is what makes `NetId::NONE` reachable
// and what the anti-vacuity guards below check for.
const M1: LayerId = LayerId(0);
const M2: LayerId = LayerId(1);
const CUT: LayerId = LayerId(2);
const GATE: LayerId = LayerId(3);
const SRC: LayerId = LayerId(4);
const DRN: LayerId = LayerId(5);
const MARK: LayerId = LayerId(6);
const LAYER_COUNT: usize = 7;

/// One rectangle of the fixture. Rectilinear on purpose: `DIRECT_PAIR_BUDGET`
/// is 1024, so a four-vertex ring never reaches `rings_meet_sweep` and no claim
/// here is secretly about the sweep. The sweep has its own differential test
/// inside `net.rs`, which is the right place for it.
struct Rect {
    layer: LayerId,
    xlo: i64,
    ylo: i64,
    xhi: i64,
    yhi: i64,
}

// Indices into `fixture()`, by name. The push order *is* the base order, so
// these double as the identity permutation's shape ids.
const M1_A: usize = 0;
const M2_A: usize = 1;
const CUT_A: usize = 2;
const M2_B: usize = 3;
const M2_B_INNER: usize = 4;
const M1_C1: usize = 5;
const M1_C2: usize = 6;
const GATE_D: usize = 7;
const SRC_D: usize = 8;
const DRN_D: usize = 9;
const MARK_D: usize = 10;
const GATE_E: usize = 11;
const SRC_E: usize = 12;
const MARK_E: usize = 13;

/// The layout every law below is stated over.
///
/// It is built to reach the three places these laws can catch anything, and
/// each one is asserted present by [`assert_the_base_run_can_fail_a_law`] so a
/// later edit cannot quietly remove it:
///
/// 1. **A cut strictly inside both conductors it joins** (`CUT_A`), which is
///    the via-mediated join and one of `polys_intersect`'s containment probes.
/// 2. **A same-layer shape strictly inside a plate with no boundary contact**
///    (`M2_B_INNER` in `M2_B`), which is the *other* containment probe — the
///    one `rings_meet` answers `false` to. Without it the laws exercise the two
///    sorts and the box prune, and both of those are already tested.
/// 3. **A marker that fires beside a marker that does not** (`MARK_D` against
///    `MARK_E`, which has no shape on `DRN` under it), so `recognise_into`'s
///    `NetId::NONE` skip is on both sides of the transform.
///
/// Exactly one shape on each terminal layer meets each marker. That is
/// mandatory rather than tidy: `device.rs:296-298` iterates `exact.iter().rev()`
/// so the *lowest* `PolyId` under a marker wins, which is legitimately
/// `PolyId`-order dependent. Asserting terminal invariance under a permutation
/// on a layout where two shapes share a terminal layer under one marker — the
/// F3 shape — would be asserting a bug.
fn fixture() -> Vec<Rect> {
    let rect = |layer, xlo, ylo, xhi, yhi| Rect {
        layer,
        xlo,
        ylo,
        xhi,
        yhi,
    };
    vec![
        // A conductor plate, a wire above it, and the cut that joins them. The
        // cut is strictly inside both, sharing an edge with neither.
        rect(M1, 0, 0, 200, 100),
        rect(M2, 50, 20, 150, 80),
        rect(CUT, 60, 30, 90, 60),
        // A plate with a second shape of the same layer strictly inside it.
        rect(M2, 400, 0, 700, 300),
        rect(M2, 500, 100, 600, 200),
        // Two shapes abutting along x = -300, on the negative side of both
        // axes so a mirror moves material across the origin rather than
        // sliding a wholly-positive layout somewhere else wholly positive.
        rect(M1, -500, -300, -300, -100),
        rect(M1, -300, -300, -100, -100),
        // The device that fires: one gate, one source, one drain, one marker.
        rect(GATE, 1_000, 0, 1_100, 400),
        rect(SRC, 900, 150, 1_010, 250),
        rect(DRN, 1_090, 150, 1_200, 250),
        rect(MARK, 950, 150, 1_150, 250),
        // The device that does not: no shape on DRN reaches it, so its drain
        // slot stays `NetId::NONE` and `recognise_into` skips the marker.
        rect(GATE, 1_550, 0, 1_650, 400),
        rect(SRC, 1_500, 150, 1_560, 250),
        rect(MARK, 1_500, 150, 1_700, 250),
    ]
}

/// The deck's connectivity: five conductors and one via joining M1 to M2.
fn connectivity() -> Connectivity {
    Connectivity {
        conductors: vec![M1, M2, GATE, SRC, DRN],
        via_cut: vec![CUT],
        via_connects: vec![(M1, M2)],
        intra_layer_touch: true,
        label_layer: Vec::new(),
        label_names: Vec::new(),
    }
}

/// A three-terminal MOS recogniser, one terminal layer per role.
///
/// Three and not four, and each on its own layer, for F3's reason: the corpus
/// deck writes `terminals: [poly, diff, diff]`, which puts source and drain on
/// one layer and collapses them onto one net. That is a real finding about the
/// corpus and is filed; reproducing it here would only make every terminal
/// claim below untestable.
fn mos_recogniser(strings: &mut StrTable) -> DeviceRecognition {
    DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![MARK],
        terminal_start: vec![0, 3],
        terminal: vec![GATE, SRC, DRN],
        model: vec![strings.intern("nch")],
    }
}

/// Build the fixture with the vertices mapped through `t` and pushed in
/// `order`, and report where each shape landed.
///
/// Returns `(store, id_of_shape)` where `id_of_shape[s]` is the [`PolyId`] the
/// store gave `fixture()[s]`. `LayoutBuilder` inverts the layer sort's
/// permutation, so this is the only place either transform needs to know about
/// it.
fn build(
    shapes: &[Rect],
    order: &[usize],
    t: impl Fn(i64, i64) -> (i64, i64),
) -> (GeometryStore, Vec<PolyId>) {
    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    let mut handles = vec![None; shapes.len()];
    for &s in order {
        let r = &shapes[s];
        let corners = [
            (r.xlo, r.ylo),
            (r.xhi, r.ylo),
            (r.xhi, r.yhi),
            (r.xlo, r.yhi),
        ];
        let mapped: Vec<(i64, i64)> = corners.iter().map(|&(x, y)| t(x, y)).collect();
        let xs: Vec<i64> = mapped.iter().map(|&(x, _)| x).collect();
        let ys: Vec<i64> = mapped.iter().map(|&(_, y)| y).collect();
        handles[s] = Some(layout.push(r.layer, &xs, &ys));
    }
    let (store, ids) = layout.finish();
    let id_of_shape = handles
        .into_iter()
        .map(|h| ids.of(h.expect("every shape is pushed exactly once")))
        .collect();
    (store, id_of_shape)
}

/// Nets and devices from one store, through the two transforms under test.
fn extract(store: &GeometryStore, recognition: &DeviceRecognition) -> (NetTable, DeviceTable) {
    let mut nets = NetTable::default();
    extract_nets_into(store, &connectivity(), &mut nets);
    let mut devices = DeviceTable::default();
    recognise_into(
        store,
        &Evaluator::default(),
        &nets,
        recognition,
        &mut devices,
    );
    (nets, devices)
}

/// Every net id in a run, as ids rather than as a count.
fn net_ids(nets: &NetTable) -> Vec<NetId> {
    (0..nets.net_count())
        .map(|k| NetId(u32::try_from(k).expect("this fixture holds tens of nets")))
        .collect()
}

/// The guards that stop any of these laws being satisfied by an extractor that
/// reports nothing.
///
/// Every clause is a property of the *base* run, asserted before a single
/// comparison is made. A law over two empty tables is a tautology, and this
/// project already carries enough tests that cannot fail.
fn assert_the_base_run_can_fail_a_law(
    store: &GeometryStore,
    ids: &[PolyId],
    nets: &NetTable,
    devices: &DeviceTable,
) {
    assert!(
        nets.net_count() > 1,
        "one net cannot show a partition moving"
    );

    let multi = net_ids(nets)
        .into_iter()
        .filter(|&n| nets.polys_of(n).len() > 1)
        .count();
    assert!(
        multi >= 3,
        "a partition of singletons is invariant under anything: {multi} nets hold two or more \
         polygons"
    );

    // The via-mediated join, and the cut that made it. `CUT_A` is on no
    // conductor layer, so it is `NetId::NONE` and belongs to no net — which is
    // also the `NONE` polygon the permutation law requires.
    assert!(
        nets.same_net(ids[M1_A], ids[M2_A]),
        "the M1 plate and the M2 wire are joined only by the cut, and they did not join"
    );
    assert_eq!(
        nets.net_of(ids[CUT_A]),
        NetId::NONE,
        "a cut conducts nothing and must carry no net"
    );
    assert_eq!(nets.net_of(ids[MARK_D]), NetId::NONE, "nor does a marker");

    // The two containment probes, each asserted to be a real strict nesting
    // rather than merely a pair that happens to intersect.
    for (inner, outer) in [(CUT_A, M1_A), (CUT_A, M2_A), (M2_B_INNER, M2_B)] {
        let (small, large) = (store.poly_bbox(ids[inner]), store.poly_bbox(ids[outer]));
        assert!(
            small.xlo > large.xlo
                && small.ylo > large.ylo
                && small.xhi < large.xhi
                && small.yhi < large.yhi,
            "shape {inner} must be strictly inside shape {outer}, boundaries not meeting"
        );
    }
    assert!(
        nets.same_net(ids[M2_B], ids[M2_B_INNER]),
        "a same-layer shape wholly inside a plate is the same conductor as the plate"
    );
    assert!(
        nets.same_net(ids[M1_C1], ids[M1_C2]),
        "two shapes abutting along an edge are one conductor"
    );

    // One recogniser fired and one did not, so both sides of the `NetId::NONE`
    // skip are exercised by every comparison below.
    assert_eq!(devices.len(), 1, "exactly one of the two markers may fire");
    assert_eq!(
        store.polys_on_layer(MARK).len(),
        2,
        "the layout draws two markers, and the second one must fail to fire"
    );
    assert_eq!(devices.marker, vec![ids[MARK_D]], "the wrong marker fired");
    assert!(
        !devices.terminal_net.is_empty() && !devices.terminal_net.contains(&NetId::NONE),
        "a device with no bound terminal makes every terminal claim vacuous"
    );
    assert_eq!(
        devices.terminals_of(DeviceId(0)).1,
        [
            TerminalRole::Gate,
            TerminalRole::Source,
            TerminalRole::Drain
        ],
        "terminal roles follow the recogniser's terminal order"
    );

    // The three terminals are on three *different* nets. Not decoration: with
    // source and drain on one layer they would collapse onto one net (F3), and
    // a terminal law over a table whose terminals are all the same net cannot
    // see a terminal move.
    let bound = devices.terminals_of(DeviceId(0)).0;
    assert_eq!(
        bound,
        [
            nets.net_of(ids[GATE_D]),
            nets.net_of(ids[SRC_D]),
            nets.net_of(ids[DRN_D])
        ],
        "the device bound its terminals to shapes other than the three drawn under its marker"
    );
    assert!(
        bound[0] != bound[1] && bound[1] != bound[2] && bound[0] != bound[2],
        "the three terminals must be three distinct nets: {bound:?}"
    );

    // And the marker that did not fire failed on its drain slot alone — its
    // gate and source really are there, so the skip is `recognise_into`'s
    // `NetId::NONE` rule and not an empty corner of the layout.
    assert_eq!(
        nets.net_of(ids[MARK_E]),
        NetId::NONE,
        "a marker carries no net"
    );
    assert!(
        nets.net_of(ids[GATE_E]) != NetId::NONE && nets.net_of(ids[SRC_E]) != NetId::NONE,
        "the second marker must have a gate and a source under it and no drain"
    );
}

/// Assert two device tables agree in every column, with `Area` scaled by
/// `area_scale` and `Width`/`Length` by `wl_scale = (width, length)` in the
/// second — `(1, 1)` for an isometry, whose extents (and channel axis, which
/// moves with the source/drain geometry) are preserved.
///
/// Column by column rather than through a derived `PartialEq`, because
/// `DeviceTable` has none and adding one would be a signature change.
fn assert_device_columns_agree(
    base: &DeviceTable,
    other: &DeviceTable,
    area_scale: i128,
    wl_scale: (i64, i64),
    ctx: &str,
) {
    assert_eq!(base.kind, other.kind, "{ctx}: kind");
    assert_eq!(base.marker, other.marker, "{ctx}: marker");
    assert_eq!(base.model, other.model, "{ctx}: model");
    assert_eq!(
        base.terminal_start, other.terminal_start,
        "{ctx}: terminal_start"
    );
    assert_eq!(base.terminal_net, other.terminal_net, "{ctx}: terminal_net");
    assert_eq!(
        base.terminal_role, other.terminal_role,
        "{ctx}: terminal_role"
    );
    assert_eq!(base.param_start, other.param_start, "{ctx}: param_start");

    let want: Vec<_> = base
        .param
        .iter()
        .map(|&(param, measure)| {
            let scaled = match (param, measure) {
                (_, DeviceMeasure::Area(a)) => {
                    DeviceMeasure::Area(DbuArea::new(a.raw() * area_scale))
                }
                (DeviceParam::Width, DeviceMeasure::Length(w)) => {
                    DeviceMeasure::Length(Dbu::new_unchecked(w.raw() * wl_scale.0))
                }
                (DeviceParam::Length, DeviceMeasure::Length(l)) => {
                    DeviceMeasure::Length(Dbu::new_unchecked(l.raw() * wl_scale.1))
                }
                (_, unchanged) => unchanged,
            };
            (param, scaled)
        })
        .collect();
    assert_eq!(other.param, want, "{ctx}: param");
}

/// The reverse index, compared net by net. Only valid where the two runs share
/// a net numbering, which is exactly what laws 1 and 3 assert first.
fn assert_reverse_index_agrees(
    nets: &NetTable,
    base: &DeviceTable,
    other: &DeviceTable,
    ctx: &str,
) {
    let mut carried = 0usize;
    for net in net_ids(nets) {
        assert_eq!(
            base.devices_on(net),
            other.devices_on(net),
            "{ctx}: devices_on({net:?})"
        );
        carried += usize::from(!base.devices_on(net).is_empty());
    }
    assert_eq!(
        carried, 3,
        "{ctx}: the gate, source and drain nets each carry the one device"
    );
}

/// One isometry of the `Dbu` grid, as a map on a vertex.
type Motion = fn(i64, i64) -> (i64, i64);

/// The eight elements of the dihedral group of the square, plus one
/// translation.
///
/// **Translation is deliberately one row of nine.** `SpatialIndex::build_into`
/// takes its grid origin from `extent.xlo`/`extent.ylo`
/// (`crates/core/src/index.rs:178`), so the grid translates *with* the data and
/// comes out bit-identical; `crates/core/tests/index_pairs.rs:289` already
/// covers that half. Mirror and rotation are where the power is: mirroring
/// moves the grid's ragged last cell to the other end of the axis, so the cell
/// partition — and with it the candidate superset the box prune emits — really
/// does differ, while the answer may not.
const MOTIONS: [(&str, Motion); 9] = [
    ("mirror x", |x, y| (-x, y)),
    ("mirror y", |x, y| (x, -y)),
    ("rotate 90", |x, y| (-y, x)),
    ("rotate 180", |x, y| (-x, -y)),
    ("rotate 270", |x, y| (y, -x)),
    ("mirror about y = x", |x, y| (y, x)),
    ("mirror about y = -x", |x, y| (-y, -x)),
    // A mirror composed with an odd-parity shift that straddles the origin, so
    // the ragged cell moves and the layout does not stay on one side of either
    // axis.
    ("mirror x then shift", |x, y| (-x + 777, y - 333)),
    ("translate", |x, y| (x + 7_777, y - 3_333)),
];

/// Oracle: **law** — rigid-motion invariance of the whole extraction.
///
/// `net.rs`'s join rule is set intersection: two shapes on one conductor layer
/// join when they share at least one point, and a cut joins the shapes it
/// shares a point with. An isometry of the plane is a bijection that preserves
/// set intersection, so the edge list it produces is the same edge list under
/// the same polygon ids — the push order, and so the `PolyId` numbering, does
/// not move. `recognise_into` binds terminals through the same predicate and
/// measures the marker's area with `area2(..).abs()`, and an isometry of the
/// integer grid has determinant ±1, so the area is invariant too.
///
/// Therefore `NetTable` must be equal and every `DeviceTable` column must be
/// identical, `DeviceMeasure::Area` included. Nothing here is a tolerance: the
/// arithmetic is exact in `i128`.
///
/// The one thing that legitimately *does* move is the spatial index's cell
/// partition, which is why this can fail at all — a candidate superset that
/// differs must still produce the same answer after the exact re-test.
#[test]
fn a_rigid_motion_of_every_vertex_leaves_the_extraction_bit_identical() {
    let shapes = fixture();
    let identity: Vec<usize> = (0..shapes.len()).collect();
    let mut strings = StrTable::default();
    let recognition = mos_recogniser(&mut strings);

    let (store, ids) = build(&shapes, &identity, |x, y| (x, y));
    let (nets, devices) = extract(&store, &recognition);
    assert_the_base_run_can_fail_a_law(&store, &ids, &nets, &devices);

    for (name, motion) in MOTIONS {
        let (moved_store, moved_ids) = build(&shapes, &identity, motion);
        assert_eq!(
            moved_ids, ids,
            "{name}: an isometry must not renumber polygons — the push order and the layer \
             sort are both untouched, so a difference here means the fixture moved, not the \
             extractor"
        );

        let (moved_nets, moved_devices) = extract(&moved_store, &recognition);
        assert_eq!(
            moved_nets, nets,
            "{name}: the net partition changed under an isometry"
        );
        assert_device_columns_agree(&devices, &moved_devices, 1, (1, 1), name);
        assert_reverse_index_agrees(&nets, &devices, &moved_devices, name);
    }
}

/// A permutation of `0 .. n` that fixes nothing, for `n` coprime to 5.
///
/// A global shuffle of the push sequence is what is wanted, and it lands as a
/// permutation *within* each layer: `GeometryStoreBuilder::finish` sorts by
/// layer and by nothing else, stably, so shapes never cross a layer boundary
/// and their order inside one layer is exactly their push order.
fn shuffled(n: usize) -> Vec<usize> {
    (0..n).map(|i| (5 * i + 3) % n).collect()
}

/// Oracle: **law** — permuting arrival order gives the same partition and the
/// same canonical numbering.
///
/// A net is a connected component of a graph whose vertices are polygons, and
/// relabelling vertices cannot change which of them are connected. So under the
/// induced `PolyId` permutation π, `same_net` must map through π exactly, the
/// net-size multiset must be unchanged, and — because `NetId` is documented as
/// the *rank* of a net in ascending order of its smallest `PolyId` — the ids
/// must be **pinned**, not merely isomorphic. The last clause is the one that
/// has teeth: an extractor that numbered nets in discovery order would satisfy
/// everything else here.
///
/// Two scope corrections, both mandatory and both load-bearing:
///
/// - `DeviceId` is the rank of the marker polygon (`matched.sort_by_key`), so
///   device rows genuinely **reorder** under π. They are compared as a multiset
///   keyed on π's image of the marker, never positionally.
/// - `recognise_into`'s terminal binding keeps the lowest `PolyId` under the
///   marker and is therefore order-dependent by design. The fixture puts
///   exactly one shape of each terminal layer under each marker, which is what
///   makes the terminal claim a claim about extraction rather than about that
///   tie-break.
///
/// This law goes through `extract_nets_into`, not `NetTable::from_assignment` —
/// that constructor's own doc says it does not re-canonicalise, so a
/// permutation law over it would assert nothing.
#[test]
fn permuting_arrival_order_gives_the_same_partition_and_the_same_net_ids() {
    let shapes = fixture();
    let identity: Vec<usize> = (0..shapes.len()).collect();
    let order = shuffled(shapes.len());
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, identity, "the shuffle is not a permutation");
    assert_ne!(order, identity, "an identity permutation proves nothing");

    let mut strings = StrTable::default();
    let recognition = mos_recogniser(&mut strings);

    let (store, ids) = build(&shapes, &identity, |x, y| (x, y));
    let (nets, devices) = extract(&store, &recognition);
    assert_the_base_run_can_fail_a_law(&store, &ids, &nets, &devices);

    let (other_store, other_ids) = build(&shapes, &order, |x, y| (x, y));
    let (other_nets, other_devices) = extract(&other_store, &recognition);

    // π, indexed by the base `PolyId`.
    let mut pi = vec![PolyId(0); ids.len()];
    for (shape, &base) in ids.iter().enumerate() {
        pi[base.idx()] = other_ids[shape];
    }
    let mut image = pi.clone();
    image.sort_unstable();
    assert_eq!(
        image,
        (0..u32::try_from(ids.len()).expect("tens of shapes"))
            .map(PolyId)
            .collect::<Vec<_>>(),
        "the induced map on PolyId is not a permutation"
    );
    assert_ne!(
        pi,
        (0..u32::try_from(ids.len()).expect("tens of shapes"))
            .map(PolyId)
            .collect::<Vec<_>>(),
        "the shuffle left every PolyId where it was, so nothing below is a test"
    );

    // (a) the partition maps through π, and being on no net is preserved.
    let rows = u32::try_from(ids.len()).expect("tens of shapes");
    for p in (0..rows).map(PolyId) {
        assert_eq!(
            nets.net_of(p) == NetId::NONE,
            other_nets.net_of(pi[p.idx()]) == NetId::NONE,
            "{p:?} changed whether it is on a net at all"
        );
        for q in (0..rows).map(PolyId) {
            assert_eq!(
                nets.same_net(p, q),
                other_nets.same_net(pi[p.idx()], pi[q.idx()]),
                "the partition moved at ({p:?}, {q:?})"
            );
        }
    }

    // (b) the net count and the multiset of net sizes.
    assert_eq!(
        nets.net_count(),
        other_nets.net_count(),
        "a permutation split or merged a net"
    );
    let sizes = |table: &NetTable| {
        let mut s: Vec<usize> = net_ids(table)
            .into_iter()
            .map(|n| table.polys_of(n).len())
            .collect();
        s.sort_unstable();
        s
    };
    assert_eq!(
        sizes(&nets),
        sizes(&other_nets),
        "the net-size multiset moved"
    );

    // (c) the ids are pinned. First the documented invariant inside each run —
    // nets ascending by smallest `PolyId` — then the stronger claim that the
    // permuted run's numbering is exactly the π-image renumbering.
    for (label, table) in [("base", &nets), ("permuted", &other_nets)] {
        let mins: Vec<PolyId> = net_ids(table)
            .into_iter()
            .map(|n| table.polys_of(n)[0])
            .collect();
        assert!(
            mins.windows(2).all(|w| w[0] < w[1]),
            "{label}: nets are documented as ranked by their smallest PolyId, and are not: \
             {mins:?}"
        );
    }
    let mut images: Vec<Vec<PolyId>> = net_ids(&nets)
        .into_iter()
        .map(|n| {
            let mut polys: Vec<PolyId> = nets.polys_of(n).iter().map(|&p| pi[p.idx()]).collect();
            polys.sort_unstable();
            polys
        })
        .collect();
    images.sort_by_key(|polys| polys[0]);
    for (rank, want) in images.iter().enumerate() {
        let net = NetId(u32::try_from(rank).expect("tens of nets"));
        assert_eq!(
            other_nets.polys_of(net),
            want.as_slice(),
            "net {rank} of the permuted run is not the π-image of net {rank} of the base run"
        );
    }

    // Base net id to permuted net id, checked to be well defined on every
    // polygon of the net rather than read off the first one.
    let net_map: Vec<NetId> = net_ids(&nets)
        .into_iter()
        .map(|n| {
            let polys = nets.polys_of(n);
            let mapped = other_nets.net_of(pi[polys[0].idx()]);
            for &p in polys {
                assert_eq!(
                    other_nets.net_of(pi[p.idx()]),
                    mapped,
                    "net {n:?} came apart under π"
                );
            }
            mapped
        })
        .collect();

    // Devices, as a multiset keyed on π's image of the marker.
    assert_eq!(
        devices.len(),
        other_devices.len(),
        "a permutation changed how many devices were recognised"
    );
    let device_map: Vec<DeviceId> = (0..devices.len())
        .map(|d| {
            let want = pi[devices.marker[d].idx()];
            let row = other_devices
                .marker
                .iter()
                .position(|&m| m == want)
                .unwrap_or_else(|| panic!("no device on the π-image {want:?} of marker {d}"));
            DeviceId(u32::try_from(row).expect("tens of devices"))
        })
        .collect();
    for (d, &other) in device_map.iter().enumerate() {
        let row = other.0 as usize;
        assert_eq!(devices.kind[d], other_devices.kind[row], "device {d}: kind");
        assert_eq!(
            devices.model[d], other_devices.model[row],
            "device {d}: model"
        );

        let base_device = DeviceId(u32::try_from(d).expect("tens of devices"));
        let (base_nets_of, base_roles) = devices.terminals_of(base_device);
        let (other_nets_of, other_roles) = other_devices.terminals_of(other);
        assert_eq!(base_roles, other_roles, "device {d}: terminal roles");
        let want: Vec<NetId> = base_nets_of.iter().map(|&n| net_map[n.idx()]).collect();
        assert_eq!(
            other_nets_of,
            want.as_slice(),
            "device {d}: a terminal moved to a different net"
        );
        assert_eq!(
            devices.params_of(base_device),
            other_devices.params_of(other),
            "device {d}: params"
        );
    }

    // And the reverse index, through both maps.
    for (rank, net) in net_ids(&nets).into_iter().enumerate() {
        let mut want: Vec<DeviceId> = devices
            .devices_on(net)
            .iter()
            .map(|&d| device_map[d.0 as usize])
            .collect();
        want.sort_unstable();
        assert_eq!(
            other_devices.devices_on(net_map[rank]),
            want.as_slice(),
            "the reverse index of net {rank} moved"
        );
    }
}

/// The anisotropic scale. `sx != sy` on purpose — `box_extent` is `max(dx, dy)`
/// (`crates/core/src/index.rs:65`), so unequal factors genuinely reassign boxes
/// between index levels and move `nx` and `ny` independently, where `s·I` moves
/// the whole grid together and barely tests the index at all.
const SX: i64 = 3;
const SY: i64 = 5;

/// Oracle: **law** — an integer scale of the geometry, with the deck unchanged,
/// leaves the netlist alone and multiplies only the measured area.
///
/// A diagonal map with positive integer factors is an invertible affine
/// bijection, so it preserves set intersection exactly as an isometry does: the
/// edge list, the partition, the numbering and every terminal binding are
/// unchanged. `DeviceMeasure::Area` is the one thing that must move, and it
/// moves by the determinant: `area2` is a sum of cross products, each of which
/// picks up `sx·sy`, so `Area(a)` becomes `Area(sx·sy·a)` — **exactly**, with no
/// rounding, because the halving in `device.rs` is of an already-even number.
///
/// Nothing about the deck is scaled: `Connectivity` carries no distance, and
/// the two prunes are at distance zero, which is scale-invariant.
#[test]
fn an_anisotropic_integer_scale_moves_only_the_measured_area() {
    let shapes = fixture();
    let identity: Vec<usize> = (0..shapes.len()).collect();
    let mut strings = StrTable::default();
    let recognition = mos_recogniser(&mut strings);

    let (store, ids) = build(&shapes, &identity, |x, y| (x, y));
    let (nets, devices) = extract(&store, &recognition);
    assert_the_base_run_can_fail_a_law(&store, &ids, &nets, &devices);
    assert!(
        devices.param.iter().any(|&(_, m)| match m {
            DeviceMeasure::Area(a) => a.raw() > 0,
            _ => false,
        }),
        "a zero area would satisfy any scaling law"
    );

    let (scaled_store, scaled_ids) = build(&shapes, &identity, |x, y| (x * SX, y * SY));
    assert_eq!(scaled_ids, ids, "a scale must not renumber polygons");

    let (scaled_nets, scaled_devices) = extract(&scaled_store, &recognition);
    assert_eq!(
        scaled_nets, nets,
        "scaling every coordinate changed the net partition"
    );
    // The fixture's channel runs along x — the flanking diffusion is offset in
    // x — so `L` picks up `SX` and `W` picks up `SY`; the area their product.
    assert_device_columns_agree(
        &devices,
        &scaled_devices,
        i128::from(SX) * i128::from(SY),
        (SY, SX),
        "anisotropic scale",
    );
    assert_reverse_index_agrees(&nets, &devices, &scaled_devices, "anisotropic scale");
}
