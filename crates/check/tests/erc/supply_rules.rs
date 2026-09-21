//! Supply, substrate and pad integrity — topological, but geometry-aware.
//!
//! Oracle throughout: construct-from-answer. Each layout below is drawn so that
//! its answer is decided by the drawing: a well with a tap in it and a well
//! without, a conductor carrying both tap types, a net whose two halves meet
//! only through a resistive body, a region whose furthest point from its tap is
//! an exact ten thousand database units away.
//!
//! The distance case is the one with a fully determined coordinate *and* a
//! fully determined measurement, and it is built on a 6-8-10 triangle so both
//! are exact integers rather than a rounding the test would have to accept.

use crate::common;

use common::{head, rule};
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_geom::{Evaluator, LayerRef};
use gpurify_check::erc::facts::{classify_nets_into, NetFacts};
use gpurify_check::erc::rules::supply::{
    check_esd_topological, check_missing_tie, check_soft_connection, check_supply_short,
    check_tie_high_low, EsdTopologicalTable, MissingTieTable, SoftConnectionTable,
    SupplyShortTable, TieHighLowTable,
};
use gpurify_check::erc::rules::topology::{check_floating_well, FloatingWellTable};
use gpurify_check::erc::{Design, Scratch};
use gpurify_ingest::deck::{Connectivity, DeviceKind};
use gpurify_ingest::{StrId, StrTable};
use gpurify_check::report::{Measurement, RuleRun, Violations};
use gpurify_testgen::shapes::l_shape;
use gpurify_testgen::{
    assert_clean, assert_rule_ran, dbu, layout_from_netlist, point, DeviceSpec, Floorplan,
    LayoutBuilder, NetlistSpec,
};
use gpurify_check::topology::{DeviceTable, NetTable, TerminalRole};

/// A hand-drawn layout, extracted under a stated connectivity.
struct Drawn {
    store: GeometryStore,
    derived: Evaluator,
    nets: NetTable,
    devices: DeviceTable,
}

impl Drawn {
    fn new(store: GeometryStore, connectivity: &Connectivity) -> Self {
        let mut nets = NetTable::default();
        gpurify_check::topology::extract_nets_into(&store, connectivity, &mut nets);
        Self {
            store,
            derived: Evaluator::default(),
            nets,
            devices: DeviceTable::default(),
        }
    }

    fn design(&self) -> Design<'_> {
        Design {
            store: &self.store,
            derived: &self.derived,
            nets: &self.nets,
            devices: &self.devices,
        }
    }
}

/// Connectivity where every listed layer conducts and cuts on `cut` join them
/// to layer zero.
fn via_connectivity(cut: LayerId, joined: &[LayerId]) -> Connectivity {
    Connectivity {
        conductors: std::iter::once(LayerId(0))
            .chain(joined.iter().copied())
            .collect(),
        // One `via_cut` row per `via_connects` row: `Connectivity`'s documented
        // shape is parallel columns, one per via layer, and both
        // `build_connectivity` and `extract_nets_into` assert it. A single cut
        // row against several joins is ragged and panics before any erc code
        // runs.
        via_cut: vec![cut; joined.len()],
        via_connects: joined.iter().map(|&layer| (LayerId(0), layer)).collect(),
        // Off: every join here is via-mediated, so a broken via edge splits a
        // net rather than being masked by shapes that happen to touch.
        intra_layer_touch: false,
        ..Connectivity::default()
    }
}

/// Geometry with no conductors at all, for the two rules that read shapes and
/// never ask what net they are on.
fn no_connectivity() -> Connectivity {
    Connectivity {
        conductors: Vec::new(),
        via_cut: Vec::new(),
        via_connects: Vec::new(),
        intra_layer_touch: false,
        ..Connectivity::default()
    }
}

fn report() -> (Violations, Vec<RuleRun>) {
    (Violations::default(), Vec::new())
}

// ---------------------------------------------------------------- floating well

/// Layer zero is the well, layer one the tap.
fn wells(tapped_well_has_a_tap: bool) -> (Drawn, PolyId) {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(LayerId(0), 0, 0, 1_000, 1_000);
    let right = layout.rect(LayerId(0), 3_000, 0, 4_000, 1_000);
    layout.rect(LayerId(1), 200, 200, 800, 800);
    if tapped_well_has_a_tap {
        layout.rect(LayerId(1), 3_200, 200, 3_800, 800);
    }
    let (store, ids) = layout.finish();
    let untapped = ids.of(right);
    (Drawn::new(store, &no_connectivity()), untapped)
}

fn floating_well_table(id: StrId) -> FloatingWellTable {
    FloatingWellTable {
        head: head(id),
        well: vec![LayerRef::Base(LayerId(0))],
        tap: vec![LayerRef::Base(LayerId(1))],
    }
}

/// Oracle: construct-from-answer. Two wells, one with a tap drawn inside it and
/// one without. The untapped well is a latch-up path and a threshold shift at
/// once, and it is the polygon the violation must name — naming the tapped one,
/// or naming the layer as a whole, sends a user to the wrong place.
#[test]
fn a_well_with_no_tap_inside_it_is_flagged_at_that_well() {
    let (drawn, untapped) = wells(false);
    let id = rule(50);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_floating_well(
        drawn.design(),
        &floating_well_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    assert_eq!(violations.shape_a[0], untapped);
    assert_eq!(violations.layer[0], LayerId(0));
    common::assert_at_is_on_a_named_shape(&drawn.store, &violations, 0);

    let run = assert_rule_ran(&runs, id);
    assert_eq!(run.examined, 2, "both wells were looked at");
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. With a tap in each well the rule finds
/// nothing — and `assert_clean` insists it looked at both wells first, so this
/// cannot be satisfied by a layer lookup that returned an empty range.
#[test]
fn wells_that_each_hold_a_tap_are_clean() {
    let (drawn, _) = wells(true);
    let id = rule(51);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_floating_well(
        drawn.design(),
        &floating_well_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

/// Oracle: construct-from-answer, on the case the rule's doc comment names. An
/// L-shaped well has a notch its bounding box covers and its geometry does not.
/// A tap drawn in that notch overlaps the box and is not in the well, so the
/// well is untapped — and a containment test done on bounding boxes, as the old
/// implementation did, calls it tapped and reports the design clean.
#[test]
fn a_tap_in_the_notch_of_an_l_shaped_well_does_not_tie_it() {
    let mut layout = LayoutBuilder::new(2);
    let well = layout.shape(LayerId(0), &l_shape(0, 0, 4_000, 1_000));
    // The notch of that L is x and y both in 1000..4000. This tap sits squarely
    // inside the well's bounding box and squarely outside the well.
    layout.rect(LayerId(1), 2_000, 2_000, 3_000, 3_000);
    let (store, ids) = layout.finish();
    let untapped = ids.of(well);
    let drawn = Drawn::new(store, &no_connectivity());

    let id = rule(52);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_floating_well(
        drawn.design(),
        &floating_well_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(
        violations.rule.len(),
        1,
        "the only tap sits in the notch, so the well is untied"
    );
    assert_eq!(violations.shape_a[0], untapped);
    assert_eq!(assert_rule_ran(&runs, id).examined, 1);
}

// ------------------------------------------------------------------ missing tie

/// Oracle: construct-from-answer, exact in both columns. The region is a
/// 9000-by-7000 rectangle and the tap fills the corner up to (1000, 1000), so
/// the furthest point of the region from the tap is the opposite corner: eight
/// thousand across and six thousand up, which is ten thousand away on the
/// 6-8-10 triangle. Both the coordinate and the distance are integers, so
/// neither assertion has to accept a rounding.
///
/// Sampling the region's corners would find this one too. What it would miss is
/// a long thin region whose corners are all near a tap, which is the failure the
/// rule's doc comment records — so the measurement is asserted, not just the
/// presence of a finding.
#[test]
fn the_point_of_a_region_furthest_from_its_tap_is_reported_with_its_distance() {
    let mut layout = LayoutBuilder::new(2);
    let region = layout.rect(LayerId(0), 0, 0, 9_000, 7_000);
    layout.rect(LayerId(1), 0, 0, 1_000, 1_000);
    let (store, ids) = layout.finish();
    let region_poly = ids.of(region);
    let drawn = Drawn::new(store, &no_connectivity());

    let id = rule(53);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_missing_tie(
        drawn.design(),
        &MissingTieTable {
            head: head(id),
            region: vec![LayerRef::Base(LayerId(0))],
            tap: vec![LayerRef::Base(LayerId(1))],
            max_distance: vec![dbu(5_000)],
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.shape_a[0], region_poly);
    assert_eq!(
        violations.at[0],
        point(9_000, 7_000),
        "the reported point is the furthest point of the region from any tap"
    );
    assert_eq!(violations.measured[0], Measurement::Length(dbu(10_000)));
    assert_eq!(violations.limit[0], Measurement::Length(dbu(5_000)));
    assert_eq!(assert_rule_ran(&runs, id).examined, 1);
}

/// Oracle: construct-from-answer. The same layout against a limit that covers
/// its furthest point. The distance did not change; the verdict did.
#[test]
fn a_region_within_the_stated_tap_distance_is_clean() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(LayerId(0), 0, 0, 9_000, 7_000);
    layout.rect(LayerId(1), 0, 0, 1_000, 1_000);
    let (store, _) = layout.finish();
    let drawn = Drawn::new(store, &no_connectivity());

    let id = rule(54);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_missing_tie(
        drawn.design(),
        &MissingTieTable {
            head: head(id),
            region: vec![LayerRef::Base(LayerId(0))],
            tap: vec![LayerRef::Base(LayerId(1))],
            max_distance: vec![dbu(20_000)],
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

// ----------------------------------------------------------------- supply short

/// Layer 0 metal, layer 1 cut, layer 2 the n-type tap, layer 3 the p-type tap.
/// `shorted` decides whether one metal shape carries both or two carry one each.
fn taps(shorted: bool) -> Drawn {
    let mut layout = LayoutBuilder::new(4);
    if shorted {
        layout.rect(LayerId(0), 0, 0, 3_000, 1_000);
    } else {
        layout.rect(LayerId(0), 0, 0, 1_000, 1_000);
        layout.rect(LayerId(0), 2_000, 0, 3_000, 1_000);
    }
    layout.rect(LayerId(2), 0, 0, 1_000, 1_000);
    layout.rect(LayerId(3), 2_000, 0, 3_000, 1_000);
    layout.rect(LayerId(1), 400, 400, 600, 600);
    layout.rect(LayerId(1), 2_400, 400, 2_600, 600);
    let (store, _) = layout.finish();
    Drawn::new(
        store,
        &via_connectivity(LayerId(1), &[LayerId(2), LayerId(3)]),
    )
}

fn supply_short_table(id: StrId) -> SupplyShortTable {
    SupplyShortTable {
        head: head(id),
        tap_a: vec![LayerRef::Base(LayerId(2))],
        tap_b: vec![LayerRef::Base(LayerId(3))],
    }
}

/// Oracle: construct-from-answer. One metal shape carries an n-type tie and a
/// p-type tie, so the well sits at the substrate's potential. The rule needs no
/// net names and no device polarity to say so: it is two named tap markers
/// landing on one extracted net.
#[test]
fn one_conductor_carrying_both_tap_types_is_a_supply_short() {
    let drawn = taps(true);
    let id = rule(55);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_supply_short(
        drawn.design(),
        &supply_short_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    let shorted_net = drawn.nets.net_of(violations.shape_a[0]);
    assert!(
        drawn
            .nets
            .polys_of(shorted_net)
            .contains(&violations.shape_a[0]),
        "the violation must name a shape on the net that carries both taps"
    );
    common::assert_at_is_on_a_named_shape(&drawn.store, &violations, 0);
    assert_eq!(
        assert_rule_ran(&runs, id).examined,
        2,
        "the two tap polygons across both layers are the population"
    );
}

/// Oracle: construct-from-answer. The same two taps on two separate
/// conductors: each net carries one tie, which is what a correctly built CMOS
/// row looks like. The rule must examine both taps and report nothing.
#[test]
fn two_conductors_each_carrying_one_tap_type_are_clean() {
    let drawn = taps(false);
    let id = rule(56);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_supply_short(
        drawn.design(),
        &supply_short_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

// --------------------------------------------------------------- soft connection

/// Two metal islands bridged by a resistive body on layer two, or one metal
/// shape with the same body alongside it.
fn bridged(two_islands: bool) -> (Drawn, Option<(PolyId, PolyId)>) {
    let mut layout = LayoutBuilder::new(3);
    let halves = if two_islands {
        let left = layout.rect(LayerId(0), 0, 0, 1_000, 1_000);
        let right = layout.rect(LayerId(0), 3_000, 0, 4_000, 1_000);
        Some((left, right))
    } else {
        layout.rect(LayerId(0), 0, 0, 4_000, 1_000);
        None
    };
    layout.rect(LayerId(2), 0, 200, 4_000, 800);
    layout.rect(LayerId(1), 400, 400, 600, 600);
    layout.rect(LayerId(1), 3_400, 400, 3_600, 600);
    let (store, ids) = layout.finish();
    let named = halves.map(|(a, b)| (ids.of(a), ids.of(b)));
    (
        Drawn::new(store, &via_connectivity(LayerId(1), &[LayerId(2)])),
        named,
    )
}

fn soft_connection_table(id: StrId) -> SoftConnectionTable {
    SoftConnectionTable {
        head: head(id),
        soft_start: vec![0, 1],
        soft: vec![LayerRef::Base(LayerId(2))],
    }
}

/// Oracle: construct-from-answer. The two metal islands are one extracted net
/// and two conductors in the silicon, joined only through the resistive body on
/// layer two. That passes LVS and does not work, and the test is a partition
/// rather than a distance: take the soft layer out of the net's connectivity
/// and the net falls into two components.
///
/// The violation names the shapes on either side of the bridge, so a viewer
/// lands on the gap and not on the net as a whole.
#[test]
fn a_net_held_together_only_by_a_resistive_body_is_flagged_on_both_halves() {
    let (drawn, halves) = bridged(true);
    let (left, right) = halves.expect("two islands were drawn");
    let id = rule(57);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_soft_connection(
        drawn.design(),
        &soft_connection_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    let named = (
        violations.shape_a[0],
        violations.shape_b[0].expect("a bridge has two sides"),
    );
    assert!(
        named == (left, right) || named == (right, left),
        "the violation names {named:?}, not the two halves {:?}",
        (left, right)
    );
    assert_eq!(
        assert_rule_ran(&runs, id).examined,
        1,
        "one net touches the soft layer"
    );
}

/// Oracle: construct-from-answer. One metal shape with the same resistive body
/// alongside it: removing the soft layer still leaves one component, so there
/// is no bridge. The net is still examined, which is what makes this clean
/// result a claim rather than a silence.
#[test]
fn a_net_that_survives_losing_its_soft_layer_is_clean() {
    let (drawn, _) = bridged(false);
    let id = rule(58);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_soft_connection(
        drawn.design(),
        &soft_connection_table(id),
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

// ------------------------------------------------------------------ tie high/low

/// A layout emitted from `spec`, extracted and classified, together with every
/// polygon of netlist net zero — the net each case below is built around, and
/// the one a per-net violation has to name.
fn tie_case(spec: &NetlistSpec) -> (Drawn, NetFacts, Vec<PolyId>) {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(spec, Floorplan::default(), &mut strings);
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    gpurify_check::topology::device::recognise_into(
        &case.store,
        &Evaluator::default(),
        &nets,
        &case.recognition,
        &mut devices,
    );
    let mut facts = NetFacts::default();
    classify_nets_into(&nets, &devices, &mut facts);
    let net_zero = case.expected_net_polys[0].clone();
    (
        Drawn {
            store: case.store,
            derived: Evaluator::default(),
            nets,
            devices,
        },
        facts,
        net_zero,
    )
}

fn tied_off(drain_net: u32) -> NetlistSpec {
    NetlistSpec {
        nets: 3,
        devices: vec![DeviceSpec {
            kind: DeviceKind::Mos,
            model: "nch".to_owned(),
            terminals: vec![
                (TerminalRole::Gate, 0),
                (TerminalRole::Source, 0),
                (TerminalRole::Drain, drain_net),
                (TerminalRole::Bulk, 2),
            ],
        }],
    }
}

/// Oracle: construct-from-answer. Net zero carries a gate and a source and no
/// drain, so nothing in the design can change its state: it is held at a rail.
/// Often that is deliberate, which is why the severity is a deck column — but
/// the rule still has to find it.
#[test]
fn a_net_holding_a_gate_and_a_source_with_no_drain_is_flagged() {
    let (drawn, facts, net_zero) = tie_case(&tied_off(1));
    let id = rule(59);
    let (mut violations, mut runs) = report();
    check_tie_high_low(
        drawn.design(),
        &facts,
        &TieHighLowTable { head: head(id) },
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    assert_eq!(
        violations.shape_a[0], net_zero[0],
        "the tied-off net is net zero, and a per-net violation is reported at its \
         lowest-numbered polygon"
    );
    assert_eq!(
        violations.layer[0],
        drawn.store.poly_layer(net_zero[0]),
        "the reported layer is the layer of the reported shape"
    );
    common::assert_at_is_on_a_named_shape(&drawn.store, &violations, 0);
    let run = assert_rule_ran(&runs, id);
    assert_eq!(run.examined, 1, "one net carries a gate terminal");
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. The same net, now also carrying the drain, is
/// drivable and is not tied off. Three bit tests per net, and this is the one
/// that must come out the other way.
#[test]
fn a_net_that_also_holds_a_drain_is_not_tied_off() {
    let (drawn, facts, _) = tie_case(&tied_off(0));
    let id = rule(60);
    let (mut violations, mut runs) = report();
    check_tie_high_low(
        drawn.design(),
        &facts,
        &TieHighLowTable { head: head(id) },
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

// ------------------------------------------------------------ ESD topological

/// Three nets, each with a rail that doubles as the pad marker; an ordinary
/// transistor on nets zero and one, and a clamp on nets one and two.
///
/// The two recognisers are told apart by their terminal layers — a MOS column
/// carries no pin stubs and a diode column carries no gate stub — so each marker
/// polygon is exactly one device. That is the reading recorded in
/// `docs/NEED_TESTING.md` under `DeviceRecognition`.
fn pads_and_a_clamp() -> (gpurify_testgen::NetlistCase, NetTable, DeviceTable) {
    let mut strings = StrTable::default();
    let spec = NetlistSpec {
        nets: 3,
        devices: vec![
            DeviceSpec {
                kind: DeviceKind::Mos,
                model: "nch".to_owned(),
                terminals: vec![(TerminalRole::Gate, 0), (TerminalRole::Source, 1)],
            },
            DeviceSpec {
                kind: DeviceKind::Diode,
                model: "esd_clamp".to_owned(),
                terminals: vec![(TerminalRole::Pin(0), 1), (TerminalRole::Pin(1), 2)],
            },
        ],
    };
    let case = layout_from_netlist(&spec, Floorplan::default(), &mut strings);
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    gpurify_check::topology::device::recognise_into(
        &case.store,
        &Evaluator::default(),
        &nets,
        &case.recognition,
        &mut devices,
    );
    (case, nets, devices)
}

/// Oracle: construct-from-answer. The netlist decided which nets the clamp
/// reaches before a polygon was drawn: nets one and two, and not net zero. So
/// net zero is the pad whose first discharge goes through a gate oxide, and it
/// is the one net of the three the rule must name.
///
/// The clamp is identified by its model name, taken from the case's own answer
/// rather than re-interned, so the test cannot pass by matching the wrong
/// string.
#[test]
fn a_pad_net_reaching_none_of_the_listed_clamp_models_is_flagged() {
    let (case, nets, devices) = pads_and_a_clamp();
    let derived = Evaluator::default();
    let design = Design {
        store: &case.store,
        derived: &derived,
        nets: &nets,
        devices: &devices,
    };
    let id = rule(61);
    let (mut violations, mut runs) = report();
    check_esd_topological(
        design,
        &EsdTopologicalTable {
            head: head(id),
            pad: vec![case.layers.rail],
            clamp_start: vec![0, 1],
            clamp_model: vec![case.expected_devices[1].model],
        },
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    assert!(
        case.expected_net_polys[0].contains(&violations.shape_a[0]),
        "the violation names {:?}, which is not a polygon of the unprotected net",
        violations.shape_a[0]
    );
    common::assert_at_is_on_a_named_shape(&case.store, &violations, 0);

    let run = assert_rule_ran(&runs, id);
    assert_eq!(
        run.examined, 3,
        "one rail per net, so three distinct pad nets"
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. With both models on the clamp list every pad
/// net reaches something the deck calls protection, so the rule finds nothing —
/// and `assert_clean` insists it looked at all three pad nets first, which an
/// empty violation table on its own does not say.
#[test]
fn every_pad_net_reaching_a_listed_clamp_model_is_clean() {
    let (case, nets, devices) = pads_and_a_clamp();
    let derived = Evaluator::default();
    let design = Design {
        store: &case.store,
        derived: &derived,
        nets: &nets,
        devices: &devices,
    };
    let id = rule(62);
    let (mut violations, mut runs) = report();
    check_esd_topological(
        design,
        &EsdTopologicalTable {
            head: head(id),
            pad: vec![case.layers.rail],
            clamp_start: vec![0, 2],
            clamp_model: vec![
                case.expected_devices[0].model,
                case.expected_devices[1].model,
            ],
        },
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}
