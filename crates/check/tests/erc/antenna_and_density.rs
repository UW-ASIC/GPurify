//! Antenna ratios and windowed density.
//!
//! Both are areas divided by areas, so both have a closed form and neither
//! needs a fixture to compare against. The antenna cases state the collecting
//! area and the gate area by drawing them; the density cases state the
//! numerator either by drawing exactly half a die or by asking
//! `gpurify_testgen::shapes::random_rectilinear_layer` for arbitrary geometry
//! whose covered area it computed while placing it.
//!
//! The random case is the interesting one: the geometry is unrecognisable and
//! the expected density is still exact, because the generator's shapes are
//! disjoint by construction and the coverage is a sum rather than a union.

use crate::common;

use common::{head, rule};
use gpurify_check::erc::rules::antenna::{
    check_antenna, check_antenna_electrical, check_density_cmp, AntennaElectricalTable,
    AntennaMeasure, AntennaTable, DensityCmpTable, Stack,
};
use gpurify_check::erc::{Design, Scratch};
use gpurify_check::report::{Measurement, RuleRun, Severity, Violations};
use gpurify_check::topology::{DeviceTable, NetTable};
use gpurify_geom::{Bbox, GeometryStore, LayerId};
use gpurify_ingest::deck::Connectivity;
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::{random_rectilinear_layer, RandomLayerSpec};
use gpurify_testgen::{
    assert_clean, assert_close_relative, assert_rule_ran, dbu, LayoutBuilder, Rng,
};

fn report() -> (Violations, Vec<RuleRun>) {
    (Violations::default(), Vec::new())
}

/// The ratio on a violation row.
///
/// # Panics
///
/// When the row measured something other than a dimensionless ratio.
fn measured_ratio(violations: &Violations, row: usize) -> f64 {
    match violations.measured[row] {
        Measurement::Ratio(value) => value,
        other => panic!("row {row} measured {other:?}, not a ratio"),
    }
}

/// A gate joined by a via to a metal wire four times its area.
///
/// Layer zero is the wire, layer one the cut, layer two the gate. The gate is a
/// thousand units square and the wire is four thousand by one thousand, so the
/// antenna ratio is exactly four with no rounding anywhere.
fn gate_on_a_long_wire() -> (GeometryStore, NetTable, gpurify_geom::PolyId) {
    let mut layout = LayoutBuilder::new(3);
    layout.rect(LayerId(0), 0, 0, 4_000, 1_000);
    let gate = layout.rect(LayerId(2), 0, 0, 1_000, 1_000);
    layout.rect(LayerId(1), 400, 400, 600, 600);
    let (store, ids) = layout.finish();

    let connectivity = Connectivity {
        conductors: vec![LayerId(0), LayerId(2)],
        via_cut: vec![LayerId(1)],
        via_connects: vec![(LayerId(0), LayerId(2))],
        intra_layer_touch: false,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&store, &connectivity, &mut nets);
    let gate_poly = ids.of(gate);
    (store, nets, gate_poly)
}

fn antenna_table(id: StrId, max_ratio: f64) -> AntennaTable {
    AntennaTable {
        head: head(id),
        gate: vec![LayerId(2)],
        collector_start: vec![0, 1],
        collector: vec![LayerId(0)],
        collector_measure: vec![AntennaMeasure::Area],
        max_ratio: vec![max_ratio],
        stack: Stack::default(),
    }
}

/// Oracle: closed form. Four square micrometres of wire on one square
/// micrometre of gate is a ratio of exactly four, and the violation is reported
/// at the gate — which is what fails and what a fix adds a diode to, not the
/// wire that collected the charge.
#[test]
fn a_per_stage_antenna_ratio_is_the_collecting_area_over_the_gate_area() {
    let (store, nets, gate) = gate_on_a_long_wire();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let id = rule(70);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_antenna(
        design,
        &antenna_table(id, 3.0),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    assert_eq!(
        violations.shape_a[0], gate,
        "an antenna violation is reported at the gate, not at the wire"
    );
    assert_close_relative(
        "the antenna ratio",
        measured_ratio(&violations, 0),
        4.0,
        1e-12,
    );
    assert_eq!(violations.limit[0], Measurement::Ratio(3.0));
    common::assert_at_is_on_a_named_shape(&store, &violations, 0);

    let run = assert_rule_ran(&runs, id);
    assert_eq!(run.examined, 1, "one net carries a gate polygon");
}

/// Oracle: closed form. The same four-to-one ratio against a limit of five. The
/// geometry did not change and neither did the ratio; only the verdict did, and
/// the clean assertion still insists the gate net was examined.
#[test]
fn an_antenna_ratio_under_its_limit_is_clean() {
    let (store, nets, _) = gate_on_a_long_wire();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let id = rule(71);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_antenna(
        design,
        &antenna_table(id, 5.0),
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_clean(&runs, &violations, id);
}

/// Oracle: closed form. With no diode configured the cumulative form reduces to
/// the same division, so it must report the same four. Stating that explicitly
/// is what pins the two tables to one accumulation: a cumulative rule that
/// counted the gate layer into its own numerator would report five here and
/// four in the per-stage test, and only comparing the two catches it.
#[test]
fn the_cumulative_antenna_ratio_with_no_diode_is_the_same_division() {
    let (store, nets, gate) = gate_on_a_long_wire();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let id = rule(72);
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_antenna_electrical(
        design,
        &AntennaElectricalTable {
            head: head(id),
            gate: vec![LayerId(2)],
            collector_start: vec![0, 1],
            collector: vec![LayerId(0)],
            diode: vec![None],
            diode_credit: vec![0.0],
            diode_bonus: vec![0.0],
            max_ratio: vec![3.0],
            stack: Stack::default(),
        },
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.shape_a[0], gate);
    assert_close_relative(
        "the cumulative ratio",
        measured_ratio(&violations, 0),
        4.0,
        1e-12,
    );
    assert_eq!(assert_rule_ran(&runs, id).examined, 1);
}

/// A gate under a two-level stack, everything on one net.
///
/// Layer 0 is metal 1, layer 1 the cut joining it to the gate, layer 2 the gate,
/// layer 3 metal 2 and layer 4 the cut joining metal 1 to metal 2. The gate is a
/// thousand units square, metal 1 is twice that area and metal 2 ten times it,
/// so the stage-one ratio is exactly two and the stage-two ratio exactly twelve
/// with no rounding anywhere.
fn gate_under_a_two_level_stack() -> (GeometryStore, NetTable, gpurify_geom::PolyId) {
    let mut layout = LayoutBuilder::new(5);
    layout.rect(LayerId(0), 0, 0, 2_000, 1_000);
    let gate = layout.rect(LayerId(2), 0, 0, 1_000, 1_000);
    layout.rect(LayerId(3), 0, 0, 10_000, 1_000);
    layout.rect(LayerId(1), 400, 400, 600, 600);
    layout.rect(LayerId(4), 1_500, 400, 1_700, 600);
    let (store, ids) = layout.finish();

    let connectivity = Connectivity {
        conductors: vec![LayerId(0), LayerId(2), LayerId(3)],
        via_cut: vec![LayerId(1), LayerId(4)],
        via_connects: vec![(LayerId(0), LayerId(2)), (LayerId(0), LayerId(3))],
        intra_layer_touch: false,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&store, &connectivity, &mut nets);
    (store, nets, ids.of(gate))
}

/// Oracle: closed form. A cumulative antenna check is one measurement **per
/// fabrication stage**, not one over the finished stack — at the moment metal
/// *k* is etched only the layers up to *k* exist, so a wire later tied to a huge
/// upper plane is, at that instant, just itself. This crate spells that as one
/// rule row per stage, and the two rows below are the same gate under the same
/// geometry differing only in which layers had been deposited.
///
/// Both numbers are decided by the drawing: two thousand by one thousand of
/// metal 1 on a thousand-square gate is a ratio of two, and metal 2's ten
/// thousand by one thousand added to it is twelve. Each is asserted exactly,
/// which is what separates the per-stage form from the two ways of getting it
/// wrong — a rule measuring the final stack at every stage reports twelve
/// twice, and a rule collecting only the layer a stage names rather than
/// everything already under it reports ten for the second.
#[test]
fn a_cumulative_antenna_check_measures_each_fabrication_stage_over_what_exists_at_it() {
    let (store, nets, gate) = gate_under_a_two_level_stack();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let (early, late) = (rule(80), rule(81));
    let table = AntennaTable {
        head: gpurify_check::erc::ruleset::RuleHead {
            rule: vec![early, late],
            severity: vec![Severity::Error, Severity::Error],
        },
        gate: vec![LayerId(2), LayerId(2)],
        // Stage one collects metal 1 alone; stage two collects metal 1 *and*
        // metal 2, because metal 2's etch sees everything already under it.
        collector_start: vec![0, 1, 3],
        collector: vec![LayerId(0), LayerId(0), LayerId(3)],
        collector_measure: vec![AntennaMeasure::Area; 3],
        // Limits below both ratios, so each stage's own measurement lands in the
        // table and can be read rather than inferred from a verdict.
        max_ratio: vec![1.0, 1.0],
        stack: Stack::default(),
    };

    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_antenna(design, &table, &mut scratch, &mut violations, &mut runs);

    assert_eq!(runs.len(), 2, "one run row per stage, whatever the verdict");
    assert_eq!(
        assert_rule_ran(&runs, early).examined,
        1,
        "one net carries a gate polygon at either stage"
    );
    assert_eq!(assert_rule_ran(&runs, late).examined, 1);

    assert_eq!(violations.rule.len(), 2, "one report per stage");
    assert_eq!(violations.rule, vec![early, late]);
    for row in 0..2 {
        assert_eq!(
            violations.shape_a[row], gate,
            "a stage's violation is reported at the gate it would damage"
        );
    }
    assert_close_relative(
        "the ratio at the stage that has only metal 1 under it",
        measured_ratio(&violations, 0),
        2.0,
        1e-12,
    );
    assert_close_relative(
        "the ratio at the stage that has both metals under it",
        measured_ratio(&violations, 1),
        12.0,
        1e-12,
    );
}

/// Oracle: law. Cumulative collecting area only grows as the stack is built, so
/// the ratio a stage reports is non-decreasing in the stage index — a later
/// stage can never measure less than an earlier one over the same gate. Stating
/// it against a floor of zero puts every stage's number in the table where the
/// law can be read, whatever the geometry.
#[test]
fn each_later_fabrication_stage_reports_at_least_the_ratio_the_one_before_it_did() {
    let (store, nets, _) = gate_under_a_two_level_stack();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let stages = [rule(82), rule(83)];
    let table = AntennaTable {
        head: gpurify_check::erc::ruleset::RuleHead {
            rule: stages.to_vec(),
            severity: vec![Severity::Error; 2],
        },
        gate: vec![LayerId(2); 2],
        collector_start: vec![0, 1, 3],
        collector: vec![LayerId(0), LayerId(0), LayerId(3)],
        collector_measure: vec![AntennaMeasure::Area; 3],
        // A ratio strictly above zero violates a zero ceiling, so every stage
        // that collects anything at all lands in the table.
        max_ratio: vec![f64::MIN_POSITIVE; 2],
        stack: Stack::default(),
    };

    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_antenna(design, &table, &mut scratch, &mut violations, &mut runs);

    assert_eq!(runs.len(), 2);
    let ratios: Vec<f64> = stages
        .iter()
        .map(|&id| {
            let row = violations
                .rule
                .iter()
                .position(|&r| r == id)
                .unwrap_or_else(|| panic!("stage {id:?} collected area and must report it"));
            measured_ratio(&violations, row)
        })
        .collect();

    assert!(
        ratios[0] <= ratios[1],
        "stage one measured {} and stage two {}, so the stack lost collecting area",
        ratios[0],
        ratios[1]
    );
}

/// One antenna row over `stack`, run against empty finished nets (the row
/// builds its own at its etch step).
fn run_staged(
    store: &GeometryStore,
    stack: Stack,
    gate: LayerId,
    collectors: &[LayerId],
    measure: AntennaMeasure,
    max_ratio: f64,
) -> (Violations, Vec<RuleRun>) {
    let nets = NetTable::default();
    let devices = DeviceTable::default();
    let design = Design {
        store,
        nets: &nets,
        devices: &devices,
    };
    let table = AntennaTable {
        head: head(rule(90)),
        gate: vec![gate],
        collector_start: vec![0, u32::try_from(collectors.len()).expect("few")],
        collector: collectors.to_vec(),
        collector_measure: vec![measure; collectors.len()],
        max_ratio: vec![max_ratio],
        stack,
    };
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_antenna(design, &table, &mut scratch, &mut violations, &mut runs);
    (violations, runs)
}

/// gf180 ANT.2: metal1 *perimeter* area (perimeter x 0.55 um thickness) over
/// the gate area, at most 400. The gate is the derived `poly2 and comp` shape,
/// not a conductor: it joins the net through the poly it sits on. A 1 mm x
/// 0.2 um wire on a 1 um2 gate collects 2 * 1000.2 um * 0.55 um = 1100.22
/// um2, a ratio of 1100.22. The old rule refused every sidewall row and saw no
/// net on a derived gate.
#[test]
fn gf180_ant_2_sidewall_area_of_metal1_over_a_derived_gate() {
    let (poly, gate, contact, metal1) = (LayerId(0), LayerId(1), LayerId(2), LayerId(3));
    let mut layout = LayoutBuilder::new(4);
    layout.rect(poly, 0, 0, 3_000, 1_000);
    let gate_poly = layout.rect(gate, 0, 0, 1_000, 1_000);
    layout.rect(contact, 2_400, 400, 2_600, 600);
    layout.rect(metal1, 2_000, 400, 1_002_000, 600);
    let (store, ids) = layout.finish();
    let stack = Stack {
        conductors: vec![poly, metal1],
        vias: vec![(contact, poly, metal1)],
        intra_layer_touch: true,
    };

    let (violations, runs) = run_staged(
        &store,
        stack,
        gate,
        &[metal1],
        AntennaMeasure::Sidewall {
            thickness: dbu(550),
        },
        400.0,
    );

    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.shape_a[0], ids.of(gate_poly));
    assert_close_relative(
        "the sidewall ratio",
        measured_ratio(&violations, 0),
        1100.22,
        1e-12,
    );
    assert_eq!(assert_rule_ran(&runs, rule(90)).examined, 1);
}

/// SVRF/KLayout antenna decks `CONNECT` layer by layer between ratio checks:
/// at the metal1 etch, metal2 does not exist yet. Gate A carries a 6 um2 metal1
/// plate (ratio 6); gate B, joined to it only through metal2, carries 1 um2.
/// On the finished net the two gates share 7 um2 of metal1 over 2 um2 of gate,
/// 3.5, under a limit of 4. At the metal1 etch gate A stands alone at 6.
#[test]
fn a_gate_joined_only_through_upper_metal_does_not_share_the_charge_at_metal1() {
    let (poly, contact, metal1, via1, metal2) =
        (LayerId(0), LayerId(1), LayerId(2), LayerId(3), LayerId(4));
    let mut layout = LayoutBuilder::new(5);
    let gate_a = layout.rect(poly, 0, 0, 1_000, 1_000);
    layout.rect(poly, 10_000, 0, 11_000, 1_000);
    layout.rect(contact, 400, 400, 600, 600);
    layout.rect(contact, 10_400, 400, 10_600, 600);
    layout.rect(metal1, 0, 0, 6_000, 1_000);
    layout.rect(metal1, 10_000, 0, 11_000, 1_000);
    layout.rect(via1, 5_400, 400, 5_600, 600);
    layout.rect(via1, 10_400, 400, 10_600, 600);
    layout.rect(metal2, 5_000, 0, 11_000, 1_000);
    let (store, ids) = layout.finish();
    let stack = || Stack {
        conductors: vec![poly, metal1, metal2],
        vias: vec![(contact, poly, metal1), (via1, metal1, metal2)],
        intra_layer_touch: true,
    };

    let (violations, runs) =
        run_staged(&store, stack(), poly, &[metal1], AntennaMeasure::Area, 4.0);
    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.shape_a[0], ids.of(gate_a));
    assert_close_relative("gate A alone", measured_ratio(&violations, 0), 6.0, 1e-12);
    assert_eq!(assert_rule_ran(&runs, rule(90)).examined, 2);

    // At the metal2 etch the two gates are one net: 7 um2 of metal1 plus 6 um2
    // of metal2 over 2 um2 of gate.
    let (violations, _) = run_staged(
        &store,
        stack(),
        poly,
        &[metal1, metal2],
        AntennaMeasure::Area,
        4.0,
    );
    assert_eq!(violations.rule.len(), 1);
    assert_close_relative("both gates", measured_ratio(&violations, 0), 6.5, 1e-12);
}

/// A gate sits on its poly, not on the well under it. The well is a net (tied
/// to a tap carrying a 10 um2 metal plate) listed below poly in the stack; the
/// gate overlaps both. Attached to the well it would read a ratio of 10; on
/// its own poly, which collects nothing, it is clean. The Philis rc_filter
/// fixture's false sky130 ar.licon.1 once the n-well became a net.
#[test]
fn a_gate_joins_its_poly_not_the_well_it_sits_in() {
    let (well, tap, tie, poly, gate, contact, metal1) = (
        LayerId(0),
        LayerId(1),
        LayerId(2),
        LayerId(3),
        LayerId(4),
        LayerId(5),
        LayerId(6),
    );
    let mut layout = LayoutBuilder::new(7);
    layout.rect(well, -20_000, -5_000, 20_000, 5_000);
    layout.rect(tap, -15_000, 0, -10_000, 1_000);
    layout.rect(tie, -15_000, 0, -10_000, 1_000);
    layout.rect(contact, -12_600, 400, -12_400, 600);
    layout.rect(metal1, -15_000, 0, -5_000, 1_000);
    layout.rect(poly, 0, 0, 1_000, 1_000);
    layout.rect(gate, 0, 0, 1_000, 1_000);
    let (store, _) = layout.finish();
    let stack = Stack {
        conductors: vec![tap, well, poly, metal1],
        vias: vec![(tie, tap, well), (contact, tap, metal1)],
        intra_layer_touch: true,
    };

    let (violations, runs) = run_staged(&store, stack, gate, &[metal1], AntennaMeasure::Area, 1.0);
    assert_clean(&runs, &violations, rule(90));
}

/// A die-sized window over one layer, with only the bound the caller states.
fn density_table(id: StrId, side: i64, min: Option<f64>, max: Option<f64>) -> DensityCmpTable {
    DensityCmpTable {
        head: head(id),
        layer: vec![LayerId(0)],
        window: vec![(dbu(side), dbu(side))],
        step: vec![(dbu(side), dbu(side))],
        min_density: vec![min],
        max_density: vec![max],
        max_neighbour_delta: vec![None],
        cmp: vec![None],
        include_partial_windows: vec![true],
    }
}

fn die_of(side: i64) -> Bbox {
    Bbox {
        xlo: dbu(0),
        ylo: dbu(0),
        xhi: dbu(side),
        yhi: dbu(side),
    }
}

fn run_density(
    store: &GeometryStore,
    die: Bbox,
    table: &DensityCmpTable,
) -> (Violations, Vec<RuleRun>) {
    let nets = NetTable::default();
    let devices = DeviceTable::default();
    let design = Design {
        store,
        nets: &nets,
        devices: &devices,
    };
    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = report();
    check_density_cmp(design, die, table, &mut scratch, &mut violations, &mut runs);
    (violations, runs)
}

/// Oracle: closed form. A shape covering the left half of a square die is a
/// density of exactly one half. One window the size of the die means one
/// evaluation, so the number is unambiguous — and both bounds are checked from
/// the same geometry, once from above and once from below, because a rule that
/// applied one limit in place of the other passes whichever test states only
/// one of them.
#[test]
fn a_layer_covering_half_the_die_reads_as_a_density_of_one_half() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(LayerId(0), 0, 0, 1_000, 2_000);
    let (store, _) = layout.finish();
    let die = die_of(2_000);

    let over = rule(73);
    let (violations, runs) = run_density(&store, die, &density_table(over, 2_000, None, Some(0.4)));
    assert_eq!(violations.rule.len(), 1, "half a die is over a 0.4 ceiling");
    assert_close_relative("the density", measured_ratio(&violations, 0), 0.5, 1e-12);
    assert_eq!(violations.limit[0], Measurement::Ratio(0.4));
    assert_eq!(
        assert_rule_ran(&runs, over).examined,
        1,
        "one window covers the die"
    );

    let under = rule(74);
    let (violations, runs) =
        run_density(&store, die, &density_table(under, 2_000, Some(0.6), None));
    assert_eq!(assert_rule_ran(&runs, under).examined, 1);
    assert_eq!(violations.rule.len(), 1, "half a die is under a 0.6 floor");
    assert_close_relative("the density", measured_ratio(&violations, 0), 0.5, 1e-12);
    assert_eq!(violations.limit[0], Measurement::Ratio(0.6));

    let between = rule(75);
    let (violations, runs) = run_density(
        &store,
        die,
        &density_table(between, 2_000, Some(0.4), Some(0.6)),
    );
    assert_clean(&runs, &violations, between);
}

/// Oracle: construct-from-answer. Quartering the die into four windows makes
/// the two left windows fully covered and the two right ones empty, so a
/// ceiling of 0.9 catches exactly two and a floor of 0.1 catches the other two.
/// The window count is what the run row reports, and it is what distinguishes a
/// clean run from a step configuration that produced no windows at all.
#[test]
fn a_die_quartered_into_four_windows_reports_each_windows_own_density() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(LayerId(0), 0, 0, 1_000, 2_000);
    let (store, _) = layout.finish();
    let die = die_of(2_000);

    let over = rule(76);
    let (violations, runs) = run_density(&store, die, &density_table(over, 1_000, None, Some(0.9)));
    assert_eq!(
        assert_rule_ran(&runs, over).examined,
        4,
        "two by two windows"
    );
    assert_eq!(
        violations.rule.len(),
        2,
        "the two left windows are fully covered"
    );
    for row in 0..2 {
        assert_close_relative(
            "a covered window",
            measured_ratio(&violations, row),
            1.0,
            1e-12,
        );
    }

    let under = rule(77);
    let (violations, runs) =
        run_density(&store, die, &density_table(under, 1_000, Some(0.1), None));
    assert_eq!(assert_rule_ran(&runs, under).examined, 4);
    assert_eq!(violations.rule.len(), 2, "the two right windows are empty");
    for row in 0..2 {
        assert_eq!(violations.measured[row], Measurement::Ratio(0.0));
    }
}

/// Oracle: closed form, on arbitrary geometry. The generator places disjoint
/// squares and reports the area it covered while placing them, so the density
/// of a window spanning the whole region is `covered / extent^2` exactly — with
/// no union and no overlap correction to approximate. A rule accumulating
/// bounding boxes instead of areas, which is what the old implementation did,
/// reads high here and reads correct on a rectangle.
#[test]
fn windowed_density_over_generated_geometry_matches_the_area_the_generator_covered() {
    let mut rng = Rng::new(97);
    let mut layout = LayoutBuilder::new(1);
    let placed = random_rectilinear_layer(
        &mut layout,
        &mut rng,
        LayerId(0),
        (0, 0),
        RandomLayerSpec {
            cells: 8,
            cell: 500,
            density: 0.35,
        },
    );
    let (store, _) = layout.finish();

    #[allow(
        clippy::cast_precision_loss,
        reason = "a covered area of a few million database units is far below 2^53"
    )]
    let expected = placed.covered as f64 / (placed.extent as f64 * placed.extent as f64);

    let id = rule(78);
    let (violations, runs) = run_density(
        &store,
        die_of(placed.extent),
        // A ceiling below the generator's own answer, so the window reports and
        // its measurement can be read.
        &density_table(id, placed.extent, None, Some(expected / 2.0)),
    );

    assert_eq!(assert_rule_ran(&runs, id).examined, 1);
    assert_eq!(violations.rule.len(), 1);
    assert_close_relative(
        "the density of generated geometry",
        measured_ratio(&violations, 0),
        expected,
        1e-12,
    );
}

/// Oracle: law. A density is a covered fraction, so it lies in `0.0 ..= 1.0`
/// for every window of every layout — no closed form needed, and it holds over
/// the generated corpus. A rule summing overlapping contributions, or dividing
/// by a window area rather than by the window clipped to the die, escapes that
/// interval and this is what notices.
#[test]
fn every_windows_density_is_a_fraction_between_zero_and_one() {
    for seed in [1u64, 2, 3] {
        let mut rng = Rng::new(seed);
        let mut layout = LayoutBuilder::new(1);
        let placed = random_rectilinear_layer(
            &mut layout,
            &mut rng,
            LayerId(0),
            (0, 0),
            RandomLayerSpec {
                cells: 6,
                cell: 400,
                density: 0.5,
            },
        );
        let (store, _) = layout.finish();

        let id = rule(79);
        // A floor of one reports every window, whatever its density, so every
        // window's measurement lands in the table where the law can be checked.
        let (violations, runs) = run_density(
            &store,
            die_of(placed.extent),
            &density_table(id, placed.extent / 3, Some(1.000_001), None),
        );

        let run = assert_rule_ran(&runs, id);
        assert_eq!(
            run.examined, 9,
            "a third of the extent each way is nine windows"
        );
        assert_eq!(
            violations.rule.len(),
            9,
            "a floor above one reports every window"
        );
        for row in 0..violations.rule.len() {
            let density = measured_ratio(&violations, row);
            assert!(
                (0.0..=1.0).contains(&density),
                "seed {seed}: window {row} reports a density of {density}"
            );
        }
    }
}
