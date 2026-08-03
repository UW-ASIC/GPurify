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

mod common;

use common::{head, rule};
use gpurify_core::{Bbox, GeometryStore, LayerId};
use gpurify_derived::{Evaluator, LayerRef};
use gpurify_erc::rules::antenna::{
    check_antenna, check_antenna_electrical, check_density_cmp, AntennaElectricalTable,
    AntennaMeasure, AntennaTable, DensityCmpTable,
};
use gpurify_erc::{Design, Scratch};
use gpurify_ingest::deck::Connectivity;
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, RuleRun, Violations};
use gpurify_testgen::shapes::{random_rectilinear_layer, RandomLayerSpec};
use gpurify_testgen::{
    assert_clean, assert_close_relative, assert_rule_ran, dbu, LayoutBuilder, Rng,
};
use gpurify_topology::{DeviceTable, NetTable};

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
fn gate_on_a_long_wire() -> (GeometryStore, NetTable, gpurify_core::PolyId) {
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
    };
    let mut nets = NetTable::default();
    gpurify_topology::extract_nets_into(&store, &connectivity, &mut nets);
    let gate_poly = ids.of(gate);
    (store, nets, gate_poly)
}

fn antenna_table(id: StrId, max_ratio: f64) -> AntennaTable {
    AntennaTable {
        head: head(id),
        gate: vec![LayerRef::Base(LayerId(2))],
        collector_start: vec![0, 1],
        collector: vec![LayerRef::Base(LayerId(0))],
        collector_measure: vec![AntennaMeasure::Area],
        max_ratio: vec![max_ratio],
    }
}

/// Oracle: closed form. Four square micrometres of wire on one square
/// micrometre of gate is a ratio of exactly four, and the violation is reported
/// at the gate — which is what fails and what a fix adds a diode to, not the
/// wire that collected the charge.
#[test]
fn a_per_stage_antenna_ratio_is_the_collecting_area_over_the_gate_area() {
    let (store, nets, gate) = gate_on_a_long_wire();
    let derived = Evaluator::default();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        derived: &derived,
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
    let derived = Evaluator::default();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        derived: &derived,
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
    let derived = Evaluator::default();
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        derived: &derived,
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
            gate: vec![LayerRef::Base(LayerId(2))],
            collector_start: vec![0, 1],
            collector: vec![LayerRef::Base(LayerId(0))],
            diode: vec![None],
            diode_credit: vec![0.0],
            diode_bonus: vec![0.0],
            max_ratio: vec![3.0],
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

/// A die-sized window over one layer, with only the bound the caller states.
fn density_table(id: StrId, side: i64, min: Option<f64>, max: Option<f64>) -> DensityCmpTable {
    DensityCmpTable {
        head: head(id),
        layer: vec![LayerRef::Base(LayerId(0))],
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
    let derived = Evaluator::default();
    let nets = NetTable::default();
    let devices = DeviceTable::default();
    let design = Design {
        store,
        derived: &derived,
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
