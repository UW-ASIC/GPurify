//! Point-to-point resistance, and the network that tells it apart from a proxy.
//!
//! The rule's doc comment makes a specific claim: the measurement is the
//! **effective** resistance of the whole network between two attach points, not
//! a path length and not a sum of squares. Those three agree on a single wire
//! and disagree on anything with a parallel route, so the tests here are built
//! on the disagreement — a net of four parallel straps, where the effective
//! answer is a sixteenth of the sum of squares and a quarter of one strand.

use crate::common;

use common::{head, one_row_network, rule};
use gpurify_check::erc::power::NetNetworks;
use gpurify_check::erc::rules::electrical::{check_p2p_resistance, P2pResistanceTable};
use gpurify_check::erc::{Design, Scratch};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, Violations};
use gpurify_check::topology::{DeviceTable, NetTable};
use gpurify_geom::Evaluator;
use gpurify_geom::{prefix, Qty, Resistance};
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_testgen::{assert_clean, assert_close_relative, point, LayoutBuilder};

/// A net whose two attach points are joined by `strands` identical straps.
///
/// The effective resistance is `ohm / strands`, the sum along one route is
/// `ohm`, and the sum of squares over the straps is `strands * ohm^2`. Three
/// answers that a one-strand net cannot distinguish.
fn strapped_net(strands: u32, ohm: f64) -> (GeometryStore, NetNetworks, PolyId, PolyId) {
    let mut layout = LayoutBuilder::new(1);
    let left = layout.rect(LayerId(0), 0, 0, 1_000, 1_000);
    let right = layout.rect(LayerId(0), 5_000, 0, 6_000, 1_000);
    let (store, ids) = layout.finish();
    let (a, b) = (ids.of(left), ids.of(right));

    let edges: Vec<(u32, u32, f64)> = (0..strands).map(|_| (0, 1, ohm)).collect();
    let mut networks = one_row_network(2, &[0, 1], &edges);
    networks.node_poly = vec![a, b];
    networks.node_at = vec![point(500, 500), point(5_500, 500)];
    (store, networks, a, b)
}

fn table(id: gpurify_ingest::StrId, max_ohm: f64) -> P2pResistanceTable {
    P2pResistanceTable {
        head: head(id),
        max_resistance: vec![Qty::<Resistance, { prefix::BASE }>::new(max_ohm)],
    }
}

/// Run the rule over one net's network.
fn run(
    store: &GeometryStore,
    networks: &NetNetworks,
    rules: &P2pResistanceTable,
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
    let mut out = Violations::default();
    let mut runs = Vec::new();
    check_p2p_resistance(design, networks, rules, &mut scratch, &mut out, &mut runs);
    (out, runs)
}

/// The measured resistance on one violation row.
///
/// # Panics
///
/// When the row measured something other than a resistance. A rule reporting an
/// antenna ratio in a resistance column would be a dimension error the report's
/// sum type exists to make impossible, so it is asserted rather than coerced.
fn measured_ohms(violations: &Violations, row: usize) -> f64 {
    match violations.measured[row] {
        Measurement::Resistance(r) => r.raw(),
        other => panic!("row {row} measured {other:?}, not a resistance"),
    }
}

/// Oracle: closed form, on the network that distinguishes the three candidate
/// answers. Four eight-ohm straps in parallel are two ohms. A sum along one
/// route would report eight, and the old sum-of-squares proxy would report two
/// hundred and fifty-six — so a rule reporting anything but two here is not
/// computing effective resistance, whatever it is computing.
#[test]
fn p2p_resistance_reports_the_effective_resistance_between_the_attach_points() {
    let (store, networks, a, b) = strapped_net(4, 8.0);
    let id = rule(1);
    let (violations, runs) = run(&store, &networks, &table(id, 1.0));

    assert_eq!(
        violations.rule.len(),
        1,
        "one net over one limit is one row"
    );
    assert_eq!(violations.rule[0], id);
    assert_eq!(violations.severity[0], Severity::Error);
    assert_eq!(
        (violations.shape_a[0], violations.shape_b[0]),
        (a, Some(b)),
        "the violation must name both ends of the offending run"
    );
    assert_eq!(violations.layer[0], store.poly_layer(a));
    assert_close_relative(
        "the reported resistance",
        measured_ohms(&violations, 0),
        2.0,
        1e-9,
    );
    assert_eq!(
        violations.limit[0],
        Measurement::Resistance(Qty::<Resistance, { prefix::BASE }>::new(1.0))
    );
    common::assert_at_is_on_a_named_shape(&store, &violations, 0);

    let run = gpurify_testgen::assert_rule_ran(&runs, id);
    assert_eq!(
        run.violations, 1,
        "the run row's count is derived from the pushes"
    );
    assert_eq!(run.examined, 1, "one net was probed");
}

/// Oracle: closed form, stated as the discriminating case. The same four straps
/// against a ten-ohm limit: the effective resistance is two and passes, while
/// the sum over the straps (thirty-two) and the sum of squares (two hundred and
/// fifty-six) both fail. A rule using either proxy reports a violation here,
/// and this test is what says that is wrong.
///
/// The clean assertion goes through `assert_clean`, so it also asserts the rule
/// ran and examined a net — an empty violation table alone is satisfied by a
/// rule that never executed.
#[test]
fn a_net_whose_strands_sum_over_the_limit_still_passes_on_its_effective_resistance() {
    let (store, networks, _, _) = strapped_net(4, 8.0);
    let id = rule(2);
    let (violations, runs) = run(&store, &networks, &table(id, 10.0));
    assert_clean(&runs, &violations, id);
}

/// Oracle: law. Rayleigh monotonicity at the level of the rule: adding metal in
/// parallel can only lower the number the report shows. This is the property a
/// designer acts on, and the old proxy inverted it — the reported figure went
/// up when the net was improved, which trained users to ignore the rule.
#[test]
fn adding_a_parallel_strap_lowers_the_resistance_the_rule_reports() {
    let id = rule(3);
    let mut previous = f64::INFINITY;
    for strands in [1u32, 2, 4, 8] {
        let (store, networks, _, _) = strapped_net(strands, 8.0);
        // A limit below any of the four answers, so every case reports and the
        // measurement can be read off.
        let (violations, _) = run(&store, &networks, &table(id, 1e-6));
        assert_eq!(violations.rule.len(), 1);
        let measured = measured_ohms(&violations, 0);
        assert!(
            measured < previous,
            "{strands} straps report {measured} ohm, no better than the {previous} ohm \
             reported with half as many"
        );
        assert_close_relative(
            &format!("{strands} straps"),
            measured,
            8.0 / f64::from(strands),
            1e-9,
        );
        previous = measured;
    }
}

/// Oracle: construct-from-answer. A net with fewer than two attach points has
/// no row in `NetNetworks`, so there is no pair to measure. The rule must still
/// record itself, with `examined` at zero: that reads as "this rule ran and had
/// nothing to measure", which is a different claim from clean and the only
/// honest one here.
#[test]
fn a_design_with_no_probeable_net_runs_and_examines_nothing() {
    let layout = LayoutBuilder::new(1);
    let (store, _) = layout.finish();
    let id = rule(4);
    let (violations, runs) = run(&store, &NetNetworks::default(), &table(id, 5.0));

    let run = common::run_of(&runs, id);
    assert_eq!(
        run.outcome,
        Outcome::Ran,
        "no intent is needed to probe geometry"
    );
    assert_eq!(run.examined, 0);
    assert_eq!(run.violations, 0);
    assert!(violations.rule.is_empty());
}

/// Oracle: construct-from-answer. Two rule rows at two limits produce two run
/// rows, and only the tighter one reports. The invariant the crate is shaped
/// around — one `RuleRun` per configured row, always — is what makes a report
/// attributable, and a transform that returned early after the first row would
/// break it silently.
#[test]
fn each_configured_rule_row_produces_its_own_run_row() {
    let (store, networks, _, _) = strapped_net(4, 8.0);
    let (tight, loose) = (rule(5), rule(6));
    let rules = P2pResistanceTable {
        head: gpurify_check::erc::ruleset::RuleHead {
            rule: vec![tight, loose],
            severity: vec![Severity::Error, Severity::Warning],
        },
        max_resistance: vec![
            Qty::<Resistance, { prefix::BASE }>::new(1.0),
            Qty::<Resistance, { prefix::BASE }>::new(10.0),
        ],
    };
    let (violations, runs) = run(&store, &networks, &rules);

    assert_eq!(runs.len(), 2, "two configured rows, two run rows");
    assert_eq!(common::run_of(&runs, tight).violations, 1);
    assert_eq!(common::run_of(&runs, loose).violations, 0);
    assert_eq!(violations.rule, vec![tight]);
}

/// Oracle: determinism. The same net probed twice through two fresh scratches
/// must produce the same columns, including the reported coordinate. The
/// probe's elimination order is the implementation's choice; the report is not.
#[test]
fn running_the_rule_twice_produces_identical_violation_columns() {
    let (store, networks, _, _) = strapped_net(4, 8.0);
    let id = rule(7);
    let (first, first_runs) = run(&store, &networks, &table(id, 1.0));
    let (second, second_runs) = run(&store, &networks, &table(id, 1.0));

    gpurify_testgen::assert_violations_eq(&first, &second);
    assert_eq!(first_runs, second_runs);
}
