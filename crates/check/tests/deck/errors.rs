//! Every way a deck fails to compile, now that the values a rule can hold are
//! checked on the typed rule (deck-library plan P1, ledger D2).
//!
//! Oracle: construct-from-answer. Each deck breaks exactly one constraint a
//! rule kind states in its documentation (a limit is positive, a fraction lies
//! in `0..=1`, a kind is one a domain runs, an id is unique), so the error it
//! must raise is known before anything runs. The exit test of P1: every
//! `DrcError` and `ErcError` variant is still produced.

use gpurify_check::deck::{compile, CompileError, CompiledDeck};
use gpurify_check::drc::DrcError;
use gpurify_check::erc::{ErcError, RuleSet as ErcRules};
use gpurify_check::report::Severity;
use gpurify_geom::{Dbu, Grid, LayerId, Qty, StrTable};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};

fn grid() -> Grid {
    Grid::new(1000).expect("a 1 nm grid")
}

fn len(nm: i64) -> ParamValue {
    ParamValue::Length(Dbu::new_unchecked(nm))
}

/// One hand-built rule row: id, kind, how many layer arguments (each layer
/// 0), and its parameters.
struct Row {
    id: &'static str,
    kind: &'static str,
    layers: u32,
    params: Vec<(&'static str, ParamValue)>,
}

fn row(
    id: &'static str,
    kind: &'static str,
    layers: u32,
    params: &[(&'static str, ParamValue)],
) -> Row {
    Row {
        id,
        kind,
        layers,
        params: params.to_vec(),
    }
}

/// A deck of `rows` and an empty layer table. The parser refuses most of
/// these rows; a deck built in code reaches the rule sets as written.
fn deck_of(strings: &mut StrTable, rows: &[Row]) -> Deck {
    let narrow = |n: usize| u32::try_from(n).expect("a handful of rows");
    let mut deck = Deck::default();
    for row in rows {
        let layer_start = narrow(deck.rules.layer_ref.len());
        deck.rules
            .layer_ref
            .extend((0..row.layers).map(|_| LayerId(0)));
        let param_start = narrow(deck.rules.param.len());
        for &(name, value) in &row.params {
            let name = strings.intern(name);
            deck.rules.param.push((name, value));
        }
        let spec = RuleSpec {
            id: strings.intern(row.id),
            kind: strings.intern(row.kind),
            layer_start,
            layer_len: row.layers,
            param_start,
            param_len: narrow(row.params.len()),
        };
        deck.rules.spec.push(spec);
    }
    deck
}

/// What compiling `rows` refuses.
fn refusal(rows: &[Row]) -> CompileError {
    let mut strings = StrTable::default();
    let deck = deck_of(&mut strings, rows);
    CompiledDeck::from_deck(deck, grid(), &strings).expect_err("the deck breaks one constraint")
}

fn drc(error: CompileError) -> DrcError {
    match error {
        CompileError::Drc(why) => why,
        other => panic!("not a DRC refusal: {other:?}"),
    }
}

fn erc(error: CompileError) -> ErcError {
    match error {
        CompileError::Erc(why) => why,
        other => panic!("not an ERC refusal: {other:?}"),
    }
}

/// Every `DrcError` variant, each from a deck that breaks only its constraint.
/// Oracle: construct-from-answer: each deck differs from a legal one in the
/// one value the variant's documented constraint forbids.
#[test]
fn every_drc_error_is_still_produced() {
    let rule = |id: &str| id.to_owned();
    let width = |limit| row("w", "min_width", 1, &[("limit", limit)]);
    assert_eq!(
        drc(refusal(&[row("w", "min_widht", 1, &[("limit", len(10))])])),
        DrcError::UnknownKind {
            rule: rule("w"),
            kind: "min_widht".to_owned()
        }
    );
    assert_eq!(
        drc(refusal(&[row("w", "min_width", 1, &[])])),
        DrcError::MissingParam {
            rule: rule("w"),
            param: "limit"
        }
    );
    assert_eq!(
        drc(refusal(&[width(ParamValue::Ratio(1.0))])),
        DrcError::WrongParamType {
            rule: rule("w"),
            param: "limit"
        }
    );
    assert_eq!(
        drc(refusal(&[row("w", "min_width", 2, &[("limit", len(10))])])),
        DrcError::WrongLayerCount {
            rule: rule("w"),
            expected: 1,
            found: 2
        }
    );
    assert_eq!(
        drc(refusal(&[width(len(0))])),
        DrcError::NonPositiveLimit {
            rule: rule("w"),
            limit: 0
        }
    );
    assert_eq!(
        drc(refusal(&[row(
            "a",
            "angle",
            0,
            &[("angle", ParamValue::Count(30))]
        )])),
        DrcError::UnrepresentableAngle {
            rule: rule("a"),
            degrees: 30
        }
    );
    assert_eq!(
        drc(refusal(&[width(len(10)), width(len(20))])),
        DrcError::DuplicateRule(rule("w"))
    );
    // A cell of zero: not a positive space, so not a valid table.
    assert_eq!(
        drc(refusal(&[row(
            "t",
            "spacing_table",
            1,
            &[("prl", len(0)), ("width", len(0)), ("space", len(0))]
        )])),
        DrcError::BadTable(rule("t"))
    );
}

/// Every `ErcError` variant, each from a deck that breaks only its
/// constraint. A duplicate id across domains is refused by DRC first, so the
/// ERC duplicate comes from the ERC rule set alone.
/// Oracle: construct-from-answer: each deck differs from a legal one in the
/// one value the variant's documented constraint forbids.
#[test]
fn every_erc_error_is_still_produced() {
    let rule = |id: &str| id.to_owned();
    assert_eq!(
        erc(refusal(&[row(
            "g",
            "gate_oxide",
            0,
            &[("max_voltage", ParamValue::Ratio(1800.0))]
        )])),
        ErcError::MissingParam {
            rule: rule("g"),
            param: "model"
        }
    );
    assert_eq!(
        erc(refusal(&[row(
            "d",
            "multiple_drivers",
            0,
            &[("max_drivers", ParamValue::Ratio(1.0))]
        )])),
        ErcError::WrongParamType {
            rule: rule("d"),
            param: "max_drivers"
        }
    );
    // A non-finite limit would pass everything: refused as the wrong kind of value.
    assert_eq!(
        erc(refusal(&[row(
            "p",
            "p2p_resistance",
            0,
            &[("max_resistance", ParamValue::Ratio(f64::INFINITY))]
        )])),
        ErcError::WrongParamType {
            rule: rule("p"),
            param: "max_resistance"
        }
    );
    assert_eq!(
        erc(refusal(&[row("f", "floating_well", 1, &[])])),
        ErcError::WrongLayerCount {
            rule: rule("f"),
            expected: 2,
            found: 1
        }
    );
    assert_eq!(
        erc(refusal(&[row(
            "p",
            "p2p_resistance",
            0,
            &[("max_resistance", ParamValue::Ratio(0.0))]
        )])),
        ErcError::NonPositiveLimit {
            rule: rule("p"),
            limit: "max_resistance".to_owned()
        }
    );
    let window = [
        ("window_x", len(10)),
        ("window_y", len(10)),
        ("step_x", len(10)),
        ("step_y", len(10)),
    ];
    let mut over = window.to_vec();
    over.push(("max_density", ParamValue::Ratio(1.5)));
    assert_eq!(
        erc(refusal(&[row("c", "density_cmp", 1, &over)])),
        ErcError::NotAFraction {
            rule: rule("c"),
            param: "max_density"
        }
    );
    assert_eq!(
        erc(refusal(&[row("c", "density_cmp", 1, &window)])),
        ErcError::MissingParam {
            rule: rule("c"),
            param: "max_density"
        },
        "a density_cmp row bounding nothing"
    );

    let mut strings = StrTable::default();
    let twice = deck_of(
        &mut strings,
        &[
            row("x", "ir_drop", 0, &[]),
            row("x", "tie_high_low", 0, &[]),
        ],
    );
    assert_eq!(
        ErcRules::from_deck(&twice, &strings).unwrap_err(),
        ErcError::DuplicateRule(rule("x"))
    );
}

/// The ERC checks hold a table built in code too, not only a deck row.
/// Oracle: construct-from-answer: a zero resistance limit breaks the
/// documented positive domain; ten ohms keeps it.
#[test]
fn erc_validation_holds_a_table_built_in_code() {
    let mut strings = StrTable::default();
    let mut set = ErcRules::default();
    assert_eq!(set.validate(&strings), Ok(()), "no row, nothing to refuse");
    set.p2p_resistance.head.rule.push(strings.intern("p"));
    set.p2p_resistance.head.severity.push(Severity::Error);
    set.p2p_resistance.max_resistance.push(Qty::new(0.0));
    assert_eq!(
        set.validate(&strings),
        Err(ErcError::NonPositiveLimit {
            rule: "p".to_owned(),
            limit: "max_resistance".to_owned()
        })
    );
    set.p2p_resistance.max_resistance[0] = Qty::new(10.0);
    assert_eq!(set.validate(&strings), Ok(()));
}

/// A deck header every rule below can name: two polygon layers that conduct,
/// their edges, and a declared MOS model.
const HEADER: &str = "grid 1nm
layer a = gds(1, 0)
layer b = gds(2, 0)
layer e = a.edges()
layer f = b.edges()
connect conductors [a, b]
device mos a model \"nfet\" terminals [a, b, b, b]
";

/// An `antenna_electrical` row's values, each legal.
const ANTENNA_ELECTRICAL: &str = "max_ratio: 400, sidewall: 10nm, cut_factor: 1, \
    diode: none, diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0, \
    diode_reduce: none, diode_max_ratio: [(0nm2, 400), (100nm2, 800)], exempt: none";

/// One value written into a rule template: zero, which the kind refuses, and
/// a legal positive value.
const LEN: (&str, &str) = ("0nm", "10nm");
const AREA: (&str, &str) = ("0nm2", "100nm2");
const FRACTION: (&str, &str) = ("0", "0.5");
const COUNT: (&str, &str) = ("0", "2");

/// Every positive DRC value, one per row: each template compiles with the
/// legal value and is refused as not positive with zero in its `{}`. Kills a
/// field the typed check forgets.
/// Oracle: the kinds' documented domains: each value is a length, area or
/// count the checker documents as positive.
#[test]
fn every_positive_drc_value_written_as_zero_is_refused() {
    let cases: &[(&str, (&str, &str))] = &[
        ("width(a) >= {}", LEN),
        ("width(a) <= {}", LEN),
        ("size(a) == {} x 10nm", LEN),
        ("size(a) == 10nm x {}", LEN),
        ("edge_length(a) >= {}", LEN),
        ("notch(a) >= {}", LEN),
        ("space(a) >= {}", LEN),
        ("space(a, b) >= {}", LEN),
        ("eol_space(a; eol_width: {}) >= 10nm", LEN),
        ("eol_space(a; eol_width: 10nm) >= {}", LEN),
        ("prl_space(a; prl: {}) >= 10nm", LEN),
        ("prl_space(a; prl: 10nm) >= {}", LEN),
        ("corner_space(a) >= {}", LEN),
        ("wide_space(a; width: {}) >= 10nm", LEN),
        ("wide_space(a; width: 10nm) >= {}", LEN),
        ("area(a) >= {}", AREA),
        ("hole_area(a) >= {}", AREA),
        ("cheesing(a) <= {}", AREA),
        ("density(a; window: {}, step: 10nm) >= 0.5", LEN),
        ("density(a; window: 10nm, step: {}) >= 0.5", LEN),
        ("density(a; window: 10nm, step: 10nm) >= {}", FRACTION),
        ("global_density(a) >= {}", FRACTION),
        ("enclosure(a, b) >= {}", LEN),
        ("enclosure(a, b, opposite) >= {}", LEN),
        ("extension(a, b) >= {}", LEN),
        ("overlap(a, b) >= {}", LEN),
        ("tap_distance(a, b) <= {}", LEN),
        ("off_grid(; pitch: {})", LEN),
        ("redundant_via(a; within: 10nm) >= {}", COUNT),
        ("redundant_via(a; within: {}) >= 2", LEN),
        ("via_array_space(a; array: 2) >= {}", LEN),
        ("patterning(a; colors: {}) >= 10nm", COUNT),
        ("patterning(a; colors: 2) >= {}", LEN),
        ("contains(a, b) >= {}", COUNT),
        ("space(a; nets: same) >= {}", LEN),
        ("wide_space(a; width: {}, attached: 10nm) >= 10nm", LEN),
        ("wide_space(a; width: 10nm, attached: {}) >= 10nm", LEN),
        ("wide_space(a; width: 10nm, attached: 10nm) >= {}", LEN),
        ("length(e) >= {}", LEN),
        ("space(e) >= {}", LEN),
        ("space(e, f) >= {}", LEN),
        ("enclosure(e, b) >= {}", LEN),
    ];
    for &(template, (zero, legal)) in cases {
        let deck = |value: &str| format!("{HEADER}rule r {}\n", template.replace("{}", value));
        compile(&deck(legal), grid(), &mut StrTable::default())
            .unwrap_or_else(|why| panic!("{template} with {legal}: {why}"));
        match compile(&deck(zero), grid(), &mut StrTable::default()) {
            Err(CompileError::Drc(DrcError::NonPositiveLimit { rule, .. })) => {
                assert_eq!(rule, "r");
            }
            other => panic!("{template} with {zero}: {other:?}"),
        }
    }
}

/// Every positive ERC value, one per row, as for DRC: each refusal names
/// the parameter, by its engine name.
/// Oracle: the kinds' documented domains, as for DRC.
#[test]
fn every_positive_erc_value_written_as_zero_is_refused() {
    const EM: &str = "max_density: 1000A/m, max_current_per_cut: 80uA, blech_limit: 15000uA, \
         reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2";
    const RELIABILITY: &str = "required_lifetime: 1000h, reference_lifetime: 1000h, \
         reference_stress: 1.8V, stress_exponent: 2, reference_temperature: 378K, \
         activation_energy: 0.9eV, max_abs_voltage: 1.8V, duty_cycle: 0.5";
    const DENSITY: &str = "window: 10nm x 10nm, step: 10nm x 10nm, min: none, max: 0.5, \
         max_delta: none, partial_windows: true";
    // (the rule, the value to zero in it, that value's zero, the engine name)
    let cases: Vec<(String, &str, &str, &str)> = vec![
        (
            "antenna(a, b; max_ratio: 400, sidewall: none, diode: none)".into(),
            "400",
            "0",
            "max_ratio",
        ),
        (
            "antenna(a, b; max_ratio: 400, sidewall: 10nm, diode: none)".into(),
            "10nm",
            "0nm",
            "sidewall_thickness",
        ),
        (
            format!("antenna_electrical(a, b; {ANTENNA_ELECTRICAL})"),
            "max_ratio: 400",
            "max_ratio: 0",
            "max_ratio",
        ),
        (
            format!("antenna_electrical(a, b; {ANTENNA_ELECTRICAL})"),
            "10nm",
            "0nm",
            "sidewall_thickness",
        ),
        (
            format!("antenna_electrical(a, b; {ANTENNA_ELECTRICAL})"),
            "cut_factor: 1",
            "cut_factor: 0",
            "cut_factor",
        ),
        (
            format!("antenna_electrical(a, b; {ANTENNA_ELECTRICAL})"),
            "(0nm2, 400)",
            "(0nm2, 0)",
            "diode_max_ratio",
        ),
        (
            format!("density_cmp(a; {DENSITY}, cmp: none)").replacen("10nm", "77nm", 1),
            "77nm",
            "0nm",
            "window_x",
        ),
        (
            format!("density_cmp(a; {DENSITY}, cmp: (target: 0.5, sensitivity: 10nm, max_delta: 77nm))"),
            "77nm",
            "0nm",
            "cmp_max_abs_thickness_delta",
        ),
        (
            format!("electromigration(a; {EM})"),
            "1000A/m",
            "0A/m",
            "max_density",
        ),
        (
            format!("electromigration(a; {EM})"),
            "80uA",
            "0uA",
            "max_current_per_cut",
        ),
        (
            format!("electromigration(a; {EM})"),
            "15000uA",
            "0uA",
            "blech_limit",
        ),
        (
            format!("electromigration(a; {EM})"),
            "378K",
            "0K",
            "reference_temperature",
        ),
        (
            format!("electromigration(a; {EM})"),
            "0.9eV",
            "0eV",
            "activation_energy_ev",
        ),
        (
            format!("electromigration(a; {EM})"),
            "current_exponent: 2",
            "current_exponent: 0",
            "current_exponent",
        ),
        (
            "em_current_density(a; max_density: 1000A/m, max_current_per_cut: 80uA, narrow: (width: 30nm, current: 50uA))"
                .into(),
            "80uA",
            "0uA",
            "max_current_per_cut",
        ),
        (
            "em_current_density(a; max_density: 1000A/m, max_current_per_cut: 80uA, narrow: (width: 30nm, current: 50uA))"
                .into(),
            "30nm",
            "0nm",
            "narrow_width",
        ),
        (
            "em_current_density(a; max_density: 1000A/m, max_current_per_cut: 80uA, narrow: (width: 30nm, current: 50uA))"
                .into(),
            "50uA",
            "0uA",
            "narrow_current",
        ),
        (
            "esd_latchup(a, b; min_guard_ring_width: 10nm, max_tap_distance: 20nm, clamps: [\"nfet\"])"
                .into(),
            "20nm",
            "0nm",
            "max_tap_distance",
        ),
        (
            "hv_domain(; max_delta: 1.8V, isolation: none)".into(),
            "1.8V",
            "0V",
            "max_domain_delta",
        ),
        (
            "missing_tie(a, b; max_distance: 10nm)".into(),
            "10nm",
            "0nm",
            "max_distance",
        ),
        (
            "multiple_drivers(; max: 2)".into(),
            "2",
            "0",
            "max_drivers",
        ),
        (
            "p2p_resistance(; max: 10ohm)".into(),
            "10ohm",
            "0ohm",
            "max_resistance",
        ),
        (
            format!("reliability(; {RELIABILITY})").replacen("1000h", "999h", 1),
            "999h",
            "0h",
            "required_lifetime_hours",
        ),
        (
            format!("reliability(; {RELIABILITY})"),
            "stress_exponent: 2",
            "stress_exponent: 0",
            "stress_exponent",
        ),
        (
            format!("reliability(; {RELIABILITY})"),
            "duty_cycle: 0.5",
            "duty_cycle: 0",
            "duty_cycle",
        ),
        (
            "gate_oxide(; models: [\"nfet\"], max: 1.8V)".into(),
            "1.8V",
            "0V",
            "max_voltage",
        ),
        (
            "drain_source(; models: [\"nfet\"], max: 1.8V)".into(),
            "1.8V",
            "0V",
            "max_voltage",
        ),
    ];
    for (text, legal, zero, param) in cases {
        let deck = |text: &str| format!("{HEADER}rule r {text}\n");
        compile(&deck(&text), grid(), &mut StrTable::default())
            .unwrap_or_else(|why| panic!("{text}: {why}"));
        assert!(text.contains(legal), "{text} holds {legal}");
        let broken = text.replacen(legal, zero, 1);
        match compile(&deck(&broken), grid(), &mut StrTable::default()) {
            Err(CompileError::Erc(ErcError::NonPositiveLimit { rule, limit })) => {
                assert_eq!((rule.as_str(), limit.as_str()), ("r", param), "{broken}");
            }
            other => panic!("{broken}: {other:?}"),
        }
    }
}

/// Every value check of the ERC kinds the zero sweep above does not reach,
/// one broken value per deck, each refused with the error and parameter
/// its kind documents: a limit that must be positive written as zero or
/// below, a fraction outside `0..=1`, a list a row cannot be without left
/// out, an AC table out of order or short of a density, a conditional-tie
/// table with a limit too few or thresholds out of order.
///
/// Oracle: construct-from-answer, as above: each deck differs from a legal
/// row (compiled first) in the one value the kind's documentation forbids,
/// so the error is known before anything runs.
#[test]
fn every_erc_value_check_refuses_its_one_broken_value() {
    const PATH: &str = "esd_path(a; clamps: [\"nfet\"], current: 1330mA, clamp_resistance: 1ohm, \
        max_resistance: 2ohm, clamp_it2: 9.25mA/um, max_density: 1mA/um, max_current_per_cut: 10mA, \
        max_voltage: 5V, min_width: 7nm, clamp_voltage: 700mV)";
    const CROSS: &str =
        "esd_cross_domain(; diodes: [\"nfet\"], local: [\"nfet\"], resistors: [\"nfet\"], \
        min_series: 100ohm, max_ground_resistance: 2ohm, coupling_resistance: 1ohm)";
    const PIN_PAIR: &str =
        "esd_pin_pair(a; clamps: [\"nfet\"], current: 1330mA, clamp_resistance: 1ohm, \
        max_resistance: 5ohm)";
    const RMS: &str = "em_rms(a; frequency: [100MHz, 300MHz], width: [500nm, 1500nm], \
        density: [[1mA/um, 2mA/um], [3mA/um, 4mA/um]], max_current_per_cut: 1mA)";
    const THERMAL: &str = "em_thermal(a; max_density: 10mA/um, max_current_per_cut: 1mA, \
        blech_limit: 1nA, reference_temperature: 125C, activation_energy: 0.9eV, current_exponent: 2, \
        thermal_conductivity: 0.05W/mK, spreading: 0.88, sigma: 0.5, limit_failure: 10%, max_failure: 20%)";
    const GUARD: &str =
        "guard_ring(a, b; max_space: 15um, min_width: 2um, pad: a, near: b, within: 50um, clear: none)";
    const TIE: &str = "conditional_tie(a, b, a, b; within: 50um, spacing: [1um, 2um], \
        max_distance: [15um, 30um, 50um])";
    const SPACE: &str = "voltage_space(a; voltage: [0V, 3.3V, 5V], space: [140nm, 300nm, 600nm])";
    const RELIABILITY: &str = "reliability(; required_lifetime: 1000h, reference_lifetime: 1000h, \
        reference_stress: 1.8V, stress_exponent: 2, reference_temperature: 378K, \
        activation_energy: 0.9eV, max_abs_voltage: 1.8V, duty_cycle: 0.5)";
    const LATCHUP: &str = "esd_latchup(a, b; min_guard_ring_width: 10nm, max_tap_distance: 20nm, \
        clamps: [\"nfet\"])";
    const VICTIM: &str =
        "latchup_victim(a, b, a; within: 15um, max_distance: 2um, pad: a, bias: none, \
        forward: none)";
    const CLAMP_R: &str = "esd_clamp_resistance(a; clamps: [\"nfet\"], max_resistance: 1ohm)";
    const PEAK: &str = "em_peak(a; frequency: [1GHz], width: [0nm], density: [[6.1mA/um]], \
        max_current_per_cut: 100uA)";
    const NO_LIMIT: &str = "esd_path(a; clamps: [\"nfet\"], current: 1mA, clamp_resistance: 1ohm, \
        max_resistance: none, clamp_it2: none, max_density: none, max_current_per_cut: none, \
        max_voltage: none, min_width: 7nm, clamp_voltage: none)";
    let antenna = format!("antenna_electrical(a, b; {ANTENNA_ELECTRICAL})");
    let r = || "r".to_owned();
    let zero = |param: &str| ErcError::NonPositiveLimit {
        rule: r(),
        limit: param.to_owned(),
    };
    let missing = |param: &'static str| ErcError::MissingParam { rule: r(), param };
    let fraction = |param: &'static str| ErcError::NotAFraction { rule: r(), param };
    let table = |why: &'static str| ErcError::BadTable { rule: r(), why };
    let wrong = |param: &'static str| ErcError::WrongParamType { rule: r(), param };
    let ac_order = table("an AC current table's frequencies and widths rise strictly");
    let ac_shape = table("an AC current table has one density per frequency and width");
    let rising = table("a voltage table's voltages start at 0 V or more and rise strictly");
    let falling = table("a voltage table's spaces never fall as the voltage rises");
    // (a legal row, the text to replace in it, its replacement, the error)
    let cases: Vec<(&str, &str, &str, ErcError)> = vec![
        (
            "well_bias(; pmos: none, nmos: [\"nfet\"])",
            "[\"nfet\"]",
            "none",
            missing("pmos"),
        ),
        (PATH, "current: 1330mA", "current: 0mA", zero("current")),
        (
            PATH,
            "clamp_resistance: 1ohm",
            "clamp_resistance: 0ohm",
            zero("clamp_resistance"),
        ),
        (
            PATH,
            "max_resistance: 2ohm",
            "max_resistance: 0ohm",
            zero("max_resistance"),
        ),
        (PATH, "9.25mA/um", "0mA/um", zero("clamp_it2")),
        (
            PATH,
            "max_density: 1mA/um",
            "max_density: 0mA/um",
            zero("max_density"),
        ),
        (
            PATH,
            "max_current_per_cut: 10mA",
            "max_current_per_cut: 0mA",
            zero("max_current_per_cut"),
        ),
        (
            PATH,
            "max_voltage: 5V",
            "max_voltage: 0V",
            zero("max_voltage"),
        ),
        (PATH, "min_width: 7nm", "min_width: 0nm", zero("min_width")),
        (
            PATH,
            "clamp_voltage: 700mV",
            "clamp_voltage: 0mV",
            zero("clamp_voltage"),
        ),
        (
            NO_LIMIT,
            "min_width: 7nm",
            "min_width: none",
            missing("max_resistance"),
        ),
        (
            CROSS,
            "min_series: 100ohm",
            "min_series: 0ohm",
            zero("min_series"),
        ),
        (
            CROSS,
            "max_ground_resistance: 2ohm",
            "max_ground_resistance: 0ohm",
            zero("max_ground_resistance"),
        ),
        (
            CROSS,
            "coupling_resistance: 1ohm",
            "coupling_resistance: 0ohm",
            zero("coupling_resistance"),
        ),
        (
            CROSS,
            "resistors: [\"nfet\"]",
            "resistors: none",
            missing("resistor"),
        ),
        (
            CROSS,
            "coupling_resistance: 1ohm",
            "coupling_resistance: none",
            missing("coupling_resistance"),
        ),
        (
            CROSS,
            "max_ground_resistance: 2ohm",
            "max_ground_resistance: none",
            missing("max_ground_resistance"),
        ),
        (PIN_PAIR, "current: 1330mA", "current: 0mA", zero("current")),
        (
            PIN_PAIR,
            "clamp_resistance: 1ohm",
            "clamp_resistance: 0ohm",
            zero("clamp_resistance"),
        ),
        (
            PIN_PAIR,
            "max_resistance: 5ohm",
            "max_resistance: 0ohm",
            zero("max_resistance"),
        ),
        (CLAMP_R, "1ohm", "0ohm", zero("max_resistance")),
        (
            "esd_parasitic(a, b; min_spacing: 5um)",
            "5um",
            "0um",
            zero("min_spacing"),
        ),
        (LATCHUP, "10nm", "0nm", zero("min_guard_ring_width")),
        (GUARD, "15um", "0um", zero("max_space")),
        (GUARD, "2um", "0um", zero("min_width")),
        (GUARD, "50um", "0um", zero("within")),
        (TIE, "within: 50um", "within: 0um", zero("within")),
        (TIE, "[1um, 2um]", "[0um, 2um]", zero("spacing")),
        (TIE, "50um]", "0um]", zero("max_distance")),
        (
            TIE,
            "[15um, 30um, 50um]",
            "[15um, 30um]",
            wrong("max_distance"),
        ),
        (TIE, "[1um, 2um]", "[2um, 2um]", wrong("max_distance")),
        (VICTIM, "15um", "0um", zero("within")),
        (VICTIM, "2um", "0um", zero("max_distance")),
        ("fanout(; max: 2)", "2", "0", zero("max_gates")),
        ("hv_tag(a, b; voltage: 3V)", "3V", "0V", zero("voltage")),
        (
            "dielectric_field(a; max_field: 10V/um)",
            "10V/um",
            "0V/um",
            zero("max_field"),
        ),
        (
            RELIABILITY,
            "reference_lifetime: 1000h",
            "reference_lifetime: 0h",
            zero("reference_lifetime_hours"),
        ),
        (
            RELIABILITY,
            "1.8V, stress",
            "0V, stress",
            zero("reference_stress"),
        ),
        (RELIABILITY, "378K", "0K", zero("reference_temperature")),
        (RELIABILITY, "0.9eV", "0eV", zero("activation_energy_ev")),
        (
            RELIABILITY,
            "max_abs_voltage: 1.8V",
            "max_abs_voltage: 0V",
            zero("max_abs_voltage"),
        ),
        (RMS, "100MHz", "0MHz", zero("frequency")),
        (RMS, "[[1mA/um", "[[0mA/um", zero("density")),
        (
            RMS,
            "max_current_per_cut: 1mA",
            "max_current_per_cut: 0mA",
            zero("max_current_per_cut"),
        ),
        (RMS, "300MHz", "100MHz", ac_order.clone()),
        (RMS, "1500nm", "500nm", ac_order.clone()),
        (RMS, ", [3mA/um, 4mA/um]", "", ac_shape),
        (PEAK, "[1GHz]", "[2GHz, 1GHz]", ac_order),
        (THERMAL, "0.05W/mK", "0W/mK", zero("thermal_conductivity")),
        (THERMAL, "sigma: 0.5", "sigma: 0", zero("sigma")),
        (
            THERMAL,
            "spreading: 0.88",
            "spreading: -1",
            zero("heat_spreading"),
        ),
        (
            THERMAL,
            "limit_failure: 10%",
            "limit_failure: 0%",
            zero("limit_failure"),
        ),
        (
            THERMAL,
            "max_failure: 20%",
            "max_failure: 0%",
            zero("max_failure"),
        ),
        (
            THERMAL,
            "limit_failure: 10%",
            "limit_failure: 100%",
            fraction("limit_failure"),
        ),
        (
            THERMAL,
            "max_density: 10mA/um",
            "max_density: 0mA/um",
            zero("max_density"),
        ),
        (
            THERMAL,
            "max_current_per_cut: 1mA",
            "max_current_per_cut: 0mA",
            zero("max_current_per_cut"),
        ),
        (
            THERMAL,
            "blech_limit: 1nA",
            "blech_limit: 0nA",
            zero("blech_limit"),
        ),
        (THERMAL, "125C", "-273.15C", zero("reference_temperature")),
        (THERMAL, "0.9eV", "0eV", zero("activation_energy_ev")),
        (
            THERMAL,
            "current_exponent: 2",
            "current_exponent: 0",
            zero("current_exponent"),
        ),
        (SPACE, "[0V, 3.3V", "[-1V, 3.3V", rising.clone()),
        (SPACE, "3.3V, 5V", "5V, 5V", rising),
        (SPACE, "140nm", "0nm", zero("space")),
        (SPACE, "300nm, 600nm", "600nm, 300nm", falling),
        (
            &antenna,
            "area_minus_diode: 0",
            "area_minus_diode: -1",
            zero("area_minus_diode"),
        ),
        (
            &antenna,
            "gate_plus_diode: 0",
            "gate_plus_diode: -1",
            zero("gate_plus_diode"),
        ),
    ];
    let deck = |text: &str| format!("{HEADER}rule r {text}\n");
    let mut failures = Vec::new();
    for (legal, from, to, want) in cases {
        if let Err(why) = compile(&deck(legal), grid(), &mut StrTable::default()) {
            failures.push(format!("legal {legal}: {why}"));
            continue;
        }
        assert!(legal.contains(from), "{legal} holds {from}");
        let broken = legal.replacen(from, to, 1);
        match compile(&deck(&broken), grid(), &mut StrTable::default()) {
            Err(CompileError::Erc(got)) if got == want => {}
            other => failures.push(format!("{broken}: want {want:?}, got {other:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The value checks a deck's text cannot reach (the parser refuses an empty
/// model list and a fraction over one first) still hold a table built or
/// edited in code: each row, legal as compiled, refused once one column is
/// broken, by its own id and the parameter its kind documents.
///
/// Oracle: construct-from-answer: every row of the deck compiles, then one
/// row's model, clamp or diode list is emptied or one fraction set to 1.5,
/// which the kind's documentation forbids.
#[test]
fn erc_validation_refuses_a_table_broken_in_code() {
    let text = format!(
        "{HEADER}\
rule gc esd_ground_coupling(; diodes: [\"nfet\"])
rule xd esd_cross_domain(; diodes: [\"nfet\"], local: none, resistors: none, min_series: none, \
max_ground_resistance: none, coupling_resistance: none)
rule ps power_switch(; models: [\"nfet\"])
rule pp esd_pin_pair(a; clamps: [\"nfet\"], current: 1330mA, clamp_resistance: 1ohm, max_resistance: 5ohm)
rule cr esd_clamp_resistance(a; clamps: [\"nfet\"], max_resistance: 1ohm)
rule et esd_topological(a; clamps: [\"nfet\"])
rule ex esd_exposed(a; clamps: [\"nfet\"], resistors: none, rated: [\"nfet\"], min_series: none)
rule fd forward_diode(a; models: [\"nfet\"])
rule el esd_latchup(a, b; min_guard_ring_width: 10nm, max_tap_distance: 20nm, clamps: [\"nfet\"])
rule go gate_oxide(; models: [\"nfet\"], max: 1.8V)
rule ds drain_source(; models: [\"nfet\"], max: 1.8V)
rule ta tie_area(a, b, a; min_ratio: 3%)
rule rl reliability(; required_lifetime: 1000h, reference_lifetime: 1000h, reference_stress: 1.8V, \
stress_exponent: 2, reference_temperature: 378K, activation_energy: 0.9eV, max_abs_voltage: 1.8V, \
duty_cycle: 0.5)
rule th em_thermal(a; max_density: 10mA/um, max_current_per_cut: 1mA, blech_limit: 1nA, \
reference_temperature: 125C, activation_energy: 0.9eV, current_exponent: 2, \
thermal_conductivity: 0.05W/mK, spreading: 0.88, sigma: 0.5, limit_failure: 10%, max_failure: 20%)
"
    );
    let mut strings = StrTable::default();
    let deck = compile(&text, grid(), &mut strings).expect("every row is legal");
    let legal = deck.erc;
    assert_eq!(legal.validate(&strings), Ok(()));
    // Each table holds one row, so `start[1] = 0` empties its CSR span.
    let missing = |rule: &str, param: &'static str| ErcError::MissingParam {
        rule: rule.to_owned(),
        param,
    };
    let fraction = |rule: &str, param: &'static str| ErcError::NotAFraction {
        rule: rule.to_owned(),
        param,
    };
    type Break = fn(&mut ErcRules);
    let cases: Vec<(Break, ErcError)> = vec![
        (
            |s| s.esd_ground_coupling.diode_start[1] = 0,
            missing("gc", "diode"),
        ),
        (
            |s| s.esd_cross_domain.diode_start[1] = 0,
            missing("xd", "diode"),
        ),
        (
            |s| s.power_switch.model_start[1] = 0,
            missing("ps", "model"),
        ),
        (
            |s| s.esd_pin_pair.clamp_start[1] = 0,
            missing("pp", "clamp"),
        ),
        (
            |s| s.esd_clamp_resistance.clamp_start[1] = 0,
            missing("cr", "clamp"),
        ),
        (
            |s| s.esd_topological.clamp_start[1] = 0,
            missing("et", "clamp"),
        ),
        (|s| s.esd_exposed.clamp_start[1] = 0, missing("ex", "clamp")),
        (
            |s| s.forward_diode.model_start[1] = 0,
            missing("fd", "model"),
        ),
        (|s| s.esd_latchup.clamp_start[1] = 0, missing("el", "clamp")),
        (|s| s.gate_oxide.model_start[1] = 0, missing("go", "model")),
        (
            |s| s.drain_source.model_start[1] = 0,
            missing("ds", "model"),
        ),
        (
            |s| s.tie_area.min_ratio[0] = 1.5,
            fraction("ta", "min_ratio"),
        ),
        (
            |s| s.tie_area.min_ratio[0] = -0.5,
            fraction("ta", "min_ratio"),
        ),
        (
            |s| s.reliability.duty_cycle[0] = 1.5,
            fraction("rl", "duty_cycle"),
        ),
        (
            |s| s.em_thermal.max_failure[0] = 1.5,
            fraction("th", "max_failure"),
        ),
        (
            |s| s.em_thermal.limit_failure[0] = f64::NAN,
            ErcError::WrongParamType {
                rule: "th".to_owned(),
                param: "limit_failure",
            },
        ),
    ];
    for (k, (break_it, want)) in cases.into_iter().enumerate() {
        let mut set = legal.clone();
        break_it(&mut set);
        assert_eq!(set.validate(&strings), Err(want), "case {k}");
    }
}
