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
