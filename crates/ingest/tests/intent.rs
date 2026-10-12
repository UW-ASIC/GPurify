//! Design intent, and what its absence has to look like.
//!
//! Six ERC rules need facts no PDK can supply. A run without an intent file is
//! legitimate, and those rules then report themselves *skipped*. That verdict
//! is driven entirely by `DesignIntent::is_empty`, so the accessors on an
//! absent intent have to say "not declared" rather than return a plausible
//! default: a `max_drop` of `None` means unchecked, and a `max_drop` of zero
//! would mean every net fails.

use gpurify_geom::StrTable;
use gpurify_ingest::intent::DesignIntent;
use gpurify_ingest::IntentError;

/// Oracle: construct-from-answer. An absent intent is the input; the correct
/// output is known because "nothing was declared" has exactly one answer for
/// every accessor. Each one is checked, because it is the accessors and not
/// `is_empty` that an ERC rule reads once it decides to run.
#[test]
fn an_absent_intent_declares_nothing_and_every_accessor_says_so() {
    let mut strings = StrTable::default();
    let vdd = strings.intern("VDD");
    let vss = strings.intern("VSS");

    let intent = DesignIntent::default();

    assert!(
        intent.is_empty(),
        "an intent nobody wrote reported itself non-empty, so the six rules \
         that depend on one would run against nothing and report clean"
    );
    assert!(
        intent.supply_role(vdd).is_none(),
        "a net nobody declared came back as a supply"
    );
    assert!(intent.supply_role(vss).is_none());

    let limits = intent.limits(vdd);
    assert!(
        limits.max_drop.is_none(),
        "an undeclared net has no IR-drop limit; `None` is unchecked, and any \
         value here would be a limit nobody stated"
    );
    assert!(limits.max_drop_fraction.is_none());
    assert!(limits.max_overvoltage.is_none());
    assert!(limits.budget_current_ua.is_none());
}

/// Oracle: construct-from-answer. An intent file that cannot be read is an
/// error, never an empty intent. The two are not interchangeable even though
/// both leave the six rules unable to run: a missing file is a run the operator
/// chose, an unreadable one is a run that should stop.
#[test]
fn an_intent_file_that_cannot_be_opened_is_an_error_rather_than_an_empty_intent() {
    let mut strings = StrTable::default();
    let missing = std::path::Path::new("/nonexistent/gpurify/no-such-intent.json");

    match gpurify_ingest::intent::read_intent(missing, &mut strings) {
        Err(IntentError::Io(_)) => {}
        other => panic!("an unreadable intent file produced {other:?} rather than IntentError::Io"),
    }
}

/// Oracle: construct-from-answer. Each of the limits, stated as zero,
/// is refused with a message naming that limit's key; a current budget is not
/// "an IR-drop limit" and not a voltage.
#[test]
fn a_bad_limit_names_the_limit_it_is() {
    for key in [
        "max_drop_mv",
        "max_drop_fraction",
        "max_overvoltage_mv",
        "budget_current_ua",
        "rms_current_ua",
        "peak_current_ua",
    ] {
        let source = format!(
            r#"{{"domains":{{"core":{{"voltage_mv":1800}}}},
            "supplies":[{{"net":"VDD","domain":"core","role":"power"}}],
            "limits":[{{"net":"VDD","{key}":0}}]}}"#
        );
        let error = gpurify_ingest::intent::parse_intent(&source, &mut StrTable::default())
            .expect_err("a zero limit is refused");
        assert_eq!(
            error.to_string(),
            format!("net VDD: {key} is not a positive finite number")
        );
    }
}

/// Oracle: construct-from-answer. A supply listed twice in the same domain is
/// refused, and the message says what is wrong: the repeat, not two domains.
#[test]
fn a_supply_listed_twice_in_one_domain_is_named_as_a_repeat() {
    let source = r#"{"domains":{"core":{"voltage_mv":1800}},
        "supplies":[{"net":"VDD","domain":"core","role":"power"},
                    {"net":"VDD","domain":"core","role":"power"}],
        "limits":[]}"#;
    let error = gpurify_ingest::intent::parse_intent(source, &mut StrTable::default())
        .expect_err("a repeated supply is refused");
    assert_eq!(
        error.to_string(),
        "net VDD is listed more than once in supplies"
    );
}

/// Oracle: construct-from-answer, on the schema in docs/usage.md (Power
/// states). Two states read back in file order with their switched-off
/// supplies and held inputs in mV; a file of states alone is not empty; a
/// state repeated, one turning off a net no supply declares, and an input
/// held twice are each refused by name.
#[test]
fn power_states_read_back_and_a_malformed_one_is_refused() {
    let head = r#"{"domains":{"core":{"voltage_mv":1800},"sw":{"voltage_mv":1800}},
        "supplies":[{"net":"VDD","domain":"core","role":"power"},
                    {"net":"VDD_SW","domain":"sw","role":"power"},
                    {"net":"VSS","domain":"core","role":"ground"}],"#;
    let mut strings = StrTable::default();
    let intent = gpurify_ingest::intent::parse_intent(
        &format!(
            r#"{head}"states":[{{"name":"sleep","off":["VDD_SW"]}},
            {{"name":"disable","inputs":[{{"net":"EN","voltage_mv":0}},{{"net":"SEL","voltage_mv":1800}}]}}]}}"#
        ),
        &mut strings,
    )
    .expect("two well-formed states");
    let states = intent.states();
    assert_eq!(states.len(), 2);
    assert_eq!(strings.resolve(states[0].name), "sleep");
    assert_eq!(states[0].off, [strings.get("VDD_SW").expect("interned")]);
    assert!(states[0].inputs.is_empty());
    assert_eq!(strings.resolve(states[1].name), "disable");
    let held: Vec<(&str, f64)> = states[1]
        .inputs
        .iter()
        .map(|&(net, mv)| (strings.resolve(net), mv.raw()))
        .collect();
    assert_eq!(held, [("EN", 0.0), ("SEL", 1800.0)]);

    let only_states = gpurify_ingest::intent::parse_intent(
        r#"{"states":[{"name":"idle"}]}"#,
        &mut StrTable::default(),
    )
    .expect("a state with nothing switched is legal");
    assert!(!only_states.is_empty());

    for (states, said) in [
        (
            r#"[{"name":"sleep"},{"name":"sleep"}]"#,
            "power state sleep is declared twice",
        ),
        (
            r#"[{"name":"sleep","off":["EN"]}]"#,
            "power state sleep turns off EN, which no supply declares",
        ),
        (
            r#"[{"name":"d","inputs":[{"net":"EN","voltage_mv":0},{"net":"EN","voltage_mv":1}]}]"#,
            "power state d: input EN is held twice",
        ),
    ] {
        let error = gpurify_ingest::intent::parse_intent(
            &format!(r#"{head}"states":{states}}}"#),
            &mut StrTable::default(),
        )
        .expect_err("a malformed state is refused");
        assert_eq!(error.to_string(), format!("malformed intent file: {said}"));
    }
}

/// The `dynamic` entry of the `docs/usage.md` example, on VDD, with `budget`
/// beside it and `extra` spliced into it.
fn dynamic_intent(budget: &str, extra: &str) -> String {
    format!(
        r#"{{"temperature_c":105,"domains":{{"core":{{"voltage_mv":1800}}}},
        "supplies":[{{"net":"VDD","domain":"core","role":"power"}}],
        "limits":[{{"net":"VDD"{budget},"dynamic":{{"max_drop_mv":180,
        "toggle_rate":0.2,"clock_period_ps":2000,"rise_time_ps":100{extra}}}}}]}}"#
    )
}

/// Oracle: round trip against the schema `docs/usage.md` documents: the
/// junction temperature reads back absolute (105 °C is 378.15 K) and every
/// `dynamic` number lands in its field, an absent `decap_pf` as zero.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "a value read back is the value written, bit for bit"
)]
fn a_dynamic_entry_and_a_temperature_read_back_as_written() {
    let mut strings = StrTable::default();
    let intent = gpurify_ingest::intent::parse_intent(
        &dynamic_intent(r#","budget_current_ua":2000"#, ""),
        &mut strings,
    )
    .expect("the usage.md example parses");
    assert_eq!(
        intent.temperature().map(gpurify_geom::Qty::raw),
        Some(105.0 + 273.15)
    );
    let limits = intent.limits(strings.intern("VDD"));
    let dynamic = limits.dynamic.expect("VDD states a dynamic entry");
    assert_eq!(dynamic.max_drop.raw(), 180.0);
    assert_eq!(dynamic.toggle_rate, 0.2);
    assert_eq!(dynamic.clock_period_ps, 2000.0);
    assert_eq!(dynamic.rise_time_ps, 100.0);
    assert_eq!(dynamic.decap_pf, 0.0);
    assert!(DesignIntent::default().temperature().is_none());
}

/// Oracle: construct-from-answer, against `IntentError`'s documented cases: a
/// `dynamic` entry with no budget beside it, a toggle rate above 1, a rise
/// longer than the period, a negative decap, a zero toggle rate, and a
/// temperature below absolute zero are each refused with a message naming
/// what is wrong.
#[test]
fn a_dynamic_entry_that_cannot_be_simulated_is_refused() {
    let budget = r#","budget_current_ua":2000"#;
    for (source, message) in [
        (
            dynamic_intent("", ""),
            "malformed intent file: net VDD: dynamic needs budget_current_ua, the current it switches",
        ),
        (
            dynamic_intent(budget, "").replace("0.2", "1.5"),
            "malformed intent file: net VDD: dynamic toggle_rate is a fraction of cycles, at most 1",
        ),
        (
            dynamic_intent(budget, "").replace(":100", ":3000"),
            "malformed intent file: net VDD: dynamic rise_time_ps is longer than clock_period_ps",
        ),
        (
            dynamic_intent(budget, r#","decap_pf":-1"#),
            "malformed intent file: net VDD: dynamic decap_pf is negative or not finite",
        ),
        (
            dynamic_intent(budget, "").replace("0.2", "0"),
            "net VDD: dynamic.toggle_rate is not a positive finite number",
        ),
        (
            dynamic_intent(budget, "").replace("105", "-300"),
            "malformed intent file: temperature_c is -300, not a temperature above absolute zero",
        ),
    ] {
        let error = gpurify_ingest::intent::parse_intent(&source, &mut StrTable::default())
            .expect_err(message);
        assert_eq!(error.to_string(), message, "{source}");
    }
}
