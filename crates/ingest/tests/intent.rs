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

/// Oracle: construct-from-answer. Each of the four limits, stated as zero,
/// is refused with a message naming that limit's key; a current budget is not
/// "an IR-drop limit" and not a voltage.
#[test]
fn a_bad_limit_names_the_limit_it_is() {
    for key in [
        "max_drop_mv",
        "max_drop_fraction",
        "max_overvoltage_mv",
        "budget_current_ua",
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
