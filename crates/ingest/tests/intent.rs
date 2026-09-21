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
    assert_eq!(intent.domain_count(), 0);
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

/// Oracle: law. `limits` is documented as returning the default for any
/// undeclared net, so it is total: no net id, however it was obtained, may
/// panic or produce a limit. An intent holding no nets is the sharpest case,
/// because a lookup implemented as an unguarded binary search over an empty
/// column is where that goes wrong.
#[test]
fn limits_are_total_over_every_net_id_even_with_nothing_declared() {
    let mut strings = StrTable::default();
    let intent = DesignIntent::default();
    for name in ["a", "b", "net_0", "VDD!", "x"] {
        let net = strings.intern(name);
        let limits = intent.limits(net);
        assert!(
            limits.max_drop.is_none() && limits.budget_current_ua.is_none(),
            "{name} was undeclared but came back with limits"
        );
        assert!(intent.supply_role(net).is_none());
    }
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
