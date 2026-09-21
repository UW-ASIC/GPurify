//! The JSON report: what it must contain, what order it must contain it in,
//! and where the run metadata is allowed to live.
//!
//! The key names of the schema are not asserted anywhere here. Those are the
//! Implementation-Phase's to choose. What is asserted is everything the module
//! already commits to in prose: the output is JSON, it carries both halves of
//! the report, it does not reorder the violation table, its floats go through
//! `format_f64`, and everything that varies between two runs is confined to
//! the [`Header`](gpurify_export::Header).

mod fixture;

use fixture::World;
use gpurify_export::json;
use gpurify_check::report::{Measurement, Outcome};
use gpurify_testgen::{dbu, point};
use serde_json::Value;

fn report_of(world: &World) -> String {
    let mut out = String::new();
    json::write_report(&world.report(), &mut out).expect("the report is writable");
    out
}

fn summary_of(world: &World) -> String {
    let mut out = String::new();
    json::write_summary(&world.runs, &world.strings, &mut out).expect("the summary is writable");
    out
}

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("not JSON: {error}\n{text}"))
}

fn formatted(value: f64) -> String {
    let mut out = String::new();
    json::format_f64(value, &mut out);
    out
}

/// Oracle: law. A writer named `write_report` in a module named `json` that
/// emitted something a JSON parser rejects has failed at the only thing it
/// claims to do, whatever else it got right.
#[test]
fn the_report_and_the_summary_are_both_valid_json_objects() {
    let world = World::named();
    for (what, text) in [
        ("report", report_of(&world)),
        ("summary", summary_of(&world)),
    ] {
        let value = parsed(&text);
        assert!(
            value.is_object(),
            "the {what} is JSON but not an object, so it has no place to put a header: {value}"
        );
    }
}

/// Oracle: construct-from-answer. The rule ids and the shape counts are stated
/// by the fixture before anything runs, and the report is the only place a
/// `StrId` becomes readable again — a report that dropped either would be a
/// report nobody can act on.
#[test]
fn the_report_names_every_rule_that_ran_and_what_it_examined() {
    let world = World::named();
    let text = report_of(&world);

    for name in ["m1.width", "m1.density", "m1.antenna"] {
        assert!(
            text.contains(name),
            "the report does not name rule {name}:\n{text}"
        );
    }
    for examined in ["1234", "5678"] {
        assert!(
            text.contains(examined),
            "the report does not carry the {examined} shapes a rule examined:\n{text}"
        );
    }
}

/// Oracle: construct-from-answer, and the whole reason `RuleRun` exists.
///
/// Half the previous suite's DRC cases asserted only that nothing was found, so
/// a rule that never executed passed all of them. A clean report has to carry
/// the difference: the rule that was skipped for want of design intent must be
/// distinguishable in the text from the two that ran and examined shapes.
#[test]
fn a_clean_report_still_says_which_rules_ran_and_which_were_skipped() {
    let mut world = World::named();
    world.violations = fixture::table_of(&[]);
    let text = report_of(&world);

    assert!(
        text.contains("m1.antenna"),
        "the skipped rule is absent, so an empty violation list is unreadable:\n{text}"
    );
    assert!(
        text.contains("1234") && text.contains("5678"),
        "the examined counts are absent, so 'clean' cannot be told from 'nothing ran':\n{text}"
    );
    // And the outcome is in the text, not merely the count: a rule that refused
    // an input it could not represent exactly must not read like one that ran.
    let mut refused = World::named();
    refused.violations = fixture::table_of(&[]);
    refused.runs[0].outcome = Outcome::Refused;
    assert_ne!(
        text,
        report_of(&refused),
        "a rule that refused reads the same as one that ran clean"
    );
}

/// Oracle: construct-from-answer. `format_f64` is the single float-to-bytes
/// site in this crate, so the text it produces for the measured density is the
/// text the report must contain. A writer that formatted the number its own way
/// is exactly the drift the centralisation exists to prevent.
#[test]
fn the_report_writes_its_floats_through_format_f64() {
    let world = World::named();
    let text = report_of(&world);
    let expected = formatted(fixture::MEASURED_RATIO);
    assert!(
        text.contains(&expected),
        "the measured ratio {} should appear as {expected:?}:\n{text}",
        fixture::MEASURED_RATIO
    );
}

/// Oracle: construct-from-answer, and the one the previous suite never had. Its
/// ERC, LVS and PEX cases compared counts and statuses only, so a rule flagging
/// the wrong shape at the wrong coordinate with the wrong measurement passed. A
/// report that carries neither the coordinate nor the measurement is that
/// failure made permanent, because nothing downstream can recover them.
///
/// The digits are readable because of the grid. The fixture's `Grid` is 1000
/// database units per micrometre, so one `Dbu` is exactly one nanometre — and
/// `Measurement` formats layout units "in nanometres against the run's grid".
/// The nanometre value of `Dbu(n)` on this grid is `n`, so whether the report
/// serialises a raw database unit or a formatted nanometre, the digits are the
/// same ones. The values are deliberately unlike anything else in the world so
/// a substring match cannot succeed by accident.
#[test]
fn the_report_carries_the_coordinate_and_the_measurement_of_every_violation() {
    let mut world = World::named();
    let mut rows = world.rows;
    rows[1].at = point(31_337, 42_424);
    rows[1].measured = Measurement::Length(dbu(7_654_321));
    rows[1].limit = Measurement::Length(dbu(8_765_432));
    world.violations = fixture::table_of(&rows);

    let text = report_of(&world);
    for (what, digits) in [
        ("the x coordinate", "31337"),
        ("the y coordinate", "42424"),
        ("the measured length", "7654321"),
        ("the limit it was measured against", "8765432"),
    ] {
        assert!(
            text.contains(digits),
            "the report does not carry {what}, {digits}:\n{text}"
        );
    }
}

/// Oracle: construct-from-answer. The module states that it iterates the table
/// as it stands and does not sort — "if the order is wrong it is wrong at the
/// source". Reversing the two rows must therefore reverse them in the output,
/// and a writer that sorted would produce the same bytes from both.
#[test]
fn the_report_preserves_the_violation_table_order_and_does_not_sort() {
    let world = World::named();

    let forward = report_of(&world);
    let mut reversed_world = World::named();
    let mut rows = world.rows;
    rows.reverse();
    reversed_world.violations = fixture::table_of(&rows);
    let reversed = report_of(&reversed_world);

    assert_ne!(
        forward, reversed,
        "reversing the table changed nothing, so the writer sorted it"
    );

    let forward_order = order_of(&forward);
    let reversed_order = order_of(&reversed);
    assert_ne!(
        forward_order, reversed_order,
        "the two rules appear in the same order either way, so the writer sorted them"
    );
}

/// Which of the two rules is mentioned first in a report.
///
/// The fixture's rows carry one rule each, so the order of the first mention of
/// each name is the order of the rows.
fn order_of(text: &str) -> (usize, usize) {
    let density = text
        .find("m1.density")
        .unwrap_or_else(|| panic!("the density rule is missing:\n{text}"));
    let width = text
        .find("m1.width")
        .unwrap_or_else(|| panic!("the width rule is missing:\n{text}"));
    (density, width)
}

/// Oracle: law. "Everything that varies between two otherwise-identical runs
/// lives here and nowhere else" is a checkable claim, not a comment: changing
/// one header field may move one top-level value in the JSON and no other. That
/// is what makes a header "a region a diff can skip".
#[test]
fn changing_one_header_field_moves_nothing_outside_the_header() {
    let world = World::named();
    let base = parsed(&report_of(&world));

    for (what, header) in [
        ("timestamp", fixture::header(Some("2031-07-04T12:00:00Z"))),
        ("timestamp removal", fixture::header(None)),
        ("deck path", {
            let mut other = fixture::header(Some("2020-01-01T00:00:00Z"));
            other.deck_path = "decks/other.json".to_owned();
            other
        }),
    ] {
        let mut altered = World::named();
        altered.header = header;
        let other = parsed(&report_of(&altered));

        let differing = differing_keys(&base, &other);
        assert_eq!(
            differing.len(),
            1,
            "changing the {what} moved {differing:?}; it must move the header \
             and nothing else, and a field that moves nothing was dropped"
        );
    }
}

/// The top-level keys whose values differ between two JSON objects.
fn differing_keys(left: &Value, right: &Value) -> Vec<String> {
    let (left, right) = (
        left.as_object().expect("a report is a JSON object"),
        right.as_object().expect("a report is a JSON object"),
    );
    let mut keys: Vec<String> = left
        .iter()
        .filter(|(key, value)| right.get(key.as_str()) != Some(value))
        .map(|(key, _)| key.clone())
        .collect();
    keys.extend(
        right
            .keys()
            .filter(|key| !left.contains_key(key.as_str()))
            .cloned(),
    );
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Oracle: construct-from-answer. The timestamp reaches the output through the
/// header field and through nothing else: two values of it produce two reports,
/// and `None` produces a third. A writer that ignored the field would collapse
/// all three.
#[test]
fn the_timestamp_reaches_the_report_only_through_the_header() {
    let mut with_one = World::named();
    with_one.header = fixture::header(Some("2020-01-01T00:00:00Z"));
    let mut with_another = World::named();
    with_another.header = fixture::header(Some("2031-07-04T12:00:00Z"));
    let mut without = World::named();
    without.header = fixture::header(None);

    let one = report_of(&with_one);
    let another = report_of(&with_another);
    let none = report_of(&without);

    assert!(
        one.contains("2020-01-01T00:00:00Z"),
        "the timestamp handed in is not in the report:\n{one}"
    );
    assert_ne!(one, another, "two timestamps produced one report");
    assert_ne!(one, none, "omitting the timestamp changed nothing");
    assert!(
        !none.contains("2020-01-01T00:00:00Z") && !none.contains("2031-07-04T12:00:00Z"),
        "a report with no timestamp carries one anyway:\n{none}"
    );
}

/// Oracle: construct-from-answer. The summary is "the answer to did this run
/// actually check anything", so it has to carry the rule that was skipped as
/// well as the two that ran, and it must not be a re-encoding of the violation
/// table.
#[test]
fn the_summary_carries_every_rule_record_and_no_violations() {
    let world = World::named();
    let text = summary_of(&world);

    for name in ["m1.width", "m1.density", "m1.antenna"] {
        assert!(
            text.contains(name),
            "the summary does not name rule {name}:\n{text}"
        );
    }
    assert!(
        text.contains("1234") && text.contains("5678"),
        "the summary does not carry the examined counts:\n{text}"
    );
    let measured = formatted(fixture::MEASURED_RATIO);
    assert!(
        !text.contains(&measured),
        "the summary carries the measured value {measured:?} from a violation, \
         so it is a whole report wearing a smaller name:\n{text}"
    );
}

/// Oracle: construct-from-answer. The summary iterates the slice it is handed,
/// so reordering the slice reorders the summary. Same claim as for violations,
/// and the same reason: sorting here would hide a source that produced the
/// wrong order.
#[test]
fn the_summary_preserves_the_order_of_the_runs_it_was_handed() {
    let world = World::named();
    let forward = summary_of(&world);

    let mut backward_world = World::named();
    backward_world.runs.reverse();
    let backward = summary_of(&backward_world);

    let forward_first = forward.find("m1.width").expect("the width rule is named");
    let forward_last = forward
        .find("m1.antenna")
        .expect("the antenna rule is named");
    let backward_first = backward.find("m1.width").expect("the width rule is named");
    let backward_last = backward
        .find("m1.antenna")
        .expect("the antenna rule is named");

    assert!(forward_first < forward_last, "the runs came out reordered");
    assert!(
        backward_first > backward_last,
        "reversing the runs did not reverse the summary, so the writer sorted them"
    );
}
