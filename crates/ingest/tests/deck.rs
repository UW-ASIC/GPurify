//! `RuleTable`'s CSR accessors, and the deck reader's refusal to read what it
//! cannot open.
//!
//! `RuleTable` is the one part of a deck a test can build: its columns are
//! public and it derives `Default`. `LayerTable` is not — every field is
//! private and `read_deck` is its only producer — so the layer-resolution
//! half of a deck is tested from inside the crate instead, and the gap is
//! recorded in `docs/NEED_TESTING.md`.

use gpurify_geom::Grid;
use gpurify_geom::{StrId, StrTable};
use gpurify_ingest::deck::{ParamValue, RuleSpec, RuleTable};
use gpurify_ingest::DeckError;

/// Compare two `ParamValue`. The enum does not derive `PartialEq`, and a float
/// variant should not get a derived one: `Ratio` is compared to a stated
/// tolerance of 1e-12, which is far below any antenna or density limit a deck
/// states and far above the error of parsing one.
fn same_param(left: ParamValue, right: ParamValue) -> bool {
    match (left, right) {
        (ParamValue::Length(a), ParamValue::Length(b)) => a == b,
        (ParamValue::Ratio(a), ParamValue::Ratio(b)) => (a - b).abs() <= 1e-12,
        (ParamValue::Count(a), ParamValue::Count(b)) => a == b,
        (ParamValue::Flag(a), ParamValue::Flag(b)) => a == b,
        (ParamValue::Layer(a), ParamValue::Layer(b)) => a == b,
        _ => false,
    }
}

/// Compare a parameter run against the one the table was built holding, name
/// and value both. Stated as a helper because both accessor tests need an
/// anchor outside themselves: `param` and `params_of` agreeing with each other
/// is worth nothing if both agree on returning nothing.
fn assert_same_params(what: &str, found: &[(StrId, ParamValue)], expected: &[(StrId, ParamValue)]) {
    assert_eq!(
        found.len(),
        expected.len(),
        "{what} read a parameter run of the wrong length, so a neighbouring \
         rule's parameters are inside its range"
    );
    for (&(name, value), &(want_name, want_value)) in found.iter().zip(expected) {
        assert_eq!(name, want_name, "{what}: parameters came back out of order");
        assert!(
            same_param(value, want_value),
            "{what}: {name:?} came back as {value:?} rather than {want_value:?}"
        );
    }
}

/// A rule occupying a stated slice of each side array.
fn spec(id: StrId, kind: StrId, layers: (u32, u32), params: (u32, u32)) -> RuleSpec {
    RuleSpec {
        id,
        kind,
        layer_start: layers.0,
        layer_len: layers.1,
        param_start: params.0,
        param_len: params.1,
    }
}

/// Oracle: construct-from-answer. The side arrays are built holding rules whose
/// ranges are known before anything is read back, so every accessor has an
/// answer stated independently of it. The case that matters is the second rule:
/// a table whose ranges are off by one returns the first rule's tail, which is
/// a well-formed parameter list belonging to another rule.
#[test]
fn each_rule_reads_back_exactly_its_own_slice_of_the_side_arrays() {
    use gpurify_geom::LayerId;
    use gpurify_testgen::dbu;

    let mut strings = StrTable::default();
    let spacing = strings.intern("M1.S.1");
    let width = strings.intern("M1.W.1");
    let kind_spacing = strings.intern("min_spacing");
    let kind_width = strings.intern("min_width");
    let value = strings.intern("value");
    let count = strings.intern("count");
    let absent = strings.intern("a parameter no rule declares");

    let table = RuleTable {
        spec: vec![
            spec(spacing, kind_spacing, (0, 2), (0, 2)),
            spec(width, kind_width, (2, 1), (2, 1)),
        ],
        layer_ref: vec![LayerId(0), LayerId(1), LayerId(0)],
        param: vec![
            (value, ParamValue::Length(dbu(140))),
            (count, ParamValue::Count(2)),
            (value, ParamValue::Length(dbu(90))),
        ],
    };

    assert_eq!(table.layers_of(&table.spec[0]), [LayerId(0), LayerId(1)]);
    assert_eq!(table.layers_of(&table.spec[1]), [LayerId(0)]);
    assert_same_params(
        "the spacing rule",
        table.params_of(&table.spec[0]),
        &[
            (value, ParamValue::Length(dbu(140))),
            (count, ParamValue::Count(2)),
        ],
    );
    assert_same_params(
        "the width rule",
        table.params_of(&table.spec[1]),
        &[(value, ParamValue::Length(dbu(90)))],
    );

    let found = table
        .param(&table.spec[1], value)
        .expect("the width rule declares a value");
    assert!(
        same_param(found, ParamValue::Length(dbu(90))),
        "the width rule's limit came back as {found:?}, which is the spacing \
         rule's 140 dbu limit read through the wrong range"
    );
    assert!(
        table.param(&table.spec[1], count).is_none(),
        "a parameter the second rule does not declare was found in the first \
         rule's range"
    );
    assert!(
        table.param(&table.spec[0], absent).is_none(),
        "an undeclared parameter name resolved to a value"
    );
}

/// Oracle: law. `param` is documented as a linear scan over the two or three
/// entries `params_of` returns, so the two must agree for every rule and every
/// name. Stating it as a law rather than a case is what makes it survive
/// someone replacing the scan with a binary search over a sorted range.
#[test]
fn param_lookup_agrees_with_a_scan_of_the_same_rules_parameters() {
    let mut strings = StrTable::default();
    let names: Vec<StrId> = ["value", "count", "ratio", "enabled"]
        .iter()
        .map(|n| strings.intern(n))
        .collect();
    let rule = strings.intern("R.1");
    let kind = strings.intern("antenna");

    let table = RuleTable {
        spec: vec![spec(rule, kind, (0, 0), (0, 3))],
        layer_ref: Vec::new(),
        param: vec![
            (names[0], ParamValue::Count(7)),
            (names[2], ParamValue::Ratio(400.0)),
            (names[3], ParamValue::Flag(true)),
        ],
    };

    // The anchor. Without it the law below is satisfied by both accessors
    // returning nothing, which is a rule table that runs no rules at all.
    assert_same_params(
        "the antenna rule",
        table.params_of(&table.spec[0]),
        &[
            (names[0], ParamValue::Count(7)),
            (names[2], ParamValue::Ratio(400.0)),
            (names[3], ParamValue::Flag(true)),
        ],
    );

    for &name in &names {
        let scanned = table
            .params_of(&table.spec[0])
            .iter()
            .find(|(n, _)| *n == name)
            .map(|&(_, v)| v);
        match (table.param(&table.spec[0], name), scanned) {
            (None, None) => {}
            (Some(found), Some(expected)) => assert!(
                same_param(found, expected),
                "param({name:?}) returned {found:?}, the scan found {expected:?}"
            ),
            (found, expected) => {
                panic!("param({name:?}) returned {found:?} where the scan found {expected:?}")
            }
        }
    }
}

/// Oracle: construct-from-answer. A deck that cannot be opened is an error, not
/// an empty deck. That distinction is the whole of "fail closed" here: an empty
/// deck runs zero rules and reports clean, which is the false-clean result this
/// tool exists to prevent.
#[test]
fn a_deck_that_cannot_be_opened_is_an_error_rather_than_an_empty_deck() {
    let grid = Grid::new(1_000).expect("1000 database units per micrometre is a legal grid");
    let mut strings = StrTable::default();
    let missing = std::path::Path::new("/nonexistent/gpurify/no-such-deck.json");

    match gpurify_ingest::deck::read_deck(missing, grid, &mut strings) {
        Err(DeckError::Io(_)) => {}
        other => panic!("an unreadable deck produced {other:?} rather than DeckError::Io"),
    }
}
