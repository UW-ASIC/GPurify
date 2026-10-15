//! What `drc::RuleSet::from_deck` refuses, at each boundary its rustdoc and
//! the rule kinds' rustdocs state: each case one value either side of the
//! line, the refusal named with the value it reports.

use crate::deck_fixture::{check, met1, new_deck, one_layer_deck};
use gpurify_check::drc::{DrcError, RuleSet};
use gpurify_geom::Grid;
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::StrTable;

/// Parses `deck` on a 1 nm grid and builds its DRC rule set.
fn compile(deck: &str) -> Result<RuleSet, DrcError> {
    let mut strings = StrTable::default();
    let parsed = parse_deck(deck, Grid::new(1000).expect("a 1 nm grid"), &mut strings)
        .unwrap_or_else(|why| panic!("the deck parses: {why}\n{deck}"));
    RuleSet::from_deck(&parsed, &strings)
}

fn non_positive(rule: &str, limit: i64) -> DrcError {
    DrcError::NonPositiveLimit {
        rule: rule.to_owned(),
        limit,
    }
}

/// Oracle: `WireBand`'s rustdoc: `below` is "above `from`". A band whose
/// `below` is at or under its `from` is refused with the band's width,
/// `below - from`: -1000 for 2000 over 1000, 0 for equal ends; one unit
/// above is a band.
#[test]
fn an_enclosure_band_must_end_above_where_it_starts() {
    let band = |width: i64, below: i64| {
        compile(&new_deck(
            &["via", "met2"],
            &format!("rule e enclosure(via, met2; width: {width}nm, below: {below}nm) >= 50nm"),
        ))
    };
    assert_eq!(band(2000, 1000).unwrap_err(), non_positive("e", -1000));
    assert_eq!(band(1000, 1000).unwrap_err(), non_positive("e", 0));
    assert!(band(1000, 1001).is_ok());
}

/// Oracle: `via_map`'s grammar (`OpenROAD`'s `VIA cutLayer w1 w2`): each
/// width band's low end at most its high end. A low end past its high end
/// is refused with `high - low`; equal ends are an exact width.
#[test]
fn a_via_map_band_must_not_run_backwards() {
    let map = |below: (i64, i64), above: (i64, i64)| {
        compile(&new_deck(
            &["v1", "m1", "m2"],
            &format!(
                "rule vm via_map(v1, m1, m2; below_min: {}nm, below_max: {}nm, above_min: {}nm, \
                 above_max: {}nm, cut: 30nm x 30nm)",
                below.0, below.1, above.0, above.1
            ),
        ))
    };
    assert_eq!(
        map((60, 50), (80, 80)).unwrap_err(),
        non_positive("vm", -10)
    );
    assert_eq!(
        map((50, 50), (90, 80)).unwrap_err(),
        non_positive("vm", -10)
    );
    assert!(map((50, 50), (80, 80)).is_ok());
    assert!(map((49, 50), (80, 81)).is_ok());
}

/// Oracle: `Rule::ForbiddenSpacing`'s range is "from `min` to `max`, both
/// included": `min` past `max` is no range (a bad table); `min` equal to
/// `max` forbids one gap.
#[test]
fn a_forbidden_range_must_not_run_backwards() {
    let range = |min: i64, max: i64| {
        compile(&one_layer_deck(&format!(
            "rule f forbidden_space(met1; min: {min}nm, max: {max}nm, prl: 0nm)"
        )))
    };
    assert_eq!(
        range(151, 150).unwrap_err(),
        DrcError::BadTable("f".to_owned())
    );
    assert!(range(150, 150).is_ok());
}

/// Oracle: `Rule::ViaStack` with `single` lists "the metals and cuts
/// alternating", a metal at each end: an odd count of at least 5 layers
/// (metal, cut, metal, cut, metal). Four or six layers are refused,
/// expecting 5; five and seven build.
#[test]
fn a_single_cut_via_stack_alternates_metal_and_cut() {
    let stack = |layers: &[&str]| {
        compile(&new_deck(
            &["m1", "v1", "m2", "v2", "m3", "v3", "m4"],
            &format!("rule s via_stack({}, single) <= 2", layers.join(", ")),
        ))
    };
    let refused = |found: u32| DrcError::WrongLayerCount {
        rule: "s".to_owned(),
        expected: 5,
        found,
    };
    assert_eq!(stack(&["m1", "v1", "m2", "v2"]).unwrap_err(), refused(4));
    assert!(stack(&["m1", "v1", "m2", "v2", "m3"]).is_ok());
    assert_eq!(
        stack(&["m1", "v1", "m2", "v2", "m3", "v3"]).unwrap_err(),
        refused(6)
    );
    assert!(stack(&["m1", "v1", "m2", "v2", "m3", "v3", "m4"]).is_ok());
}

/// Oracle: `Rule::AnchoredPatterning`'s rustdoc: one layer split into
/// `colors` masks with one anchor layer per mask, at most four. With two
/// colours, one anchor and two build; none (one layer) and three anchors
/// are refused, expecting 1 + 2 = 3 layers.
#[test]
fn anchored_patterning_takes_one_anchor_per_colour() {
    let anchored = |layers: &[&str]| {
        compile(&new_deck(
            &["met1", "c1", "c2", "c3"],
            &format!(
                "rule a patterning({}; colors: 2) >= 100nm",
                layers.join(", ")
            ),
        ))
    };
    let refused = |found: u32| DrcError::WrongLayerCount {
        rule: "a".to_owned(),
        expected: 3,
        found,
    };
    assert!(anchored(&["met1", "c1"]).is_ok());
    assert!(anchored(&["met1", "c1", "c2"]).is_ok());
    assert_eq!(
        anchored(&["met1", "c1", "c2", "c3"]).unwrap_err(),
        refused(4)
    );
}

/// Oracle: `Rule::CutClass`'s rustdoc: each class a positive width and
/// height. A side of 0 is refused with that side; 1 builds.
#[test]
fn a_cut_class_needs_positive_sides() {
    let classes = |allowed: &str| {
        compile(&new_deck(
            &["via"],
            &format!("rule cc size(via; allowed: [{allowed}])"),
        ))
    };
    assert_eq!(
        classes("100nm x 100nm, 0nm x 200nm").unwrap_err(),
        non_positive("cc", 0)
    );
    assert_eq!(
        classes("100nm x 100nm, 100nm x 0nm").unwrap_err(),
        non_positive("cc", 0)
    );
    assert!(classes("1nm x 1nm").is_ok());
}

/// Oracle: `Rule::AllowedWidth`'s rustdoc: every width positive. A width
/// of 0 is refused with it; 1 builds.
#[test]
fn an_allowed_width_must_be_positive() {
    let widths = |allowed: &str| {
        compile(&one_layer_deck(&format!(
            "rule aw width(met1; allowed: [{allowed}])"
        )))
    };
    assert_eq!(widths("100nm, 0nm").unwrap_err(), non_positive("aw", 0));
    assert!(widths("1nm").is_ok());
}

/// Oracle: each count a rule stores in a narrower integer is a value of
/// that integer: a via stack's height is a `u16` (65535 builds, 65536 is
/// the wrong kind of value), a patterning's colour count a `u8` (255
/// builds, 256 is refused).
#[test]
fn a_count_must_fit_the_rule_that_stores_it() {
    let stack = |height: u32| {
        compile(&new_deck(
            &["v1", "v2"],
            &format!("rule s via_stack(v1, v2) <= {height}"),
        ))
    };
    assert!(stack(65_535).is_ok());
    assert_eq!(
        stack(65_536).unwrap_err(),
        DrcError::WrongParamType {
            rule: "s".to_owned(),
            param: "max_height",
        }
    );
    let colours = |n: u32| {
        compile(&one_layer_deck(&format!(
            "rule p patterning(met1; colors: {n}) >= 100nm"
        )))
    };
    assert!(colours(255).is_ok());
    assert_eq!(
        colours(256).unwrap_err(),
        DrcError::WrongParamType {
            rule: "p".to_owned(),
            param: "colors",
        }
    );
}

/// Oracle: `pattern`'s shapes and don't-care boxes are rectangles by two
/// opposite corners each: an odd count of corners is no list of
/// rectangles (a bad table); the even L of the root fixture builds.
#[test]
fn a_pattern_lists_rectangles_by_corner_pairs() {
    let pattern = |shapes: &str| {
        compile(&one_layer_deck(&format!(
            "rule p pattern(met1; window: 300nm x 300nm, shapes: [{shapes}], ignore: none)"
        )))
    };
    assert!(pattern("0nm x 0nm, 300nm x 100nm, 0nm x 100nm, 100nm x 300nm").is_ok());
    assert_eq!(
        pattern("0nm x 0nm, 300nm x 100nm, 0nm x 100nm").unwrap_err(),
        DrcError::BadTable("p".to_owned())
    );
}

/// Oracle: `RuleSet::first_derived`'s rustdoc: "`Rule::OffGrid` ... check
/// drawn rows only". A 100 square on a 10 nm pitch grown by 5 nm is a
/// derived layer whose every vertex is off the pitch; the drawn square is
/// on it, so the rule finds nothing. Unmoved: the harness's far offset is
/// off the pitch itself.
#[test]
fn off_grid_reads_only_the_drawn_layers() {
    check(
        "sized",
        &one_layer_deck("layer fat = met1.sized(5nm)\nrule g off_grid(; pitch: 10nm)"),
        &met1(&[[0, 0, 100, 100]]),
        &[("g", vec![])],
    );
}
