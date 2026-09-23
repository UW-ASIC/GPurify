//! The deck language: what it accepts, what it lowers to, and every error class.

use gpurify_geom::{Grid, StrTable};
use gpurify_ingest::deck::{parse_deck, Deck, DeckError, ParamValue};
use std::fmt::Write as _;

fn grid() -> Grid {
    Grid::new(1000).expect("1 nm grid")
}

const HEAD: &str = "grid 5nm
layer diff = gds(65, 20)
layer poly = gds(66, 20)
layer licon = gds(66, 44)
layer li = gds(67, 20)
layer mcon = gds(67, 44)
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
layer met3 = gds(70, 20)
";

fn parse(body: &str) -> Result<(Deck, StrTable), DeckError> {
    let mut strings = StrTable::default();
    let source = format!("{HEAD}{body}");
    parse_deck(&source, grid(), &mut strings).map(|deck| (deck, strings))
}

fn ok(body: &str) -> (Deck, StrTable) {
    parse(body).unwrap_or_else(|why| panic!("{why}"))
}

/// Every diagnostic message, asserting the deck was refused.
fn errors(body: &str) -> Vec<String> {
    match parse(body) {
        Ok(_) => panic!("accepted:\n{body}"),
        Err(DeckError::Invalid { diagnostics, .. }) => {
            diagnostics.into_iter().map(|d| d.message).collect()
        }
        Err(other) => panic!("refused, but not with diagnostics: {other}"),
    }
}

fn one_error(body: &str, needle: &str) {
    let found = errors(body);
    assert!(
        found.iter().any(|message| message.contains(needle)),
        "wanted an error containing {needle:?}, got {found:#?}"
    );
}

/// (rule id, engine kind, layer names, params as text) for every rule.
fn rules(deck: &Deck, strings: &StrTable) -> Vec<(String, String, Vec<String>, Vec<String>)> {
    let names: Vec<String> = (0..deck.layers.len())
        .map(|i| {
            layer_name(
                deck,
                strings,
                gpurify_geom::LayerId(u16::try_from(i).expect("few")),
            )
        })
        .collect();
    deck.rules
        .spec
        .iter()
        .map(|spec| {
            let layers = deck
                .rules
                .layers_of(spec)
                .iter()
                .map(|l| names[l.idx()].clone())
                .collect();
            let params = deck
                .rules
                .params_of(spec)
                .iter()
                .map(|&(name, value)| {
                    let value = match value {
                        ParamValue::Length(d) => format!("{}dbu", d.raw()),
                        ParamValue::Area(a) => format!("{}dbu2", a.raw()),
                        ParamValue::Ratio(r) => format!("{r}"),
                        ParamValue::Count(c) => format!("#{c}"),
                        ParamValue::Flag(f) => format!("{f}"),
                        ParamValue::Layer(l) => names[l.idx()].clone(),
                    };
                    format!("{}={value}", strings.resolve(name))
                })
                .collect();
            (
                strings.resolve(spec.id).to_owned(),
                strings.resolve(spec.kind).to_owned(),
                layers,
                params,
            )
        })
        .collect()
}

fn layer_name(deck: &Deck, strings: &StrTable, id: gpurify_geom::LayerId) -> String {
    // No reverse lookup is public; search the names this file declares.
    for name in [
        "diff", "poly", "licon", "li", "mcon", "met1", "met2", "met3", "gate", "x", "x#1", "active",
    ] {
        if deck.layers.id(strings, name) == Some(id) {
            return name.to_owned();
        }
    }
    format!("?{}", id.0)
}

#[test]
fn a_one_line_rule_lowers_to_the_engine_kind_and_grid_units() {
    let (deck, strings) = ok("rule m1.1 width(met1) >= 0.14um\n\
         rule m1.2 width(met1) <= 10um\n\
         rule m1.4 enclosure(mcon, met1) >= 30nm\n\
         rule m1.5 enclosure(mcon, met1, opposite) >= 60nm\n\
         rule m1.6 area(met1) >= 0.083um2\n\
         rule d.1 density(met1; window: 100um, step: 50um) <= 80%\n\
         rule a.1 angle(; allowed: [0deg, 90deg, 45deg])\n");
    let got = rules(&deck, &strings);
    let expect = |id: &str, kind: &str, layers: &[&str], params: &[&str]| {
        let row = got
            .iter()
            .find(|r| r.0 == id)
            .unwrap_or_else(|| panic!("{id} missing"));
        assert_eq!(row.1, kind, "{id}");
        assert_eq!(row.2, layers, "{id}");
        assert_eq!(row.3, params, "{id}");
    };
    expect("m1.1", "min_width", &["met1"], &["limit=140dbu"]);
    expect("m1.2", "max_width", &["met1"], &["limit=10000dbu"]);
    // The engine takes outer first.
    expect("m1.4", "min_enclosure", &["met1", "mcon"], &["limit=30dbu"]);
    expect(
        "m1.5",
        "asymmetric_enclosure",
        &["met1", "mcon"],
        &["min_one_side=60dbu"],
    );
    expect("m1.6", "min_area", &["met1"], &["limit=83000dbu2"]);
    expect(
        "d.1",
        "density",
        &["met1"],
        &[
            "window=100000dbu",
            "step=50000dbu",
            "limit=0.8",
            "maximum=true",
        ],
    );
    expect("a.1", "angle", &[], &["angle=#0", "angle=#90", "angle=#45"]);
}

#[test]
fn erc_named_arguments_convert_to_engine_units_and_none_leaves_a_param_out() {
    let (deck, strings) = ok("rule em.li warning electromigration(li, licon,
    max_density: 0.28mA/um, max_current_per_cut: 80uA, blech_limit: 15mA,
    reference_temperature: 105C, activation_energy: 0.9eV, current_exponent: 2)
rule hv hv_domain(; max_delta: 1.8V, isolation: none)
rule cmp density_cmp(met1; window: 50um x 40um, step: 25um x 20um, min: 20%, max: none,
    max_delta: none, partial_windows: false, cmp: none)
");
    let got = rules(&deck, &strings);
    assert_eq!(
        got[0].3,
        [
            "max_density=280",
            "max_current_per_cut=80",
            "blech_limit=15000",
            "reference_temperature=378.15",
            "activation_energy_ev=0.9",
            "current_exponent=2",
            "warning=true",
        ]
    );
    assert_eq!(got[0].2, ["li", "licon"]);
    assert_eq!(got[1].3, ["max_domain_delta=1800"]);
    assert_eq!(
        got[2].3,
        [
            "window_x=50000dbu",
            "window_y=40000dbu",
            "step_x=25000dbu",
            "step_y=20000dbu",
            "min_density=0.2",
            "include_partial_windows=false",
        ]
    );
}

#[test]
fn let_and_for_expand_with_interpolated_ids() {
    let (deck, strings) = ok("let metals = [(met1, 140nm), (met2, 140nm), (met3, 300nm)]
for (m, w) in metals {
    rule {m}.width width(m) >= w
    rule {m}.space space(m) >= w
}
let wide = 1um
for m in [met1, met2] {
    rule {m}.max width(m) <= wide
}
");
    let got = rules(&deck, &strings);
    let ids: Vec<&str> = got.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        ids,
        [
            "met1.width",
            "met1.space",
            "met2.width",
            "met2.space",
            "met3.width",
            "met3.space",
            "met1.max",
            "met2.max"
        ]
    );
    assert_eq!(got[4].2, ["met3"]);
    assert_eq!(got[4].3, ["limit=300dbu"]);
    assert_eq!(got[7].3, ["limit=1000dbu"]);
}

#[test]
fn derived_layers_fold_one_operator_and_nest_the_rest() {
    let (deck, strings) = ok("layer gate = poly and diff\n\
         layer x = gate or li not met1\n");
    assert_eq!(deck.layers.len(), 8 + 3, "gate, x and one intermediate");
    let x = deck.layers.id(&strings, "x").expect("x");
    assert!(deck.layers.is_derived(x));
    assert!(deck.layers.id(&strings, "x#1").is_some());
}

#[test]
fn connectivity_devices_and_pex_lower() {
    let (deck, strings) = ok("layer gate = poly and diff
connect conductors [poly, li, met1]
connect touch_within_layer
connect via mcon [li, met1]
connect label met2 names met1
device mos gate model \"nfet \\\"01v8\\\"\" terminals [poly, diff, diff]
pex met1 thickness 360nm height 1.376um sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um
");
    let c = &deck.connectivity;
    assert_eq!(c.conductors.len(), 3);
    assert!(c.intra_layer_touch);
    assert_eq!(c.via_cut.len(), 1);
    assert_eq!(c.label_layer.len(), 1);
    assert_eq!(strings.resolve(deck.devices.model[0]), "nfet \"01v8\"");
    let met1 = deck.layers.id(&strings, "met1").expect("met1").idx();
    assert_eq!(deck.stack.thickness_nm[met1].to_bits(), 360.0f64.to_bits());
    assert_eq!(deck.stack.height_nm[met1].to_bits(), 1376.0f64.to_bits());
    assert_eq!(
        deck.stack.area_cap_af_um2[met1].to_bits(),
        25.8f64.to_bits()
    );
}

#[test]
fn the_example_in_the_language_spec_parses() {
    let spec = include_str!("../../../docs/deck.md");
    let start = spec.find("```\n# sky130 (excerpt)").expect("the example") + 4;
    let example = &spec[start..start + spec[start..].find("```").expect("closed")];
    let deck =
        parse_deck(example, grid(), &mut StrTable::default()).unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(deck.rules.spec.len(), 10);
}

// ---- error classes ----

#[test]
fn a_missing_parameter_is_an_error() {
    one_error(
        "rule e eol_space(met1) >= 100nm\n",
        "missing parameter `eol_width`",
    );
    one_error(
        "rule a antenna(poly, met1; max_ratio: 400)\n",
        "missing parameter `sidewall`",
    );
}

#[test]
fn an_unknown_parameter_is_an_error() {
    one_error(
        "rule e eol_space(met1; eol_width: 100nm, colour: 3) >= 100nm\n",
        "unknown parameter `colour`",
    );
}

#[test]
fn a_bare_number_where_a_unit_belongs_is_an_error() {
    one_error(
        "rule m1.5 enclosure(mcon, met1, opposite) >= 60\n",
        "m1.5: enclosure needs a length, got 60 (no unit)",
    );
}

#[test]
fn a_unit_of_the_wrong_dimension_is_an_error() {
    one_error(
        "rule w width(met1) >= 0.083um2\n",
        "needs a length, got 0.083um2 (an area)",
    );
    one_error(
        "rule hv hv_domain(; max_delta: 5uA, isolation: none)\n",
        "needs a voltage",
    );
}

#[test]
fn an_off_grid_length_is_an_error() {
    one_error(
        "rule w width(met1) >= 142nm\n",
        "142nm is not a multiple of the grid",
    );
    one_error(
        "rule a area(met1) >= 30nm2\n",
        "not a multiple of the grid squared",
    );
}

#[test]
fn the_wrong_comparator_is_an_error_not_a_flip() {
    one_error(
        "rule t tap_distance(diff, li) >= 10um\n",
        "`>=` is not legal on `tap_distance`; it takes `<=`",
    );
    one_error("rule w width(met1)\n", "`width` needs a comparison");
    one_error(
        "rule g off_grid(; pitch: 5nm) >= 5nm\n",
        "`off_grid` takes no comparison",
    );
}

#[test]
fn an_unknown_layer_is_an_error() {
    one_error("rule w width(met9) >= 100nm\n", "unknown layer `met9`");
}

#[test]
fn a_forward_reference_is_an_error() {
    one_error(
        "rule w width(met4) >= 100nm\nlayer met4 = gds(71, 20)\n",
        "`met4` is used before its declaration on line",
    );
    one_error(
        "rule w width(met1) >= w\nlet w = 100nm\n",
        "`w` is used before its declaration",
    );
}

#[test]
fn rebinding_a_name_is_an_error() {
    one_error("let w = 1nm\nlet w = 2nm\n", "`w` is already bound");
    one_error("layer met1 = gds(1, 1)\n", "`met1` is already bound");
    one_error("let met1 = 5nm\n", "`met1` is already bound");
}

#[test]
fn layer_operations_chain_and_a_rule_can_name_the_result() {
    let (deck, strings) = ok("layer huge = met1.sized(-1500nm).sized(1500nm)\n\
         layer x = (met1 and met2).holes() or met3.extents()\n\
         layer gate = poly.interacting(diff).not_interacting(licon)\n\
         layer active = diff.with_area(>= 1um2, < 4um2).with_width(== 150nm)\n\
         rule m1.3 width(huge) >= 3um\n");
    let huge = deck.layers.id(&strings, "huge").expect("huge");
    assert!(deck.layers.is_derived(huge) && !deck.layers.is_edges(huge));
    // huge, huge#1; x and three hidden rows; gate, gate#1; active, active#1.
    assert_eq!(deck.layers.len(), 8 + 10);
    let spec = &deck.rules.spec[0];
    assert_eq!(deck.rules.layers_of(spec), [huge]);
}

#[test]
fn edge_layers_are_typed_and_only_edge_operations_take_them() {
    let (deck, strings) = ok("layer e = diff.edges()\n\
         layer butt = e and poly.edges()\n\
         layer e_in = e.inside_part(met1).with_length(<= 1um)\n\
         layer touch = e.interacting(met1)\n");
    for name in ["e", "butt", "e_in", "touch"] {
        let id = deck.layers.id(&strings, name).expect(name);
        assert!(deck.layers.is_edges(id), "{name} is edges");
    }
    one_error(
        "layer e = diff.edges()\nrule w width(e) >= 100nm\n",
        "`e` is an edge layer; only a check that takes edges can use it",
    );
    one_error(
        "layer e = diff.edges()\nconnect conductors [e]\n",
        "`e` is an edge layer",
    );
    one_error(
        "layer e = diff.edges()\nlayer x = e and met1\n",
        "cannot combine an edge layer with a polygon layer",
    );
    one_error(
        "layer e = diff.edges()\nlayer x = e.sized(10nm)\n",
        "`.sized` needs a polygon layer, not edges",
    );
    one_error(
        "layer x = met1.with_length(>= 10nm)\n",
        "`.with_length` needs an edge layer, not polygons",
    );
    one_error(
        "layer e = diff.edges()\nlayer x = met1.inside(e)\n",
        "`.inside` takes a polygon layer",
    );
}

#[test]
fn a_layer_operation_checks_its_arguments() {
    one_error(
        "layer x = met1.sized(3nm)\n",
        "is not a multiple of the grid",
    );
    one_error(
        "layer x = met1.grow(10nm)\n",
        "unknown layer operation `.grow`",
    );
    one_error(
        "layer x = met1.with_area(> 4um2, < 1um2)\n",
        "the range is empty",
    );
    one_error(
        "layer x = met1.with_area(>= 1um2, > 2um2)\n",
        "takes one bound on each side",
    );
    one_error(
        "layer x = met1.with_width(150nm)\n",
        "expected a bound such as `>= 1um`",
    );
    one_error("layer x = met1.with_area(>= 1um)\n", "needs an area");
    one_error("layer x = met1\n", "a derived layer needs an operator");
}

#[test]
fn a_duplicate_rule_and_warning_on_drc_are_errors() {
    one_error(
        "rule w width(met1) >= 100nm\nrule w width(met1) >= 200nm\n",
        "duplicate rule id `w`",
    );
    one_error(
        "rule w warning width(met1) >= 100nm\n",
        "`warning` is not legal on `width`",
    );
}

#[test]
fn errors_are_collected_and_capped_at_fifty() {
    let body = (0..80).fold(String::new(), |mut body, i| {
        let _ = writeln!(body, "rule r{i} width(met1) >= 142nm");
        body
    });
    assert_eq!(errors(&body).len(), 50);
    let three =
        errors("rule a width(met1) >= 1nm\nrule b width(met9) >= 5nm\nrule c space(met1) <= 5nm\n");
    assert_eq!(three.len(), 3, "{three:#?}");
}

#[test]
fn an_error_renders_file_line_column_and_a_caret() {
    let mut strings = StrTable::default();
    let source = "grid 5nm\nlayer met1 = gds(68, 20)\nrule m1.1 width(met1) >= 60\n";
    let error = parse_deck(source, grid(), &mut strings)
        .expect_err("a bare number")
        .in_file("pdks/x.deck");
    assert_eq!(
        error.to_string(),
        "pdks/x.deck:3:26: m1.1: width needs a length, got 60 (no unit)\n\
         rule m1.1 width(met1) >= 60\n                         ^^"
    );
}
