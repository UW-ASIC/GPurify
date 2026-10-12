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
                        ParamValue::Model(m) => format!("\"{}\"", strings.resolve(m)),
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

/// Oracle: hand-derived. Each check's engine kind is the Kind / Deck form table
/// of `docs/klayout-mirror.md` (`width >=` is `min_width`, `<=` `max_width`,
/// `enclosure(i, o, opposite)` `asymmetric_enclosure`), and the values are the
/// deck's units converted by hand on the 1 nm grid: 0.14 um is 140 dbu, 0.083
/// um2 is 83 000 dbu2, 80 % is 0.8.
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
    let (deck, strings) = ok("rule x.2 angle(poly; allowed: [0deg, 90deg])\n");
    assert_eq!(
        rules(&deck, &strings)[0],
        (
            "x.2".to_owned(),
            "angle".to_owned(),
            vec!["poly".to_owned()],
            vec!["angle=#0".to_owned(), "angle=#90".to_owned()],
        )
    );
}

/// Oracle: `docs/deck.md`'s spelling of each check ledger H added, and the
/// engine kind and parameters each lowers to: the cut-spacing forms, the
/// cut-class table, LEF MINIMUMCUT and MAXVIASTACK, the gate-shape pair, the
/// maximum, non-coincident and wire-banded enclosures, and contains' maximum
/// and exact counts.
#[test]
fn the_overlay_and_cut_checks_lower_to_their_engine_kinds() {
    let (deck, strings) = ok("rule c2c space(mcon, center) >= 300nm\n\
         rule adj adjacent_space(mcon; cuts: 3, within: 250nm) >= 220nm\n\
         rule adjc adjacent_space(mcon, center; cuts: 3, within: 300nm) >= 300nm\n\
         rule ccs cut_class_space(licon; short: [170nm, 190nm], long: [170nm, 2000nm],\n\
             space: [[170nm, 170nm, 510nm, 510nm], [170nm, 170nm, 510nm, 510nm],\n\
                     [510nm, 510nm, 350nm, 510nm], [510nm, 510nm, 510nm, 510nm]])\n\
         rule mc min_cuts(mcon, met1, li; width: 1um) >= 2\n\
         rule mcw min_cuts(mcon, met1, li; width: 1um, within: 300nm) >= 2\n\
         rule vs via_stack(licon, mcon) <= 1\n\
         rule bend bend(poly, diff)\n\
         rule cov covers_corner(poly, diff)\n\
         rule maxe enclosure(licon, li) <= 95nm\n\
         rule nce enclosure(licon, li, noncoincident) >= 380nm\n\
         rule we enclosure(mcon, met1; width: 1um) >= 20nm\n\
         rule wb enclosure(mcon, met1, opposite; below: 1um) >= 50nm\n\
         rule wwb enclosure(mcon, met1; width: 1um, below: 2um) >= 20nm\n\
         rule most contains(diff, licon) <= 1\n\
         rule exact contains(diff, licon) == 2\n\
         rule fw full_width(mcon, met1)\n\
         rule ps space(licon, poly, projection) >= 235nm\n");
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
    expect(
        "c2c",
        "cut_spacing",
        &["mcon"],
        &["limit=300dbu", "center=true"],
    );
    expect(
        "adj",
        "cut_spacing",
        &["mcon"],
        &[
            "adjacent=#3",
            "within=250dbu",
            "limit=220dbu",
            "center=false",
        ],
    );
    expect(
        "adjc",
        "cut_spacing",
        &["mcon"],
        &[
            "adjacent=#3",
            "within=300dbu",
            "limit=300dbu",
            "center=true",
        ],
    );
    let ccs = got.iter().find(|r| r.0 == "ccs").expect("ccs");
    assert_eq!(
        (ccs.1.as_str(), ccs.2.as_slice()),
        ("cut_class_spacing", &["licon".to_owned()][..])
    );
    assert_eq!(
        ccs.3[..4],
        [
            "class_short=170dbu",
            "class_short=190dbu",
            "class_long=170dbu",
            "class_long=2000dbu"
        ]
    );
    assert_eq!(ccs.3.len(), 4 + 16, "two classes and a 4 x 4 table");
    expect(
        "mc",
        "minimum_cut",
        &["mcon", "met1", "li"],
        &["width=1000dbu", "min_count=#2"],
    );
    expect(
        "mcw",
        "minimum_cut",
        &["mcon", "met1", "li"],
        &["width=1000dbu", "within=300dbu", "min_count=#2"],
    );
    expect("vs", "via_stack", &["licon", "mcon"], &["max_height=#1"]);
    expect(
        "bend",
        "gate_corner",
        &["poly", "diff"],
        &["of_reference=false"],
    );
    expect(
        "cov",
        "gate_corner",
        &["poly", "diff"],
        &["of_reference=true"],
    );
    // Enclosures take the outer layer first.
    expect("maxe", "max_enclosure", &["li", "licon"], &["limit=95dbu"]);
    expect(
        "nce",
        "noncoincident_enclosure",
        &["li", "licon"],
        &["limit=380dbu"],
    );
    expect(
        "we",
        "min_enclosure",
        &["met1", "mcon"],
        &["wire_width=1000dbu", "limit=20dbu"],
    );
    expect(
        "wb",
        "asymmetric_enclosure",
        &["met1", "mcon"],
        &["wire_below=1000dbu", "min_one_side=50dbu"],
    );
    expect(
        "wwb",
        "min_enclosure",
        &["met1", "mcon"],
        &["wire_width=1000dbu", "wire_below=2000dbu", "limit=20dbu"],
    );
    expect(
        "most",
        "must_contain",
        &["diff", "licon"],
        &["max_count=#1"],
    );
    expect("exact", "must_contain", &["diff", "licon"], &["count=#2"]);
    expect("fw", "full_width", &["met1", "mcon"], &[]);
    expect(
        "ps",
        "projection_spacing",
        &["licon", "poly"],
        &["limit=235dbu"],
    );
}

/// gf180 M1.4 "Metal1 minimum density 30 % over the entire die", and a
/// windowed row whose die is a named boundary layer.
///
/// Oracle: foundry example, gf180 M1.4 (30 % over the die), lowered by the
/// `global_density` and `density` rows of `docs/deck.md`; the fractions and the
/// boundary layer's place are read off the rule text.
#[test]
fn die_density_lowers_with_an_optional_boundary_layer() {
    let (deck, strings) = ok("rule M1.4 global_density(met1) >= 30%\n\
         rule M1.k global_density(met1, met3) <= 60%\n\
         rule M1.j density(met1, met3; window: 800um, step: 400um) >= 35%\n");
    let got = rules(&deck, &strings);
    assert_eq!(got[0].1, "global_density");
    assert_eq!(got[0].2, ["met1"]);
    assert_eq!(got[0].3, ["limit=0.3", "maximum=false"]);
    assert_eq!(got[1].2, ["met1", "met3"]);
    assert_eq!(got[1].3, ["limit=0.6", "maximum=true"]);
    assert_eq!(got[2].1, "density");
    assert_eq!(got[2].2, ["met1", "met3"]);
}

/// sky130 licon.1 "min and max L and W of licon: 0.17": one exact square.
///
/// Oracle: foundry example, sky130 licon.1 (0.17 um square), and
/// `docs/deck.md`'s `size(L) == len x len`: 170 nm on the 1 nm grid is 170 dbu
/// a side; `>=` is not the documented comparator.
#[test]
fn an_exact_cut_size_lowers_to_both_sides() {
    let (deck, strings) = ok("rule licon.1 size(licon) == 0.17um x 0.17um\n\
         rule ct.slot size(licon) == 170nm x 510nm\n");
    let got = rules(&deck, &strings);
    assert_eq!(
        got[0],
        (
            "licon.1".to_owned(),
            "cut_size".to_owned(),
            vec!["licon".to_owned()],
            vec!["width=170dbu".to_owned(), "height=170dbu".to_owned()],
        )
    );
    assert_eq!(got[1].3, ["width=170dbu", "height=510dbu"]);
    one_error("rule licon.1 size(licon) >= 170nm x 170nm\n", "==");
}

/// Oracle: hand-derived unit conversions: 0.28 mA/um is 280 A/m, 15 mA is
/// 15 000 uA, 105 C is 378.15 K, 1.8 V is 1800 mV, 50 um is 50 000 dbu, 20 % is
/// 0.2; and `docs/deck.md`'s rule that `none` states a parameter absent, so it
/// lowers to no row.
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

/// Oracle: the Electrical rules section of `docs/deck.md`: `models` is a list
/// of quoted names, each declared by a `device` line, and `none` leaves the
/// parameter out; the lowered rows (one `model` per name, 1.98 V as 1980 mV)
/// are read off the deck text.
#[test]
fn model_lists_lower_to_one_param_per_model_and_must_name_a_device() {
    let (deck, strings) = ok(r#"device mos poly model "nfet" terminals [poly, diff, diff]
device mos met3 model "pfet" terminals [poly, diff, diff]
rule ox gate_oxide(; models: ["nfet", "pfet"], max: 1.98V)
rule wb well_bias(; pmos: ["pfet"], nmos: none)
rule ls missing_level_shifter(; shifters: none)
rule esd esd_topological(met1; clamps: ["nfet"])
let both = ["nfet", "pfet"]
rule ds drain_source(; models: both, max: 3.3V)
"#);
    let got = rules(&deck, &strings);
    assert_eq!(
        got[0].3,
        [r#"model="nfet""#, r#"model="pfet""#, "max_voltage=1980"]
    );
    assert_eq!(got[1].3, [r#"pmos="pfet""#]);
    assert_eq!(got[2].3, [] as [&str; 0]);
    assert_eq!(got[3].3, [r#"clamp="nfet""#]);
    assert_eq!(
        got[4].3,
        [r#"model="nfet""#, r#"model="pfet""#, "max_voltage=3300"]
    );

    one_error(
        "rule ox gate_oxide(; models: [nfet], max: 1.98V)",
        "a model name in quotes",
    );
    one_error(
        "rule ox gate_oxide(; models: [], max: 1.98V)",
        "needs at least one model",
    );
    let typo = parse(
        r#"device mos poly model "nfet" terminals [poly, diff, diff]
rule ox gate_oxide(; models: ["nfet_typo"], max: 1.98V)
"#,
    );
    assert!(
        matches!(typo, Err(DeckError::Malformed(ref why)) if why.contains("nfet_typo")),
        "a model no device declares checks nothing and must be refused"
    );
}

/// Oracle: spec example. The `let`/`for` example of `docs/deck.md` (Reuse),
/// expanded by hand: a width and a space rule per metal in list order, then a
/// `max` rule per metal of the second loop; met3's limit is 300 nm and `wide`
/// 1 um, 300 and 1000 dbu.
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

/// Oracle: hand count. `gate = poly and diff` is one operator, one row;
/// `x = gate or li not met1` is two, folded left to right, so `x` plus one
/// hidden intermediate `x#1`: the eight drawn layers and three more.
#[test]
fn derived_layers_fold_one_operator_and_nest_the_rest() {
    let (deck, strings) = ok("layer gate = poly and diff\n\
         layer x = gate or li not met1\n");
    assert_eq!(deck.layers.len(), 8 + 3, "gate, x and one intermediate");
    let x = deck.layers.id(&strings, "x").expect("x");
    assert!(deck.layers.is_derived(x));
    assert!(deck.layers.id(&strings, "x#1").is_some());
}

/// Oracle: construct-from-answer. Each statement's values are read back as
/// written: three conductors, one via, one label layer, the escaped model name
/// unescaped, and the `pex` row's 360 nm, 1.376 um (1376 nm) and 25.8 aF/um2,
/// bit for bit.
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

/// A resistor's `sheet` and a capacitor's `area_cap` and `fringe_cap` are
/// optional, in the units of a `pex` row, and lower to one `DeviceValue` per
/// recogniser; one left out is `None`, never zero. Each belongs to one kind,
/// and is given once.
///
/// Oracle: hand-derived conversions in the units of a `pex` row (0.3 kohm is
/// 300 ohm, 2 fF/um2 is 2000 aF/um2, a value left out is `None`), and the
/// Devices section of `docs/deck.md`: `sheet` is a resistor's, `area_cap` and
/// `fringe_cap` a capacitor's, each optional and given once.
#[test]
fn device_values_lower_per_recogniser_and_belong_to_their_kind() {
    use gpurify_ingest::deck::DeviceValue;
    let (deck, _) = ok(
        "device resistor poly model \"rpoly\" terminals [li, li] sheet 0.3kohm
device capacitor met2 model \"cmim\" terminals [met2, met1] area_cap 2fF/um2 fringe_cap 190aF/um
device capacitor met3 model \"cvar\" terminals [met3, met2] area_cap 1fF/um2
device mos diff model \"nfet\" terminals [poly, diff, diff]
",
    );
    assert_eq!(
        deck.devices.value,
        [
            DeviceValue {
                sheet_ohm_sq: Some(300.0),
                ..DeviceValue::default()
            },
            DeviceValue {
                area_cap_af_um2: Some(2000.0),
                fringe_cap_af_um: Some(190.0),
                ..DeviceValue::default()
            },
            DeviceValue {
                area_cap_af_um2: Some(1000.0),
                ..DeviceValue::default()
            },
            DeviceValue::default(),
        ]
    );

    let wrong = [
        (
            "device capacitor met2 model \"c\" terminals [met2, met1] sheet 1ohm\n",
            "`sheet` is a resistor's value, not a capacitor's",
        ),
        (
            "device resistor poly model \"r\" terminals [li, li] area_cap 1fF/um2\n",
            "`area_cap` is a capacitor's value, not a resistor's",
        ),
        (
            "device resistor poly model \"r\" terminals [li, li] sheet 1ohm sheet 2ohm\n",
            "`sheet` is given twice",
        ),
        (
            "device resistor poly model \"r\" terminals [li, li] rho 1ohm\n",
            "unknown device value `rho`",
        ),
        (
            "device resistor poly model \"r\" terminals [li, li] sheet 1fF/um2\n",
            "a resistance",
        ),
        // Past f64's range a decimal reads as infinite, which no device has.
        (
            "device resistor poly model \"r\" terminals [li, li] sheet 1e999ohm\n",
            "`sheet` is too large a number",
        ),
    ];
    for (body, needle) in wrong {
        one_error(body, needle);
    }
}

/// Oracle: the language spec (deck.md, "LVS controls"), values converted by
/// hand. `lvs tolerance` lowers to SI: 1 % is 0.01, 5 nm is 5e-9 m, 0.2 um²
/// is 2e-13 m², 2 kohm is 2000 ohm, 3 fF is 3e-15 F, and a part left out is
/// zero. The parameter is lowercased, as the netlist reader stores it. Each
/// error class is refused: an unknown control or part, a part given twice,
/// a parameter given a row twice, a row with no part, a relative part past
/// 100 %, an absolute part in the wrong unit, negative, or on a parameter
/// with no known unit, and a model no device declares.
#[test]
fn lvs_tolerances_lower_to_si_on_a_declared_model() {
    use gpurify_ingest::deck::LvsTolerance;
    let devices = "device mos poly model \"nfet\" terminals [poly, diff, diff]
device resistor met1 model \"rpoly\" terminals [met1, met1]
device capacitor met2 model \"cmim\" terminals [met2, met1]
";
    let (deck, strings) = ok(&format!(
        "{devices}lvs tolerance \"nfet\" W relative 1%
lvs tolerance \"nfet\" l relative 0.5% absolute 5nm
lvs tolerance \"nfet\" as absolute 0.2um2
lvs tolerance \"rpoly\" r absolute 2kohm
lvs tolerance \"cmim\" c relative 0.02 absolute 3fF
lvs tolerance \"nfet\" m absolute 1
"
    ));
    let row = |model: &str, param: &str, relative: f64, absolute: f64| LvsTolerance {
        model: strings.get(model).expect("interned"),
        param: strings.get(param).expect("interned"),
        relative,
        absolute,
        stated: 0.0,
    };
    let want = [
        row("nfet", "w", 0.01, 0.0),
        row("nfet", "l", 0.005, 5e-9),
        row("nfet", "as", 0.0, 2e-13),
        row("rpoly", "r", 0.0, 2000.0),
        row("cmim", "c", 0.02, 3e-15),
        row("nfet", "m", 0.0, 1.0),
    ];
    assert_eq!(deck.lvs.tolerance.len(), want.len());
    for (got, want) in deck.lvs.tolerance.iter().zip(&want) {
        assert_eq!((got.model, got.param), (want.model, want.param));
        for (a, b) in [(got.relative, want.relative), (got.absolute, want.absolute)] {
            assert!((a - b).abs() <= 1e-12 * b.abs(), "{got:?} against {want:?}");
        }
    }

    for (body, needle) in [
        (
            "lvs widen \"nfet\" w relative 1%\n",
            "unknown lvs control `widen`",
        ),
        (
            "lvs tolerance \"nfet\" w by 1%\n",
            "unknown tolerance part `by`",
        ),
        (
            "lvs tolerance \"nfet\" w relative 1% relative 2%\n",
            "`relative` is given twice",
        ),
        (
            "lvs tolerance \"nfet\" w relative 1%\nlvs tolerance \"nfet\" W absolute 1nm\n",
            "`w` of \"nfet\" already has a tolerance",
        ),
        (
            "lvs tolerance \"nfet\" w\n",
            "needs relative, absolute or both",
        ),
        ("lvs tolerance \"nfet\" w relative 150%\n", "0% to 100%"),
        ("lvs tolerance \"nfet\" w absolute 1ohm\n", "a length"),
        ("lvs tolerance \"nfet\" w absolute -1nm\n", "zero or more"),
        (
            "lvs tolerance \"nfet\" vth0 absolute 1mV\n",
            "takes a relative tolerance only",
        ),
        (
            "lvs tolerance nfet w relative 1%\n",
            "a model name in quotes",
        ),
    ] {
        one_error(&format!("{devices}{body}"), needle);
    }
    let typo = parse(&format!(
        "{devices}lvs tolerance \"nfet_typo\" w relative 1%\n"
    ));
    assert!(
        matches!(typo, Err(DeckError::Malformed(ref why)) if why.contains("nfet_typo")),
        "a tolerance on a model no device declares changes nothing and must be refused"
    );
}

/// Oracle: the language spec (deck.md, "LVS controls"). `lvs
/// ignore_parameter` lowers to `(model, parameter)`, the parameter
/// lowercased; `m` is refused, and so are a repeat, a tolerance on an
/// ignored parameter, and a model no device declares.
#[test]
fn lvs_ignored_parameters_lower_and_exclude_a_tolerance() {
    let devices = "device mos poly model \"nfet\" terminals [poly, diff, diff]\n";
    let (deck, strings) = ok(&format!(
        "{devices}lvs ignore_parameter \"nfet\" AS\nlvs ignore_parameter \"nfet\" pd\n"
    ));
    let id = |name: &str| strings.get(name).expect("interned");
    assert_eq!(
        deck.lvs.ignore_parameter,
        [(id("nfet"), id("as")), (id("nfet"), id("pd"))]
    );
    one_error(
        &format!("{devices}lvs ignore_parameter \"nfet\" m\n"),
        "cannot be ignored",
    );
    one_error(
        &format!("{devices}lvs ignore_parameter \"nfet\" w\nlvs ignore_parameter \"nfet\" W\n"),
        "already ignored",
    );
    for body in [
        "lvs ignore_parameter \"nfet\" w\nlvs tolerance \"nfet\" w relative 1%\n",
        "lvs ignore_parameter \"pfet\" w\n",
    ] {
        assert!(
            matches!(
                parse(&format!("{devices}{body}")),
                Err(DeckError::Malformed(_))
            ),
            "{body}"
        );
    }
}

/// Oracle: the language spec (deck.md, "LVS controls"). `lvs asymmetric`
/// lowers to the model; a model declared twice, one that is no `mos`
/// device, and one no device declares are refused.
#[test]
fn lvs_asymmetric_names_a_declared_transistor() {
    let devices = "device mos poly model \"ldmos\" terminals [poly, diff, diff]
device resistor met1 model \"rpoly\" terminals [met1, met1]
";
    let (deck, strings) = ok(&format!("{devices}lvs asymmetric \"ldmos\"\n"));
    assert_eq!(
        deck.lvs.asymmetric,
        [strings.get("ldmos").expect("interned")]
    );
    one_error(
        &format!("{devices}lvs asymmetric \"ldmos\"\nlvs asymmetric \"ldmos\"\n"),
        "already asymmetric",
    );
    for body in ["lvs asymmetric \"rpoly\"\n", "lvs asymmetric \"nfet\"\n"] {
        assert!(
            matches!(
                parse(&format!("{devices}{body}")),
                Err(DeckError::Malformed(_))
            ),
            "{body}"
        );
    }
}

/// Oracle: the language spec (deck.md, "LVS controls", Netgen's pin names).
/// `lvs permute` lowers each pin to its position in the device statement's
/// terminal order: a capacitor's `top` and `bottom` are 0 and 1, a
/// bipolar's `emitter` and `collector` 1 and 2, a transistor's `gate` and
/// `bulk` 0 and 3. A pin the kind lacks, a pin with itself, an asymmetric
/// transistor's source and drain, and an undeclared model are refused.
#[test]
fn lvs_permute_names_pins_by_kind() {
    use gpurify_ingest::deck::pin_names;
    use gpurify_ingest::deck::DeviceKind;
    let devices = "device mos poly model \"nfet\" terminals [poly, diff, diff]
device mos met2 model \"ldmos\" terminals [poly, diff, diff]
device bjt met3 model \"npn\" terminals [met1, met2, met3]
device capacitor met2 model \"cmim\" terminals [met2, met1]
";
    let (deck, strings) = ok(&format!(
        "{devices}lvs permute \"cmim\" bottom top
lvs permute \"npn\" emitter collector
lvs permute \"nfet\" gate bulk
"
    ));
    let id = |name: &str| strings.get(name).expect("interned");
    assert_eq!(
        deck.lvs.permute,
        [(id("cmim"), 1, 0), (id("npn"), 1, 2), (id("nfet"), 0, 3)]
    );
    assert_eq!(pin_names(DeviceKind::Diode), ["anode", "cathode"]);
    for body in [
        "lvs permute \"cmim\" top gate\n",
        "lvs permute \"cmim\" top top\n",
        "lvs asymmetric \"ldmos\"\nlvs permute \"ldmos\" drain source\n",
        "lvs permute \"pnp\" emitter collector\n",
    ] {
        assert!(
            matches!(
                parse(&format!("{devices}{body}")),
                Err(DeckError::Malformed(_))
            ),
            "{body}"
        );
    }
    one_error(
        &format!("{devices}lvs permute \"cmim\" top\n"),
        "a pin name",
    );
}

/// Oracle: the language spec (deck.md, "LVS controls"). `lvs ignore` and
/// `lvs ignore_shorted` lower to the model, which no device statement need
/// declare; a model given twice is refused.
#[test]
fn lvs_ignore_names_any_model_once() {
    let devices = "device mos poly model \"nfet\" terminals [poly, diff, diff]\n";
    let (deck, strings) = ok(&format!(
        "{devices}lvs ignore \"nfet\"\nlvs ignore \"decap\"\n"
    ));
    let id = |name: &str| strings.get(name).expect("interned");
    assert_eq!(deck.lvs.ignore, [id("nfet"), id("decap")]);
    one_error(
        &format!("{devices}lvs ignore \"decap\"\nlvs ignore \"decap\"\n"),
        "already ignored",
    );
    let (deck, strings) = ok(&format!("{devices}lvs ignore_shorted \"nfet\"\n"));
    assert_eq!(
        deck.lvs.ignore_shorted,
        [strings.get("nfet").expect("interned")]
    );
    one_error(
        &format!("{devices}lvs ignore_shorted \"nfet\"\nlvs ignore_shorted \"nfet\"\n"),
        "already ignored",
    );
}

/// Oracle: the language spec (deck.md, "LVS controls"). `lvs ports_by_name`
/// sets the flag, which is off without it; stated twice it is refused. `lvs
/// topology` is strict unless it says relaxed, takes one of the two words,
/// and is stated once. `lvs connect_implicit` keeps its pattern and `lvs
/// connect_explicit` its labels, two or more.
#[test]
fn lvs_ports_by_name_is_a_flag() {
    assert!(!ok("").0.lvs.ports_by_name);
    assert!(ok("lvs ports_by_name\n").0.lvs.ports_by_name);
    assert!(!ok("").0.lvs.relaxed);
    assert!(ok("lvs topology relaxed\n").0.lvs.relaxed);
    assert!(!ok("lvs topology strict\n").0.lvs.relaxed);
    one_error("lvs topology loose\n", "unknown topology `loose`");
    let (deck, strings) =
        ok("lvs connect_implicit \"VDD*\"\nlvs connect_explicit \"VSS\" \"GND\"\n");
    assert_eq!(deck.lvs.connect_implicit, ["VDD*"]);
    let id = |name: &str| strings.get(name).expect("interned");
    assert_eq!(deck.lvs.connect_explicit, [vec![id("VSS"), id("GND")]]);
    one_error("lvs connect_explicit \"VSS\"\n", "joins two labels or more");
    one_error("lvs connect_implicit VDD\n", "a label pattern in quotes");
    one_error(
        "lvs topology strict\nlvs topology relaxed\n",
        "the topology is already stated",
    );
    one_error(
        "lvs ports_by_name\nlvs ports_by_name\n",
        "already compared by name",
    );
}

/// Oracle: the language spec (deck.md, "LVS controls"), converted by hand
/// on the 5 nm deck grid and 1 nm layout grid. `lvs range` lowers each
/// bound to the parameter's kind: 420 nm and 100 um as lengths, 0.2 um² as
/// 200 000 square units, an `nf` as a count. A parameter no device has, a
/// length off the grid, a bound twice, a range that admits nothing, a row
/// with no bound, a repeat and an undeclared model are refused.
#[test]
fn lvs_ranges_lower_to_layout_units() {
    use gpurify_geom::{Dbu, DbuArea};
    use gpurify_ingest::deck::{LvsLimit, LvsRange};
    let devices = "device mos poly model \"nfet\" terminals [poly, diff, diff]\n";
    let (deck, strings) = ok(&format!(
        "{devices}lvs range \"nfet\" W >= 420nm <= 100um
lvs range \"nfet\" as >= 0.2um2
lvs range \"nfet\" nf <= 4
"
    ));
    let id = |name: &str| strings.get(name).expect("interned");
    let length = |nm| Some(LvsLimit::Length(Dbu::new_unchecked(nm)));
    assert_eq!(
        deck.lvs.range,
        [
            LvsRange {
                model: id("nfet"),
                param: id("w"),
                min: length(420),
                max: length(100_000),
            },
            LvsRange {
                model: id("nfet"),
                param: id("as"),
                min: Some(LvsLimit::Area(DbuArea::new(200_000))),
                max: None,
            },
            LvsRange {
                model: id("nfet"),
                param: id("nf"),
                min: None,
                max: Some(LvsLimit::Count(4)),
            },
        ]
    );
    for (body, needle) in [
        ("lvs range \"nfet\" r >= 1ohm\n", "not measured on a device"),
        (
            "lvs range \"nfet\" w >= 422nm\n",
            "not a multiple of the grid",
        ),
        ("lvs range \"nfet\" w >= 420nm >= 500nm\n", "already given"),
        ("lvs range \"nfet\" w >= 1um <= 500nm\n", "admits no value"),
        ("lvs range \"nfet\" w\n", "needs >=, <= or both"),
        ("lvs range \"nfet\" w > 1um\n", "expected >= or <="),
        (
            "lvs range \"nfet\" w >= 1um\nlvs range \"nfet\" w <= 2um\n",
            "already has a range",
        ),
    ] {
        one_error(&format!("{devices}{body}"), needle);
    }
    assert!(
        matches!(
            parse("lvs range \"pfet\" w >= 1um\n"),
            Err(DeckError::Malformed(_))
        ),
        "a range on a model no device declares"
    );
}

/// Oracle: spec example. The sky130 excerpt in `docs/deck.md` is the deck users
/// copy; it holds ten rules, counted in the document: six written out, three
/// from its `for` loop and the `em.li` row.
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

/// Oracle: the documented forms in `docs/deck.md`: `eol_space(L; eol_width:
/// len)`, and `antenna(..; max_ratio, sidewall, diode)` under "Every parameter
/// below is required".
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

/// Oracle: the documented parameter lists of `docs/deck.md`: `eol_space` has no
/// `colour` and the CMP model no `thickness`.
#[test]
fn an_unknown_parameter_is_an_error() {
    one_error(
        "rule e eol_space(met1; eol_width: 100nm, colour: 3) >= 100nm\n",
        "unknown parameter `colour`",
    );
    // The CMP model limits only the excursion from nominal; a nominal
    // thickness would be read by nothing, so the deck cannot state one.
    one_error(
        "rule d density_cmp(met1; window: 1um x 1um, step: 1um x 1um, min: none, max: 0.7,
    max_delta: none, partial_windows: false,
    cmp: (target: 0.5, thickness: 400nm, sensitivity: 200nm, max_delta: 50nm))\n",
        "unknown parameter `thickness`",
    );
}

/// Oracle: `docs/deck.md`, Basics: numbers carry units, and only a count, ratio
/// or exponent is bare; the message is the spec's own Errors example.
#[test]
fn a_bare_number_where_a_unit_belongs_is_an_error() {
    one_error(
        "rule m1.5 enclosure(mcon, met1, opposite) >= 60\n",
        "m1.5: enclosure needs a length, got 60 (no unit)",
    );
}

/// Oracle: the units table of `docs/deck.md`: `um2` is an area, `uA` a current,
/// neither a length nor a voltage.
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

/// Oracle: `docs/deck.md`, Basics: "`142nm` on a 5 nm grid is an error, not a
/// rounding"; 30 nm2 is likewise not a multiple of 25 nm2.
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

/// Oracle: `docs/deck.md`, Rules: "Writing `<=` on a minimum rule is an error,
/// not a flipped rule"; `tap_distance` is documented with `<=`, `width` with a
/// comparison, `off_grid` with none.
#[test]
fn the_wrong_comparator_is_an_error_not_a_flip() {
    one_error(
        "rule t tap_distance(diff, li) >= 10um\n",
        "`>=` is not legal on `tap_distance`; it takes `<=`",
    );
    one_error("rule w width(met1)\n", "`width` needs a comparison");
    // `size` also has a form without one, `size(L; allowed: [..])`.
    one_error("rule s size(met1)\n", "`size` needs a comparison: `==`");
    one_error(
        "rule g off_grid(; pitch: 5nm) >= 5nm\n",
        "`off_grid` takes no comparison",
    );
}

/// Oracle: `docs/deck.md`: a layer must be declared, and `met9` is not in the
/// header.
#[test]
fn an_unknown_layer_is_an_error() {
    one_error("rule w width(met9) >= 100nm\n", "unknown layer `met9`");
}

/// Oracle: `docs/deck.md`, Layers: "A layer must be declared before anything
/// uses it", and a `let` name likewise.
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

/// Oracle: `docs/deck.md`, Reuse: "A name can be bound once", whether by `let`
/// or `layer`.
#[test]
fn rebinding_a_name_is_an_error() {
    one_error("let w = 1nm\nlet w = 2nm\n", "`w` is already bound");
    one_error("layer met1 = gds(1, 1)\n", "`met1` is already bound");
    one_error("let met1 = 5nm\n", "`met1` is already bound");
}

/// Oracle: hand count. Each operator or operation is one layer row, the last
/// named and the others hidden (`huge`, `huge#1`; `x` and three; `gate`,
/// `gate#1`; `active`, `active#1`), so ten past the eight drawn layers, and the
/// rule reads `huge` itself.
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

/// Oracle: the Edge checks section of `docs/deck.md`: edge layers come from
/// `.edges()` and edge operations, and only a check or operation that takes
/// edges accepts one; each refusal is a documented type rule.
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
        "layer e = diff.edges()\nrule n notch(e) >= 100nm\n",
        "`e` is an edge layer; only a check that takes edges can use it",
    );
    // `width` takes edges as the edge twin of its polygon check.
    let (deck, strings) = ok("layer e = diff.edges()\nrule w width(e) >= 100nm\n");
    assert_eq!(strings.resolve(deck.rules.spec[0].kind), "edge_width");
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

/// Oracle: the operations of `docs/deck.md`, Layers: sizes on the grid, a
/// documented operation name, a non-empty range with one bound a side, a bound
/// written with a comparator, an area for `with_area`.
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

/// Oracle: `docs/deck.md`, Rules: the id is how violations are reported, so it
/// is unique, and `warning` is "ERC only".
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

/// Oracle: `docs/deck.md`, Errors: problems are "reported together (up to 50)".
/// Eighty off-grid rules give fifty; three different faults give three.
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

/// F74: a `pex` row that no process has is refused at the value, not read
/// as a capacitance or a gap that silently drops out. A conductor has a
/// thickness and a stated dielectric a permittivity, so zero is refused at
/// both; every other value only below zero, since a zero is "not stated".
/// A dielectric is not stated by leaving it out (how `generic_finfet` says
/// it extracts no capacitance), never by writing 0.
///
/// Oracle: `docs/deck.md`, Parasitic stack: "the thickness positive, a stated
/// dielectric positive, the rest zero or more", and the error marks the value,
/// so each case's caret is placed by hand under its value.
#[test]
fn a_pex_row_with_a_value_no_process_has_is_refused_at_the_value() {
    let row = |value: &str| {
        let text = "pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 \
                    area_cap 25.8aF/um2 fringe_cap 40.5aF/um";
        let (key, stated) = value.split_once(' ').expect("key and value");
        let at = text.find(&format!("{key} ")).expect("a key") + key.len() + 1;
        let end = at + text[at..].find(' ').unwrap_or(text.len() - at);
        format!("{}{stated}{}\n", &text[..at], &text[end..])
    };
    for (value, bound) in [
        ("thickness 0nm", "thickness must be positive"),
        ("thickness -360nm", "thickness must be positive"),
        ("height -1nm", "height must be zero or more"),
        ("sheet -0.125ohm", "sheet must be zero or more"),
        ("dielectric -3.9", "dielectric must be positive"),
        ("dielectric 0", "dielectric must be positive"),
        ("area_cap -25aF/um2", "area_cap must be zero or more"),
        ("fringe_cap -40aF/um", "fringe_cap must be zero or more"),
        // Past f64's range a decimal reads as infinite, which no process has.
        ("thickness 1e999nm", "thickness must be positive and finite"),
        ("sheet 1e999ohm", "sheet must be zero or more, and finite"),
    ] {
        let body = row(value);
        let mut strings = StrTable::default();
        let error = parse_deck(&format!("{HEAD}{body}"), grid(), &mut strings)
            .expect_err(value)
            .to_string();
        let stated = value.split_once(' ').expect("a value").1;
        let caret = format!(
            "{}{}",
            " ".repeat(body.find(stated).expect("the value")),
            "^".repeat(stated.len())
        );
        assert!(
            error.contains(&format!("pex `met1`: {bound}")) && error.ends_with(&caret),
            "{value}: {error}"
        );
    }
    for value in [
        "height 0nm",
        "sheet 0ohm",
        "area_cap 0aF/um2",
        "fringe_cap 0aF/um",
    ] {
        ok(&row(value));
    }
}

/// N-c7-2 (fixed on the base by D4 the same way): a decimal past `f64`'s range converts to infinity, which passed
/// "positive" and "zero or more" alike, so `thickness 1e400nm` was a stack
/// row of infinite thickness (and an infinite capacitance downstream). The
/// stack's own invariant, every value finite (asserted where it is built,
/// C7), refuses it at the value.
///
/// Oracle: IEEE 754, `1e400` overflows binary64 (largest finite about
/// `1.8e308`).
#[test]
fn a_pex_value_past_the_range_of_a_float_is_refused_at_the_value() {
    let full = |key: &str, stated: &str| {
        let row = [
            ("thickness", "360nm"),
            ("height", "1376nm"),
            ("sheet", "0.125ohm"),
            ("dielectric", "3.9"),
            ("area_cap", "25.8aF/um2"),
            ("fringe_cap", "40.5aF/um"),
        ]
        .map(|(k, v)| format!("{k} {}", if k == key { stated } else { v }));
        format!("pex met1 {}\n", row.join(" "))
    };
    for (key, stated) in [
        ("thickness", "1e400nm"),
        ("height", "1e400nm"),
        ("sheet", "1e400ohm"),
        ("dielectric", "1e400"),
        ("area_cap", "1e400aF/um2"),
        ("fringe_cap", "1e400aF/um"),
    ] {
        let mut strings = StrTable::default();
        let error = parse_deck(
            &format!("{HEAD}{}", full(key, stated)),
            grid(),
            &mut strings,
        )
        .expect_err(key)
        .to_string();
        assert!(
            error.contains(&format!("pex `met1`: {key} must be")) && error.contains("finite"),
            "{key} {stated}: {error}"
        );
    }
}

/// F74: a `pex` row may leave its dielectric out, which states none: it
/// lowers to `0.0`, the stack's "not stated", as a layer with no row does.
/// Every other key stays required.
///
/// Oracle: `docs/deck.md`, Parasitic stack: "Every value is required but the
/// dielectric", and a zero is "not stated"; the sheet is read back as written,
/// 1.2675 ohm.
#[test]
fn a_pex_row_may_leave_its_dielectric_out_and_nothing_else() {
    let (deck, strings) = ok("pex met1 thickness 36nm height 0nm sheet 1.2675ohm \
                              area_cap 0aF/um2 fringe_cap 0aF/um\n");
    let met1 = deck.layers.id(&strings, "met1").expect("met1").idx();
    assert_eq!(deck.stack.dielectric_k[met1].to_bits(), 0.0f64.to_bits());
    assert_eq!(
        deck.stack.sheet_res_ohm_sq[met1].to_bits(),
        1.2675f64.to_bits()
    );
    one_error(
        "pex met1 thickness 36nm height 0nm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n",
        "pex `met1` is missing sheet",
    );
}

/// Oracle: hand-derived. The format is `docs/deck.md`'s Errors example; the
/// `60` is on line 3 (after `grid` and `layer`) at column 26, two characters
/// wide.
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

/// The presence, net, table and attached-wide rows lower to their engine
/// kinds; which `space` and `wide_space` row is meant is read off the named
/// arguments given.
///
/// Oracle: the Kind / Deck form table of `docs/klayout-mirror.md` for each
/// row's kind, and the deck's values on the 1 nm grid by hand (280 nm is
/// 280 dbu, 3 um 3000, 1 um 1000; the table's cells in row order).
#[test]
fn presence_net_table_and_attached_rows_lower() {
    let (deck, strings) = ok("rule f forbidden(met3)\n\
         rule c contains(diff, licon) >= 2\n\
         rule i inside(licon, diff)\n\
         connect conductors [met1]\n\
         rule s space(met1) >= 140nm\n\
         rule n space(met1; nets: same) >= 200nm\n\
         rule w wide_space(met1; width: 3um) >= 280nm\n\
         rule a wide_space(met1; width: 3um, attached: 280nm) >= 280nm\n\
         rule t space_table(met1; prl: [0um, 1um], width: [0um, 300nm], \
            space: [[180nm, 180nm], [180nm, 220nm]])\n");
    let got = rules(&deck, &strings);
    let row = |id: &str| got.iter().find(|r| r.0 == id).expect(id).clone();
    let text = |items: &[&str]| items.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
    assert_eq!(row("f").1, "forbidden");
    assert_eq!(
        (row("c").1, row("c").2, row("c").3),
        (
            "must_contain".to_owned(),
            text(&["diff", "licon"]),
            text(&["min_count=#2"])
        )
    );
    assert_eq!(
        (row("i").1, row("i").2),
        ("must_be_inside".to_owned(), text(&["licon", "diff"]))
    );
    assert_eq!(row("s").1, "min_spacing");
    assert_eq!(
        (row("n").1, row("n").3),
        (
            "net_spacing".to_owned(),
            text(&["same_net=true", "limit=200dbu"])
        )
    );
    assert_eq!(row("w").1, "wide_dependent_spacing");
    assert_eq!(
        (row("a").1, row("a").3),
        (
            "attached_wide_spacing".to_owned(),
            text(&["width_threshold=3000dbu", "attached=280dbu", "limit=280dbu"])
        )
    );
    assert_eq!(
        (row("t").1, row("t").3),
        (
            "spacing_table".to_owned(),
            text(&[
                "prl=0dbu",
                "prl=1000dbu",
                "width=0dbu",
                "width=300dbu",
                "space=180dbu",
                "space=180dbu",
                "space=180dbu",
                "space=220dbu",
            ])
        )
    );
    one_error(
        "rule n space(met1; nets: some) >= 1um\n",
        "needs same or different",
    );
}

/// A spacing table must say what every pair needs, and never less for a wider
/// shape or a longer run.
///
/// Oracle: the spacing table rules of `docs/deck.md`: `prl` and `width` start
/// at 0 and rise, one row per width and one cell per run length, and no cell
/// smaller than the one before it in its row or column. Each case breaks one.
#[test]
fn a_spacing_table_is_complete_and_monotone() {
    let table = |prl: &str, width: &str, space: &str| {
        format!("rule t space_table(met1; prl: {prl}, width: {width}, space: {space})\n")
    };
    let rows = "[[180nm, 180nm], [180nm, 220nm]]";
    one_error(
        &table("[100nm, 1um]", "[0um, 300nm]", rows),
        "`prl` starts at 0",
    );
    one_error(
        &table("[0um, 1um]", "[0um, 0um]", rows),
        "`width` must rise strictly",
    );
    one_error(
        &table("[0um, 1um]", "[0um, 300nm]", "[[180nm, 180nm]]"),
        "one row per width: 2, got 1",
    );
    one_error(
        &table("[0um, 1um]", "[0um, 300nm]", "[[180nm, 180nm], [180nm]]"),
        "one cell per run length: 2, got 1",
    );
    one_error(
        &table(
            "[0um, 1um]",
            "[0um, 300nm]",
            "[[180nm, 170nm], [180nm, 220nm]]",
        ),
        "cannot fall along a row or down a column",
    );
    one_error(
        &table(
            "[0um, 1um]",
            "[0um, 300nm]",
            "[[180nm, 220nm], [180nm, 200nm]]",
        ),
        "cannot fall along a row or down a column",
    );
    one_error(
        &table(
            "[0um, 1um]",
            "[0um, 300nm]",
            "[[180, 180nm], [180nm, 220nm]]",
        ),
        "needs a length",
    );
}

/// A rule may take a layer expression where it takes a layer; it becomes a
/// derived layer of its own.
///
/// Oracle: `docs/deck.md`'s `forbidden(licon and poly and (diff or tap))` form:
/// an expression argument becomes a derived layer, and a named layer stays
/// itself.
#[test]
fn a_rule_argument_may_be_a_layer_expression() {
    let (deck, strings) = ok("rule x.1 forbidden(licon and poly and (diff or met1))\n\
         rule x.2 space(met1.sized(10nm), met2) >= 100nm\n\
         rule x.3 width(met1) >= 100nm\n");
    let got = rules(&deck, &strings);
    for (spec, id) in deck.rules.spec.iter().zip(["x.1", "x.2"]) {
        let layer = deck.rules.layers_of(spec)[0];
        assert!(deck.layers.is_derived(layer), "{id} reads a derived layer");
    }
    assert_eq!(got[1].2[1], "met2");
    assert_eq!(got[2].2, ["met1"]);
    one_error(
        "rule x.1 forbidden(licon and nothing)\n",
        "unknown layer `nothing`",
    );
}

/// Edge checks take edge layers where they say so, and an edge layer picks
/// the edge form of `space` and `enclosure`.
///
/// Oracle: the Edge checks table of `docs/deck.md` with the Kind / Deck form
/// table of `docs/klayout-mirror.md`: `length(E)` is `edge_min_length`,
/// `space(E[, F])` `edge_spacing`, `enclosure(E, L)` `edge_enclosure`, and the
/// same names on polygon layers keep their polygon kinds.
#[test]
fn edge_checks_take_edge_layers_in_their_edge_slots() {
    let (deck, strings) = ok("layer e = diff.edges() not poly.edges()\n\
         rule l length(e) >= 290nm\n\
         rule s1 space(e) >= 400nm\n\
         rule s2 space(e, poly.edges()) >= 130nm\n\
         rule en enclosure(e, met1) >= 125nm\n\
         rule f forbidden(e.outside_part(met1))\n\
         rule p space(diff, poly) >= 100nm\n\
         rule q enclosure(licon, diff) >= 40nm\n");
    let kinds: Vec<String> = rules(&deck, &strings).into_iter().map(|r| r.1).collect();
    assert_eq!(
        kinds,
        [
            "edge_min_length",
            "edge_spacing",
            "edge_spacing",
            "edge_enclosure",
            "forbidden",
            "min_spacing_diff",
            "min_enclosure"
        ]
    );
    one_error(
        "rule l length(met1) >= 1um\n",
        "takes an edge layer; `met1` is polygons",
    );
    one_error(
        "layer e = diff.edges()\nrule s space(e, met1) >= 1um\n",
        "takes an edge layer; `met1` is polygons",
    );
    one_error(
        "layer e = diff.edges()\nrule en enclosure(e, e) >= 1um\n",
        "`e` is an edge layer",
    );
}

/// `with_text` reads a drawn text layer and a quoted pattern.
///
/// Oracle: the `with_text` operation of `docs/deck.md`: text is drawn on a GDS
/// layer, and the pattern is a non-empty quoted string.
#[test]
fn a_text_selection_needs_a_drawn_layer_and_a_pattern() {
    let (deck, strings) = ok("layer label = gds(68, 5)\n\
         layer vdd = met1.with_text(label, \"VDD*\")\n\
         layer other = met1.without_text(label, \"VDD?\")\n");
    let vdd = deck.layers.id(&strings, "vdd").expect("vdd");
    assert!(deck.layers.is_derived(vdd) && !deck.layers.is_edges(vdd));
    one_error(
        "layer x = met1 and met2\nlayer y = met1.with_text(x, \"A\")\n",
        "`x` is derived; text is drawn on a GDS layer",
    );
    one_error(
        "layer y = met1.with_text(met2, VDD)\n",
        "expected a text pattern in quotes",
    );
    one_error(
        "layer y = met1.with_text(met2, \"\")\n",
        "an empty pattern matches no text",
    );
}

/// A cell selection built in code meets the parser's refusals in `lower`:
/// a derived receiver, a pattern range past the table, a refused glob
/// character; the well-formed one lowers (DRC-092).
///
/// Oracle: `lower`'s contract, "a source built by anyone lowers to a deck the
/// engines can trust as one parsed from text", against the parser's rules.
#[test]
fn a_cell_selection_built_in_code_is_held_to_the_parser_s_rules() {
    use gpurify_ingest::deck::{lower, DeckSource, DerivedOp, DerivedSource};
    let source = |receiver: &str, first: u32, count: u32, pattern: &str| {
        let mut source = DeckSource::default();
        source.layers.push(("met1".to_owned(), (68, 20)));
        source.derived.push(DerivedSource {
            name: "big".to_owned(),
            op: DerivedOp::Sized(gpurify_geom::Dbu::new_unchecked(10)),
            layers: vec!["met1".to_owned()],
        });
        source.derived.push(DerivedSource {
            name: "pad".to_owned(),
            op: DerivedOp::InCells {
                keep: true,
                first,
                count,
            },
            layers: vec![receiver.to_owned()],
        });
        source.texts.push(pattern.to_owned());
        lower(&source, &mut StrTable::default())
    };
    assert!(source("met1", 0, 1, "PAD*").is_ok());
    assert!(source("big", 0, 1, "PAD*").is_err(), "a derived receiver");
    assert!(
        source("met1", 0, 2, "PAD*").is_err(),
        "a range past the table"
    );
    assert!(source("met1", 0, 0, "PAD*").is_err(), "no pattern");
    assert!(source("met1", 0, 1, "PAD[12]").is_err(), "a class");
}

/// `in_cells` / `not_in_cells` (DRC-092) select a drawn layer by one or more
/// quoted cell-name patterns, `*` and `?` only, at most 64 in a deck.
///
/// Oracle: the `in_cells` operation of `docs/deck.md`: a drawn receiver, a
/// non-empty pattern list, `KLayout`'s other glob characters refused rather
/// than read differently, and `MAX_CELL_SELECTIONS` (one tag bit each).
#[test]
fn a_cell_selection_takes_a_drawn_layer_and_glob_patterns() {
    let (deck, strings) = ok("layer pad = met1.in_cells(\"PAD_*\", \"pad?\")\n\
         layer rest = met1.not_in_cells(\"PAD_*\")\n");
    let pad = deck.layers.id(&strings, "pad").expect("pad");
    assert!(deck.layers.is_derived(pad) && !deck.layers.is_edges(pad));
    assert!(matches!(
        deck.layers.op(pad),
        Some(gpurify_ingest::deck::DerivedOp::InCells {
            keep: true,
            count: 2,
            ..
        })
    ));
    one_error(
        "layer x = met1 and met2\nlayer y = x.in_cells(\"A\")\n",
        "apply it to a `gds(..)` layer",
    );
    one_error(
        "layer y = (met1 and met2).not_in_cells(\"A\")\n",
        "apply it to a `gds(..)` layer",
    );
    one_error(
        "layer y = met1.in_cells(PAD)\n",
        "expected a cell-name pattern in quotes",
    );
    one_error(
        "layer y = met1.in_cells(\"\")\n",
        "an empty pattern matches no cell",
    );
    for refused in ["[AB]*", "{A,B}", "A\\\\*"] {
        one_error(
            &format!("layer y = met1.in_cells(\"{refused}\")\n"),
            "takes `*` and `?` only",
        );
    }
    let mut many = String::new();
    for i in 0..=gpurify_ingest::deck::MAX_CELL_SELECTIONS {
        writeln!(many, "layer s{i} = met1.in_cells(\"C{i}\")").expect("a String takes any write");
    }
    one_error(&many, "at most 64");
}

/// `ignore gds(L, D)` lists stream pairs to drop. It may not repeat, nor name a
/// declared layer's pair, whichever statement comes first.
///
/// Oracle: `docs/deck.md`, Layers: "A pair cannot be both ignored and declared,
/// and cannot be ignored twice", in either statement order.
#[test]
fn an_ignored_pair_is_listed_and_may_not_repeat_or_be_declared() {
    let (deck, _) = ok("ignore gds(81, 4)\nignore gds(12, 0)\n");
    assert!(deck.layers.is_ignored(81, 4) && deck.layers.is_ignored(12, 0));
    assert!(
        !deck.layers.is_ignored(68, 20),
        "a declared layer is not ignored"
    );
    assert!(!deck.layers.is_ignored(81, 5));

    one_error(
        "ignore gds(81, 4)\nignore gds(81, 4)\n",
        "gds(81, 4) is already ignored",
    );
    one_error(
        "ignore gds(68, 20)\n",
        "gds(68, 20) is ignored, but layer `met1` is declared on it",
    );
    one_error(
        "ignore gds(90, 0)\nlayer late = gds(90, 0)\n",
        "gds(90, 0) is ignored, but layer `late` is declared on it",
    );
    one_error(
        "ignore met1\n",
        "expected `gds(layer, datatype)`, found `met1`",
    );
}

/// sky130's metal rows as `pex` lines: `sheet` at the models' `tnom`, 30 °C,
/// with the models' `tc1rm1`/`tc2rm1` and `tc1rm2`/`tc2rm2`.
const SKY130_METALS: &str = "\
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um tc1 3.179e-3/K tc2 3.094e-7/K2
pex met2 thickness 360nm height 2006nm sheet 0.125ohm dielectric 3.9 area_cap 17.5aF/um2 fringe_cap 37.6aF/um tc1 3.161e-3/K tc2 -7.272e-7/K2
";

/// PEX-007: a deck's `temperature` moves each `pex` row's sheet resistance
/// from the nominal temperature it is stated at to the operating one, by the
/// row's own coefficients, and becomes the run's operating temperature.
///
/// Oracle: closed form `R(T) = R0 (1 + tc1 ΔT + tc2 ΔT²)` (ngspice's resistor
/// law), evaluated by hand with sky130's published met1 and met2 coefficients
/// (`sky130_fd_pr__model__r+c.model.spice`, `tnom = 30`) at 85 °C, ΔT = 55 K:
/// met1 `0.125 × (1 + 0.174845 + 0.000935935) = 0.146972616875 Ω`, met2
/// `0.125 × (1 + 0.173855 − 0.00219978) = 0.1464569025 Ω`; and 85 °C is
/// 358.15 K. Dropping `tc2` (0.08 % and 0.19 % off), or reading ΔT from 0 °C,
/// misses far past the 1e-12 tolerance.
#[test]
fn a_temperature_moves_each_sheet_resistance_by_its_own_coefficients() {
    let (deck, strings) = ok(&format!("temperature 85C nominal 30C\n{SKY130_METALS}"));
    for (layer, want) in [("met1", 0.146_972_616_875), ("met2", 0.146_456_902_5)] {
        let at = deck.layers.id(&strings, layer).expect("declared").idx();
        let got = deck.stack.sheet_res_ohm_sq[at];
        assert!(
            (got / want - 1.0).abs() < 1e-12,
            "{layer}: {got} ohm, the closed form says {want}"
        );
    }
    let kelvin = deck.temperature.expect("stated").raw();
    assert!((kelvin - 358.15).abs() < 1e-9, "{kelvin} K");
}

/// PEX-007: at its nominal temperature a deck reads every sheet resistance
/// exactly as written, so stating the temperature changes nothing there.
///
/// Oracle: metamorphic relation: the deck run at `T = T0` and the same deck
/// with no temperature and no coefficients give bit-identical stacks (ΔT is
/// exactly 0, so the factor is exactly 1), each sheet the 0.125 Ω written.
#[test]
fn at_its_nominal_temperature_a_deck_reads_its_sheets_as_written() {
    let (hot, strings) = ok(&format!("temperature 30C nominal 30C\n{SKY130_METALS}"));
    let plain: String = SKY130_METALS
        .lines()
        .flat_map(|line| [&line[..line.find(" tc1").expect("a tc1")], "\n"])
        .collect();
    let (cold, _) = ok(&plain);
    let bits = |stack: &[f64]| stack.iter().map(|v| v.to_bits()).collect::<Vec<_>>();
    let met1 = hot.layers.id(&strings, "met1").expect("met1").idx();
    assert_eq!(
        hot.stack.sheet_res_ohm_sq[met1].to_bits(),
        0.125f64.to_bits()
    );
    assert_eq!(
        bits(&hot.stack.sheet_res_ohm_sq),
        bits(&cold.stack.sheet_res_ohm_sq)
    );
    assert!(cold.temperature.is_none());
}

/// A temperature and its coefficients come together or not at all, and every
/// value has its unit.
///
/// Oracle: `docs/deck.md`, Parasitic stack: with a `temperature` every row
/// gives `tc1` and `tc2`, without one none does, both or neither on a row,
/// coefficients in `/K` and `/K2`, the resistance positive at temperature
/// (`1 − 0.02 × 55 = −0.1` here), one statement, above absolute zero.
#[test]
fn a_temperature_and_its_coefficients_come_together() {
    let malformed = |body: &str, needle: &str| match parse(body) {
        Err(DeckError::Malformed(message)) => {
            assert!(message.contains(needle), "{message}");
        }
        Err(other) => panic!("{body}: {other}"),
        Ok(_) => panic!("accepted:\n{body}"),
    };
    malformed(
        SKY130_METALS,
        "pex met1: tc1 and tc2 need a `temperature` statement",
    );
    let row = "pex met1 thickness 360nm height 1376nm sheet 0.125ohm area_cap 0aF/um2 \
               fringe_cap 0aF/um";
    malformed(
        &format!("temperature 85C nominal 30C\n{row}\n"),
        "pex met1: the deck states a temperature, so the row needs tc1 and tc2",
    );
    malformed(
        &format!("temperature 85C nominal 30C\n{row} tc1 -0.02/K tc2 0/K2\n"),
        "a resistance stays positive",
    );
    one_error(
        &format!("temperature 85C nominal 30C\n{row} tc1 3e-3/K\n"),
        "pex `met1` gives one of tc1 and tc2; give both, or neither",
    );
    one_error(
        &format!("temperature 85C nominal 30C\n{row} tc1 3e-3 tc2 0/K2\n"),
        "tc1 needs a coefficient per kelvin",
    );
    one_error(
        &format!("temperature 85C nominal 30C\n{row} tc1 3e-3/K tc2 3e-7/K\n"),
        "tc2 needs a coefficient per kelvin squared",
    );
    one_error(
        "temperature 85C nominal 30C\ntemperature 85C nominal 30C\n",
        "the temperature is already stated",
    );
    one_error(
        "temperature -300C nominal 30C\n",
        "temperature must be above absolute zero",
    );
    one_error("temperature 85C\n", "expected `nominal`");
}

/// Oracle: LEF/DEF 5.8's `PWL ( ( d1 r1 ) ( d2 r2 ) ... )`, written as a list
/// of `(area, number)` points: each point lowers to its area in square grid
/// units (1 nm grid: 0.0125 µm² is 12 500) and its number, in deck order.
/// Areas must start at 0 or more and rise strictly, as LEF's diffusion values
/// do; a point is a pair, and a table has one.
#[test]
fn a_piecewise_linear_table_lowers_point_by_point_and_must_rise() {
    let row = |table: &str| {
        format!(
            "rule ae antenna_electrical(poly, met1; max_ratio: 400, sidewall: none, cut_factor: 1, diode: diff,
    diode_credit: 0, diode_bonus: 0, area_minus_diode: 0, gate_plus_diode: 0,
    diode_reduce: none, diode_max_ratio: {table}, exempt: none)\n"
        )
    };
    let (deck, strings) = ok(&row("[(0um2, 400), (0.0125um2, 400), (22.5um2, 11600)]"));
    assert_eq!(
        rules(&deck, &strings)[0].3,
        [
            "max_ratio=400",
            "cut_factor=1",
            "diode_layer=diff",
            "diode_credit=0",
            "diode_bonus=0",
            "area_minus_diode=0",
            "gate_plus_diode=0",
            "diode_max_ratio_area=0dbu2",
            "diode_max_ratio=400",
            "diode_max_ratio_area=12500dbu2",
            "diode_max_ratio=400",
            "diode_max_ratio_area=22500000dbu2",
            "diode_max_ratio=11600",
        ]
    );
    one_error(&row("[(0.1um2, 400), (0.1um2, 500)]"), "rise strictly");
    one_error(&row("[(0.1um2, 400), (0.05um2, 500)]"), "rise strictly");
    one_error(&row("[(0um2, 400, 1)]"), "(area, number) points");
    one_error(&row("[]"), "at least one point");
}
