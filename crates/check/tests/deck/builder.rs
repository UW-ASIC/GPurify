//! The deck builder: the Rust twin of every shipped deck, the builder's twin
//! of every parser refusal, and the override algebra (deck-library plan P3,
//! testing-plan L9b).

use super::{grid, twins, DECKS};
use gpurify_check::deck::rules::{
    antenna, forbidden, gate_oxide, max_distance_to_tap, min_area, min_spacing, min_width,
    net_spacing,
};
use gpurify_check::deck::{
    compile, Bound, BuildError, CompileError, CompiledDeck, DeckBuilder, LayerRef, Origin,
};
use gpurify_check::drc::DrcError;
use gpurify_geom::{Dbu, DbuArea, StrId, StrTable};
use gpurify_ingest::deck::DeckError;

fn nm(raw: i64) -> Dbu {
    Dbu::new_unchecked(raw)
}

/// `got` is `expected`: named the same, layer by layer and rule by rule, so a
/// difference is reported by name before the typed decks are compared whole.
pub(crate) fn assert_same(
    what: &str,
    expected: &CompiledDeck,
    got: &CompiledDeck,
    strings: &StrTable,
) {
    let (want, have) = (expected.source(strings), got.source(strings));
    let layers = |kind: &str, want: &[(String, (u16, u16))], have: &[(String, (u16, u16))]| {
        let sorted = |rows: &[(String, (u16, u16))]| {
            let mut rows = rows.to_vec();
            rows.sort();
            rows
        };
        assert_eq!(sorted(want), sorted(have), "{what}: the {kind} layers");
    };
    layers("drawn", &want.layers, &have.layers);
    for (at, (want_row, have_row)) in want.derived.iter().zip(&have.derived).enumerate() {
        assert_eq!(want_row, have_row, "{what}: derived layer {at}");
    }
    assert_eq!(
        want.derived.len(),
        have.derived.len(),
        "{what}: derived layers"
    );
    assert_eq!(want.texts, have.texts, "{what}: text patterns");
    for (want_rule, have_rule) in want.rules.iter().zip(&have.rules) {
        assert_eq!(want_rule, have_rule, "{what}: rule {}", want_rule.id);
    }
    assert_eq!(want.rules.len(), have.rules.len(), "{what}: rules");
    assert_eq!(want.connectivity, have.connectivity, "{what}: connectivity");
    assert_eq!(want.devices, have.devices, "{what}: devices");
    assert_eq!(want.pex, have.pex, "{what}: pex rows");
    assert_eq!(want.ignored, have.ignored, "{what}: ignored pairs");
    assert_eq!(want.lvs, have.lvs, "{what}: lvs statements");
    assert!(
        expected == got,
        "{what}: the compiled decks differ beyond their names"
    );
}

/// Every shipped deck equals its Rust twin: `parse(text) == build(rust)`,
/// field by field (L9b "text and Rust decks are the same thing"). Both are
/// compiled into one string table, so their ids are comparable.
/// Oracle: differential against the parser, of a twin translated from the
/// deck text by a reader of `docs/deck.md` independent of the parser.
#[test]
fn every_shipped_deck_equals_its_rust_twin() {
    type Build = fn(&mut StrTable) -> Result<CompiledDeck, BuildError>;
    let builds: [Build; 4] = [
        twins::generic_finfet::build,
        twins::gf180mcu::build,
        twins::ihp_sg13g2::build,
        twins::sky130::build,
    ];
    for ((name, text), build) in DECKS.iter().zip(builds) {
        let mut strings = StrTable::default();
        let parsed = compile(text, grid(), &mut strings).expect("a shipped deck compiles");
        let built = build(&mut strings).unwrap_or_else(|why| panic!("{name}: the twin: {why}"));
        assert_same(name, &parsed, &built, &strings);
    }
}

/// The parser's refusal of `text`, as one message.
fn parser_refusal(text: &str) -> String {
    match compile(text, grid(), &mut StrTable::default()) {
        Err(CompileError::Deck(DeckError::Invalid { diagnostics, .. })) => diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join("\n"),
        Err(CompileError::Deck(DeckError::Malformed(why))) => why,
        other => panic!("{text:?} is not refused as text: {other:?}"),
    }
}

/// The builder's refusal, as one message, and the line of the first call it
/// names.
fn builder_refusal(error: BuildError) -> (String, Option<u32>) {
    match error {
        BuildError::Invalid(diagnostics) => (
            diagnostics
                .iter()
                .map(|d| d.message.clone())
                .collect::<Vec<_>>()
                .join("\n"),
            diagnostics.first().map(|d| {
                assert!(d.at.file().ends_with("builder.rs"), "{:?}", d.at);
                d.at.line()
            }),
        ),
        BuildError::Compile(CompileError::Deck(DeckError::Malformed(why))) => (why, None),
        other @ BuildError::Compile(_) => panic!("not a builder refusal: {other:?}"),
    }
}

/// The parser's message, the builder's with the line it names, and the
/// line expected.
type Case = (String, (String, Option<u32>), Option<u32>);

/// The text twins' two layers, in a builder of its own string table.
fn start(strings: &mut StrTable) -> (DeckBuilder<'_>, LayerRef, LayerRef) {
    let mut d = DeckBuilder::new(grid(), strings);
    let m = d.layer("m", (1, 0));
    let n = d.layer("n", (2, 0));
    (d, m, n)
}

/// Every refusal of the parser has a builder twin that refuses the same
/// thing in the same words, at the line of the call that did it (L9b "the
/// builder validates like the parser"). A missing unit and `<=` on a minimum
/// cannot be written in Rust at all: no constructor takes a bare number for
/// a length, and none spells a maximum of a minimum rule (see the
/// `compile_fail` examples of `deck::rules`). `DeckError::Io` is a file
/// read, which a builder never does.
/// Oracle: differential, the parser's message for the text twin, and the
/// line of each call, counted with `line!()`.
#[test]
fn every_parser_refusal_has_a_builder_twin() {
    const HEADER: &str = "grid 1nm\nlayer m = gds(1, 0)\nlayer n = gds(2, 0)\n";
    let text = |rest: &str| format!("{HEADER}{rest}");
    let mut cases: Vec<Case> = Vec::new();

    // A rule id used twice.
    let mut strings = StrTable::default();
    let (mut d, m, _) = start(&mut strings);
    d.rule("a", min_width(m, nm(10)));
    let line = line!() + 1;
    d.rule("a", min_width(m, nm(20)));
    cases.push((
        parser_refusal(&text("rule a width(m) >= 10nm\nrule a width(m) >= 20nm\n")),
        builder_refusal(d.finish().unwrap_err()),
        Some(line),
    ));

    // A layer the deck does not declare.
    let mut strings = StrTable::default();
    let (mut d, _, _) = start(&mut strings);
    let line = line!() + 1;
    let nope = d.get("nope");
    d.rule("a", min_width(nope, nm(10)));
    cases.push((
        parser_refusal(&text("rule a width(nope) >= 10nm\n")),
        builder_refusal(d.finish().unwrap_err()),
        Some(line),
    ));

    // A layer name bound twice.
    let mut strings = StrTable::default();
    let (mut d, _, _) = start(&mut strings);
    let line = line!() + 1;
    d.layer("m", (3, 0));
    cases.push((
        parser_refusal(&text("layer m = gds(3, 0)\n")),
        builder_refusal(d.finish().unwrap_err()),
        Some(line),
    ));

    // Bounds nothing satisfies.
    let mut strings = StrTable::default();
    let (mut d, m, _) = start(&mut strings);
    let line = line!() + 1;
    let empty = m.with_area(&[
        Bound::AtLeast(DbuArea::new(2)),
        Bound::AtMost(DbuArea::new(1)),
    ]);
    d.derived("x", empty);
    cases.push((
        parser_refusal(&text("layer x = m.with_area(>= 2nm2, <= 1nm2)\n")),
        builder_refusal(d.finish().unwrap_err()),
        Some(line),
    ));

    // A derived layer that is only a layer.
    let mut strings = StrTable::default();
    let (mut d, m, _) = start(&mut strings);
    let line = line!() + 1;
    d.derived("x", m);
    cases.push((
        parser_refusal(&text("layer x = m\n")),
        builder_refusal(d.finish().unwrap_err()),
        Some(line),
    ));

    // A model no device declares (malformed: a relation between statements).
    let mut strings = StrTable::default();
    let (mut d, _, _) = start(&mut strings);
    d.rule("r", gate_oxide(&["ghost"], 1000.0));
    cases.push((
        parser_refusal(&text("rule r gate_oxide(; models: [\"ghost\"], max: 1V)\n")),
        builder_refusal(d.finish().unwrap_err()),
        None,
    ));

    // Net spacing on a layer that carries no net.
    let mut strings = StrTable::default();
    let (mut d, m, _) = start(&mut strings);
    d.rule("r", net_spacing(m, true, nm(10)));
    cases.push((
        parser_refusal(&text("rule r space(m; nets: same) >= 10nm\n")),
        builder_refusal(d.finish().unwrap_err()),
        None,
    ));

    for (parsed, (built, at), line) in cases {
        assert!(
            parsed.contains(&built) || built.contains(&parsed),
            "the builder refuses {built:?} where the parser refuses {parsed:?}"
        );
        assert_eq!(at, line, "{built}: reported at the wrong call");
    }

    // `warning` on a DRC rule, a recommended rule (DRC-110): the parser and
    // the builder both take it.
    assert!(compile(
        &text("rule a warning width(m) >= 10nm\n"),
        grid(),
        &mut StrTable::default()
    )
    .is_ok());
    let mut strings = StrTable::default();
    let (mut d, m, _) = start(&mut strings);
    d.rule("a", min_width(m, nm(10)).warning());
    assert!(d.finish().is_ok());

    // A value a kind cannot hold is refused by the same typed check.
    let mut strings = StrTable::default();
    let (mut d, m, _) = start(&mut strings);
    d.rule("a", min_width(m, nm(0)));
    assert!(matches!(
        d.finish(),
        Err(BuildError::Compile(CompileError::Drc(
            DrcError::NonPositiveLimit { .. }
        )))
    ));
}

/// A small base deck to override: two DRC rules, an ERC rule, a device.
const BASE: &str = "grid 1nm
layer gate = gds(1, 0)
layer met1 = gds(2, 0)
layer met3 = gds(3, 0)
layer tap = gds(4, 0)
layer well = gds(5, 0)
rule m1.1 width(met1) >= 140nm
rule m1.2 space(met1) >= 140nm
rule ar.met3.1 antenna(gate, met3; max_ratio: 400, sidewall: 2000nm, diode: none)
rule x.18 forbidden(met3 and tap)
connect conductors [met1, met3]
device mos gate model \"nfet\" terminals [gate, met1, met1, well]
";

/// The overrides of one permutation, in the order given.
#[derive(Debug, Clone, Copy)]
enum Override {
    AddLu,
    AddArea,
    ReplaceAntenna,
    RemoveForbidden,
}

fn apply(d: &mut DeckBuilder<'_>, overrides: &[Override]) {
    let met1 = d.get("met1");
    let met3 = d.get("met3");
    let gate = d.get("gate");
    let (well, tap) = (d.get("well"), d.get("tap"));
    for &step in overrides {
        match step {
            Override::AddLu => d.add("LU.2", max_distance_to_tap(well, tap, nm(15_000))),
            Override::AddArea => d.add("m1.6", min_area(met1, DbuArea::new(83_000))),
            Override::ReplaceAntenna => d.replace(
                "ar.met3.1",
                antenna(gate, &[met3], 400.0, Some(nm(845)), None),
            ),
            Override::RemoveForbidden => d.remove("x.18"),
        }
    }
}

/// The override algebra (L9b "overrides are explicit"): replacing or
/// removing an absent id is refused, never an add; adding an id that exists
/// is refused; removing an id then adding it equals replacing it; the order
/// of the overrides does not change the deck; and the provenance says which
/// rules were added and which replaced.
/// Oracle: laws, each one deck-library plan §4.3 states.
#[test]
fn overrides_are_explicit_and_their_order_does_not_matter() {
    use Override::{AddArea, AddLu, RemoveForbidden, ReplaceAntenna};
    let mut strings = StrTable::default();
    let base = compile(BASE, grid(), &mut strings).expect("the base deck compiles");

    // Absent ids are refused, and a present one cannot be added again.
    let mut d = DeckBuilder::from_deck(&base, &mut strings);
    let met1 = d.get("met1");
    d.replace("no.such", min_width(met1, nm(1)));
    d.remove("no.such");
    d.add("m1.1", min_width(met1, nm(1)));
    let BuildError::Invalid(refused) = d.finish().unwrap_err() else {
        panic!("an override of an absent or present id is the builder's refusal");
    };
    let messages: Vec<&str> = refused.iter().map(|d| d.message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "replace of rule `no.such`, which the deck does not have",
            "remove of rule `no.such`, which the deck does not have",
            "duplicate rule id `m1.1`",
        ]
    );

    // Remove then add is replace.
    let replaced = {
        let mut d = DeckBuilder::from_deck(&base, &mut strings);
        let met1 = d.get("met1");
        d.replace("m1.2", min_spacing(met1, nm(200)));
        d.finish().expect("a replacement builds")
    };
    let removed_and_added = {
        let mut d = DeckBuilder::from_deck(&base, &mut strings);
        let met1 = d.get("met1");
        d.remove("m1.2");
        d.add("m1.2", min_spacing(met1, nm(200)));
        d.finish().expect("a removal and an add build")
    };
    assert_same("remove then add", &replaced, &removed_and_added, &strings);

    // Every order of four overrides gives one deck, each in a string table of
    // its own: the same names interned in the same order, so the same ids and
    // so the same report bytes (deck-library plan §4.3).
    let orders = [
        [AddLu, AddArea, ReplaceAntenna, RemoveForbidden],
        [RemoveForbidden, ReplaceAntenna, AddArea, AddLu],
        [AddArea, RemoveForbidden, AddLu, ReplaceAntenna],
        [ReplaceAntenna, AddLu, RemoveForbidden, AddArea],
    ];
    let names = |strings: &StrTable| -> Vec<String> {
        (0..strings.len())
            .map(|at| {
                let id = StrId(u32::try_from(at).expect("a deck has few names"));
                strings.resolve(id).to_owned()
            })
            .collect()
    };
    let mut decks = orders.iter().map(|order| {
        let mut strings = StrTable::default();
        let base = compile(BASE, grid(), &mut strings).expect("the base deck compiles");
        let mut d = DeckBuilder::from_deck(&base, &mut strings);
        apply(&mut d, order);
        let deck = d.finish().unwrap_or_else(|why| panic!("{order:?}: {why}"));
        (deck, strings)
    });
    let (first, mut first_strings) = decks.next().expect("four orders");
    for (order, (deck, strings)) in orders.iter().skip(1).zip(decks) {
        assert_eq!(
            names(&strings),
            names(&first_strings),
            "{order:?}: interning order"
        );
        assert_same(&format!("{order:?}"), &first, &deck, &first_strings);
    }

    // Provenance: what was added, replaced, kept; the removed rule is gone.
    let origin: Vec<(&str, Origin)> = first
        .provenance
        .iter()
        .map(|&(id, origin)| (first_strings.resolve(id), origin))
        .collect();
    assert_eq!(
        origin,
        [
            ("m1.1", Origin::Base),
            ("m1.2", Origin::Base),
            ("ar.met3.1", Origin::Replaced),
            ("LU.2", Origin::Added),
            ("m1.6", Origin::Added),
        ]
    );
    assert!(
        first
            .drc
            .rules
            .iter()
            .all(|(id, _)| first_strings.resolve(*id) != "x.18"),
        "x.18 was removed"
    );

    // An override deck survives printing like any other.
    super::printer::assert_round_trip("overridden", &first, &mut first_strings);
}

/// Layers, devices and parasitic rows take the same operations: add a drawn
/// and a derived layer, replace a derived layer in place, remove a device,
/// add a pex row.
/// Oracle: construct-from-answer: the same deck written as text.
#[test]
fn layers_devices_and_pex_rows_are_overridden_too() {
    let mut strings = StrTable::default();
    let base = compile(
        &format!("{BASE}layer lu = (tap and well).sized(1000nm)\n"),
        grid(),
        &mut strings,
    )
    .expect("the base deck compiles");
    let mut d = DeckBuilder::from_deck(&base, &mut strings);
    let npn = d.layer("npn", (82, 20));
    let well = d.get("well");
    let tap = d.get("tap");
    d.derived("lu_npn", npn.and(well));
    d.replace_layer("lu", tap.and(well).group().sized(nm(2000)));
    d.remove_device("nfet");
    let met1 = d.get("met1");
    d.pex(
        met1,
        gpurify_ingest::deck::StackSource {
            thickness_nm: 360.0,
            height_nm: 1376.0,
            sheet_res_ohm_sq: 0.125,
            area_cap_af_um2: 25.8,
            fringe_cap_af_um: 40.5,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    let lu_npn = d.get("lu_npn");
    d.add("LU.3", forbidden(lu_npn));
    let built = d.finish().expect("the overridden deck builds");

    let written = BASE
        .replace("device mos gate model \"nfet\" terminals [gate, met1, met1, well]\n", "")
        .replace(
            "layer well = gds(5, 0)\n",
            "layer well = gds(5, 0)\nlayer npn = gds(82, 20)\n",
        )
        + "layer lu = (tap and well).sized(2000nm)\nlayer lu_npn = npn and well\nrule LU.3 forbidden(lu_npn)\n"
        + "pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um\n";
    let text = compile(&written, grid(), &mut strings).expect("the text twin compiles");
    let mut expected = text;
    // The provenance of the text twin is all its own; the override's says LU.3 was added.
    for (id, origin) in &mut expected.provenance {
        if strings.resolve(*id) == "LU.3" {
            *origin = Origin::Added;
        }
    }
    assert_same(
        "layer, device and pex overrides",
        &expected,
        &built,
        &strings,
    );
}
