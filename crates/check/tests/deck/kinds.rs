//! Every rule kind and layer operation the shipped decks do not exercise:
//! its constructor, the printer and the query API, on one deck that states
//! each of them (`docs/deck.md`'s spellings).

use super::builder::assert_same;
use super::grid;
use super::printer::assert_round_trip;
use gpurify_check::deck::rules::{
    allowed_width, aspect_ratio, count, cut_class, edge_facing_space, edge_width, forbidden,
    min_interior_angle, min_step, polygon_validity, region_density, total_area,
};
use gpurify_check::deck::{compile, Bound, CompiledDeck, DeckBuilder};
use gpurify_check::drc::StepKind;
use gpurify_geom::{Dbu, DbuArea, StrTable};
use gpurify_ingest::deck::StackSource;

const TEXT: &str = "grid 1nm
layer m = gds(1, 0)
layer r = gds(2, 0)
layer v = gds(3, 0)
layer rects = m.rectangles()
layer squares = m.squares()
layer odd = m.non_rectangles()
layer long = m.with_bbox_max(> 1000nm)
layer thin = v.non_squares().with_bbox_min(>= 100nm, < 200nm)
rule c.min count(m) >= 1
rule c.max count(m) <= 4
rule ar aspect_ratio(m) <= 3
rule ta total_area(m) <= 1000000nm2
rule cc size(v; allowed: [150nm x 150nm, 230nm x 150nm])
rule ew width(m.edges().horizontal()) >= 40nm
rule fs facing_space(m.edges().vertical()) >= 30nm
rule rd.min region_density(m, r) >= 0.1
rule rd.max region_density(m, r) <= 0.5
rule aw width(m; allowed: [350nm, 690nm])
rule ia.m interior_angle(m) >= 87deg
rule ia interior_angle() >= 90deg
rule vd.m valid(m)
rule vd valid()
rule ms.edges min_step(m; max_edges: 2) >= 50nm
rule ms.inside min_step(m; corner: inside, length_sum: 100nm) >= 50nm
rule ms.step min_step(m; corner: step, length_sum: none) >= 60nm
rule odd.none forbidden(odd)
temperature 358.15K nominal 303.15K
pex m thickness 360nm height 1376nm sheet 0.125ohm area_cap 25.8aF/um2 fringe_cap 40.5aF/um tc1 3.179e-3/K tc2 3.094e-7/K2
";

fn nm(raw: i64) -> Dbu {
    Dbu::new_unchecked(raw)
}

/// [`TEXT`] built in Rust, statement by statement.
fn build(strings: &mut StrTable) -> CompiledDeck {
    let mut d = DeckBuilder::new(grid(), strings);
    let m = d.layer("m", (1, 0));
    let r = d.layer("r", (2, 0));
    let v = d.layer("v", (3, 0));
    d.derived("rects", m.rectangles());
    d.derived("squares", m.squares());
    let odd = d.derived("odd", m.non_rectangles());
    d.derived("long", m.with_bbox_max(&[Bound::Above(nm(1000))]));
    d.derived(
        "thin",
        v.non_squares()
            .with_bbox_min(&[Bound::AtLeast(nm(100)), Bound::Below(nm(200))]),
    );
    d.rule("c.min", count(m, 1, false));
    d.rule("c.max", count(m, 4, true));
    d.rule("ar", aspect_ratio(m, 3.0));
    d.rule("ta", total_area(m, DbuArea::new(1_000_000)));
    d.rule(
        "cc",
        cut_class(v, &[(nm(150), nm(150)), (nm(230), nm(150))]),
    );
    d.rule("ew", edge_width(m.edges().horizontal(), nm(40)));
    d.rule("fs", edge_facing_space(m.edges().vertical(), nm(30)));
    d.rule("rd.min", region_density(m, r, 0.1, false));
    d.rule("rd.max", region_density(m, r, 0.5, true));
    d.rule("aw", allowed_width(m, &[nm(350), nm(690)]));
    d.rule("ia.m", min_interior_angle(Some(m.into()), 87.0));
    d.rule("ia", min_interior_angle(None, 90.0));
    d.rule("vd.m", polygon_validity(Some(m.into())));
    d.rule("vd", polygon_validity(None));
    d.rule("ms.edges", min_step(m, nm(50), StepKind::MaxEdges(2), None));
    d.rule(
        "ms.inside",
        min_step(m, nm(50), StepKind::InsideCorner, Some(nm(100))),
    );
    d.rule("ms.step", min_step(m, nm(60), StepKind::Step, None));
    d.rule("odd.none", forbidden(odd));
    d.temperature(358.15, 303.15);
    d.pex(
        m,
        StackSource {
            thickness_nm: 360.0,
            height_nm: 1376.0,
            sheet_res_ohm_sq: 0.125,
            area_cap_af_um2: 25.8,
            fringe_cap_af_um: 40.5,
            dielectric_k: 0.0,
            tc: Some((3.179e-3, 3.094e-7)),
        },
    );
    d.finish().expect("the Rust deck builds")
}

/// Each kind's constructor and each operation's method states what its deck
/// spelling does.
/// Oracle: differential against the parser, the same deck written as text.
#[test]
fn every_new_kind_has_a_constructor_equal_to_its_text() {
    let mut strings = StrTable::default();
    let parsed = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    let built = build(&mut strings);
    assert_same("new kinds", &parsed, &built, &strings);
}

/// Every kind and operation, and a temperature with real coefficients,
/// survives printing.
/// Oracle: round trip.
#[test]
fn every_new_kind_survives_printing() {
    let mut strings = StrTable::default();
    let deck = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    assert_round_trip("new kinds", &deck, &mut strings);
}

/// The queries answer what the deck states.
/// Oracle: the deck text above: widths 350 and 690 nm; cut sizes 150 x 150
/// and 150 x 230 nm (short side first, sorted); aspect ratio 3; total area
/// 10^6 nm^2; the strictest min_step 60 nm.
#[test]
fn the_new_queries_read_what_the_deck_states() {
    let mut strings = StrTable::default();
    let deck = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    let layer = |name| deck.layers.id(&strings, name).expect("declared");
    let (m, v) = (layer("m"), layer("v"));
    assert_eq!(deck.allowed_widths(m), Some(&[nm(350), nm(690)][..]));
    assert_eq!(
        deck.cut_classes(v),
        Some(&[(nm(150), nm(150)), (nm(150), nm(230))][..])
    );
    assert_eq!(deck.max_aspect_ratio(m), Some(3.0));
    assert_eq!(deck.max_total_area(m), Some(DbuArea::new(1_000_000)));
    assert_eq!(deck.min_step(m), Some(nm(60)));
    assert_eq!(deck.allowed_widths(v), None);
}
