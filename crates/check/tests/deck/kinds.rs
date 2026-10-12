//! Every rule kind and layer operation the shipped decks do not exercise:
//! its constructor, the printer and the query API, on one deck that states
//! each of them (`docs/deck.md`'s spellings).

use super::builder::assert_same;
use super::grid;
use super::printer::assert_round_trip;
use gpurify_check::deck::rules::{
    allowed_width, aspect_ratio, asymmetric_enclosure, convex_corner_spacing, count, cut_class,
    cut_class_spacing, cut_spacing, edge_facing_space, edge_width, eol_keep_out,
    eol_within_spacing, exact_pitch, forbidden, forbidden_spacing, full_width, gate_corner,
    max_enclosure, min_enclosure, min_interior_angle, min_step, min_step_adjacent, minimum_cut,
    must_contain, noncoincident_enclosure, polygon_validity, projection_spacing, region_density,
    span_length, tip_spacing_table, total_area, two_width_spacing_table, via_stack,
};
use gpurify_check::deck::{compile, Bound, CompiledDeck, DeckBuilder};
use gpurify_check::drc::ruleset::EolParallel;
use gpurify_check::drc::{StepKind, StepNeighbour, WireBand};
use gpurify_geom::{Dbu, DbuArea, StrTable};
use gpurify_ingest::deck::StackSource;

const TEXT: &str = "grid 1nm
layer m = gds(1, 0)
layer r = gds(2, 0)
layer v = gds(3, 0)
layer v2 = gds(4, 0)
layer m2 = gds(5, 0)
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
rule fs.prl facing_space(m.edges().vertical(); prl: 50nm) >= 30nm
rule rd.min region_density(m, r) >= 0.1
rule rd.max region_density(m, r) <= 0.5
rule aw width(m; allowed: [350nm, 690nm])
rule aw.open width(thin; allowed: [100nm, 150nm], open_last: true)
rule ia.m interior_angle(m) >= 87deg
rule ia interior_angle() >= 90deg
rule vd.m valid(m)
rule vd valid()
rule ms.edges min_step(m; max_edges: 2) >= 50nm
rule ms.inside min_step(m; corner: inside, length_sum: 100nm) >= 50nm
rule ms.step min_step(m; corner: step, length_sum: none) >= 60nm
rule msa min_step(m; adjacent: 60nm, except_rectangle: true) >= 50nm
rule msa.eol min_step(m; adjacent: 30nm, adjacent_eol: 120nm, except_rectangle: false) >= 50nm
rule msa.between min_step(m; between_eol: 120nm) >= 50nm
rule odd.none forbidden(odd)
rule tip tip_space_table(m; length: [0nm, 100nm], space: [[60nm, 70nm], [70nm, 80nm]])
rule tw two_width_table(m; width: [0nm, 200nm], prl: [none, 300nm], space: [[50nm, 60nm], [60nm, 90nm]])
rule sl span_length(m; x: [100nm, 200nm], y: [150nm])
rule fsp forbidden_space(m; min: 40nm, max: 50nm, prl: 0nm)
rule eol.w eol_space(m; eol_width: 60nm, within: 20nm, parallel: none, end_to_end: none) >= 80nm
rule eol.p eol_space(m; eol_width: 60nm, within: 20nm, parallel: (space: 120nm, within: 50nm, two_edges: true), end_to_end: 70nm) >= 80nm
rule ko eol_keep_out(m; eol_width: 60nm, backward: 0nm, side: 30nm, forward: 90nm)
rule cs corner_space(m; corner_to_corner: true, except_eol: 60nm) >= 100nm
rule cs.none corner_space(m; corner_to_corner: false, except_eol: none) >= 100nm
rule pv pitch(m, vertical) == 27nm
rule ph pitch(m, horizontal) == 54nm
rule ps space(m, r, projection) >= 235nm
rule en.band enclosure(v, m; width: 400nm, below: 1000nm) >= 30nm
rule en.op enclosure(v, m, opposite; below: 340nm) >= 60nm
rule en.nc enclosure(v, m, noncoincident) >= 20nm
rule fw full_width(v, m)
rule en.max enclosure(v, m) <= 95nm
rule bend bend(m, r)
rule corner covers_corner(m, r)
rule mc min_cuts(v, m2, m; width: 1000nm, within: 300nm) >= 2
rule mc.any min_cuts(v, m, m2; width: 500nm) >= 3
rule stack via_stack(v, v2) <= 2
rule cs.center space(v, center) >= 250nm
rule cs.adj adjacent_space(v; cuts: 3, within: 250nm) >= 180nm
rule ccs cut_class_space(v;
    short: [170nm, 190nm],
    long:  [170nm, 2000nm],
    space: [[170nm, 170nm, 510nm, 510nm],
            [170nm, 170nm, 510nm, 510nm],
            [510nm, 510nm, 350nm, 510nm],
            [510nm, 510nm, 510nm, 510nm]])
rule mc.ge contains(m, v) >= 1
rule mc.le contains(r, v) <= 1
rule mc.eq contains(m2, v) == 2
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
    let v2 = d.layer("v2", (4, 0));
    let m2 = d.layer("m2", (5, 0));
    d.derived("rects", m.rectangles());
    d.derived("squares", m.squares());
    let odd = d.derived("odd", m.non_rectangles());
    d.derived("long", m.with_bbox_max(&[Bound::Above(nm(1000))]));
    let thin = d.derived(
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
    d.rule(
        "fs.prl",
        edge_facing_space(m.edges().vertical(), nm(30)).prl(nm(50)),
    );
    d.rule("rd.min", region_density(m, r, 0.1, false));
    d.rule("rd.max", region_density(m, r, 0.5, true));
    d.rule("aw", allowed_width(m, &[nm(350), nm(690)]));
    d.rule(
        "aw.open",
        allowed_width(thin, &[nm(100), nm(150)]).open_last(),
    );
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
    let adjacent = |length, eol, except_rectangle| StepNeighbour::Adjacent {
        length,
        eol,
        except_rectangle,
    };
    d.rule(
        "msa",
        min_step_adjacent(m, nm(50), adjacent(nm(60), None, true)),
    );
    d.rule(
        "msa.eol",
        min_step_adjacent(m, nm(50), adjacent(nm(30), Some(nm(120)), false)),
    );
    d.rule(
        "msa.between",
        min_step_adjacent(m, nm(50), StepNeighbour::BetweenEol(nm(120))),
    );
    d.rule("odd.none", forbidden(odd));
    d.rule(
        "tip",
        tip_spacing_table(m, &[nm(0), nm(100)], &[nm(60), nm(70), nm(70), nm(80)]),
    );
    d.rule(
        "tw",
        two_width_spacing_table(
            m,
            &[nm(0), nm(200)],
            &[None, Some(nm(300))],
            &[nm(50), nm(60), nm(60), nm(90)],
        ),
    );
    d.rule("sl", span_length(m, &[nm(100), nm(200)], &[nm(150)]));
    d.rule("fsp", forbidden_spacing(m, nm(40), nm(50), nm(0)));
    d.rule(
        "eol.w",
        eol_within_spacing(m, nm(60), nm(20), None, None, nm(80)),
    );
    let parallel = EolParallel {
        space: nm(120),
        within: nm(50),
        two_edges: true,
    };
    d.rule(
        "eol.p",
        eol_within_spacing(m, nm(60), nm(20), Some(parallel), Some(nm(70)), nm(80)),
    );
    d.rule("ko", eol_keep_out(m, nm(60), nm(0), nm(30), nm(90)));
    d.rule("cs", convex_corner_spacing(m, true, Some(nm(60)), nm(100)));
    d.rule("cs.none", convex_corner_spacing(m, false, None, nm(100)));
    d.rule("pv", exact_pitch(m, true, nm(27)));
    d.rule("ph", exact_pitch(m, false, nm(54)));
    d.rule("ps", projection_spacing(m, r, nm(235)));
    d.rule(
        "en.band",
        min_enclosure(v, m, nm(30)).wire(WireBand {
            from: nm(400),
            below: Some(nm(1000)),
        }),
    );
    d.rule(
        "en.op",
        asymmetric_enclosure(v, m, nm(60)).wire(WireBand {
            from: nm(0),
            below: Some(nm(340)),
        }),
    );
    d.rule("en.nc", noncoincident_enclosure(v, m, nm(20)));
    d.rule("fw", full_width(v, m));
    d.rule("en.max", max_enclosure(v, m, nm(95)));
    d.rule("bend", gate_corner(m, r, false));
    d.rule("corner", gate_corner(m, r, true));
    d.rule("mc", minimum_cut(v, m2, m, nm(1000), Some(nm(300)), 2));
    d.rule("mc.any", minimum_cut(v, m, m2, nm(500), None, 3));
    d.rule("stack", via_stack(&[v, v2], 2));
    d.rule("cs.center", cut_spacing(v, true, None, nm(250)));
    d.rule("cs.adj", cut_spacing(v, false, Some((3, nm(250))), nm(180)));
    let (a, b) = (nm(170), nm(510));
    d.rule(
        "ccs",
        cut_class_spacing(
            v,
            &[a, nm(190)],
            &[a, nm(2000)],
            &[a, a, b, b, a, a, b, b, b, b, nm(350), b, b, b, b, b],
        ),
    );
    d.rule("mc.ge", must_contain(m, v, 1, None));
    d.rule("mc.le", must_contain(r, v, 0, Some(1)));
    d.rule("mc.eq", must_contain(m2, v, 2, Some(2)));
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
/// 10^6 nm^2; the strictest `min_step` 60 nm.
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
    assert_eq!(deck.allowed_widths_from(m), None);
    assert_eq!(deck.allowed_widths_from(layer("thin")), Some(nm(150)));
}

/// The queries for the cut and enclosure kinds answer what the deck states.
/// Oracle: the deck text above: projection 235 nm between `m` and `r`;
/// enclosures 30 nm all round (its band counted as every wire), 60 nm
/// opposite, 20 nm off `m`'s edge, at most 95 nm, full width; 2 cuts on `m2`
/// wider than 1000 nm and 3 on `m` wider than 500 nm; stacks of at most 2;
/// cut spacing 250 nm centre to centre, none edge to edge for every cut (the
/// 180 nm one holds only crowded cuts); the cut-class table's 350 nm cell;
/// `contains` bounds 1 to unbounded, 0 to 1 and exactly 2.
#[test]
fn the_cut_and_enclosure_queries_read_what_the_deck_states() {
    let mut strings = StrTable::default();
    let deck = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    let layer = |name| deck.layers.id(&strings, name).expect("declared");
    let (m, r, v, v2, m2) = (layer("m"), layer("r"), layer("v"), layer("v2"), layer("m2"));
    assert_eq!(deck.projection_spacing(r, m), Some(nm(235)));
    let enclosure = deck.enclosure(v, m);
    assert_eq!(enclosure.all_sides, Some(nm(30)));
    assert_eq!(enclosure.opposite, Some(nm(60)));
    assert_eq!(enclosure.noncoincident, Some(nm(20)));
    assert_eq!(enclosure.at_most, Some(nm(95)));
    assert!(enclosure.full_width);
    assert_eq!(deck.minimum_cuts(v, m2, nm(1001)), Some(2));
    assert_eq!(deck.minimum_cuts(v, m2, nm(1000)), None);
    assert_eq!(deck.minimum_cuts(v, m, nm(501)), Some(3));
    assert_eq!(deck.max_via_stack(v2), Some(2));
    assert_eq!(deck.max_via_stack(m), None);
    assert_eq!(deck.cut_spacing(v, true), Some(nm(250)));
    assert_eq!(deck.cut_spacing(v, false), None);
    let table = deck.cut_class_spacing(v).expect("stated");
    assert_eq!(table.long, [nm(170), nm(2000)]);
    assert_eq!(table.space[10], nm(350));
    assert_eq!(deck.contains(m, v), Some((1, u32::MAX)));
    assert_eq!(deck.contains(r, v), Some((0, 1)));
    assert_eq!(deck.contains(m2, v), Some((2, 2)));
}
