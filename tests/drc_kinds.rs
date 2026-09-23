//! Presence, net-aware, table and edge rule kinds, end to end: deck text, a
//! layout written out as GDSII and read back (so derived layers are computed
//! by the reader), net extraction, and the DRC stage.
//!
//! Oracle throughout: construct-from-answer. Every layout is drawn on a 1 nm
//! grid so the expected measurement is read off the coordinates by hand, and
//! the rules are the foundry's own wording (sky130 periphery rules, gf180
//! NW.2a/2b, IHP Metal1 M1.e/f). Each test also draws a case a plausible wrong
//! implementation would get wrong, named where it is drawn.

use gpurify::engine::pipeline::{extract, Loaded};
use gpurify::engine::run::{run_checks, Checks, RunOptions};
use gpurify_check::lvs::CompareOptions;
use gpurify_check::report::{Measurement, Outcome};
use gpurify_geom::{Dbu, DbuArea, Grid, LayerId};
use gpurify_ingest::deck::{parse_deck, DeckError};
use gpurify_ingest::layout::{gds, UnknownLayers};
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::write_store;
use gpurify_testgen::shapes::LayoutBuilder;

fn grid() -> Grid {
    Grid::new(1_000).expect("a 1 nm grid")
}

/// One finding: rule id, measured, limit, and where.
type Finding = (String, Measurement, Measurement, (i64, i64));

/// What one DRC run found, per rule id, sorted, and each rule's outcome.
struct Found {
    findings: Vec<Finding>,
    outcomes: Vec<(String, Outcome)>,
}

impl Found {
    /// The findings of one rule, as `(measured, limit)`.
    fn of(&self, rule: &str) -> Vec<(Measurement, Measurement)> {
        self.findings
            .iter()
            .filter(|f| f.0 == rule)
            .map(|f| (f.1, f.2))
            .collect()
    }

    fn outcome(&self, rule: &str) -> Outcome {
        self.outcomes
            .iter()
            .find(|(id, _)| id == rule)
            .unwrap_or_else(|| panic!("no run row for {rule}"))
            .1
    }
}

/// Parse `deck`, draw with `draw` (layers by name, rectangles), round trip the
/// base layers through GDSII, extract, and run the DRC stage.
fn run(deck: &str, rects: &[(&str, [i64; 4])]) -> Found {
    let mut strings = StrTable::default();
    let deck = parse_deck(deck, grid(), &mut strings).unwrap_or_else(|why| panic!("{why}"));
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for &(name, [xlo, ylo, xhi, yhi]) in rects {
        let layer = deck.layers.id(&strings, name).expect("a declared layer");
        layout.rect(layer, xlo, ylo, xhi, yhi);
    }
    let (base, _) = layout.finish();
    let mut bytes = Vec::new();
    write_store(&base, &deck.layers, "TOP", &mut bytes).expect("writable");
    let library = gds::Library::parse(&bytes, &mut strings).expect("parses");
    let (store, provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("reads back");
    let loaded = Loaded {
        strings,
        grid: grid(),
        deck,
        store,
        provenance,
        reference: None,
        intent: None,
    };
    let extracted = extract(&loaded).expect("extracts");
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: false,
        },
        lvs: CompareOptions::default(),
        quasistatic_nets: Vec::new(),
        quasistatic_inductance: false,
    };
    let (out, _) = run_checks(&loaded, &extracted, &options).expect("the deck builds");
    let name = |id| loaded.strings.resolve(id).to_owned();
    let v = &out.violations;
    Found {
        findings: (0..v.len())
            .map(|i| {
                (
                    name(v.rule[i]),
                    v.measured[i],
                    v.limit[i],
                    (v.at[i].x.raw(), v.at[i].y.raw()),
                )
            })
            .collect(),
        outcomes: out.runs.iter().map(|r| (name(r.rule), r.outcome)).collect(),
    }
}

fn len(v: i64) -> Measurement {
    Measurement::Length(Dbu::new_unchecked(v))
}

fn area(v: i128) -> Measurement {
    Measurement::Area(DbuArea::new(v))
}

const SKY130: &str = "grid 5nm
layer diff  = gds(65, 20)
layer tap   = gds(65, 44)
layer poly  = gds(66, 20)
layer licon = gds(66, 44)
layer npc   = gds(95, 20)
layer nsdm  = gds(93, 44)
layer psdm  = gds(94, 20)
layer met1  = gds(68, 20)
";

// ---------------------------------------------------------------- forbidden

/// sky130 licon.17 "Licons may not overlap both poly and (diff or tap)",
/// written with the layer expression inline. The licon over poly and diff
/// reports the area of the triple overlap, 100 x 50. The licon that only
/// abuts a poly and a diff on two of its sides overlaps neither: a rule that
/// flagged licons *interacting* with both would report it.
#[test]
fn licon_17_flags_the_triple_overlap_and_not_a_licon_that_only_abuts() {
    let deck = format!("{SKY130}rule licon.17 forbidden(licon and poly and (diff or tap))\n");
    let found = run(
        &deck,
        &[
            // Over poly and diff: the triple overlap is x 0..100, y 0..50.
            ("licon", [0, 0, 170, 170]),
            ("poly", [-100, 0, 100, 50]),
            ("diff", [-100, -100, 500, 50]),
            // Abutting only: poly left of it, tap right of it.
            ("licon", [2_000, 0, 2_170, 170]),
            ("poly", [1_800, 0, 2_000, 170]),
            ("tap", [2_170, 0, 2_400, 170]),
            // Over poly alone.
            ("licon", [4_000, 0, 4_170, 170]),
            ("poly", [3_900, -100, 4_300, 300]),
        ],
    );
    assert_eq!(found.of("licon.17"), [(area(100 * 50), area(0))]);
}

/// sky130 n/psd.6 "Enclosure of diff/tap butting edge by nsdm (psdm)" is 0:
/// the butting edge may not leave the implant (the foundry deck's
/// `tap.edges.and(diff.edges).not(npsdm)`). An implant reaching the butting
/// edge exactly is clean; one covering only its upper half leaves 250 of the
/// 500-long edge outside, which a rule asking only whether the implant touches
/// the edge would pass.
#[test]
fn psd_6_flags_the_part_of_the_butting_edge_outside_the_implant() {
    let deck = format!(
        "{SKY130}layer butt = tap.edges() and diff.edges()\n\
         rule psd.6 forbidden(butt.outside_part(psdm))\n"
    );
    let found = run(
        &deck,
        &[
            ("diff", [0, 0, 1_000, 500]),
            ("tap", [1_000, 0, 1_500, 500]),
            ("psdm", [1_000, -125, 1_625, 625]),
            ("diff", [0, 2_000, 1_000, 2_500]),
            ("tap", [1_000, 2_000, 1_500, 2_500]),
            ("psdm", [1_000, 2_250, 1_625, 2_625]),
        ],
    );
    assert_eq!(found.of("psd.6"), [(len(250), len(0))]);
    assert_eq!(
        found.findings[0].3,
        (1_000, 2_125),
        "the midpoint of the bare part"
    );
}

// ---------------------------------------------------------- contains, inside

/// sky130 licon.16 "every tap must enclose at least one licon1". A licon
/// straddling the tap's edge is not enclosed. The L-shaped tap's bounding box
/// holds a licon that sits in the L's notch, off the tap: a containment test
/// on boxes would count it.
#[test]
fn licon_16_counts_only_licons_entirely_on_the_tap() {
    let deck = format!("{SKY130}rule licon.16 contains(tap, licon) >= 1\n");
    let found = run(
        &deck,
        &[
            ("tap", [0, 0, 500, 500]),
            ("licon", [100, 100, 270, 270]),
            // Straddles the right edge at x = 1500.
            ("tap", [1_000, 0, 1_500, 500]),
            ("licon", [1_400, 100, 1_570, 270]),
            // An L: the foot and the left leg; the licon sits in the notch.
            ("tap", [3_000, 0, 4_000, 300]),
            ("tap", [3_000, 300, 3_300, 1_000]),
            ("licon", [3_500, 500, 3_670, 670]),
        ],
    );
    assert_eq!(
        found.of("licon.16"),
        [
            (Measurement::Count(0), Measurement::Count(1)),
            (Measurement::Count(0), Measurement::Count(1)),
        ]
    );
}

/// Two licons that touch are one shape, so a tap holding only that pair holds
/// one, short of two.
#[test]
fn contains_counts_touching_inner_shapes_as_one() {
    let deck = format!("{SKY130}rule two contains(tap, licon) >= 2\n");
    let found = run(
        &deck,
        &[
            ("tap", [0, 0, 1_000, 500]),
            ("licon", [100, 100, 270, 270]),
            ("licon", [500, 100, 670, 270]),
            ("tap", [2_000, 0, 3_000, 500]),
            ("licon", [2_100, 100, 2_270, 270]),
            ("licon", [2_270, 100, 2_440, 270]),
        ],
    );
    assert_eq!(
        found.of("two"),
        [(Measurement::Count(1), Measurement::Count(2))]
    );
}

/// sky130 licon.18 "npc must enclose `poly_licon`". A poly licon touching the
/// npc edge from inside is enclosed; one sticking 20 out of it leaves
/// 20 x 170 outside. The third sits in the notch of an L-shaped npc, inside
/// the npc's bounding box but on none of it.
#[test]
fn licon_18_reports_the_area_outside_the_npc() {
    let deck = format!("{SKY130}rule licon.18 inside(licon and poly, npc)\n");
    let found = run(
        &deck,
        &[
            ("poly", [-500, -500, 6_000, 1_500]),
            ("npc", [0, 0, 500, 500]),
            ("licon", [330, 100, 500, 270]),
            ("npc", [1_000, 0, 1_500, 500]),
            ("licon", [1_350, 100, 1_520, 270]),
            ("npc", [3_000, 0, 4_000, 300]),
            ("npc", [3_000, 300, 3_300, 1_000]),
            ("licon", [3_500, 500, 3_670, 670]),
        ],
    );
    assert_eq!(
        found.of("licon.18"),
        [(area(20 * 170), area(0)), (area(170 * 170), area(0))]
    );
}

// ------------------------------------------------------------ net spacing

const GF180_NWELL: &str = "grid 5nm
layer nwell = gds(21, 0)
layer cont  = gds(33, 0)
layer met1  = gds(34, 0)
connect conductors [nwell, met1]
connect via cont [nwell, met1]
rule NW.2a space(nwell; nets: same) >= 600nm
rule NW.2b space(nwell; nets: different) >= 1400nm
";

/// gf180 NW.2a "Min. Nwell spacing to Nwell at the same potential 0.6" and
/// NW.2b "... at different potential 1.4". W1 and W2 are 500 apart and tied
/// through metal, so they are one net: NW.2a flags them and NW.2b does not,
/// though a rule that took "not touching" for "different nets" would. W3 is
/// 800 from W2 and tied to nothing: NW.2b flags it, NW.2a does not.
#[test]
fn nwell_spacing_follows_the_extracted_net_not_the_drawing() {
    let found = run(
        GF180_NWELL,
        &[
            ("nwell", [0, 0, 2_000, 2_000]),
            ("nwell", [2_500, 0, 4_500, 2_000]),
            ("nwell", [5_300, 0, 7_300, 2_000]),
            // The strap: a contact in each of W1 and W2, and metal over both.
            ("cont", [1_000, 1_000, 1_200, 1_200]),
            ("cont", [3_000, 1_000, 3_200, 1_200]),
            ("met1", [900, 900, 3_300, 1_300]),
        ],
    );
    assert_eq!(found.of("NW.2a"), [(len(500), len(600))]);
    assert_eq!(found.of("NW.2b"), [(len(800), len(1_400))]);
    assert_eq!(found.outcome("NW.2b"), Outcome::Ran);
}

/// A layer that carries no net cannot be asked which net it is on.
#[test]
fn net_spacing_on_a_layer_that_is_not_a_conductor_is_refused_at_load() {
    let mut strings = StrTable::default();
    let refused = parse_deck(
        "grid 5nm\nlayer nwell = gds(21, 0)\nrule NW.2b space(nwell; nets: different) >= 1400nm\n",
        grid(),
        &mut strings,
    );
    assert!(
        matches!(&refused, Err(DeckError::Malformed(why)) if why.contains("not a conductor")),
        "{refused:?}"
    );
}

/// Without nets the rule cannot run, and says so.
#[test]
fn net_spacing_without_nets_is_refused_not_clean() {
    let mut strings = StrTable::default();
    let deck = parse_deck(GF180_NWELL, grid(), &mut strings).expect("parses");
    let rules = gpurify_check::drc::RuleSet::from_deck(&deck, &strings).expect("builds");
    let mut layout = LayoutBuilder::new(deck.layers.len());
    layout.rect(LayerId(2), 0, 0, 100, 100);
    let (store, _) = layout.finish();
    let (mut out, mut runs) = (gpurify_check::report::Violations::default(), Vec::new());
    rules.run(&store, &mut out, &mut runs);
    assert!(runs.iter().all(|r| r.outcome == Outcome::Refused));
}

// ---------------------------------------------------------- spacing table

/// IHP SG13G2 Metal1: M1.b 0.18; M1.e 0.22 "if at least one line is wider
/// than 0.3 µm and the parallel run is more than 1.0 µm"; M1.f 0.60 for wider
/// than 10 µm and a run of more than 10 µm.
const IHP_M1: &str = "grid 5nm
layer met1 = gds(8, 0)
rule M1.bef space_table(met1;
    prl:   [0um, 1um, 10um],
    width: [0um, 0.3um, 10um],
    space: [[180nm, 180nm, 180nm],
            [180nm, 220nm, 220nm],
            [180nm, 220nm, 600nm]])
";

/// Each pair 200 apart unless noted, read against the row of the wider line
/// and the column of the run:
/// - two 200-wide lines, run 2 µm: row 0, 180, clean. A table read by run
///   length alone would ask 220.
/// - 400 and 200 wide, run 2 µm: row 1, column 1, 220, flagged.
/// - 400 and 200 wide, run 800: column 0, 180, clean.
/// - 300 and 200 wide, run 2 µm: 300 is not wider than 0.3, row 0, clean.
/// - a 12 µm plate and a line 500 off it, run 11 µm: row 2, column 2, 600,
///   flagged.
/// - a 12 µm plate with a 200-wide tab 3 µm long, and a line 500 past the
///   tab's end: only the tab is near, and the tab is not wide, so 180 applies
///   and 500 is clean. Holding the whole shape to its widest part would ask 600.
#[test]
fn m1_e_f_pick_the_cell_by_the_wider_line_and_the_run() {
    let found = run(
        IHP_M1,
        &[
            ("met1", [0, 0, 200, 2_000]),
            ("met1", [400, 0, 600, 2_000]),
            ("met1", [2_000, 0, 2_400, 2_000]),
            ("met1", [2_600, 0, 2_800, 2_000]),
            ("met1", [4_000, 0, 4_400, 800]),
            ("met1", [4_600, 0, 4_800, 800]),
            ("met1", [6_000, 0, 6_300, 2_000]),
            ("met1", [6_500, 0, 6_700, 2_000]),
            ("met1", [10_000, 0, 22_000, 12_000]),
            ("met1", [22_500, 0, 22_700, 11_000]),
            ("met1", [30_000, 0, 42_000, 12_000]),
            ("met1", [35_000, 12_000, 35_200, 15_000]),
            ("met1", [35_000, 15_500, 35_200, 17_000]),
        ],
    );
    assert_eq!(
        found.of("M1.bef"),
        [(len(200), len(220)), (len(500), len(600))]
    );
}

// ---------------------------------------------------------- huge metal

/// sky130 m1.3a "Min. spacing of features attached to or extending from
/// `huge_met1` for a distance of up to 0.28 µm to metal1 0.28". A 4 µm plate
/// (huge: a 3 µm square fits) has a 140-wide finger going up. A line 200 to
/// the finger's side, starting 300 above the plate, is 300 from the plate but
/// only about 201 from the finger's first 280: m1.3a flags it, and spacing
/// measured from the plate alone does not. A line starting 700 above the
/// plate is clear of both.
#[test]
fn m1_3a_measures_from_what_is_attached_to_huge_metal() {
    let deck = format!(
        "{SKY130}rule m1.3a wide_space(met1; width: 3um, attached: 280nm) >= 280nm\n\
         rule m1.3b wide_space(met1; width: 3um) >= 280nm\n"
    );
    let found = run(
        &deck,
        &[
            ("met1", [0, 0, 4_000, 4_000]),
            ("met1", [1_000, 4_000, 1_140, 5_000]),
            ("met1", [1_340, 4_300, 1_480, 4_600]),
            ("met1", [1_340, 4_700, 1_480, 5_000]),
        ],
    );
    // sqrt(200² + 20²) = 200.99, reported rounded down.
    assert_eq!(found.of("m1.3a"), [(len(200), len(280))]);
    assert!(found.of("m1.3b").is_empty());
}

// ---------------------------------------------------------- edge checks

/// sky130 difftap.4 "Min tap bound by one diffusion 0.29" (the foundry deck:
/// `tap.edges.and(diff.edges).with_length(0, 0.29)`) and difftap.5 "Min tap
/// bound by two diffusions 0.40" (`.space(0.4, projection)` on the same
/// edges). One tap butts one diff along 250; another sits 350 wide between
/// two diffs; a third is exactly 400 wide, which is legal.
#[test]
fn difftap_4_and_5_measure_the_butting_edges() {
    let deck = format!(
        "{SKY130}layer butt = tap.edges() and diff.edges()\n\
         rule difftap.4 length(butt) >= 290nm\n\
         rule difftap.5 space(butt) >= 400nm\n"
    );
    let found = run(
        &deck,
        &[
            ("diff", [0, 0, 1_000, 500]),
            ("tap", [1_000, 0, 1_500, 250]),
            ("diff", [0, 2_000, 1_000, 2_500]),
            ("tap", [1_000, 2_000, 1_350, 2_500]),
            ("diff", [1_350, 2_000, 2_350, 2_500]),
            ("diff", [0, 4_000, 1_000, 4_500]),
            ("tap", [1_000, 4_000, 1_400, 4_500]),
            ("diff", [1_400, 4_000, 2_400, 4_500]),
        ],
    );
    assert_eq!(found.of("difftap.4"), [(len(250), len(290))]);
    assert_eq!(found.of("difftap.5"), [(len(350), len(400))]);
}

/// sky130 difftap.7 "Spacing of diff/tap abutting edge to a non-coinciding
/// diff or tap edge 0.13", the tap side: tap edges touching no diff, against
/// parallel diff edges, euclidean. A tap 100 above a diff is flagged twice:
/// its bottom over the diff's top, and its left edge in line with the diff's,
/// end to end. So is a tap whose corner sits 60 right and 80 above the diff's
/// corner, 100 on the diagonal, from its bottom and from its left edge; a
/// rule measuring only edges that face each other would miss it.
#[test]
fn difftap_7_measures_edge_to_edge_on_the_diagonal_too() {
    let deck = format!(
        "{SKY130}rule difftap.7 space((tap.edges() not diff.edges()).not_interacting(diff), diff.edges()) >= 130nm\n"
    );
    let found = run(
        &deck,
        &[
            ("diff", [0, 0, 1_000, 500]),
            ("tap", [0, 600, 500, 900]),
            ("diff", [3_000, 0, 4_000, 500]),
            ("tap", [4_060, 580, 4_400, 900]),
        ],
    );
    assert_eq!(found.of("difftap.7"), [(len(100), len(130)); 4]);
    let mut at: Vec<_> = found.findings.iter().map(|f| f.3).collect();
    at.sort_unstable();
    assert_eq!(at, [(0, 550), (250, 550), (4_030, 540), (4_030, 540)]);
}

/// sky130 n/psd.5a "Enclosure of diff by nsdm(psdm), except for butting edge
/// 0.125". The diff's butting edge is taken out, so the nsdm may stop at it:
/// measured straight out from each remaining edge, the top and bottom are
/// covered right up to the butting corner. Measured to the corner point
/// itself, the nsdm's end at the butting edge would be a zero enclosure. A
/// second diff whose nsdm reaches only 100 below it is flagged at 100.
#[test]
fn nsd_5a_is_measured_on_every_edge_but_the_butting_one() {
    let deck =
        format!("{SKY130}rule nsd.5a enclosure(diff.edges() not tap.edges(), nsdm) >= 125nm\n");
    let found = run(
        &deck,
        &[
            ("diff", [0, 0, 1_000, 500]),
            ("tap", [1_000, 0, 1_300, 500]),
            ("nsdm", [-125, -125, 1_000, 625]),
            ("diff", [0, 2_000, 1_000, 2_500]),
            ("nsdm", [-125, 1_900, 1_125, 2_625]),
        ],
    );
    assert_eq!(found.of("nsd.5a"), [(len(100), len(125))]);
    assert_eq!(
        found.findings[0].3,
        (500, 2_000),
        "the bottom edge's midpoint"
    );
}
