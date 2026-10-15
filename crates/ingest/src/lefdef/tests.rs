use super::lex::exact_units;
use super::*;
use crate::StrTable;

/// A technology with two metals and a cut, in the reference's own layer
/// names, and a 4 × 2 macro whose one pin is its lower-left unit square.
const LEF: &str = "\
VERSION 5.8 ;
BUSBITCHARS \"[]\" ;
UNITS
  DATABASE MICRONS 1000 ;
END UNITS
MANUFACTURINGGRID 0.005 ;
LAYER M1
  TYPE ROUTING ;
  DIRECTION HORIZONTAL ;
  PITCH 0.2 ;
  WIDTH 0.01 ;
  PROPERTY LEF58_SPACING \"SPACING 0.1 ; \" ;
END M1
LAYER cut12
  TYPE CUT ;
END cut12
LAYER M2
  TYPE ROUTING ;
  DIRECTION VERTICAL ;
  WIDTH 0.02 ;
END M2
VIA VIA12 DEFAULT
  LAYER M1 ;
    RECT -0.01 -0.01 0.01 0.01 ;
  LAYER cut12 ;
    RECT -0.005 -0.005 0.005 0.005 ;
  LAYER M2 ;
    RECT -0.01 -0.01 0.01 0.01 ;
END VIA12
VIARULE GEN GENERATE
  LAYER M1 ;
    ENCLOSURE 0 0 ;
END GEN
MACRO cell
  CLASS CORE ;
  ORIGIN 0 0 ;
  SIZE 0.004 BY 0.002 ;
  PIN a
    DIRECTION INPUT ;
    PORT
      LAYER M1 ;
        RECT 0 0 0.001 0.001 ;
    END
  END a
  OBS
    LAYER M2 ;
      RECT 0.003 0.001 0.004 0.002 ;
  END
END cell
END LIBRARY
";

fn lef() -> Lef {
    let mut lef = Lef::default();
    read_lef_into(LEF, 1000, &mut lef).expect("the test LEF reads");
    lef
}

fn def(body: &str) -> Def {
    let text = format!(
        "VERSION 5.8 ;\nDESIGN top ;\nUNITS DISTANCE MICRONS 1000 ;\n\
         DIEAREA ( 0 0 ) ( 1000 1000 ) ;\n{body}\nEND DESIGN\n"
    );
    read_def(&text, &lef()).unwrap_or_else(|e| panic!("{e}"))
}

fn boxes(shapes: &[FlatShape]) -> Vec<(&str, (i64, i64, i64, i64))> {
    shapes
        .iter()
        .map(|s| (s.shape.layer.as_str(), s.shape.bbox()))
        .collect()
}

/// Oracle: LEF/DEF 5.8 numbers are decimals of micrometres, read exactly
/// at the DEF's units: 0.145 µm at 1000/µm is 145, half a unit is no
/// unit, and 1.5 µm at 2000/µm is 3000.
#[test]
fn a_length_converts_exactly_or_not_at_all() {
    assert_eq!(exact_units("0.145", 1000), Some(145));
    assert_eq!(exact_units("-1.5", 2000), Some(-3000));
    assert_eq!(exact_units("+.5", 1000), Some(500));
    assert_eq!(exact_units("0.0005", 1000), None);
    assert_eq!(exact_units("1e-3", 1000), None);
    assert_eq!(exact_units("3000000", 1000), None);
    assert_eq!(exact_units(".", 1000), None);
}

/// Oracle: the reference's Example 4-36 and Figures 4-25 to 4-27 (5.8
/// pp. 344-345): a 2 × 3 array of 20-unit cuts 30 apart, enclosures 20, 50
/// (bottom) and 50, 20 (top), has its top metal at (−110, −55)–(110, 55);
/// ORIGIN 10 −10 moves it to (−100, −65)–(120, 45); OFFSET 0 0 20 −20 then
/// to (−80, −85)–(140, 25). The bottom metal is (−80, −85)–(80, 85) and
/// the first cut (−60, −35)–(−40, −15).
#[test]
fn a_generated_via_is_the_references_example() {
    let via = |extra: &str| {
        let d = def(&format!(
            "VIAS 1 ;\n- v + VIARULE myViaRule + CUTSIZE 20 20 + LAYERS M1 cut12 M2 \
             + CUTSPACING 30 30 + ENCLOSURE 20 50 50 20 + ROWCOL 2 3 {extra};\nEND VIAS"
        ));
        d.vias[0].1.clone()
    };
    let plain = via("");
    assert_eq!(plain.len(), 2 + 6);
    assert_eq!(plain[0].bbox(), (-80, -85, 80, 85));
    assert_eq!(plain[1].bbox(), (-110, -55, 110, 55));
    assert_eq!(plain[2].bbox(), (-60, -35, -40, -15));
    assert_eq!(via("+ ORIGIN 10 -10 ")[1].bbox(), (-100, -65, 120, 45));
    assert_eq!(
        via("+ ORIGIN 10 -10 + OFFSET 0 0 20 -20 ")[1].bbox(),
        (-80, -85, 140, 25)
    );
}

/// Oracle: the reference's cut patterns (5.8 pp. 349-351, Figures 4-31 and
/// 4-32): `ROWCOL 5 5 PATTERN 2_F0_2_F8_1_78` is, bottom row first, 11110
/// twice, 11111 twice, then 01111, and `2_F7_2_FF_1_7F` is the same;
/// `ROWCOL 5 14 PATTERN 2_FFE0_3_R4F` is two rows of eleven cuts and three
/// rows of fourteen. A pattern of the wrong row count is refused.
#[test]
fn a_cut_pattern_leaves_out_the_cuts_the_reference_marks() {
    let cuts = |rowcol: (i64, i64), pattern: &str| {
        ViaRule {
            rowcol,
            pattern: pattern.into(),
            ..ViaRule::default()
        }
        .cuts()
    };
    let rows = |bits: &[&str]| -> Vec<bool> {
        bits.iter()
            .flat_map(|r| r.chars().map(|c| c == '1'))
            .collect()
    };
    let figure_31 = rows(&["11110", "11110", "11111", "11111", "01111"]);
    assert_eq!(cuts((5, 5), "2_F0_2_F8_1_78"), Some(figure_31.clone()));
    assert_eq!(cuts((5, 5), "2_F7_2_FF_1_7F"), Some(figure_31));
    let got = cuts((5, 14), "2_FFE0_3_R4F").expect("decodes");
    let count = |row: usize| got[row * 14..(row + 1) * 14].iter().filter(|&&c| c).count();
    assert_eq!((0..5).map(count).collect::<Vec<_>>(), [11, 11, 14, 14, 14]);
    assert_eq!(cuts((4, 5), "2_F0_2_F8_1_78"), None);
    assert_eq!(cuts((5, 8), "5_F"), None);
    let d = def(
        "VIAS 1 ;\n- v + VIARULE r + CUTSIZE 10 10 + LAYERS M1 cut12 M2 + CUTSPACING 10 10 \
         + ENCLOSURE 0 0 0 0 + ROWCOL 1 4 + PATTERN 1_A ;\nEND VIAS",
    );
    // 1010: the first and third of four cuts.
    let cut_boxes: Vec<_> = d.vias[0].1[2..].iter().map(Shape::bbox).collect();
    assert_eq!(cut_boxes, [(-35, -5, -25, 5), (5, -5, 15, 5)]);
}

/// Oracle: the reference's "Specifying Coordinates" example (5.8 p. 269),
/// `ROUTED M1 ( 0 50 ) ( 50 * 20 ) VIA12 ( * * 15 ) ( * 0 )`: an M1 wire 10
/// wide from x = 0, extended by half its width (5) at the start and by 20
/// past the via, and an M2 wire 20 wide from the via down to y = 0,
/// extended 15 past the via and by half its width (10) at the end.
#[test]
fn a_wire_extends_as_the_reference_draws_it() {
    let d =
        def("NETS 1 ;\n- n + ROUTED M1 ( 0 50 ) ( 50 * 20 ) VIA12 ( * * 15 ) ( * 0 ) ;\nEND NETS");
    let shapes = flatten(&d, &lef()).expect("flattens");
    let got = boxes(&shapes);
    assert_eq!(got[0], ("M1", (-5, 45, 70, 55)));
    assert_eq!(got[1], ("M2", (40, -10, 60, 65)));
    // The via's three shapes at (50, 50).
    assert_eq!(
        &got[2..],
        &[
            ("M1", (40, 40, 60, 60)),
            ("cut12", (45, 45, 55, 55)),
            ("M2", (40, 40, 60, 60)),
        ]
    );
    assert!(shapes.iter().all(|s| s.net.as_deref() == Some("n")));
}

/// Oracle: the reference's Example 4-12 (5.8 pp. 267-268): `( 0 0 ) ( 5 0 )
/// VIRTUAL ( 7 1 ) RECT ( -3 0 -1 2 ) ( 7 7 )` draws a wire to (5, 0), no
/// wire to (7, 1), the rectangle (4, 1)–(6, 3), and a wire (7, 1)–(7, 7).
/// A special net of width 2 here, so its ends are not extended.
#[test]
fn virtual_and_rect_routing_points_are_the_references_example() {
    let d = def(
        "SPECIALNETS 1 ;\n- s + ROUTED M1 2 ( 0 0 ) ( 5 0 ) VIRTUAL ( 7 1 ) RECT ( -3 0 -1 2 ) ( 7 7 ) ;\nEND SPECIALNETS",
    );
    let got = flatten(&d, &lef()).expect("flattens");
    assert_eq!(
        boxes(&got),
        [
            ("M1", (0, -1, 5, 1)),
            ("M1", (6, 1, 8, 7)),
            ("M1", (4, 1, 6, 3)),
        ]
    );
}

/// Oracle: the reference's placement rule (5.8 p. 244: the lower-left
/// corner of the turned cell lands on the placement point) and its table of
/// orientations as OpenAccess turns, hand-derived for a 4 × 2 macro whose
/// pin is its lower-left unit square, placed at (100, 200).
#[test]
fn every_orientation_places_the_pin_where_the_reference_says() {
    let cases = [
        ("N", (100, 200, 101, 201)),
        ("S", (103, 201, 104, 202)),
        ("W", (101, 200, 102, 201)),
        ("E", (100, 203, 101, 204)),
        ("FN", (103, 200, 104, 201)),
        ("FS", (100, 201, 101, 202)),
        ("FW", (100, 200, 101, 201)),
        ("FE", (101, 203, 102, 204)),
    ];
    for (orient, pin) in cases {
        let d = def(&format!(
            "COMPONENTS 1 ;\n- u1 cell + SOURCE NETLIST + PLACED ( 100 200 ) {orient} ;\nEND COMPONENTS\n\
             NETS 1 ;\n- n ( u1 a ) ;\nEND NETS"
        ));
        let got = flatten(&d, &lef()).expect("flattens");
        assert_eq!(got[0].shape.bbox(), pin, "{orient}");
        assert_eq!(got[0].net.as_deref(), Some("n"));
        assert_eq!(got[0].origin, Origin::MacroPin(0, 0));
        // The obstruction, the upper-right unit square, stays in the cell box.
        let (x0, y0, x1, y1) = got[1].shape.bbox();
        let (w, h) = if matches!(orient, "W" | "E" | "FW" | "FE") {
            (2, 4)
        } else {
            (4, 2)
        };
        assert!(
            x0 >= 100 && y0 >= 200 && x1 <= 100 + w && y1 <= 200 + h,
            "{orient}"
        );
        assert_eq!(got[1].net, None);
    }
}

/// Oracle: the reference's macro ORIGIN (5.8 p. 122): "if the ORIGIN is 0,
/// -1, then macro geometry at 0, 1 are shifted to 0, 0, and then aligned to
/// the DEF placement point".
#[test]
fn a_macro_origin_shifts_its_geometry_first() {
    let mut lef = lef();
    lef.macros[0].origin = (0, -1);
    lef.macros[0].pins[0].shapes[0] = Shape::rect("M1", (0, 1), (1, 2));
    let d = def("COMPONENTS 1 ;\n- u1 cell + FIXED ( 10 20 ) N ;\nEND COMPONENTS");
    let got = flatten(&d, &lef).expect("flattens");
    assert_eq!(got[0].shape.bbox(), (10, 20, 11, 21));
    assert_eq!(got[0].net, None);
}

/// Oracle: the reference's PINS (5.8 p. 288): a pin's LAYER shape is given
/// about its placement point and turned with it; S turns (−5, 0)–(5, 10)
/// to (−5, −10)–(5, 0), moved to (100, 0). An unplaced port has no shape.
#[test]
fn a_pin_turns_about_its_placement_point() {
    let d = def(
        "PINS 2 ;\n- p + NET n + DIRECTION INPUT + USE SIGNAL\n  + PORT + LAYER M1 ( -5 0 ) ( 5 10 ) + PLACED ( 100 0 ) S ;\n\
         - q + NET m + LAYER M2 ( 0 0 ) ( 1 1 ) ;\nEND PINS",
    );
    assert_eq!(d.pins[0].shapes[0].bbox(), (95, -10, 105, 0));
    assert!(d.pins[1].shapes.is_empty());
}

/// Oracle: the reference's NONDEFAULTRULES and TAPER (5.8 pp. 251, 265):
/// a net under a rule draws its width; `TAPER` goes back to the LEF's.
#[test]
fn a_non_default_rule_sets_the_width_and_taper_resets_it() {
    let d = def(
        "NONDEFAULTRULES 1 ;\n- wide + HARDSPACING + LAYER M1 WIDTH 40 SPACING 10 ;\nEND NONDEFAULTRULES\n\
         NETS 1 ;\n- n + NONDEFAULTRULE wide + ROUTED M1 ( 0 0 ) ( 100 0 ) NEW M1 TAPER ( 0 100 ) ( 100 100 ) ;\nEND NETS",
    );
    assert_eq!(d.nets[0].wires[0].width, 40);
    assert_eq!(d.nets[0].wires[0].rect(), ((-20, -20), (120, 20)));
    assert_eq!(d.nets[0].wires[1].width, 10);
}

/// Oracle: the module's refusal list, each from the reference: what the
/// reader does not model is refused at its line, never drawn wrong.
#[test]
fn what_is_not_read_is_refused_with_its_line() {
    let refused = |body: &str| {
        let text = format!("UNITS DISTANCE MICRONS 1000 ;\n{body}\nEND DESIGN\n");
        read_def(&text, &lef()).expect_err(body)
    };
    let e = refused("NETS 1 ;\n- n + ROUTED M1 ( 0 0 ) ( 10 10 ) ;\nEND NETS");
    assert_eq!(e.line, 3);
    assert!(e.message.contains("neither horizontal nor vertical"), "{e}");
    assert!(
        refused("NETS 1 ;\n- n + ROUTED M1 ( 0 0 ) ( 10 0 ) nosuchvia ;\nEND NETS")
            .message
            .contains("nosuchvia")
    );
    assert!(
        refused("NETS 1 ;\n- n + ROUTED M1 STYLE 1 ( 0 0 ) ( 10 0 ) ;\nEND NETS")
            .message
            .contains("STYLE")
    );
    assert!(
        refused("NETS 1 ;\n- n + ROUTED cut12 ( 0 0 ) ( 10 0 ) ;\nEND NETS")
            .message
            .contains("no LEF WIDTH")
    );
    assert!(
        refused("COMPONENTS 1 ;\n- u cell + PLACED ( 0 0 ) NE ;\nEND COMPONENTS")
            .message
            .contains("orientation")
    );

    let mut lef = Lef::default();
    let e = read_lef_into(
        "MACRO m\n SIZE 1 BY 1 ;\n OBS\n  LAYER M1 ;\n  PATH 0 0 1 0 ;\n END\nEND m\n",
        1000,
        &mut lef,
    )
    .expect_err("PATH");
    assert_eq!((e.file, e.line), ("LEF", 5));
    assert!(read_lef_into("LAYER M1\n WIDTH 0.0001 ;\nEND M1\n", 1000, &mut lef).is_err());
    assert!(def_units("DESIGN x ;").is_err());
    assert_eq!(
        def_units("VERSION 5.8 ; UNITS DISTANCE MICRONS 2000 ;"),
        Ok(2000)
    );
}

/// Oracle: round trip through the GDS reader: the GDSII [`to_gds`] writes
/// is read back by `gds::Library` on a deck whose layer names are the
/// LEF's, every shape on its layer at its coordinates, at the DEF's units,
/// and each net's name bound to the shapes it was drawn on.
#[test]
fn the_written_stream_reads_back_shape_for_shape() {
    use crate::layout::{gds::Library, UnknownLayers};
    let d = def(
        "COMPONENTS 1 ;\n- u1 cell + PLACED ( 100 200 ) N ;\nEND COMPONENTS\n\
         NETS 1 ;\n- n ( u1 a ) + ROUTED M1 ( 0 50 ) ( 50 * ) VIA12 ( * 0 ) ;\nEND NETS",
    );
    let shapes = flatten(&d, &lef()).expect("flattens");
    let mut strings = StrTable::default();
    let grid = gpurify_geom::Grid::new(1000).expect("a grid");
    let deck = crate::deck::parse_deck(
        "layer M1 = gds(1, 0)\nlayer cut12 = gds(2, 0)\nlayer M2 = gds(3, 0)\n\
         connect conductors [M1, M2]\nconnect via cut12 [M1, M2]\n\
         connect label M1 names M1\nconnect label M2 names M2\n",
        grid,
        &mut strings,
    )
    .expect("the deck parses");
    let bytes = to_gds(
        &shapes,
        1000,
        "top",
        &deck.layers,
        &deck.connectivity,
        &strings,
    )
    .expect("writes");
    let library = Library::parse(&bytes, &mut strings).expect("reads back");
    assert_eq!(library.grid().expect("units").dbu_per_um(), 1000);
    let (store, mut provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("flattens");
    provenance
        .resolve_labels(&store, &deck.connectivity)
        .expect("every label lands");
    let mut read: Vec<(String, (i64, i64, i64, i64))> = (0..store.poly_count())
        .map(|p| {
            let poly = gpurify_geom::PolyId(u32::try_from(p).expect("small"));
            let b = store.poly_bbox(poly);
            let name = strings
                .resolve(deck.layers.name(store.poly_layer(poly)))
                .to_owned();
            (name, (b.xlo.raw(), b.ylo.raw(), b.xhi.raw(), b.yhi.raw()))
        })
        .collect();
    let mut want: Vec<(String, (i64, i64, i64, i64))> = shapes
        .iter()
        .map(|s| (s.shape.layer.clone(), s.shape.bbox()))
        .collect();
    read.sort_unstable();
    want.sort_unstable();
    assert_eq!(read, want);
    // The macro pin, the two wires and the via's metals are labelled; the
    // obstruction and the cut are not.
    assert_eq!(provenance.placed().len(), 5);
    assert!(provenance
        .placed()
        .iter()
        .all(|l| strings.resolve(l.name) == "n"));
    assert_eq!(provenance.labels().len(), 5);

    let mut no_layer = shapes.clone();
    no_layer[0].shape.layer = "M9".into();
    assert!(to_gds(
        &no_layer,
        1000,
        "top",
        &deck.layers,
        &deck.connectivity,
        &strings
    )
    .is_err());
}

/// A pin's antenna statements read as the reference's Example 1-32 and its
/// hierarchical sample state them: areas and ratios with their layer or
/// none, the `OXIDE2` model's gate area and ratios skipped while its
/// diffusion and partial areas (which no oxide model governs) are kept,
/// and a statement repeated for one layer read as its last value.
///
/// Oracle: LEF/DEF 5.8 pp. 140-142 ("the ANTENNAMODEL statement does not
/// affect ANTENNAPARTIAL*AREA and ANTENNADIFFAREA"; "if an ANTENNA
/// statement occurs twice for the same oxide model, the last value
/// specified is used"; ANTENNAMAX*CAR takes `LAYER layerName`), the
/// values copied from the statements.
#[test]
fn a_pins_antenna_statements_read_as_the_reference_states_them() {
    let pin = "MACRO g\n  SIZE 1 BY 1 ;\n  PIN IN1\n\
               ANTENNADIFFAREA 1.0 ;\n\
               ANTENNAMODEL OXIDE1 ;\n\
               ANTENNAGATEAREA 1.0 ;\n\
               ANTENNAMAXAREACAR 50.0 LAYER m1 ;\n\
               ANTENNAMAXAREACAR 60.0 LAYER m1 ;\n\
               ANTENNAPARTIALMETALAREA 10.0 LAYER METAL3 ;\n\
               ANTENNAMODEL OXIDE2 ;\n\
               ANTENNAGATEAREA 3.0 ;\n\
               ANTENNAMAXCUTCAR 5.0 LAYER VIA34 ;\n\
               ANTENNAPARTIALCUTAREA 0.1 LAYER VIA34 ;\n\
               PORT\n LAYER M1 ;\n RECT 0 0 1 1 ;\n END\n  END IN1\nEND g\n";
    let mut lef = Lef::default();
    read_lef_into(pin, 1000, &mut lef).expect("it reads");
    let got: Vec<(AntennaKind, f64, Option<&str>)> = lef.macros[0].pins[0]
        .antenna
        .iter()
        .map(|a| (a.kind, a.value, a.layer.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (AntennaKind::Diff, 1.0, None),
            (AntennaKind::Gate, 1.0, None),
            (AntennaKind::MaxAreaCar, 60.0, Some("m1")),
            (AntennaKind::PartialMetal, 10.0, Some("METAL3")),
            (AntennaKind::PartialCut, 0.1, Some("VIA34")),
        ]
    );
    let refused = read_lef_into(
        &pin.replace("50.0 LAYER m1", "50.0"),
        1000,
        &mut Lef::default(),
    )
    .expect_err("a CAR names its layer");
    assert!(refused.message.contains("LAYER"), "{refused}");
}

/// Oracle: GDSII stream format, the record header: a record's length is a
/// 16-bit byte count, its 4-byte header included, and a `BOUNDARY`'s `XY`
/// repeats its first point, so an `XY` of n vertices is 8 * (n + 1) + 4
/// <= 65535 bytes: 8190 vertices are written and read back, 8191 are
/// refused. Breaks if the limit counts the vertices without the closing
/// point: 8191 then panicked writing a 65540-byte record.
#[test]
fn a_polygon_filling_one_xy_record_is_written_and_one_vertex_more_is_refused() {
    let mut strings = StrTable::default();
    let grid = gpurify_geom::Grid::new(1000).expect("a grid");
    let deck = crate::deck::parse_deck("layer M1 = gds(1, 0)\n", grid, &mut strings)
        .expect("the deck parses");
    let polygon = |vertices: i64| FlatShape {
        shape: Shape {
            layer: "M1".into(),
            ring: (0..vertices).map(|k| (k, k % 2)).collect(),
        },
        net: None,
        origin: Origin::Route,
    };
    let write = |shape: FlatShape| {
        to_gds(
            &[shape],
            1000,
            "top",
            &deck.layers,
            &deck.connectivity,
            &strings,
        )
    };
    let bytes = write(polygon(8190)).expect("8190 vertices fill one XY record");
    crate::layout::gds::Library::parse(&bytes, &mut StrTable::default())
        .expect("the written stream reads back");
    assert!(write(polygon(8191)).is_err());
}
