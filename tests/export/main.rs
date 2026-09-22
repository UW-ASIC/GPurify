//! The writers, byte for byte, against one small world whose answer is known:
//! two disjoint rectangles on one conductor (two nets, labelled by the test),
//! two violation rows out of canonical order, three rule records, and a
//! parasitic network of exact binary fractions.

use gpurify::export::json::{format_f64, Report};
use gpurify::export::{gds, json, parasitic, Header, WriteError};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
use gpurify_check::topology::{bind_ports_into, extract_nets_into, NetId, NetTable, PortTable};
use gpurify_extract::network::{NodeId, Parasitic};
use gpurify_extract::ParasiticNetwork;
use gpurify_geom::{Grid, LayerId, Qty};
use gpurify_ingest::deck::{Connectivity, Deck, LayerTable};
use gpurify_ingest::layout::{gds as reader, UnknownLayers};
use gpurify_ingest::{Provenance, StrTable};
use gpurify_testgen::{dbu, point, LayoutBuilder};

const CONDUCTOR: LayerId = LayerId(0);

struct World {
    header: Header,
    violations: Violations,
    runs: Vec<RuleRun>,
    strings: StrTable,
    ports: PortTable,
    parasitics: ParasiticNetwork,
    upper_net: NetId,
}

impl World {
    /// `upper_name: None` leaves the upper net anonymous.
    fn new(upper_name: Option<&str>) -> Self {
        let mut layout = LayoutBuilder::new(1);
        let a = layout.rect(CONDUCTOR, 0, 0, 100, 100);
        let b = layout.rect(CONDUCTOR, 400, 0, 500, 100);
        let (store, ids) = layout.finish();
        let sorted = ids.sorted(&[a, b]);
        let (lower, upper) = (sorted[0], sorted[1]);

        let connectivity = Connectivity {
            conductors: vec![CONDUCTOR],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&store, &connectivity, &mut nets);
        let (lower_net, upper_net) = (nets.net_of(lower), nets.net_of(upper));

        let mut strings = StrTable::default();
        let width = strings.intern("m1.width");
        let density = strings.intern("m1.density");
        let antenna = strings.intern("m1.antenna");
        let mut provenance = Provenance::default();
        provenance.label(lower, strings.intern("VDD"));
        if let Some(name) = upper_name {
            provenance.label(upper, strings.intern(name));
        }
        let mut ports = PortTable::default();
        bind_ports_into(&nets, &provenance, &mut ports).expect("one label per net");

        let mut violations = Violations::default();
        for row in [
            Violation {
                rule: density,
                layer: CONDUCTOR,
                severity: Severity::Warning,
                at: point(40, 60),
                measured: Measurement::Ratio(0.812_5),
                limit: Measurement::Ratio(0.75),
                shapes: (upper, None),
            },
            Violation {
                rule: width,
                layer: CONDUCTOR,
                severity: Severity::Error,
                at: point(10, 20),
                measured: Measurement::Length(dbu(80)),
                limit: Measurement::Length(dbu(100)),
                shapes: (lower, Some(upper)),
            },
        ] {
            violations.push(row);
        }
        let run = |rule, outcome, examined, violations| RuleRun {
            rule,
            outcome,
            examined,
            violations,
        };

        Self {
            header: Header {
                tool_version: "gpurify-test",
                deck_path: "decks/test.json".to_owned(),
                layout_path: "layouts/test.gds".to_owned(),
                timestamp: Some("2020-01-01T00:00:00Z".to_owned()),
            },
            violations,
            runs: vec![
                run(width, Outcome::Ran, 1234, 1),
                run(density, Outcome::Ran, 5678, 1),
                run(antenna, Outcome::Skipped(SkipReason::NoDesignIntent), 0, 0),
            ],
            strings,
            ports,
            parasitics: ParasiticNetwork {
                node_net: vec![lower_net, lower_net, upper_net],
                node_layer: vec![CONDUCTOR; 3],
                from: vec![NodeId(0), NodeId(0), NodeId(1)],
                to: vec![None, Some(NodeId(1)), Some(NodeId(2))],
                value: vec![
                    Parasitic::GroundCap(Qty::new(0.25)),
                    Parasitic::Resistance(Qty::new(12.5)),
                    Parasitic::CouplingCap(Qty::new(0.125)),
                ],
            },
            upper_net,
        }
    }

    fn json(&self) -> Result<String, WriteError> {
        let mut out = String::new();
        json::write_report(
            &Report {
                header: &self.header,
                violations: &self.violations,
                runs: &self.runs,
                strings: &self.strings,
                grid: Grid::new(1000).expect("a 1 nm grid"),
            },
            &mut out,
        )?;
        Ok(out)
    }

    fn spef(&self) -> Result<String, WriteError> {
        let mut out = String::new();
        let world = self;
        parasitic::write_spef(&world.parasitics, &world.ports, &world.strings, &world.header, &mut out)?;
        Ok(out)
    }

    fn dspf(&self) -> Result<String, WriteError> {
        let mut out = String::new();
        let world = self;
        parasitic::write_dspf(&world.parasitics, &world.ports, &world.strings, &world.header, &mut out)?;
        Ok(out)
    }
}

/// The table's own order (not canonical), floats through `format_f64`, the
/// skipped rule carried beside the ones that ran.
#[test]
fn the_json_report_is_exactly_these_bytes() {
    let expected = concat!(
        r#"{"header":{"tool_version":"gpurify-test","deck_path":"decks/test.json","layout_path":"layouts/test.gds","timestamp":"2020-01-01T00:00:00Z"},"#,
        r#""violations":[{"rule":"m1.density","layer":0,"severity":"warning","at":{"unit":"nm","x":40.000000,"y":60.000000},"measured":{"kind":"ratio","unit":"","value":0.812500},"limit":{"kind":"ratio","unit":"","value":0.750000},"shapes":[1,null]},"#,
        r#"{"rule":"m1.width","layer":0,"severity":"error","at":{"unit":"nm","x":10.000000,"y":20.000000},"measured":{"kind":"length","unit":"nm","value":80.000000},"limit":{"kind":"length","unit":"nm","value":100.000000},"shapes":[0,1]}],"#,
        r#""runs":[{"rule":"m1.width","outcome":"ran","examined":1234,"violations":1},{"rule":"m1.density","outcome":"ran","examined":5678,"violations":1},{"rule":"m1.antenna","outcome":"skipped:no_design_intent","examined":0,"violations":0}]}"#,
    );
    let world = World::new(Some("VSS"));
    assert_eq!(world.json().expect("writable"), expected);
    // Two independently built worlds give the same bytes.
    assert_eq!(World::new(Some("VSS")).json().expect("writable"), expected);
}

#[test]
fn a_json_string_escapes_quotes_backslashes_and_controls_only() {
    let mut world = World::new(Some("VSS"));
    world.header.deck_path = "a\"b\\c\n\t\r\u{8}\u{c}\u{1}\u{1f}\u{7f}é/".to_owned();
    world.header.timestamp = None;
    let text = world.json().expect("writable");
    assert!(
        text.starts_with(
            "{\"header\":{\"tool_version\":\"gpurify-test\",\"deck_path\":\"a\\\"b\\\\c\\n\\t\\r\\b\\f\\u0001\\u001f\u{7f}é/\",\"layout_path\":\"layouts/test.gds\",\"timestamp\":null}"
        ),
        "{text}"
    );
}

#[test]
fn a_non_finite_measurement_is_refused_before_a_byte_is_written() {
    let mut world = World::new(Some("VSS"));
    world.violations.measured[0] = Measurement::Ratio(f64::NAN);
    assert_eq!(
        world.json(),
        Err(WriteError::Unrepresentable("a non-finite measurement"))
    );
}

#[test]
fn the_spef_and_dspf_files_are_exactly_these_bytes() {
    let world = World::new(Some("VSS"));
    assert_eq!(
        world.spef().expect("every net is named"),
        "*SPEF \"IEEE 1481-1998\"\n*DESIGN \"layouts/test.gds\"\n*DATE \"2020-01-01T00:00:00Z\"\n\
         *VENDOR \"gpurify\"\n*PROGRAM \"gpurify\"\n*VERSION \"gpurify-test\"\n// deck decks/test.json\n\
         *DESIGN_FLOW \"EXTRACTED\"\n*DIVIDER /\n*DELIMITER :\n*BUS_DELIMITER [ ]\n*T_UNIT 1 NS\n\
         *C_UNIT 1 FF\n*R_UNIT 1 OHM\n*L_UNIT 1 PH\n\n\
         *D_NET VDD 0.375000\n*CONN\n*P VDD B\n*CAP\n1 VDD:0 0.250000\n2 VDD:1 VSS:0 0.125000\n\
         *RES\n1 VDD:0 VDD:1 12.500000\n*INDUC\n*END\n\n\
         *D_NET VSS 0.125000\n*CONN\n*P VSS B\n*CAP\n*RES\n*INDUC\n*END\n\n"
    );
    assert_eq!(
        world.dspf().expect("every net is named"),
        "*|DSPF \"1.4\"\n*|DESIGN \"layouts/test.gds\"\n*|DATE \"2020-01-01T00:00:00Z\"\n\
         *|VENDOR \"gpurify\"\n*|PROGRAM \"gpurify\"\n*|VERSION \"gpurify-test\"\n* deck decks/test.json\n\
         *|DIVIDER /\n*|DELIMITER :\n*|GROUND_NET 0\n\n\
         *|NET VDD 0.375000f\n*|S (VDD:0 L0)\n*|S (VDD:1 L0)\n\n\
         *|NET VSS 0.125000f\n*|S (VSS:0 L0)\n\n\
         C1 VDD:0 0 0.250000f\nR1 VDD:0 VDD:1 12.500000\nC2 VDD:1 VSS:0 0.125000f\n"
    );
}

/// A placeholder name would change between runs, so an anonymous net is refused by number.
#[test]
fn both_parasitic_formats_refuse_an_anonymous_net() {
    let world = World::new(None);
    let refusal = Err(WriteError::UnnamedNet(world.upper_net.0));
    assert_eq!(world.spef(), refusal);
    assert_eq!(world.dspf(), refusal);
}

#[test]
fn both_parasitic_formats_refuse_a_resistor_with_no_far_node() {
    let mut world = World::new(Some("VSS"));
    world.parasitics.to[1] = None;
    let refusal = Err(WriteError::Unrepresentable(
        "a resistance or inductance with no far node",
    ));
    assert_eq!(world.spef(), refusal);
    assert_eq!(world.dspf(), refusal);
}

/// Every record is padded to an even length (the odd `TOP` is the case a
/// missing pad gets wrong), and the reader accepts what the writer emits.
#[test]
fn an_empty_store_writes_a_library_the_reader_reads_back_empty() {
    let store = LayoutBuilder::new(0).finish().0;
    let mut bytes = Vec::new();
    gds::write_store(&store, &LayerTable::default(), "TOP", &mut bytes).expect("writable");
    assert_eq!(bytes.len() % 2, 0);
    assert!(reader::detect(&bytes));
    let layout = reader::read(&bytes, &Deck::default(), UnknownLayers::Reject)
        .expect("the reader accepts the writer's library");
    assert_eq!(layout.store.poly_count(), 0);
}

#[test]
fn format_f64_writes_six_decimal_places_and_no_exponent() {
    for (value, text) in [
        (0.0, "0.000000"),
        (-0.0, "-0.000000"),
        (12.5, "12.500000"),
        (98_765.432_1, "98765.432100"),
        (4e-7, "0.000000"),
        (1e30, "1000000000000000019884624838656.000000"),
    ] {
        let mut out = String::new();
        format_f64(value, &mut out);
        assert_eq!(out, text, "{value}");
    }
}
