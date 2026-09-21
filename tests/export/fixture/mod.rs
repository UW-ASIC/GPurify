//! One construct-from-answer world, shared by every test file in this crate.
//!
//! Every writer here transcribes tables it does not build, so a test is only as
//! good as the tables handed to it. This module builds one small world whose
//! answer is known before any writer runs: two disjoint rectangles on one
//! conductor layer, therefore exactly two nets; labels attached to known
//! polygons, therefore known net names; a device table stating the netlist the
//! SPICE writer has to reproduce; and a parasitic network whose values are
//! exact binary fractions, so no fixed-precision formatter can round one into
//! a different number.
//!
//! # Why the values are `12.5`, `0.25` and `0.125`
//!
//! Every writer routes floats through `json::format_f64`, and several tests
//! assert that a value handed in comes back out in the text. That only works
//! for values a formatter reproduces exactly at any reasonable precision, which
//! rules out anything that is not a short binary fraction.
//!
//! # What could not be built
//!
//! `deck::LayerTable` has private fields and no constructor, so nothing outside
//! `ingest` can populate one. That is recorded in `docs/NEED_TESTING.md`, and
//! it is why the GDS tests here work on an empty layer table.

#![allow(
    dead_code,
    reason = "each test file uses the part of the world it needs"
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify::export::json::Report;
use gpurify::export::Header;
use gpurify_ingest::deck::{Connectivity, DeviceKind};
use gpurify_ingest::{Provenance, StrId, StrTable};
use gpurify_extract::network::{NodeId, Parasitic};
use gpurify_extract::ParasiticNetwork;
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations};
use gpurify_testgen::{dbu, point, LayoutBuilder};
use gpurify_check::topology::device::{DeviceMeasure, DeviceParam};
use gpurify_check::topology::{
    bind_ports_into, extract_nets_into, DeviceTable, Extraction, NetId, NetTable, PortTable,
    TerminalRole,
};
use gpurify_geom::{Grid, Qty};

/// The one conductor layer. Both rectangles live here.
pub const CONDUCTOR: LayerId = LayerId(0);
/// Where violation markers are drawn. Never carries source geometry.
pub const MARKER: LayerId = LayerId(1);
/// Layers the store reserves a (possibly empty) range for.
pub const LAYERS: usize = 2;

/// Everything the writers in this crate take, built once with a known answer.
pub struct World {
    pub header: Header,
    /// The two violation rows, as the test states them.
    pub rows: [Violation; 2],
    pub violations: Violations,
    pub runs: Vec<RuleRun>,
    pub strings: StrTable,
    pub grid: Grid,

    pub store: GeometryStore,
    pub nets: NetTable,
    pub ports: PortTable,
    pub devices: DeviceTable,
    pub parasitics: ParasiticNetwork,

    /// The rectangle with the smaller [`PolyId`], and its net.
    pub lower_poly: PolyId,
    pub lower_net: NetId,
    /// The rectangle with the larger [`PolyId`], and its net.
    pub upper_poly: PolyId,
    pub upper_net: NetId,

    pub width_rule: StrId,
    pub density_rule: StrId,
    pub antenna_rule: StrId,
    pub nfet: StrId,
    pub pfet: StrId,
}

impl World {
    /// Both nets named. The case every successful write is tested against.
    #[must_use]
    pub fn named() -> Self {
        Self::new(Some("VDD"), Some("VSS"))
    }

    /// Only the lower net named, so the upper one is anonymous.
    ///
    /// The input for the [`gpurify::export::WriteError::UnnamedNet`] assertions:
    /// a format requiring a name for every net must refuse this one by number,
    /// not invent a placeholder.
    #[must_use]
    pub fn half_named() -> Self {
        Self::new(Some("VDD"), None)
    }

    /// Build the world, naming the lower and upper rectangles' nets.
    ///
    /// The answer this states, before any code under test runs: two rectangles
    /// separated by 300 database units on one conductor layer are two nets, and
    /// the label placed on a polygon is the name of that polygon's net.
    #[must_use]
    pub fn new(lower_name: Option<&str>, upper_name: Option<&str>) -> Self {
        let mut layout = LayoutBuilder::new(LAYERS);
        let a = layout.rect(CONDUCTOR, 0, 0, 100, 100);
        let b = layout.rect(CONDUCTOR, 400, 0, 500, 100);
        let (store, ids) = layout.finish();

        // The store sorts rows, so which handle became which row is a fact to
        // read back rather than assume. Ordering them here is what lets the
        // labels, the device markers and the node-to-net map all agree.
        let sorted = ids.sorted(&[a, b]);
        let (lower_poly, upper_poly) = (sorted[0], sorted[1]);

        let connectivity = Connectivity {
            conductors: vec![CONDUCTOR],
            via_cut: Vec::new(),
            via_connects: Vec::new(),
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&store, &connectivity, &mut nets);
        let lower_net = nets.net_of(lower_poly);
        let upper_net = nets.net_of(upper_poly);

        let mut strings = StrTable::default();
        let width_rule = strings.intern("m1.width");
        let density_rule = strings.intern("m1.density");
        let antenna_rule = strings.intern("m1.antenna");
        let nfet = strings.intern("nfet_01v8");
        let pfet = strings.intern("pfet_01v8");

        // Ascending by PolyId: `Provenance::labels` states that order, and
        // `bind_ports_into` relies on it rather than sorting.
        let mut provenance = Provenance::default();
        if let Some(name) = lower_name {
            provenance.label(lower_poly, strings.intern(name));
        }
        if let Some(name) = upper_name {
            provenance.label(upper_poly, strings.intern(name));
        }
        let mut ports = PortTable::default();
        bind_ports_into(&nets, &provenance, &mut ports)
            .expect("one label per net cannot be ambiguous");

        let rows = violation_rows(width_rule, density_rule, lower_poly, upper_poly);
        Self {
            header: header(Some("2020-01-01T00:00:00Z")),
            violations: table_of(&rows),
            rows,
            runs: runs(width_rule, density_rule, antenna_rule),
            grid: Grid::new(1000).expect("1000 dbu per micrometre is a 1 nm grid"),
            devices: devices(nfet, pfet, lower_poly, upper_poly, lower_net, upper_net),
            parasitics: parasitics(lower_net, upper_net),
            store,
            nets,
            ports,
            strings,
            lower_poly,
            lower_net,
            upper_poly,
            upper_net,
            width_rule,
            density_rule,
            antenna_rule,
            nfet,
            pfet,
        }
    }

    /// The report the JSON writer takes.
    #[must_use]
    pub fn report(&self) -> Report<'_> {
        Report {
            header: &self.header,
            violations: &self.violations,
            runs: &self.runs,
            strings: &self.strings,
            grid: self.grid,
        }
    }

    /// The three topology tables, borrowed together.
    #[must_use]
    pub fn extraction(&self) -> Extraction<'_> {
        Extraction {
            nets: &self.nets,
            devices: &self.devices,
            ports: &self.ports,
        }
    }
}

/// A store with no layers and no polygons.
///
/// The only input `gds::write_store` can be given from outside `ingest`:
/// `deck::LayerTable` has private fields and no constructor, so a store holding
/// geometry has no layer table to map it against. What is left is still worth
/// writing — the library skeleton, which is where a GDSII timestamp would live
/// — and it is what the round trip is stated over. See `docs/NEED_TESTING.md`.
#[must_use]
pub fn empty_store() -> GeometryStore {
    LayoutBuilder::new(0).finish().0
}

/// Run metadata. Every field that varies between two runs is here and nowhere
/// else, which is the claim the header tests check.
#[must_use]
pub fn header(timestamp: Option<&str>) -> Header {
    Header {
        tool_version: "gpurify-test",
        deck_path: "decks/test.json".to_owned(),
        layout_path: "layouts/test.gds".to_owned(),
        timestamp: timestamp.map(str::to_owned),
    }
}

/// Two violations, deliberately not in canonical order.
///
/// `json::write_report` states that it iterates the table as it stands and does
/// not sort; a table already in canonical order could not tell the difference.
/// One row carries a ratio and one a length, so a formatter that handles only
/// one arm of `Measurement` is visible.
fn violation_rows(
    width_rule: StrId,
    density_rule: StrId,
    lower: PolyId,
    upper: PolyId,
) -> [Violation; 2] {
    [
        Violation {
            rule: density_rule,
            layer: CONDUCTOR,
            severity: Severity::Warning,
            at: point(40, 60),
            measured: Measurement::Ratio(MEASURED_RATIO),
            limit: Measurement::Ratio(0.75),
            shapes: (upper, None),
        },
        Violation {
            rule: width_rule,
            layer: CONDUCTOR,
            severity: Severity::Error,
            at: point(10, 20),
            measured: Measurement::Length(dbu(80)),
            limit: Measurement::Length(dbu(100)),
            shapes: (lower, Some(upper)),
        },
    ]
}

/// The measured density, an exact binary fraction so the text a formatter
/// produces for it is predictable enough to search the report for.
pub const MEASURED_RATIO: f64 = 0.812_5;

/// Column-wise from rows, without going through `Violations::push`.
///
/// The columns are public and the writers read them directly, so building the
/// table by hand keeps the fixture from depending on a function under test to
/// state the input that function's caller is judged against.
#[must_use]
pub fn table_of(rows: &[Violation]) -> Violations {
    let mut table = Violations::default();
    for row in rows {
        table.rule.push(row.rule);
        table.layer.push(row.layer);
        table.severity.push(row.severity);
        table.at.push(row.at);
        table.measured.push(row.measured);
        table.limit.push(row.limit);
        table.shape_a.push(row.shapes.0);
        table.shape_b.push(row.shapes.1);
    }
    table
}

/// Three rule records: two that ran and found something, one that was skipped.
///
/// The skipped row is the point. An empty violation list is ambiguous between
/// "clean" and "nothing ran", and a report that does not carry the distinction
/// cannot be read.
fn runs(width_rule: StrId, density_rule: StrId, antenna_rule: StrId) -> Vec<RuleRun> {
    vec![
        RuleRun {
            rule: width_rule,
            outcome: Outcome::Ran,
            examined: 1234,
            violations: 1,
        },
        RuleRun {
            rule: density_rule,
            outcome: Outcome::Ran,
            examined: 5678,
            violations: 1,
        },
        RuleRun {
            rule: antenna_rule,
            outcome: Outcome::Skipped(SkipReason::NoDesignIntent),
            examined: 0,
            violations: 0,
        },
    ]
}

/// Two transistors, stated as a netlist before anything writes one.
///
/// Ids run in marker-polygon order because that is how `topology` assigns them,
/// and the CSR offset arrays carry the trailing end index this workspace uses
/// everywhere (`layer_start`, `net_start`, `prop_start` are all `n + 1` long).
fn devices(
    nfet: StrId,
    pfet: StrId,
    lower: PolyId,
    upper: PolyId,
    lower_net: NetId,
    upper_net: NetId,
) -> DeviceTable {
    let mut table = DeviceTable::default();
    table.kind = vec![DeviceKind::Mos, DeviceKind::Mos];
    table.marker = vec![lower, upper];
    table.model = vec![nfet, pfet];
    table.terminal_start = vec![0, 3, 6];
    table.terminal_net = vec![
        lower_net, upper_net, upper_net, upper_net, lower_net, lower_net,
    ];
    table.terminal_role = vec![
        TerminalRole::Gate,
        TerminalRole::Source,
        TerminalRole::Drain,
        TerminalRole::Gate,
        TerminalRole::Source,
        TerminalRole::Drain,
    ];
    table.param_start = vec![0, 2, 4];
    table.param = vec![
        (DeviceParam::Width, DeviceMeasure::Length(dbu(500))),
        (DeviceParam::Length, DeviceMeasure::Length(dbu(150))),
        (DeviceParam::Width, DeviceMeasure::Length(dbu(250))),
        (DeviceParam::Length, DeviceMeasure::Length(dbu(150))),
    ];
    table
}

/// Three nodes and three elements, already in canonical order.
///
/// Canonical order is by `from`, then `to` with `None` first, then kind — so
/// the rows below are written straight into the public columns rather than
/// through `push` and `sort_canonical`. A fixture that depended on the code
/// under test to order itself would be asserting against its own output.
fn parasitics(lower_net: NetId, upper_net: NetId) -> ParasiticNetwork {
    ParasiticNetwork {
        node_net: vec![lower_net, lower_net, upper_net],
        node_layer: vec![CONDUCTOR, CONDUCTOR, CONDUCTOR],
        from: vec![NodeId(0), NodeId(0), NodeId(1)],
        to: vec![None, Some(NodeId(1)), Some(NodeId(2))],
        value: vec![
            Parasitic::GroundCap(Qty::new(GROUND_CAP_FF)),
            Parasitic::Resistance(Qty::new(SERIES_OHM)),
            Parasitic::CouplingCap(Qty::new(COUPLING_FF)),
        ],
    }
}

/// The three element values, as exact binary fractions so a formatter at any
/// reasonable precision reproduces them digit for digit.
pub const GROUND_CAP_FF: f64 = 0.25;
pub const SERIES_OHM: f64 = 12.5;
pub const COUPLING_FF: f64 = 0.125;

/// Block until the wall clock crosses a second boundary.
///
/// A writer that reached for `SystemTime::now()` rather than taking its
/// timestamp as a parameter would still emit identical bytes from two
/// back-to-back runs: a formatted time has second resolution at best. Putting a
/// second between the two runs is what turns "these two outputs agree" into
/// evidence that nothing consulted the clock.
pub fn wait_for_the_next_second() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is set before 1970");
    let to_the_boundary =
        Duration::from_secs(1).saturating_sub(Duration::from_nanos(u64::from(now.subsec_nanos())));
    std::thread::sleep(to_the_boundary + Duration::from_millis(20));
}
