//! Generators and oracles for GPurify's test suite: layouts with a planted
//! violation at a known place, netlist-shaped layouts, scale corpora, a seeded
//! RNG, a GDSII writer, and assertions that read a report the way a test should.

pub mod assertions;
pub mod gds;
pub mod graph;
pub mod netlist;
pub mod rng;
pub mod scale;
pub mod shapes;
pub mod violation;

pub use assertions::{
    assert_bytes_identical, assert_clean, assert_close, assert_close_relative,
    assert_has_violation, assert_only_violation, assert_rule_ran, assert_violations_eq,
};
pub use graph::{graph_with_partition, GraphCase};
pub use netlist::{layout_from_netlist, DeviceSpec, Floorplan, NetlistCase, NetlistSpec};
pub use rng::Rng;
pub use scale::{scale_corpus, ScaleCorpus, ScaleSpec};
pub use shapes::{dbu, point, LayoutBuilder};
pub use violation::{layout_with_violation, Amount, ShapeKind, ViolationCase, ViolationShape};
