//! Generators and oracles for the `GPUVerify` test suite.

pub mod assertions;
pub mod electrical;
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
pub use electrical::{
    ladder_network, parallel_plate, plate_answer, LadderCase, PlateAnswer, PlateCase, PlateSpec,
};
pub use graph::{graph_with_partition, GraphCase};
pub use netlist::{layout_from_netlist, DeviceSpec, Floorplan, NetlistCase, NetlistSpec};
pub use rng::Rng;
pub use scale::{scale_corpus, ScaleCorpus, ScaleSpec};
pub use shapes::{dbu, point, LayoutBuilder};
pub use violation::{layout_with_violation, Amount, ShapeKind, ViolationCase, ViolationShape};
