//! Generators and oracles for the `GPUVerify` test suite.
//!
//! # This crate is not the system under test
//!
//! Every other crate in the workspace is frozen signatures over `todo!()`
//! bodies until the Implementation-Phase. This one has real implementations,
//! because a generator that does not work cannot state an answer, and an
//! oracle that has to be run before anyone knows what it says is not an oracle.
//!
//! It also means the failure modes are inverted. A bug here does not make a
//! test fail; it makes a test *pass* against wrong behaviour, or fail against
//! right behaviour. So the arithmetic in this crate — shape areas, ladder
//! resistances, plate capacitances, component labels — carries its own unit
//! tests, and those are the only tests in the workspace expected to be green
//! before Phase 4.
//!
//! # The three oracles
//!
//! Every builder names the one it serves, in its own doc comment. They are the
//! three from `docs/TESTING.md` and there are no others:
//!
//! - **Closed form.** [`shapes`] states the area of every non-convex shape as a
//!   formula. [`electrical::ladder_network`] reduces a series-parallel network
//!   by hand. [`electrical::parallel_plate`] is `epsilon_0 k A / d`.
//! - **Law.** Nothing here computes a law — laws are properties the consuming
//!   test asserts. What this crate supplies is arbitrary input for them to hold
//!   over: [`shapes::random_rectilinear_layer`] and [`scale::scale_corpus`],
//!   both fixed by a seed.
//! - **Construct-from-answer.** [`violation::layout_with_violation`] places one
//!   known violation at a known coordinate with a known measurement.
//!   [`netlist::layout_from_netlist`] emits geometry that extraction must
//!   return the netlist from. [`graph::graph_with_partition`] builds a graph
//!   whose components were decided before any edge was drawn.
//!
//! # Determinism
//!
//! Everything random comes from [`Rng`], which is written out in this crate
//! with a stated period and no dependency. One seed gives one corpus, on every
//! platform, forever. A test that prints its seed on failure is a test someone
//! can reproduce.
//!
//! # What it deliberately does not do
//!
//! It does not build a [`Deck`](gpurify_ingest::Deck). `LayerTable`'s fields
//! are private and it has no constructor, so no caller outside `ingest` can
//! make one — see `docs/NEED_TESTING.md`. The builders here hand back the deck
//! *fragments* whose types are constructible (`Connectivity`,
//! `DeviceRecognition`, `ProcessStack` coefficients), which is what the
//! transforms under test actually take.

// No `allow(unused_variables, dead_code)`. That scaffold exists in the other
// crates because their bodies are `todo!()`; here an unused parameter is a bug.

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
