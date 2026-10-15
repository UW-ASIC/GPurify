//! Generators and oracles for the `GPurify` test suite: layouts with a planted
//! violation at a known place, netlist-shaped layouts, scale corpora, a seeded
//! RNG, a GDSII writer, and assertions that read a report the way a test should.
//!
//! Every generator returns its answer beside its geometry, computed by
//! construction rather than by running the code under test: the violation a
//! rule must report ([`violation`]), the nets and devices extraction must give
//! back ([`netlist`], [`scale`]), the components a union-find must find
//! ([`graph`]), the exact area of a shape ([`shapes`]). A test compares the
//! engine's output against that answer with [`assertions`].
//!
//! # Determinism
//!
//! Randomness comes only from [`Rng`], a seeded `xorshift64*` behind a
//! `SplitMix64` seed finaliser. One seed gives one sequence on every platform
//! and every release, so a generator handed the same seed and arguments
//! builds the same layout, and a failing seed reproduces.
//!
//! # Units and failure
//!
//! Coordinates are plain `i64` database units, wrapped by [`dbu`]. The GDSII
//! writer ([`gds`]) labels them 1 nm (`UNITS` 0.001 µm per unit). A
//! generator asked for something it cannot build exactly, such as an odd span
//! whose midpoint is not a coordinate, panics with the reason instead of
//! building something nearby: in a test, that is the failure to read.
//!
//! # Examples
//!
//! ```
//! use gpurify_check::report::Severity;
//! use gpurify_geom::LayerId;
//! use gpurify_ingest::StrTable;
//! use gpurify_testgen::{layout_with_violation, Amount, ShapeKind, ViolationShape};
//!
//! let mut strings = StrTable::default();
//! let case = layout_with_violation(
//!     ViolationShape {
//!         rule: strings.intern("met1.width"),
//!         severity: Severity::Error,
//!         kind: ShapeKind::Width { layer: LayerId(0), run: 1_000 },
//!     },
//!     (500, 500),
//!     Amount::Length(120),
//!     Amount::Length(140),
//! );
//! // One 120 x 1000 rectangle centred on (500, 500); a width rule with a
//! // 140 minimum must report exactly `case.expected` against it.
//! assert_eq!(case.shapes, 1);
//! ```

pub mod assertions;
pub mod gds;
pub mod graph;
pub mod netlist;
pub mod oracle;
pub mod prop;
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
