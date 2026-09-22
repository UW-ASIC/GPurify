//! Electrical rule checking: one table per rule kind, one transform per table.
//!
//! Data in: a [`RuleSet`] from the deck, and a [`RunInputs`] (design, net facts,
//! intent, per-net networks, the solved supply grid).
//! Data out: violations and one `RuleRun` per configured row. Six kinds need
//! design intent and record themselves skipped, never clean, without it.

pub mod facts;
pub mod power;
pub mod rules;
pub mod ruleset;

pub use facts::{classify_nets_into, resolve_intent_into, IntentMap, NetFacts, RoleMask};
pub use power::{NetNetworks, PowerError, PowerGrid, PowerSolution, Process, Solved};
pub use ruleset::{RuleHead, RuleSet, RunInputs, KINDS};

use crate::report::{Outcome, RuleRun, Violations};
use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Dbu, DbuArea, Qty, Resistance};
use gpurify_geom::{Bbox, GeometryStore, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

/// Boltzmann's constant in eV/K: activation energies are stated in eV.
pub(crate) const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262e-5;

/// Why a deck could not be turned into a [`RuleSet`]. Construction-time only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErcError {
    #[error("rule {rule}: missing required parameter {param}")]
    MissingParam { rule: String, param: &'static str },
    #[error("rule {rule}: parameter {param} is not the kind of value this rule takes")]
    WrongParamType { rule: String, param: &'static str },
    #[error("rule {rule}: takes {expected} layers, the deck names {found}")]
    WrongLayerCount {
        rule: String,
        expected: u32,
        found: u32,
    },
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: String },
    #[error("rule {rule}: {param} must be a fraction in [0, 1]")]
    NotAFraction { rule: String, param: &'static str },
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

pub use crate::Design;

/// The buffers every rule transform borrows and refills. No transform reads
/// what another left behind.
#[derive(Debug, Default)]
pub struct Scratch {
    layer_a: ValidatedLayer,
    layer_b: ValidatedLayer,
    net_marks: Vec<u32>,
    areas: Vec<DbuArea>,
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    solve: power::SolveScratch,
    probes: Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
    boxes: Vec<Bbox>,
}

/// A point on a polygon for a violation: vertex zero, which lies on the shape
/// (a box corner of an L sits in the notch).
pub(crate) fn first_vertex(store: &GeometryStore, poly: PolyId) -> Point {
    let (xs, ys) = store.poly_verts(poly);
    Point { x: xs[0], y: ys[0] }
}

/// The centre of a box, truncated toward its lower half.
pub(crate) fn centre(box_: Bbox) -> Point {
    Point {
        x: Dbu::new_unchecked(i64::midpoint(box_.xlo.raw(), box_.xhi.raw())),
        y: Dbu::new_unchecked(i64::midpoint(box_.ylo.raw(), box_.yhi.raw())),
    }
}

/// One violation per flagged net, at the net's lowest-numbered polygon; a net
/// with no polygon is skipped.
pub(crate) fn push_net_violations(
    design: Design<'_>,
    flagged: &[u32],
    rule: StrId,
    severity: crate::report::Severity,
    measured: crate::report::Measurement,
    limit: crate::report::Measurement,
    out: &mut Violations,
) {
    for &net in flagged {
        let Some(&poly) = design.nets.polys_of(crate::topology::NetId(net)).first() else {
            continue;
        };
        out.push(crate::report::Violation {
            rule,
            layer: design.store.poly_layer(poly),
            severity,
            at: first_vertex(design.store, poly),
            measured,
            limit,
            shapes: (poly, None),
        });
    }
}

/// Record every row of a table with one outcome (skipped or refused), so a
/// rule that stops early still reports each row.
pub(crate) fn fill_rows(
    head: &RuleHead,
    outcome: Outcome,
    out: &Violations,
    runs: &mut Vec<RuleRun>,
) {
    for &rule in &head.rule {
        record_run(runs, out, out.len(), rule, outcome, 0);
    }
}

/// Every row skipped for want of design intent.
pub(crate) fn skip_rows(head: &RuleHead, out: &Violations, runs: &mut Vec<RuleRun>) {
    fill_rows(
        head,
        Outcome::Skipped(crate::report::SkipReason::NoDesignIntent),
        out,
        runs,
    );
}

pub(crate) use crate::report::record_run;
