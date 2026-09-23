//! Electrical rule checking: one table per rule kind, one transform per table.
//!
//! Data in: a [`RuleSet`] from the deck and the extracted design ([`Inputs`]).
//! Data out: violations and one `RuleRun` per configured row, from [`check`].
//! Kinds that need design intent record themselves skipped, never clean,
//! without it. The submodules stay public for the integration tests.

pub mod facts;
pub mod power;
pub mod rules;
pub mod ruleset;
pub mod voltage;

pub use power::{PowerError, Process};
pub use ruleset::{RuleSet, KINDS};

use crate::report::{Outcome, RuleRun, Violations};
use crate::topology::PortTable;
use facts::{classify_nets_into, resolve_intent_into, IntentMap, NetFacts};
use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Dbu, DbuArea, Qty, Resistance, Temperature};
use gpurify_geom::{Bbox, GeometryStore, PolyId, ValidatedLayer};
use gpurify_ingest::intent::DesignIntent;
use gpurify_ingest::StrId;
use power::{NetNetworks, PowerGrid, PowerSolution, Solved};
use ruleset::{RuleHead, RunInputs};

/// What one ERC run reads, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    pub design: Design<'a>,
    pub ports: &'a PortTable,
    /// `None` skips the intent rules.
    pub intent: Option<&'a DesignIntent>,
    pub process: Process<'a>,
    /// The die boundary: the denominator of every density.
    pub die: Bbox,
    /// The applied sign-off temperature, absolute.
    pub temperature: Qty<Temperature, { prefix::BASE }>,
}

/// Classify nets, resolve intent, build the per-net networks and the supply
/// grid, solve it, then run every row. An error means no rule ran: the grid
/// could not be built or solved, and nothing was written to `out` or `runs`.
pub fn check(
    rules: &RuleSet,
    inputs: Inputs<'_>,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) -> Result<(), PowerError> {
    let Inputs {
        design,
        ports,
        intent,
        process,
        die,
        temperature,
    } = inputs;
    let mut facts = NetFacts::default();
    classify_nets_into(design.nets, design.devices, &mut facts);
    let mut intent_map = IntentMap::default();
    resolve_intent_into(intent, ports, design.nets, &mut intent_map);
    let mut voltage = voltage::NetVoltage::default();
    voltage::propagate_into(design.nets, design.devices, &intent_map, &mut voltage);

    let mut networks = NetNetworks::default();
    power::extract_nets_into(
        design.store,
        design.nets,
        design.devices,
        process,
        &mut networks,
    )?;
    let mut grid = PowerGrid::default();
    power::extract_into(
        design.store,
        design.nets,
        design.devices,
        &intent_map,
        process,
        &mut grid,
    )?;

    // No declared supply: no grid, and the electrical rules record themselves skipped.
    let mut scratch = Scratch::default();
    let mut solution = PowerSolution::default();
    let power = if grid.is_empty() {
        None
    } else {
        power::solve_into(&grid, &mut scratch.solve, &mut solution)?;
        Some(Solved {
            grid: &grid,
            solution: &solution,
        })
    };

    rules.run(
        RunInputs {
            design,
            facts: &facts,
            intent: &intent_map,
            voltage: &voltage,
            networks: &networks,
            power,
            die,
            grid: process.grid,
            operating_temperature: temperature,
        },
        &mut scratch,
        out,
        runs,
    );
    Ok(())
}

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
