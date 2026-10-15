//! Electrical rule checking: one table per rule kind, one transform per table.
//!
//! Data in: a [`RuleSet`] from the deck and the extracted design ([`Inputs`]).
//! Data out: violations and one `RuleRun` per configured row, from [`check`].
//! Kinds that need design intent record themselves skipped, never clean,
//! without it. The submodules stay public for the integration tests.
//!
//! Each kind is defined on its table type in [`rules`], reached from its
//! [`RuleSet`] field; the crate's [rule reference](crate#electrical-rules)
//! lists them all with their deck spelling.

pub mod facts;
pub mod power;
pub mod rules;
pub mod ruleset;
pub mod voltage;

pub use power::{PowerError, Process};
pub use ruleset::{RuleSet, KINDS};

use crate::report::{Outcome, RuleRun, Violations};
use crate::topology::{DeviceId, NetId, PortTable};
use facts::{classify_nets_into, resolve_intent_into, resolve_net_types_into};
use facts::{IntentMap, NetFacts, NetTypes};
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Dbu, DbuArea, Qty, Resistance, Temperature};
use gpurify_geom::{Bbox, GeometryStore, PolyId, ValidatedLayer};
use gpurify_ingest::intent::DesignIntent;
use gpurify_ingest::{StrId, StrTable};
use power::{NetNetworks, PowerGrid, PowerSolution, Solved};
use ruleset::{RuleHead, RunInputs};

/// What one ERC run reads, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// The extracted layout: geometry, nets and devices.
    pub design: Design<'a>,
    /// Net names from layout labels. They key the intent's supplies and
    /// limits, and `floating_gate` may read a labelled net as a port.
    pub ports: &'a PortTable,
    /// `None` skips the intent rules.
    pub intent: Option<&'a DesignIntent>,
    /// The deck's grid, stack and connectivity: sheet resistances for the
    /// networks, conductors for the antenna stages.
    pub process: Process<'a>,
    /// The die boundary: the denominator of every density.
    pub die: Bbox,
    /// The applied sign-off temperature, absolute.
    pub temperature: Qty<Temperature, { prefix::BASE }>,
    /// The placed macro pins' LEF antenna data (a DEF layout's), which the
    /// antenna rows count on the pins' nets; empty for a GDS layout.
    pub antenna_pins: &'a [rules::antenna::MacroPinAntenna],
    /// The run's names: label text, which the intent's net types match by
    /// name.
    pub strings: &'a StrTable,
}

/// Runs every row of `rules` over one extracted design, appending violations
/// to `out` and exactly one [`RuleRun`] per row to `runs`.
///
/// Nets are classified, the intent resolved onto them, voltages propagated,
/// and the per-net networks and the supply grid built and solved once, for
/// every row to read. A network that could not be built (a conductor whose
/// resistance the deck does not state: unknown, never zero) or a failed solve
/// refuses only the rows that read it; the rest run. Rows that need intent
/// record themselves skipped when `inputs.intent` is `None` or names nothing
/// this layout has. Nothing refuses the whole run.
pub fn check(rules: &RuleSet, inputs: Inputs<'_>, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let Inputs {
        design,
        ports,
        intent,
        process,
        die,
        temperature,
        antenna_pins,
        strings,
    } = inputs;
    let mut facts = NetFacts::default();
    classify_nets_into(design.nets, design.devices, &mut facts);
    let mut intent_map = IntentMap::default();
    resolve_intent_into(intent, ports, design.nets, &mut intent_map);
    let mut net_types = NetTypes::default();
    resolve_net_types_into(
        intent,
        ports,
        design.nets,
        design.devices,
        &intent_map,
        strings,
        &mut net_types,
    );
    let mut voltage = voltage::NetVoltage::default();
    voltage::propagate_into(design.nets, design.devices, &intent_map, &mut voltage);
    // One propagation per declared power state, its supplies off and its
    // inputs held.
    let resolved = facts::resolve_states(intent, ports, design.nets);
    let mut switched: Vec<NetId> = resolved
        .iter()
        .flat_map(|state| state.off.iter().copied())
        .collect();
    switched.sort_unstable();
    switched.dedup();
    let state_voltage: Vec<voltage::NetVoltage> = resolved
        .iter()
        .map(|state| {
            let mut reach = voltage::NetVoltage::default();
            let supplies = intent_map.in_state(state);
            voltage::propagate_into(design.nets, design.devices, &supplies, &mut reach);
            reach
        })
        .collect();

    let mut networks = NetNetworks::default();
    let built = power::extract_nets_into(
        design.store,
        design.nets,
        design.devices,
        process,
        &mut networks,
    );
    let mut grid = PowerGrid::default();
    let grid_built = power::extract_into(
        design.store,
        design.nets,
        design.devices,
        &intent_map,
        process,
        &mut grid,
    );

    // No declared supply: no grid, and the electrical rules record themselves skipped.
    let mut scratch = Scratch::default();
    let mut solution = PowerSolution::default();
    let power = match grid_built {
        Err(error) => Err(error),
        Ok(()) if grid.is_empty() => Ok(None),
        Ok(()) => power::solve_into(&grid, &mut scratch.solve, &mut solution).map(|()| {
            Some(Solved {
                grid: &grid,
                solution: &solution,
            })
        }),
    };

    // The AC current rules' grids: the supply grid again, each net loaded with
    // its RMS, then its peak, current in place of its budget. Built only for
    // rows that read them, and only when some net states that current.
    let ac_intent = [
        intent_map.with_budget(|limits| limits.rms_current_ua),
        intent_map.with_budget(|limits| limits.peak_current_ua),
    ];
    let wanted = [
        !rules.em_rms.head.is_empty(),
        !rules.em_peak.head.is_empty(),
    ];
    let mut ac_grid = [PowerGrid::default(), PowerGrid::default()];
    let mut ac_solution = [PowerSolution::default(), PowerSolution::default()];
    let mut ac_built = [Ok(false), Ok(false)];
    for k in 0..2 {
        if !wanted[k] || ac_intent[k].limit_net.is_empty() {
            continue;
        }
        ac_built[k] = power::extract_into(
            design.store,
            design.nets,
            design.devices,
            &ac_intent[k],
            process,
            &mut ac_grid[k],
        )
        .and_then(|()| {
            if ac_grid[k].is_empty() {
                return Ok(false);
            }
            power::solve_into(&ac_grid[k], &mut scratch.solve, &mut ac_solution[k]).map(|()| true)
        });
    }
    let ac: [power::Power<'_>; 2] = std::array::from_fn(|k| match ac_built[k] {
        Err(error) => Err(error),
        Ok(false) => Ok(None),
        Ok(true) => Ok(Some(Solved {
            grid: &ac_grid[k],
            solution: &ac_solution[k],
        })),
    });

    rules.run(
        RunInputs {
            design,
            facts: &facts,
            ports,
            intent: &intent_map,
            net_types: &net_types,
            voltage: &voltage,
            states: &state_voltage,
            switched: &switched,
            networks: built.map(|()| &networks),
            power,
            rms: (&ac_intent[0], ac[0]),
            peak: (&ac_intent[1], ac[1]),
            die,
            process,
            operating_temperature: temperature,
            antenna_pins,
        },
        &mut scratch,
        out,
        runs,
    );
}

/// Boltzmann's constant in eV/K: activation energies are stated in eV.
pub(crate) const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262e-5;

/// Why a deck could not be turned into a [`RuleSet`]. Construction-time only.
///
/// Every `rule` field is the deck's rule id, and every parameter name is the
/// engine's (`sidewall_thickness`, `max_drivers`), not the deck spelling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErcError {
    /// A required parameter is absent, or a row bounds nothing: a
    /// `density_cmp` row with no limit names `max_density`, a `well_bias` row
    /// with no model names `pmos`.
    #[error("rule {rule}: missing required parameter {param}")]
    MissingParam {
        /// The deck's rule id.
        rule: String,
        /// The parameter's engine name.
        param: &'static str,
    },
    /// A parameter holds the wrong kind of value, or a non-finite number.
    #[error("rule {rule}: parameter {param} is not the kind of value this rule takes")]
    WrongParamType {
        /// The deck's rule id.
        rule: String,
        /// The parameter's engine name.
        param: &'static str,
    },
    /// The row names the wrong number of layers.
    #[error("rule {rule}: takes {expected} layers, the deck names {found}")]
    WrongLayerCount {
        /// The deck's rule id.
        rule: String,
        /// The exact count, or the minimum for a kind taking a layer list.
        expected: u32,
        /// The count the row names.
        found: u32,
    },
    /// A limit that must be positive is zero or negative; also a zero
    /// `max_drivers` or `duty_cycle`, or a negative antenna diode factor.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit {
        /// The deck's rule id.
        rule: String,
        /// The parameter's engine name.
        limit: String,
    },
    /// A fraction outside `0.0 ..= 1.0`.
    #[error("rule {rule}: {param} must be a fraction in [0, 1]")]
    NotAFraction {
        /// The deck's rule id.
        rule: String,
        /// The parameter's engine name.
        param: &'static str,
    },
    /// Two rows of the deck, of any kind, share this id: a run's outcomes are
    /// attributed by id.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
    /// A table out of order: a `voltage_spacing` row whose voltages are
    /// negative or do not rise strictly, whose spacings fall as the voltage
    /// rises, or whose two lists differ in length.
    #[error("rule {rule}: {why}")]
    BadTable {
        /// The deck's rule id.
        rule: String,
        /// What is out of order.
        why: &'static str,
    },
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
    solve: power::SolveScratch,
    probes: Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
    boxes: Vec<Bbox>,
    /// An antenna row's nets at its etch step.
    staged_nets: crate::topology::NetTable,
}

/// Device row `index` as a [`DeviceId`].
///
/// # Panics
///
/// When `index` does not fit a `u32`, which a device table never holds.
pub(crate) fn device_id(index: usize) -> DeviceId {
    DeviceId(u32::try_from(index).expect("a device table indexes with u32"))
}

/// A point on a polygon for a violation: vertex zero, which lies on the shape
/// (a box corner of an L sits in the notch).
pub(crate) fn first_vertex(store: &GeometryStore, poly: PolyId) -> Point {
    let (xs, ys) = store.poly_verts(poly);
    Point { x: xs[0], y: ys[0] }
}

/// The centre of a box, each coordinate the midpoint rounded toward zero
/// (`i64::midpoint`), so up for a negative odd sum: not
/// `drc::rules::centre`, which floors.
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
