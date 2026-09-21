//! Builders shared by the `erc` integration tests.
//!
//! Nothing here states an answer. The oracles live in the tests and in
//! `gpurify_testgen`; this file only assembles the frozen input types that a
//! test cannot reach through a constructor, because `PowerGrid`,
//! `NetNetworks`, `IntentMap` and the nineteen rule tables are all public
//! columns with no builder of their own.

#![allow(
    dead_code,
    reason = "each test binary links only the fixtures it names"
)]

use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_check::erc::facts::IntentMap;
use gpurify_check::erc::power;
use gpurify_check::erc::power::{EdgeKind, NetNetworks, PowerGrid, PowerSolution, SolveConfig};
use gpurify_check::erc::ruleset::RuleHead;
use gpurify_ingest::intent::{DomainId, NetLimits, SupplyRole};
use gpurify_ingest::StrId;
use gpurify_check::report::{Outcome, RuleRun, Severity, Violations};
use gpurify_testgen::point;
use gpurify_testgen::Rng;
use gpurify_check::topology::NetId;
use gpurify_geom::{prefix, Current, Grid, Qty, Resistance, Temperature, Voltage};

/// A rule id. Tests never need the text, so they never need a `StrTable` —
/// whose `intern` is a frozen `todo!()` until the Implementation-Phase.
#[must_use]
pub fn rule(id: u32) -> StrId {
    StrId(id)
}

/// A one-row rule head at `Error` severity, which is what every table in this
/// crate embeds and what a violation is reported at.
#[must_use]
pub fn head(id: StrId) -> RuleHead {
    RuleHead {
        rule: vec![id],
        severity: vec![Severity::Error],
    }
}

#[must_use]
pub fn ohms(value: f64) -> Qty<Resistance, { prefix::BASE }> {
    Qty::new(value)
}

#[must_use]
pub fn millivolts(value: f64) -> Qty<Voltage, { prefix::MILLI }> {
    Qty::new(value)
}

#[must_use]
pub fn microamps(value: f64) -> Qty<Current, { prefix::MICRO }> {
    Qty::new(value)
}

/// The 1 nm manufacturing grid every conductor width here is stated against.
///
/// Named against `PowerGrid`, which every test in this crate calls `grid` — the
/// two are unrelated and the shorter name is taken. A function rather than a
/// `const`, because [`Grid::new`] is a `const fn` over a `todo!()` body until
/// the Implementation-Phase and a `const` would evaluate it at compile time.
/// `PowerGrid`'s edge widths are database units and the current-density limits
/// are amps per metre; this is what closes the chain between them.
#[must_use]
pub fn manufacturing_grid() -> Grid {
    Grid::new(1_000).expect("1000 database units per micrometre is a 1 nm grid")
}

/// 85 °C, absolute — the operating point every derating below is computed at.
///
/// Kelvin, and stated as a named constant rather than inline, because a bare
/// `85.0` reaching Black's equation is the exact fail-open the refusal tests
/// further down exist to catch.
#[must_use]
pub fn operating_temperature() -> Qty<Temperature, { prefix::BASE }> {
    Qty::new(358.15)
}

/// The run row a rule recorded, whatever its outcome.
///
/// `testgen::assert_rule_ran` insists the rule ran and examined something,
/// which is right for a clean assertion and wrong for a skip assertion — the
/// whole claim there is that it did *not* run.
///
/// # Panics
///
/// When the rule has no row, or more than one.
#[must_use]
pub fn run_of(runs: &[RuleRun], id: StrId) -> RuleRun {
    let matching: Vec<&RuleRun> = runs.iter().filter(|r| r.rule == id).collect();
    assert!(
        matching.len() == 1,
        "rule {id:?} recorded {} run rows; every configured rule row produces exactly one",
        matching.len()
    );
    *matching[0]
}

/// Assert a rule recorded itself skipped for want of design intent, and did so
/// without inventing a verdict.
///
/// The three claims together are what separates a skip from a clean run: there
/// is a row, it says skipped, and it examined nothing and found nothing.
///
/// # Panics
///
/// When any of the three fails.
pub fn assert_skipped_for_intent(runs: &[RuleRun], violations: &Violations, id: StrId) {
    let run = run_of(runs, id);
    assert!(
        run.outcome == Outcome::Skipped(gpurify_check::report::SkipReason::NoDesignIntent),
        "rule {id:?} recorded {:?}, not a skip for want of design intent",
        run.outcome
    );
    assert!(
        run.examined == 0,
        "rule {id:?} skipped but claims to have examined {} shapes",
        run.examined
    );
    assert!(
        run.violations == 0,
        "rule {id:?} skipped but claims {} violations",
        run.violations
    );
    assert!(
        !violations.rule.contains(&id),
        "rule {id:?} skipped and still pushed a violation"
    );
}

/// Assert the reported coordinate lies on a shape the row names.
///
/// `Violation::at` is documented as "always inside or on the geometry the
/// marker names, so a viewer can navigate to it". That is the part of the
/// coordinate contract every rule shares; a rule whose doc comment fixes the
/// point more precisely gets that asserted at its own test instead.
///
/// # Panics
///
/// When the point falls outside both named shapes.
pub fn assert_at_is_on_a_named_shape(store: &GeometryStore, violations: &Violations, row: usize) {
    let at = violations.at[row];
    let here = gpurify_geom::Bbox::point(at.x, at.y);
    let a = store.poly_bbox(violations.shape_a[row]);
    let inside_a = a.contains(here);
    let inside_b = violations.shape_b[row].is_some_and(|b| store.poly_bbox(b).contains(here));
    assert!(
        inside_a || inside_b,
        "row {row} reports {at:?}, which is on neither {:?} nor {:?}",
        violations.shape_a[row],
        violations.shape_b[row]
    );
}

/// Accumulates nodes and edges into a [`PowerGrid`].
///
/// The grid's columns are public and parallel, so pushing one node means
/// pushing six values in step. Getting that wrong in a test is a test bug that
/// reads as a solver bug.
#[derive(Debug, Default)]
pub struct GridBuilder {
    pub grid: PowerGrid,
}

impl GridBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push one node at `x` on the y axis, at `nominal_mv`, drawing `load_ua`.
    pub fn node(&mut self, x: i64, nominal_mv: f64, load_ua: f64) -> u32 {
        let index = u32::try_from(self.grid.node_net.len()).expect("a test grid is small");
        self.grid.node_net.push(NetId(0));
        self.grid.node_at.push(point(x, 0));
        self.grid.node_poly.push(PolyId(index));
        self.grid.node_layer.push(LayerId(0));
        self.grid.node_nominal.push(millivolts(nominal_mv));
        self.grid.node_load.push(microamps(load_ua));
        index
    }

    /// Hold a node at a fixed voltage. Sources must be pushed ascending, which
    /// is what the grid's own doc comment requires of the column.
    pub fn pad(&mut self, node: u32, millivolt: f64) {
        self.grid.source_node.push(node);
        self.grid.source_voltage.push(millivolts(millivolt));
    }

    /// Push a metal edge of `ohm` ohms, one micrometre wide and long, on layer
    /// zero.
    pub fn edge(&mut self, from: u32, to: u32, ohm: f64) {
        self.edge_on(LayerId(0), from, to, ohm);
    }

    /// The same, on a named layer — for the rules whose limits are per layer.
    pub fn edge_on(&mut self, layer: LayerId, from: u32, to: u32, ohm: f64) {
        self.grid.edge_from.push(from);
        self.grid.edge_to.push(to);
        self.grid.edge_resistance.push(ohms(ohm));
        self.grid.edge_width.push(gpurify_testgen::dbu(1_000));
        self.grid.edge_length.push(gpurify_testgen::dbu(1_000));
        self.grid.edge_layer.push(layer);
        self.grid.edge_kind.push(EdgeKind::Metal);
    }

    #[must_use]
    pub fn finish(self) -> PowerGrid {
        self.grid
    }
}

/// A pad at node zero and `resistors` identical resistors in series, with the
/// whole load drawn at the far end.
///
/// The closed form is Ohm's law over a series chain, which is one of the three
/// oracles named in `docs/TESTING.md`.
#[must_use]
pub fn series_chain(resistors: u32, ohm: f64, nominal_mv: f64, load_ua: f64) -> PowerGrid {
    let mut builder = GridBuilder::new();
    for node in 0..=resistors {
        let draw = if node == resistors { load_ua } else { 0.0 };
        builder.node(i64::from(node) * 1_000, nominal_mv, draw);
    }
    builder.pad(0, nominal_mv);
    for node in 0..resistors {
        builder.edge(node, node + 1, ohm);
    }
    builder.finish()
}

/// A pad and a load joined by `strands` identical resistors in parallel.
///
/// Conductances add, so the closed form is `ohm / strands` — and a solver that
/// assigns into its Laplacian rather than accumulating drops all but one of the
/// strands and reports `ohm`.
#[must_use]
pub fn parallel_bundle(strands: u32, ohm: f64, nominal_mv: f64, load_ua: f64) -> PowerGrid {
    assert!(strands > 0, "a bundle needs at least one strand");
    let mut builder = GridBuilder::new();
    builder.node(0, nominal_mv, 0.0);
    builder.node(1_000, nominal_mv, load_ua);
    builder.pad(0, nominal_mv);
    for _ in 0..strands {
        builder.edge(0, 1, ohm);
    }
    builder.finish()
}

/// A connected grid of arbitrary shape: a spanning path, `chords` extra edges,
/// one pad, and a load at every other node.
///
/// Arbitrary is the point. Kirchhoff's laws and the linearity of a resistive
/// network hold on any such grid, so this is the input a law-shaped test wants
/// and no closed form is needed for it.
#[must_use]
pub fn random_grid(seed: u64, nodes: u32, chords: u32) -> PowerGrid {
    assert!(nodes >= 2, "a grid needs at least two nodes");
    let mut rng = Rng::new(seed);
    let mut builder = GridBuilder::new();
    builder.node(0, 1_800.0, 0.0);
    for node in 1..nodes {
        #[allow(
            clippy::cast_precision_loss,
            reason = "a load in microamps is read as an f64 either way"
        )]
        let load = (rng.below(500) + 1) as f64;
        builder.node(i64::from(node) * 1_000, 1_800.0, load);
    }
    builder.pad(0, 1_800.0);
    // The path first, so every node is reachable from the pad and no island can
    // form. `solve_into` rejects islands, and a generator producing one would be
    // testing the error path while claiming to test the solve.
    for node in 0..nodes - 1 {
        builder.edge(node, node + 1, 0.5 + 4.0 * rng.unit());
    }
    for _ in 0..chords {
        let from = u32::try_from(rng.below(u64::from(nodes))).expect("bounded by nodes");
        let to = u32::try_from(rng.below(u64::from(nodes))).expect("bounded by nodes");
        if from != to {
            builder.edge(from, to, 0.5 + 4.0 * rng.unit());
        }
    }
    builder.finish()
}

/// Solve a grid at the default tolerance.
///
/// # Panics
///
/// When the solve fails. A test wanting the failure asserts on the `Result`
/// itself instead.
#[must_use]
pub fn solve(grid: &PowerGrid) -> PowerSolution {
    let mut scratch = power::SolveScratch::default();
    let mut solution = PowerSolution::default();
    power::solve_into(grid, SolveConfig::default(), &mut scratch, &mut solution)
        .expect("this grid is anchored and every resistance is positive");
    solution
}

/// One net's resistor network, as one row of a [`NetNetworks`].
///
/// Nodes are laid out along a line at unit pitch and tap polygon `n` — the
/// caller is responsible for a store holding those polygons wherever a rule
/// will report against them.
#[must_use]
pub fn one_row_network(nodes: u32, terminals: &[u32], edges: &[(u32, u32, f64)]) -> NetNetworks {
    let edge_count = u32::try_from(edges.len()).expect("a test network is small");
    let terminal_count = u32::try_from(terminals.len()).expect("a test network is small");
    let mut networks = NetNetworks {
        net: vec![NetId(0)],
        node_start: vec![0, nodes],
        node_at: Vec::with_capacity(nodes as usize),
        node_poly: Vec::with_capacity(nodes as usize),
        terminal_start: vec![0, terminal_count],
        terminal: terminals.to_vec(),
        edge_start: vec![0, edge_count],
        edge_from: Vec::with_capacity(edges.len()),
        edge_to: Vec::with_capacity(edges.len()),
        edge_resistance: Vec::with_capacity(edges.len()),
    };
    for node in 0..nodes {
        networks.node_at.push(point(i64::from(node) * 1_000, 0));
        networks.node_poly.push(PolyId(node));
    }
    for &(from, to, ohm) in edges {
        networks.edge_from.push(from);
        networks.edge_to.push(to);
        networks.edge_resistance.push(ohms(ohm));
    }
    networks
}

/// Read a probe's resistance out of the list, by terminal pair.
///
/// # Panics
///
/// When the pair is absent.
#[must_use]
pub fn probe_of(
    probes: &[(u32, u32, Qty<Resistance, { prefix::BASE }>)],
    a: u32,
    b: u32,
) -> Qty<Resistance, { prefix::BASE }> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    probes
        .iter()
        .find(|&&(x, y, _)| x == lo && y == hi)
        .map_or_else(
            || panic!("no probe between terminals {lo} and {hi}"),
            |&(_, _, r)| r,
        )
}

/// An intent map declaring one power net and one ground net in one domain.
///
/// Built directly rather than through `resolve_intent_into`, because
/// `DesignIntent`'s fields are private and its only producer is `read_intent`,
/// which takes a path — see `docs/NEED_TESTING.md`. The map is what every
/// intent-gated rule actually reads, so this is the input under test.
#[must_use]
pub fn declared_supplies(power_net: NetId, ground_net: NetId, nominal_mv: f64) -> IntentMap {
    let (first, second) = if power_net <= ground_net {
        (power_net, ground_net)
    } else {
        (ground_net, power_net)
    };
    let role_of = |net: NetId| {
        if net == power_net {
            SupplyRole::Power
        } else {
            SupplyRole::Ground
        }
    };
    let voltage_of = |net: NetId| {
        if net == power_net {
            millivolts(nominal_mv)
        } else {
            millivolts(0.0)
        }
    };
    IntentMap {
        declared: true,
        supply_net: vec![first, second],
        supply_domain: vec![DomainId(0), DomainId(0)],
        supply_role: vec![role_of(first), role_of(second)],
        supply_voltage: vec![voltage_of(first), voltage_of(second)],
        limit_net: Vec::new(),
        limit: Vec::new(),
        undeclared: Vec::new(),
    }
}

/// Declare a drop limit on a net, on top of an existing map.
pub fn limit_net(map: &mut IntentMap, net: NetId, limits: NetLimits) {
    let at = map.limit_net.partition_point(|&n| n < net);
    map.limit_net.insert(at, net);
    map.limit.insert(at, limits);
}
