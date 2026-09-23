//! Rules over a solved resistive network.
//!
//! Data in: per-net networks (p2p resistance, always runs) and the solved
//! supply grid (the other three, skipped without intent).
//! Data out: violations and one run per row.

use crate::erc::facts::IntentMap;
use crate::erc::power::{
    discarded_budget, effective_resistance_into, EdgeKind, NetNetworks, PowerGrid, Solved,
};
use crate::erc::ruleset::RuleHead;
use crate::erc::{fill_rows, record_run, skip_rows, Design, Scratch, BOLTZMANN_EV_PER_K};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::LayerId;
use gpurify_geom::{
    prefix, Current, CurrentDensity, Dbu, Grid, Qty, Resistance, Temperature, Voltage,
};
use gpurify_ingest::StrId;

/// Worst effective resistance between any two device attach points of a net.
/// Effective resistance, so a parallel strap can only lower it.
#[derive(Debug, Default)]
pub struct P2pResistanceTable {
    pub head: RuleHead,
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Node voltage against each net's declared limits (all in `NetLimits`).
#[derive(Debug, Default)]
pub struct IrDropTable {
    pub head: RuleHead,
}

/// Instantaneous current per unit conductor width against a per-layer limit.
#[derive(Debug, Default)]
pub struct EmCurrentDensityTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` and the parallel limit
    /// columns are row `i`'s per-layer limits.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut: a via has no width to divide by.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,
}

/// Lifetime under sustained current: [`EmCurrentDensityTable`]'s limits
/// derated to the operating temperature, with Blech-immortal segments exempt.
#[derive(Debug, Default)]
pub struct ElectromigrationTable {
    pub head: RuleHead,
    /// Per-layer CSR, as in [`EmCurrentDensityTable`].
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,
    /// Per layer: the Blech product `J * L` (current, since `J` is per width)
    /// at or below which a segment is immortal.
    pub blech_limit: Vec<Qty<Current, { prefix::MICRO }>>,
    /// Per row: the Arrhenius reference point, absolute.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// `n` in Black's equation.
    pub current_exponent: Vec<f64>,
}

/// Worst-pair effective resistance per net. A net with under two attach
/// points has no network row and is not examined; a net that cannot be probed
/// refuses the row.
pub fn check_p2p_resistance(
    design: Design<'_>,
    networks: &NetNetworks,
    table: &P2pResistanceTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Scratch { solve, probes, .. } = scratch;
    for row in 0..table.head.len() {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        let limit = Measurement::Resistance(table.max_resistance[row]);

        let mut examined = 0u64;
        let mut outcome = Outcome::Ran;
        for net in 0..networks.len() {
            let net = u32::try_from(net).expect("a net row is indexed by a u32");
            if effective_resistance_into(networks, net, solve, probes).is_err() {
                outcome = Outcome::Refused;
                break;
            }
            examined += 1;
            // A pair split across components is absent from the probe list.
            let Some(&first) = probes.first() else {
                continue;
            };
            // Left fold in probe order: the earliest wins a tie.
            let mut worst = first;
            for &probe in &probes[1..] {
                if probe.2.raw() > worst.2.raw() {
                    worst = probe;
                }
            }
            let measured = Measurement::Resistance(worst.2);
            if !measured.violates(limit, LimitSense::Maximum) {
                continue;
            }
            let (points, polys) = networks.nodes_of(net);
            let (a, b) = (worst.0 as usize, worst.1 as usize);
            out.push(Violation {
                rule: id,
                layer: design.store.poly_layer(polys[a]),
                severity,
                at: points[a],
                measured,
                limit,
                shapes: (polys[a], Some(polys[b])),
            });
        }
        record_run(runs, out, before, id, outcome, examined);
    }
}

/// Push one node's voltage finding when it is over `limit`.
fn report_node(
    out: &mut Violations,
    grid: &PowerGrid,
    node: usize,
    head: (StrId, Severity),
    measured: Qty<Voltage, { prefix::MILLI }>,
    limit: Qty<Voltage, { prefix::MILLI }>,
) {
    let (measured, limit) = (Measurement::Voltage(measured), Measurement::Voltage(limit));
    if !measured.violates(limit, LimitSense::Maximum) {
        return;
    }
    out.push(Violation {
        rule: head.0,
        layer: grid.node_layer[node],
        severity: head.1,
        at: grid.node_at[node],
        measured,
        limit,
        shapes: (grid.node_poly[node], None),
    });
}

/// The solve every grid rule reads, or `None` after recording every row: skipped
/// without a solve or usable intent, refused when a stated budget never reached
/// the solve (zero current would pass every limit).
fn solved_or_fill<'a>(
    power: Option<Solved<'a>>,
    intent: &IntentMap,
    head: &RuleHead,
    out: &Violations,
    runs: &mut Vec<RuleRun>,
) -> Option<Solved<'a>> {
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(head, out, runs);
        return None;
    };
    if discarded_budget(solved.grid, intent) {
        fill_rows(head, Outcome::Refused, out, runs);
        return None;
    }
    Some(solved)
}

/// Node voltages against each net's stated absolute drop, fractional drop and
/// overvoltage. A node whose net states none is not examined.
pub fn check_ir_drop(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    table: &IrDropTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Some(solved) = solved_or_fill(power, intent, &table.head, out, runs) else {
        return;
    };
    let grid = solved.grid;
    for row in 0..table.head.len() {
        let before = out.len();
        let head = (table.head.rule[row], table.head.severity[row]);
        let mut examined = 0u64;
        for node in 0..grid.node_count() {
            let limits = intent.limits_of(grid.node_net[node]);
            let stated = limits.max_drop.is_some()
                | limits.max_drop_fraction.is_some()
                | limits.max_overvoltage.is_some();
            examined += u64::from(stated);

            let drop = solved.solution.node_drop[node];
            // Magnitude: a signed nominal would flip the ground rail's sense.
            let nominal = grid.node_nominal[node].raw().abs();
            if let Some(limit) = limits.max_drop {
                report_node(out, grid, node, head, drop, limit);
            }
            if let Some(fraction) = limits.max_drop_fraction {
                report_node(out, grid, node, head, drop, Qty::new(nominal * fraction));
            }
            // Overvoltage is a negative drop.
            if let Some(limit) = limits.max_overvoltage {
                report_node(out, grid, node, head, -drop, limit);
            }
        }
        record_run(runs, out, before, head.0, Outcome::Ran, examined);
    }
}

/// One row's per-layer current limits.
struct LayerLimits<'a> {
    layer: &'a [LayerId],
    max_density: &'a [Qty<CurrentDensity, { prefix::BASE }>],
    max_current_per_cut: &'a [Qty<Current, { prefix::MICRO }>],
    /// Blech product per layer, or empty when nothing is immortal.
    blech: &'a [Qty<Current, { prefix::MICRO }>],
}

/// The current one edge may carry: density times width for metal, the per-cut
/// limit for a via (one cut per edge). A zero width allows nothing.
fn allowed_current(
    kind: EdgeKind,
    width: Dbu,
    grid: Grid,
    max_density: Qty<CurrentDensity, { prefix::BASE }>,
    max_current_per_cut: Qty<Current, { prefix::MICRO }>,
) -> Qty<Current, { prefix::MICRO }> {
    match kind {
        // `A/m * m = A`, on base values.
        EdgeKind::Metal => {
            Qty::<Current, { prefix::BASE }>::new(max_density.raw() * grid.to_length(width).base())
                .to::<{ prefix::MICRO }>()
        }
        EdgeKind::Via => max_current_per_cut,
    }
}

/// Compare every branch on a limited layer against its allowed current times
/// `derate`. Returns `examined`: in-scope edges the Blech exemption did not
/// remove.
fn check_branches(
    solved: Solved<'_>,
    grid: Grid,
    head: (StrId, Severity),
    limits: &LayerLimits<'_>,
    derate: f64,
    out: &mut Violations,
) -> u64 {
    // `power` is the network; `grid` is the manufacturing grid.
    let (power, solution) = (solved.grid, solved.solution);
    let mut examined = 0u64;
    for edge in 0..power.edge_count() {
        // First mention of a repeated layer wins; other layers are out of scope.
        let Some(limit_row) = limits
            .layer
            .iter()
            .position(|&l| l == power.edge_layer[edge])
        else {
            continue;
        };
        let current =
            Qty::<Current, { prefix::MICRO }>::new(solution.branch_current[edge].raw().abs());
        let (width, length) = (power.edge_width[edge], power.edge_length[edge]);

        // Blech product `|I| * L / W`; a zero width makes it infinite (mortal).
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
        let slenderness = length.raw() as f64 / width.raw() as f64;
        let blech_product = current.raw() * slenderness;
        let immortal = limits
            .blech
            .get(limit_row)
            .is_some_and(|&blech| blech_product <= blech.raw());
        examined += u64::from(!immortal);

        let allowed = allowed_current(
            power.edge_kind[edge],
            width,
            grid,
            limits.max_density[limit_row],
            limits.max_current_per_cut[limit_row],
        ) * derate;
        let (measured, limit) = (Measurement::Current(current), Measurement::Current(allowed));
        if immortal || !measured.violates(limit, LimitSense::Maximum) {
            continue;
        }
        let (from, to) = (power.edge_from[edge] as usize, power.edge_to[edge] as usize);
        out.push(Violation {
            rule: head.0,
            layer: power.edge_layer[edge],
            severity: head.1,
            at: power.node_at[from],
            measured,
            limit,
            shapes: (power.node_poly[from], Some(power.node_poly[to])),
        });
    }
    examined
}

/// The shared row loop of both current rules. `derate(row)` of `None` refuses
/// the row.
fn check_current_rows(
    solved: Solved<'_>,
    grid: Grid,
    head: &RuleHead,
    limits: (&[u32], &LayerLimits<'_>),
    derate: impl Fn(usize) -> Option<f64>,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (layer_start, all) = limits;
    for row in 0..head.len() {
        let before = out.len();
        let id = head.rule[row];
        let Some(derate) = derate(row) else {
            record_run(runs, out, before, id, Outcome::Refused, 0);
            continue;
        };
        let span = layer_start[row] as usize..layer_start[row + 1] as usize;
        let limits = LayerLimits {
            layer: &all.layer[span.clone()],
            max_density: &all.max_density[span.clone()],
            max_current_per_cut: &all.max_current_per_cut[span.clone()],
            blech: if all.blech.is_empty() {
                &[]
            } else {
                &all.blech[span]
            },
        };
        let examined = check_branches(solved, grid, (id, head.severity[row]), &limits, derate, out);
        record_run(runs, out, before, id, Outcome::Ran, examined);
    }
}

/// Branch currents against each layer's instantaneous limit. An edge on an
/// unlimited layer is not examined.
pub fn check_em_current_density(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    grid: Grid,
    table: &EmCurrentDensityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Some(solved) = solved_or_fill(power, intent, &table.head, out, runs) else {
        return;
    };
    let limits = LayerLimits {
        layer: &table.layer,
        max_density: &table.max_density,
        max_current_per_cut: &table.max_current_per_cut,
        blech: &[],
    };
    check_current_rows(
        solved,
        grid,
        &table.head,
        (&table.layer_start, &limits),
        |_| Some(1.0),
        out,
        runs,
    );
}

/// Black's derating of a limit characterised at `reference` to `operating`:
/// `exp(Ea / (n k) * (1/T - 1/T_ref))`, below one when hotter. `None` for an
/// unusable parameter set or an infinite factor.
fn arrhenius_derating(
    operating: Qty<Temperature, { prefix::BASE }>,
    reference: Qty<Temperature, { prefix::BASE }>,
    activation_energy_ev: f64,
    current_exponent: f64,
) -> Option<f64> {
    let (t, t_ref) = (operating.raw(), reference.raw());
    let usable = t.is_finite()
        && t > 0.0
        && t_ref.is_finite()
        && t_ref > 0.0
        && activation_energy_ev.is_finite()
        && activation_energy_ev >= 0.0
        && current_exponent.is_finite()
        && current_exponent > 0.0;
    if !usable {
        return None;
    }
    let scale = activation_energy_ev / (current_exponent * BOLTZMANN_EV_PER_K);
    let derate = (scale * (1.0 / t - 1.0 / t_ref)).exp();
    derate.is_finite().then_some(derate)
}

/// Branch currents against the Arrhenius-derated limit, Blech-immortal
/// segments exempt. A row with no usable derating is refused.
///
/// ponytail: one temperature for the whole run, no self-heating, which errs
/// open for a hot wire; upgrade is a per-edge temperature column on
/// [`PowerGrid`].
pub fn check_electromigration(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    grid: Grid,
    operating_temperature: Qty<Temperature, { prefix::BASE }>,
    table: &ElectromigrationTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Some(solved) = solved_or_fill(power, intent, &table.head, out, runs) else {
        return;
    };
    let limits = LayerLimits {
        layer: &table.layer,
        max_density: &table.max_density,
        max_current_per_cut: &table.max_current_per_cut,
        blech: &table.blech_limit,
    };
    check_current_rows(
        solved,
        grid,
        &table.head,
        (&table.layer_start, &limits),
        |row| {
            arrhenius_derating(
                operating_temperature,
                table.reference_temperature[row],
                table.activation_energy_ev[row],
                table.current_exponent[row],
            )
        },
        out,
        runs,
    );
}
