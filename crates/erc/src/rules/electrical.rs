//! Rules over a solved resistive network.
//!
//! [`check_p2p_resistance`] needs no design intent and always runs. The other
//! three read the solved supply grid, and with no intent there is no grid, so
//! they record [`Skipped`]`(`[`NoDesignIntent`]`)` rather than an empty clean
//! result.
//!
//! [`Skipped`]: gpurify_report::Outcome::Skipped
//! [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent

use crate::facts::IntentMap;
use crate::power::{
    discarded_budget, effective_resistance_into, EdgeKind, NetNetworks, PowerGrid, Solved,
};
use crate::ruleset::RuleHead;
use crate::{record_run, refuse_rows, skip_rows, Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::intent::NetLimits;
use gpurify_ingest::StrId;
use gpurify_report::{
    LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations,
};
use gpurify_units::{
    prefix, Current, CurrentDensity, Dbu, Grid, Qty, Resistance, Temperature, Voltage,
};

/// Boltzmann's constant in electronvolts per kelvin — `Ea / kT` is
/// dimensionless only if the two agree on eV.
const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262e-5;

/// Effective resistance between the device attach points of a net.
///
/// The **effective** resistance of the whole network between two terminals, not
/// a path length and not a sum of squares: effective resistance obeys Rayleigh
/// monotonicity, so adding a parallel strap can only lower the reported number.
#[derive(Debug, Default)]
pub struct P2pResistanceTable {
    pub head: RuleHead,
    /// Worst permitted effective resistance between any two attach points on
    /// one net.
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Voltage a node actually sits at, against what the design allows.
///
/// No limit columns: every one of them is a per-net number in [`NetLimits`],
/// which the design owner states and no process can.
///
/// [`NetLimits`]: gpurify_ingest::intent::NetLimits
#[derive(Debug, Default)]
pub struct IrDropTable {
    pub head: RuleHead,
}

/// Current per unit conductor width, against a per-layer limit.
///
/// The instantaneous check, distinct from [`ElectromigrationTable`], which asks
/// whether the wire survives ten years of it.
#[derive(Debug, Default)]
pub struct EmCurrentDensityTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` and the parallel
    /// `max_density` and `max_current_per_cut` are row `i`'s per-layer limits.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut, not per width: a via array has no conductor
    /// width to divide by, so comparing it against `max_density` would be a
    /// dimensional error rather than a verdict.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,
}

/// Lifetime under sustained current, with temperature derating.
#[derive(Debug, Default)]
pub struct ElectromigrationTable {
    pub head: RuleHead,
    /// Per-layer limits, CSR, as in [`EmCurrentDensityTable`]. Characterised at
    /// [`ElectromigrationTable::reference_temperature`].
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut, not per width.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,

    /// The Blech product `J · L`, above which a segment is not immortal.
    ///
    /// With [`CurrentDensity`] as current per unit *width* this product has the
    /// dimension of current; the literature's A/cm assumes current per unit
    /// *area*, so the two differ by a thickness.
    pub blech_limit: Vec<Qty<Current, { prefix::MICRO }>>,

    /// Arrhenius reference point, absolute in kelvin: Black's equation needs
    /// `1/T`, which divides by zero at 0 °C and changes sign below it.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// `n` in Black's equation.
    pub current_exponent: Vec<f64>,
}

/// Worst-pair effective resistance, per net.
///
/// A net with fewer than two attach points has no row in `networks` and is not
/// examined: there is no pair to measure, so reporting it clean would be a
/// claim about nothing.
pub fn check_p2p_resistance(
    design: Design<'_>,
    networks: &NetNetworks,
    table: &P2pResistanceTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(rows, table.head.severity.len(), "RuleHead columns diverged");
    debug_assert_eq!(rows, table.max_resistance.len(), "one limit per rule row");

    let nets = networks.len();
    // Split borrow: the probe writes its pair list and its solve workspace in
    // the same call.
    let Scratch { solve, probes, .. } = scratch;

    for row in 0..rows {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        let limit = Measurement::Resistance(table.max_resistance[row]);
        debug_assert!(limit.is_finite(), "rule {id:?} states a non-finite limit");

        let mut examined = 0u64;
        let mut outcome = Outcome::Ran;
        for net in 0..nets {
            let net = u32::try_from(net).expect("a net row is indexed by a u32");
            // Fail closed: a network this crate could not probe is not a net
            // that measured within its limit.
            if effective_resistance_into(networks, net, solve, probes).is_err() {
                outcome = Outcome::Refused;
                break;
            }
            examined += 1;

            // A pair split across components is absent from the probe list, so
            // a row with no pair has nothing to compare.
            let Some(&first) = probes.first() else {
                continue;
            };
            // A strict left fold in ascending probe order, so among equal
            // resistances the earliest probe wins on every run.
            let mut worst = first;
            for &probe in &probes[1..] {
                worst = [worst, probe][usize::from(probe.2.raw() > worst.2.raw())];
            }
            let measured = Measurement::Resistance(worst.2);

            if !measured.violates(limit, LimitSense::Maximum) {
                continue;
            }
            let (points, polys) = networks.nodes_of(net);
            let (a, b) = (worst.0 as usize, worst.1 as usize);
            debug_assert!(a < points.len() && b < points.len(), "a probe named a node outside its row");
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

        debug_assert!(
            usize::try_from(examined).expect("an examined count fits a usize") <= nets,
            "probed {examined} of {nets} networks"
        );
        record_run(runs, out, before, id, outcome, examined);
    }
}

/// Push one node's voltage finding, when it is over the limit handed in.
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
        // One shape: a node taps one polygon.
        shapes: (grid.node_poly[node], None),
    });
}

/// Node voltages against the drop each net is allowed.
///
/// Three independent limits, each reported only when stated: absolute drop,
/// drop as a fraction of the domain's nominal, and overvoltage. A net stating
/// none of the three is out of scope and does not contribute to `examined`, so
/// a design that limited nothing gets `Ran` with `examined == 0` — a different
/// claim from clean.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when `power` is `None` or
/// [`IntentMap::is_usable`] is false. Never a silent empty result.
///
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_ir_drop(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    table: &IrDropTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(rows, table.head.severity.len(), "RuleHead columns diverged");

    // Spent once above the loop; every row still records a run.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "the solution's columns do not match the grid it claims to have solved"
    );
    // A refusal rather than a skip: a stated budget that never reached the
    // solve leaves every node at its pad voltage, so every drop is zero and no
    // limit can be exceeded. Refusing the whole row is a deliberate
    // over-refusal — `Outcome` has no partial verdict, and `Ran` over the nets
    // whose budget did land is indistinguishable from a complete check.
    if discarded_budget(solved.grid, intent) {
        refuse_rows(&table.head, out, runs);
        return;
    }

    // `limit_row_of_net[n]` is one plus the row of `intent.limit` stating net
    // `n`'s limits; `0` is "this net stated none" and indexes the all-`None`
    // sentinel prepended to `limits_by_row`, so an unlimited net and a limited
    // one take the same branchless path. Sized by the highest limited net, so a
    // node above that is out of scope and `get` says so.
    debug_assert!(
        intent.limit_net.windows(2).all(|pair| pair[0] < pair[1]),
        "the limit column is documented ascending, which is what the dense \
         column below stands on"
    );
    debug_assert_eq!(
        intent.limit_net.len(),
        intent.limit.len(),
        "a limit lost its net, or a net lost its limit"
    );
    let dense_len = intent.limit_net.last().map_or(0, |net| net.idx() + 1);
    let mut limit_row_of_net = vec![0u32; dense_len];
    for (row, &net) in intent.limit_net.iter().enumerate() {
        limit_row_of_net[net.idx()] =
            u32::try_from(row + 1).expect("a design limits fewer nets than a u32 counts");
    }
    let mut limits_by_row = Vec::with_capacity(intent.limit.len() + 1);
    limits_by_row.push(NetLimits::default());
    limits_by_row.extend_from_slice(&intent.limit);
    debug_assert!(
        intent
            .limit_net
            .iter()
            .all(|&net| limit_row_of_net[net.idx()] != 0),
        "the dense net column lost a limited net"
    );

    for row in 0..rows {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        let grid = solved.grid;
        let nodes = grid.node_count();
        let mut examined = 0u64;

        for node in 0..nodes {
            // `get` on a net above the highest limited one, and on
            // `NetId::NONE`, answers the same `0`.
            let limit_row = limit_row_of_net
                .get(grid.node_net[node].idx())
                .copied()
                .unwrap_or(0) as usize;
            let limits = limits_by_row[limit_row];
            debug_assert_eq!(
                limits.max_drop,
                intent.limits_of(grid.node_net[node]).max_drop,
                "the dense net column disagrees with the search it replaced"
            );
            // A node on a net that stated nothing is out of scope.
            let stated = limits.max_drop.is_some()
                | limits.max_drop_fraction.is_some()
                | limits.max_overvoltage.is_some();
            examined += u64::from(stated);

            let head = (id, severity);
            let drop = solved.solution.node_drop[node];
            // Magnitude: a signed nominal would flip the limit's sense on the
            // ground side of the pair.
            let nominal = grid.node_nominal[node].raw().abs();

            if let Some(limit) = limits.max_drop {
                report_node(out, grid, node, head, drop, limit);
            }
            if let Some(fraction) = limits.max_drop_fraction {
                report_node(out, grid, node, head, drop, Qty::new(nominal * fraction));
            }
            // Overvoltage points the other way: a node *above* nominal is a
            // negative drop.
            if let Some(limit) = limits.max_overvoltage {
                report_node(out, grid, node, head, -drop, limit);
            }
        }

        debug_assert!(
            usize::try_from(examined).expect("an examined count fits a usize") <= nodes,
            "examined {examined} of {nodes} nodes"
        );
        record_run(runs, out, before, id, Outcome::Ran, examined);
    }
}

/// One rule row's per-layer current limits, borrowed out of its CSR span.
struct LayerLimits<'a> {
    /// The layers this row limits; an edge on any other layer is out of scope.
    layer: &'a [LayerId],
    max_density: &'a [Qty<CurrentDensity, { prefix::BASE }>],
    max_current_per_cut: &'a [Qty<Current, { prefix::MICRO }>],
    /// Blech-immortality product per layer, or empty for a rule with no
    /// lifetime to exempt a segment from.
    blech: &'a [Qty<Current, { prefix::MICRO }>],
}

/// The current one edge may carry, from whichever limit its kind is stated
/// against.
///
/// A metal segment's limit is a density times its conductor width, a via's is a
/// per-cut current times its cut count; both come out a [`Current`], which is
/// what makes them comparable against the solved branch current.
///
/// A zero width or a zero cut count yields a zero limit, so any current at all
/// violates it — the fail-closed direction. The `|I| / W` form is the same
/// inequality rearranged, and it divides by zero.
fn allowed_current(
    kind: EdgeKind,
    width: Dbu,
    grid: Grid,
    max_density: Qty<CurrentDensity, { prefix::BASE }>,
    max_current_per_cut: Qty<Current, { prefix::MICRO }>,
) -> Qty<Current, { prefix::MICRO }> {
    match kind {
        // `A/m * m = A`, on base values: `units::arith` carries no
        // `CurrentDensity * Length` operator.
        EdgeKind::Metal => {
            Qty::<Current, { prefix::BASE }>::new(max_density.raw() * grid.to_length(width).base())
                .to::<{ prefix::MICRO }>()
        }
        EdgeKind::Via { cuts } => max_current_per_cut * f64::from(cuts),
    }
}

/// One pass over the solution's branch column, comparing each edge on a
/// limited layer against the current it is allowed.
///
/// Shared by [`check_em_current_density`] and [`check_electromigration`], which
/// differ only in `derate` — unity for the instantaneous check — and
/// [`LayerLimits::blech`], empty for it.
///
/// Returns `examined`: edges on a limited layer the Blech exemption did not
/// remove.
fn check_branches(
    solved: Solved<'_>,
    grid: Grid,
    head: (StrId, Severity),
    limits: &LayerLimits<'_>,
    derate: f64,
    out: &mut Violations,
) -> u64 {
    debug_assert_eq!(limits.layer.len(), limits.max_density.len());
    debug_assert_eq!(limits.layer.len(), limits.max_current_per_cut.len());
    debug_assert!(
        limits.blech.is_empty() || limits.blech.len() == limits.layer.len(),
        "a Blech column is either absent or one entry per limited layer"
    );
    debug_assert!(
        derate.is_finite() && derate >= 0.0,
        "{derate} is not a usable derating factor"
    );

    // `power` is the resistive network; `grid` is the manufacturing grid the
    // conductor widths are indices into. Two different grids, one letter apart.
    let (power, solution) = (solved.grid, solved.solution);
    let mut examined = 0u64;

    // `limit_of_layer[l]` is one plus the row of `limits.layer` limiting layer
    // `l`; `0` is "this row does not limit that layer". Sized by the highest
    // layer this row limits, so an edge above that is out of scope and `get`
    // says so.
    let dense_len = limits
        .layer
        .iter()
        .map(|layer| layer.idx() + 1)
        .max()
        .unwrap_or(0);
    let mut limit_of_layer = vec![0u32; dense_len];
    // Reverse, so the earliest mention of a repeated layer is the one left
    // standing.
    for (row, &layer) in limits.layer.iter().enumerate().rev() {
        limit_of_layer[layer.idx()] =
            u32::try_from(row + 1).expect("a rule row limits fewer layers than a u32 counts");
    }
    debug_assert!(
        limits.layer.iter().all(|&layer| {
            let first = limits.layer.iter().position(|&l| l == layer);
            limit_of_layer[layer.idx()] as usize == first.map_or(0, |row| row + 1)
        }),
        "the dense layer column disagrees with the scan it replaced"
    );

    for edge in 0..power.edge_count() {
        // Out of scope: this row states no limit for the edge's layer.
        let limit_row = limit_of_layer
            .get(power.edge_layer[edge].idx())
            .copied()
            .unwrap_or(0);
        if limit_row == 0 {
            continue;
        }
        let limit_row = limit_row as usize - 1;
        debug_assert_eq!(
            limits.layer[limit_row], power.edge_layer[edge],
            "the dense layer column sent edge {edge} to another layer's limit"
        );

        let current =
            Qty::<Current, { prefix::MICRO }>::new(solution.branch_current[edge].raw().abs());
        let (width, length) = (power.edge_width[edge], power.edge_length[edge]);

        // The Blech product `J * L` is `|I| * (L / W)` — a ratio of two exact
        // `Dbu`, so no grid conversion enters and the result carries the
        // current's own unit. A zero width makes the product infinite, which is
        // not immortal.
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
        let slenderness = length.raw() as f64 / width.raw() as f64;
        let blech_product = current.raw() * slenderness;
        // `get` on an empty column is `None`: the instantaneous check has no
        // immortality to grant.
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
        debug_assert!(
            allowed.is_finite(),
            "edge {edge} was handed a non-finite allowed current"
        );

        let (measured, limit) = (Measurement::Current(current), Measurement::Current(allowed));
        // An immortal segment is one the mechanism does not apply to rather
        // than one that was waived.
        if immortal || !measured.violates(limit, LimitSense::Maximum) {
            continue;
        }
        let (from, to) = (power.edge_from[edge] as usize, power.edge_to[edge] as usize);
        debug_assert!(
            from < power.node_count() && to < power.node_count(),
            "edge {edge} names a node outside the grid"
        );
        out.push(Violation {
            rule: head.0,
            // The edge's layer, not either endpoint's: the limit exceeded is
            // the one stated for the conductor carrying the current.
            layer: power.edge_layer[edge],
            severity: head.1,
            at: power.node_at[from],
            measured,
            limit,
            shapes: (power.node_poly[from], Some(power.node_poly[to])),
        });
    }

    debug_assert!(
        usize::try_from(examined).expect("an examined count fits a usize") <= power.edge_count(),
        "examined {examined} of {} edges",
        power.edge_count()
    );
    examined
}

/// Branch currents against each layer's current-density limit.
///
/// The compare is per [`EdgeKind`] and the two kinds are not commensurable: a
/// metal edge's current is divided by its conductor width, a via's by its cut
/// count. `grid` is a parameter because `edge_width` is a [`Dbu`] while
/// `max_density` is amps per metre, and neither [`Solved`] nor [`IntentMap`]
/// carries a grid.
///
/// An edge on an unlimited layer is skipped and not counted in `examined`.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when there is no solve.
///
/// [`EdgeKind`]: crate::power::EdgeKind
/// [`Dbu`]: gpurify_units::Dbu
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_em_current_density(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    grid: Grid,
    table: &EmCurrentDensityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(rows, table.head.severity.len(), "RuleHead columns diverged");
    debug_assert_eq!(table.layer_start.len(), rows + 1, "CSR needs rows + 1 starts");
    debug_assert_eq!(table.layer.len(), table.max_density.len());
    debug_assert_eq!(table.layer.len(), table.max_current_per_cut.len());

    // Spent once above the loop; every row still records a run.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "the solution's columns do not match the grid it claims to have solved"
    );
    // `blech` is empty here, so a zero-current grid would report `Ran` over the
    // full in-scope population with no findings — indistinguishable from a
    // genuinely checked clean design.
    if discarded_budget(solved.grid, intent) {
        refuse_rows(&table.head, out, runs);
        return;
    }

    for row in 0..rows {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        let span = table.layer_start[row] as usize..table.layer_start[row + 1] as usize;
        debug_assert!(span.end <= table.layer.len(), "row {row}'s CSR span runs past its column");
        let limits = LayerLimits {
            layer: &table.layer[span.clone()],
            max_density: &table.max_density[span.clone()],
            max_current_per_cut: &table.max_current_per_cut[span],
            blech: &[],
        };

        let examined = check_branches(solved, grid, (id, severity), &limits, 1.0, out);
        record_run(runs, out, before, id, Outcome::Ran, examined);
    }
}

/// Black's temperature derating: how much of a limit characterised at
/// `reference` survives at `operating`.
///
/// `J(T) = J(T_ref) * exp(Ea / (n k) * (1/T - 1/T_ref))`, so a hotter operating
/// point derates the allowed current *down*; an inverted sign passes every
/// branch it should have caught.
///
/// `None` for a parameter set with no usable Arrhenius factor, which the caller
/// reports as [`Outcome::Refused`] and never as a derating of one. Both
/// temperatures must be absolute and strictly positive.
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
    // An infinite derating is an infinite allowed current, which passes every
    // branch silently. Zero is the other end and stays: it fails every branch.
    debug_assert!(derate >= 0.0, "exp is never negative");
    derate.is_finite().then_some(derate)
}

/// Branch currents against a temperature-derated lifetime limit.
///
/// As [`check_em_current_density`], with the limit scaled by the Arrhenius
/// factor between `operating_temperature` and the row's
/// `reference_temperature`, and with Blech-immortal segments exempted before
/// the compare rather than after.
///
/// `operating_temperature` is the applied point; `reference_temperature` is the
/// characterisation point. Deriving one from the other is the fail-open shape
/// where the derating silently becomes unity.
///
/// ponytail: one temperature for the whole run — no thermal solve, no
/// self-heating, so every edge derates identically. That is what a DC signoff
/// can state, and it errs *open*: a self-heated wire runs hotter than the
/// applied point and so derates further than this computes, which passes
/// branches a thermal solve would fail. Upgrade is a per-edge temperature
/// column on [`PowerGrid`], or a `thermal_resistance` column on
/// [`ElectromigrationTable`] giving `operating_temperature + I²R·θ` per edge.
///
/// A derating factor that overflows to infinity is [`Refused`], not a pass.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when there is no solve.
///
/// [`PowerGrid`]: crate::power::PowerGrid
/// [`Refused`]: gpurify_report::Outcome::Refused
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_electromigration(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    grid: Grid,
    operating_temperature: Qty<Temperature, { prefix::BASE }>,
    table: &ElectromigrationTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(rows, table.head.severity.len(), "RuleHead columns diverged");
    debug_assert_eq!(table.layer_start.len(), rows + 1, "CSR needs rows + 1 starts");
    debug_assert_eq!(table.layer.len(), table.max_density.len());
    debug_assert_eq!(table.layer.len(), table.max_current_per_cut.len());
    debug_assert_eq!(table.layer.len(), table.blech_limit.len());
    debug_assert_eq!(rows, table.reference_temperature.len());
    debug_assert_eq!(rows, table.activation_energy_ev.len());
    debug_assert_eq!(rows, table.current_exponent.len());

    // Spent once above the loop; every row still records a run.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "the solution's columns do not match the grid it claims to have solved"
    );
    // A zero branch current makes the Blech product zero, every segment
    // immortal and `examined` zero, so the row would read `Ran` having judged
    // nothing.
    if discarded_budget(solved.grid, intent) {
        refuse_rows(&table.head, out, runs);
        return;
    }

    for row in 0..rows {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        // An unusable Arrhenius parameter leaves no derating, and no derating
        // is an underated limit that passes branches it should have caught.
        let Some(derate) = arrhenius_derating(
            operating_temperature,
            table.reference_temperature[row],
            table.activation_energy_ev[row],
            table.current_exponent[row],
        ) else {
            record_run(runs, out, before, id, Outcome::Refused, 0);
            continue;
        };

        let span = table.layer_start[row] as usize..table.layer_start[row + 1] as usize;
        debug_assert!(span.end <= table.layer.len(), "row {row}'s CSR span runs past its column");
        let limits = LayerLimits {
            layer: &table.layer[span.clone()],
            max_density: &table.max_density[span.clone()],
            max_current_per_cut: &table.max_current_per_cut[span.clone()],
            blech: &table.blech_limit[span],
        };

        let examined = check_branches(solved, grid, (id, severity), &limits, derate, out);
        record_run(runs, out, before, id, Outcome::Ran, examined);
    }
}
