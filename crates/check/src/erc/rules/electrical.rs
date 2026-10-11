//! Rules over a solved resistive network.
//!
//! Data in: per-net networks (p2p resistance, which needs no intent) and the
//! solved supply grid (the other three, skipped without intent). Every kind
//! here is refused when its network could not be built.
//! Data out: violations and one run per row.

use crate::erc::facts::IntentMap;
use crate::erc::power::{
    discarded_budget, effective_resistance_into, EdgeKind, NetNetworks, Power, PowerError,
    PowerGrid, PowerSolution, Solved,
};
use crate::erc::ruleset::RuleHead;
use crate::erc::{fill_rows, record_run, skip_rows, Design, Scratch, BOLTZMANN_EV_PER_K};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::connectivity::components_into;
use gpurify_geom::LayerId;
use gpurify_geom::{
    prefix, Current, CurrentDensity, Dbu, Grid, Qty, Resistance, Temperature, Voltage,
};
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::StrId;

/// Point-to-point resistance within a net: deck kind `p2p_resistance`,
/// written `p2p_resistance(; max: resistance)`.
///
/// Every net with at least two device attach points gets a resistor network:
/// each conductor polygon is a chain of resistors along its long axis,
/// `sheet resistance * ∫ ds / w(s)`, tapped wherever something connects, and
/// each via cut is one resistor of its cut layer's sheet value. A device
/// attaches once per net, at the shape nearest its marker's centre. A row
/// flags a net whose largest effective resistance between two attach points
/// is above `max`. Effective resistance, so a parallel strap can only lower
/// it. Two attach points in separate pieces of the net are not a pair. Needs
/// no design intent, but needs a sheet resistance for every conductor and
/// via the deck connects.
///
/// # Limits
///
/// Resistance is measured within one net. The ESD discharge path a P2P
/// check is meant for, pad to device to bus to clamp across several nets
/// (ERC-C6), and a guard ring's path to the supply pins (ERC-D4) are not
/// modelled. Transverse resistance across a wide shape is not modelled.
///
/// Catalog: ERC-C6 (partial), ERC-D4 (partial) in the [check catalog].
/// Defined by [ESDA TR18.0-01] Fig. 58; [ESDA TR18.0-02] Fig. 21 and §2.3;
/// [JS-001] Tables 2A/2B (which pin pairs); [JESD78] Table 1; Calibre PERC,
/// IC Validator and Voltus (public material only). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
/// [JS-001]: https://www.jedec.org/sites/default/files/JTR001-01-12%20Final.pdf
/// [JESD78]: https://www.jedec.org/standards-documents/docs/jesd-78b
#[derive(Debug, Default)]
pub struct P2pResistanceTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the largest allowed effective resistance, Ω. Positive from a
    /// deck.
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Static IR drop on the supply grid: deck kind `ir_drop`, written
/// `ir_drop()`.
///
/// The limits are per net, in the design intent's `limits`, not in the deck:
/// `max_drop_mv`, `max_drop_fraction` (of the net's domain voltage) and
/// `max_overvoltage_mv`. The grid is every conducting shape of every declared
/// supply, modelled as for [`P2pResistanceTable`]. Each supply is held at its
/// nominal (its domain's voltage for power, 0 V for ground) at one feed
/// point, and each net's `budget_current_ua` is drawn equally by every device
/// terminal on it; Ohm's and Kirchhoff's laws give each node's voltage. Drop
/// is the loss toward the other rail: nominal minus node voltage on a power
/// net, the rise above 0 V on a ground net (ground bounce). A row flags a node
/// whose drop is above `max_drop_mv` or `max_drop_fraction` times its
/// domain's voltage, or whose overvoltage (negative drop) is above
/// `max_overvoltage_mv`. A limit left out is not checked, never unlimited.
///
/// # Limits
///
/// Each supply is fed from one point, the centre of its highest, then widest,
/// shape, so a rail fed from several pads reads more drop near that point than
/// it has. A net's budget is shared equally among its device terminals, so a
/// device drawing more than its share reads cooler than it is. Static only:
/// dynamic and vectorless IR are out of scope (ERC-E11).
///
/// Catalog: ERC-E8 in the [check catalog]. Defined by [OpenROAD psm];
/// [Weste & Harris] §13.3.2; `RedHawk`, Voltus and `mPower` (public material
/// only). No standards body defines static IR drop. Source tags are in
/// [check-sources.md]; the intent file is described in [usage.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [usage.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/usage.md#design-intent
/// [OpenROAD psm]: https://openroad.readthedocs.io/en/latest/main/src/psm/README.html
/// [Weste & Harris]: https://pages.hmc.edu/harris/cmosvlsi/4e/cmosvlsidesign_4e_fm.pdf
#[derive(Debug, Default)]
pub struct IrDropTable {
    /// Rule id and severity per row. Rows differ only in id and severity: the
    /// limits come from the intent.
    pub head: RuleHead,
}

/// Current density on the supply grid: deck kind `em_current_density`,
/// written `em_current_density(layers..; max_density: current per width,
/// max_current_per_cut: current)`.
///
/// The grid is solved as for [`IrDropTable`], which gives every resistor its
/// DC branch current. A metal segment on a listed layer may carry
/// `max_density` times its width, the narrowest width the segment's cross
/// section finds; a via cut on a listed cut layer may carry
/// `max_current_per_cut`. A row flags a segment or cut whose current
/// magnitude is above that. A layer the row does not list is not checked. The
/// limit is taken as given, with no temperature derating
/// ([`ElectromigrationTable`] derates).
///
/// # Limits
///
/// The limit is `max_density` times width only, with no width band or absolute
/// cap for narrow lines (ERC-E3); IHP states only JMAX, so this may
/// over-report but cannot under-report. The current is the static budget's,
/// with no ESD stimulus and no It2 limits (ERC-C7), and no injection stimulus
/// for a guard ring (ERC-D4).
///
/// Catalog: ERC-C7 (partial), ERC-D4 (partial), ERC-E1, ERC-E2, ERC-E3
/// (partial), ERC-E10 in the [check catalog]. Defined by [GF180MCU] Tables
/// 14.3 and 14.4; [IHP SG13G2] §2.15; [OpenROAD psm] `-enable_em`;
/// [ESDA TR18.0-01] Fig. 58; [ESDA TR22] §4.4; [ESDA TR18.0-02] §2.3. Source
/// tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [OpenROAD psm]: https://openroad.readthedocs.io/en/latest/main/src/psm/README.html
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
/// [ESDA TR22]: https://www.esda.org/store/standards/product/72/esd-tr22-0-01-14
#[derive(Debug, Default)]
pub struct EmCurrentDensityTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` and the parallel limit
    /// columns are row `i`'s per-layer limits.
    pub layer_start: Vec<u32>,
    /// Limited layers, metal or cut, CSR by `layer_start`. A layer listed
    /// twice in a row is limited by its first entry.
    pub layer: Vec<LayerId>,
    /// Parallel to `layer`: the largest current per width of metal, A/m.
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut: a via has no width to divide by.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,
}

/// Electromigration lifetime at temperature: deck kind `electromigration`,
/// written `electromigration(layers..; max_density: current per width,
/// max_current_per_cut: current, blech_limit: current,
/// reference_temperature: temp, activation_energy: eV, current_exponent: n)`.
///
/// The limits are [`EmCurrentDensityTable`]'s, characterised for the target
/// lifetime at `reference_temperature`, and derated to the run's operating
/// temperature `T` by Black's equation, `MTTF = A J^-n exp(Ea / kT)`, held at
/// equal lifetime:
///
/// `allowed(T) = allowed(T_ref) * exp(Ea / (n k) * (1/T - 1/T_ref))`,
///
/// which is below the stated limit when hotter. A segment is exempt
/// (Blech-immortal) when the Blech product `|I| * L / W` of the line it lies
/// in, current per width times the line's length, is at or below
/// `blech_limit` for its layer: back-stress halts the drift in a short line.
/// A line is the metal between two diffusion barriers: a via landing, the
/// supply's feed point, a loaded device tap (its contact), or the line's
/// end. The grid's own taps along a shape (its centre) are no barrier, so a
/// long line tapped in the middle is still long. A line's product is its
/// largest segment's, and a branched line's `L` is every branch, which errs
/// mortal. A via is a line of its own, `L` its stack height. A row flags a
/// segment or cut that is not immortal and carries more than its derated
/// limit.
///
/// # Limits
///
/// One operating temperature for the whole run (85 °C from the CLI), with no
/// self-heating, which errs open for a hot wire. RMS, peak and
/// Joule-heating limits (ERC-E7) and statistical or thermal-aware EM
/// (ERC-E13) are not modelled.
///
/// Catalog: ERC-E4, ERC-E5, ERC-E6 in the [check catalog]. Defined by
/// [GF180MCU] §14.2 (§14.2.2 for the derating); [IHP SG13G2] §2.15;
/// [Black 1969]; [Blech 1976]; [JEP122]; JESD63 and JESD202. Source tags are
/// in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [Black 1969]: https://doi.org/10.1109/T-ED.1969.16754
/// [Blech 1976]: https://doi.org/10.1063/1.322842
/// [JEP122]: https://www.jedec.org/standards-documents/docs/jep-122e
#[derive(Debug, Default)]
pub struct ElectromigrationTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per-layer CSR, as in [`EmCurrentDensityTable`].
    pub layer_start: Vec<u32>,
    /// Limited layers, metal or cut, CSR by `layer_start`.
    pub layer: Vec<LayerId>,
    /// Parallel to `layer`: current per width of metal at the reference
    /// temperature, A/m.
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Parallel to `layer`: current per via cut at the reference
    /// temperature, µA.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,
    /// Per layer: the Blech product `J * L` (current, since `J` is per width)
    /// at or below which a segment is immortal.
    pub blech_limit: Vec<Qty<Current, { prefix::MICRO }>>,
    /// Per row: the Arrhenius reference point, absolute.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    /// Per row: `Ea` in Black's equation, eV. Negative or non-finite refuses
    /// the row.
    pub activation_energy_ev: Vec<f64>,
    /// `n` in Black's equation.
    pub current_exponent: Vec<f64>,
}

/// Runs every [`P2pResistanceTable`] row over the per-net networks.
///
/// `examined` counts the networks probed, one per net with at least two
/// attach points. A violation sits at the first attach point of the worst
/// pair (the earliest pair on a tie), on that shape's layer, names both
/// shapes, and measures the pair's resistance against `max`. Every row is
/// refused when `networks` could not be built (a conductor or via with no
/// sheet resistance), and a row is refused at the first network that cannot
/// be probed; violations it found before that stay in `out`.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_p2p_resistance(
    design: Design<'_>,
    networks: Result<&NetNetworks, PowerError>,
    table: &P2pResistanceTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Ok(networks) = networks else {
        fill_rows(&table.head, Outcome::Refused, out, runs);
        return;
    };
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
/// without a solve or usable intent, refused when the solve failed or a stated
/// budget never reached it (zero current would pass every limit).
fn solved_or_fill<'a>(
    power: Power<'a>,
    intent: &IntentMap,
    head: &RuleHead,
    out: &Violations,
    runs: &mut Vec<RuleRun>,
) -> Option<Solved<'a>> {
    let Ok(power) = power else {
        fill_rows(head, Outcome::Refused, out, runs);
        return None;
    };
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

/// Runs every [`IrDropTable`] row over the solved supply grid.
///
/// `examined` counts grid nodes whose net states a drop, fractional drop or
/// overvoltage limit. A violation sits at the node, on its shape's layer,
/// measuring the drop (or overvoltage) in mV against the broken limit; a node
/// can break several. Every row is refused when the grid could not be built
/// or solved, with or without intent (a conductor with no sheet resistance
/// refuses it). Otherwise every row is skipped when no usable intent was
/// given or it declares no supply this layout has, and refused when a net's
/// non-zero current budget reached no device terminal (zero current would
/// pass every limit).
pub fn check_ir_drop(
    power: Power<'_>,
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
            let net = grid.node_net[node];
            let limits = intent.limits_of(net);
            let stated = limits.max_drop.is_some()
                | limits.max_drop_fraction.is_some()
                | limits.max_overvoltage.is_some();
            examined += u64::from(stated);

            let (role, domain) = intent
                .supply(net)
                .expect("every grid node is on a declared supply");
            // A loss moves toward the other rail: down for power, up for ground.
            let drop = match role {
                SupplyRole::Power => solved.solution.node_drop[node],
                SupplyRole::Ground => -solved.solution.node_drop[node],
            };
            if let Some(limit) = limits.max_drop {
                report_node(out, grid, node, head, drop, limit);
            }
            // A fraction of the domain, for a ground rail as for its power rail.
            if let Some(fraction) = limits.max_drop_fraction {
                let limit = Qty::new(domain.raw().abs() * fraction);
                report_node(out, grid, node, head, drop, limit);
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

/// Each edge's Blech product `|I| * L / W`, with `L` the length of the line
/// the edge lies in: the metal between diffusion barriers, which are a node
/// where a via lands, a supply's feed point and a loaded device tap (its
/// contact). A line's product is the largest of its edges', so a line is
/// immortal whole or not at all; a branched line's `L` is all of its
/// branches, which errs mortal. A via is its own line, `L` the stack height.
/// A zero width makes the product infinite (mortal).
#[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
fn blech_products(power: &PowerGrid, solution: &PowerSolution) -> Vec<f64> {
    let (nodes, edges) = (power.node_count(), power.edge_count());
    let metal = |edge: usize| power.edge_kind[edge] == EdgeKind::Metal;
    let mut barrier = vec![false; nodes];
    for &pad in &power.source_node {
        barrier[pad as usize] = true;
    }
    for (barrier, load) in barrier.iter_mut().zip(&power.node_load) {
        *barrier |= load.raw() != 0.0;
    }
    for edge in (0..edges).filter(|&edge| !metal(edge)) {
        barrier[power.edge_from[edge] as usize] = true;
        barrier[power.edge_to[edge] as usize] = true;
    }
    // Metal edges meeting at a node that is no barrier are one line.
    let mut first = vec![u32::MAX; nodes];
    let mut joins = Vec::new();
    for edge in (0..edges).filter(|&edge| metal(edge)) {
        let edge_id = u32::try_from(edge).expect("an edge index is a u32");
        for node in [power.edge_from[edge], power.edge_to[edge]] {
            let slot = &mut first[node as usize];
            if barrier[node as usize] {
                continue;
            }
            if *slot == u32::MAX {
                *slot = edge_id;
            } else {
                joins.push((*slot, edge_id));
            }
        }
    }
    let mut line = Vec::new();
    components_into(
        u32::try_from(edges).expect("an edge count is a u32"),
        &joins,
        &mut line,
    );
    let product = |edge: usize, length: i64| {
        let width = power.edge_width[edge].raw();
        if width == 0 {
            return f64::INFINITY;
        }
        solution.branch_current[edge].raw().abs() * (length as f64 / width as f64)
    };
    let mut length = vec![0i64; edges];
    for edge in (0..edges).filter(|&edge| metal(edge)) {
        length[line[edge].0 as usize] += power.edge_length[edge].raw();
    }
    let mut worst = vec![0.0f64; edges];
    for edge in (0..edges).filter(|&edge| metal(edge)) {
        let at = line[edge].0 as usize;
        worst[at] = worst[at].max(product(edge, length[at]));
    }
    (0..edges)
        .map(|edge| {
            if metal(edge) {
                worst[line[edge].0 as usize]
            } else {
                product(edge, power.edge_length[edge].raw())
            }
        })
        .collect()
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
    let blech = if limits.blech.is_empty() {
        Vec::new()
    } else {
        blech_products(power, solution)
    };
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
        let width = power.edge_width[edge];
        let immortal = limits
            .blech
            .get(limit_row)
            .zip(blech.get(edge))
            .is_some_and(|(&limit, &product)| product <= limit.raw());
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

/// Runs every [`EmCurrentDensityTable`] row over the solved supply grid's
/// branch currents.
///
/// `examined` counts grid segments and cuts on the row's layers. A violation
/// sits at the segment's first node, on its layer, names the shapes at both
/// ends, and measures the current in µA against the allowed current. Skipped
/// and refused as [`check_ir_drop`] is.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_em_current_density(
    power: Power<'_>,
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

/// Runs every [`ElectromigrationTable`] row over the solved supply grid's
/// branch currents, derated to `operating_temperature` (absolute).
///
/// `examined` counts grid segments and cuts on the row's layers that are not
/// Blech-immortal. A violation reports as [`check_em_current_density`]'s,
/// against the derated limit. A row is refused when its derating is not
/// usable: a non-positive temperature, a negative activation energy, a
/// non-positive current exponent, or an infinite factor. Otherwise skipped
/// and refused as [`check_ir_drop`] is.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_electromigration(
    power: Power<'_>,
    intent: &IntentMap,
    grid: Grid,
    operating_temperature: Qty<Temperature, { prefix::BASE }>,
    table: &ElectromigrationTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // ponytail: one temperature for the whole run, no self-heating, which errs
    // open for a hot wire; upgrade is a per-edge temperature column on
    // `PowerGrid`.
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
