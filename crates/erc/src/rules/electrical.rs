//! Rules over a solved resistive network.
//!
//! Four kinds, and the line between them is which network they read.
//!
//! [`check_p2p_resistance`] reads [`NetNetworks`] — one resistor network per
//! net, built from geometry and the process stack. It needs no design intent
//! and **always runs**.
//!
//! The other three read the solved supply grid, and the supply grid exists only
//! because design intent said which nets are supplies, at what voltage, drawing
//! what current. With no intent there is no grid, `power` is `None`, and all
//! three record [`Skipped`]`(`[`NoDesignIntent`]`)`.
//!
//! # The one thing these rules must never do
//!
//! Return early with an empty violation list. "No IR-drop violations" and "no
//! supply voltage was ever declared, so nothing was compared" produce the same
//! empty [`Violations`], and only the [`RuleRun`] tells them apart. Every path
//! out of every transform below goes through `record_run` for exactly
//! that reason.
//!
//! [`Skipped`]: gpurify_report::Outcome::Skipped
//! [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent

use crate::facts::IntentMap;
use crate::power::{effective_resistance_into, EdgeKind, NetNetworks, PowerGrid, Solved};
use crate::ruleset::RuleHead;
use crate::{record_run, skip_rows, Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::intent::NetLimits;
use gpurify_ingest::StrId;
use gpurify_report::{
    LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations,
};
use gpurify_units::{
    prefix, Current, CurrentDensity, Dbu, Grid, Qty, Resistance, Temperature, Voltage,
};

/// Boltzmann's constant in electronvolts per kelvin. The one place it is
/// written down, because Black's equation is the only thing in this tree that
/// needs it and `Ea / kT` is dimensionless only if the two agree on eV.
const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262e-5;

/// Effective resistance between the device attach points of a net.
///
/// A net that is one node in the netlist and kilohms across in the silicon. The
/// measurement is the **effective** resistance of the whole network between two
/// terminals, not a path length and not a sum of squares: effective resistance
/// obeys Rayleigh monotonicity, so adding a parallel strap can only lower the
/// reported number. That is a law, it is one of this project's three oracles,
/// and the old sum-of-squares proxy violated it — it went *up* when a designer
/// added metal to fix it.
#[derive(Debug, Default)]
pub struct P2pResistanceTable {
    pub head: RuleHead,
    /// Worst permitted effective resistance between any two attach points on
    /// one net.
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Voltage a node actually sits at, against what the design allows.
///
/// The table holds no limits. Every one of them — absolute drop, drop as a
/// fraction of nominal, overvoltage — is a per-net number in
/// [`NetLimits`], because a chip's own owner states it and no process
/// can. The row exists to say the deck enabled the rule, and to carry the id
/// and severity it reports at.
///
/// [`NetLimits`]: gpurify_ingest::intent::NetLimits
#[derive(Debug, Default)]
pub struct IrDropTable {
    pub head: RuleHead,
}

/// Current per unit conductor width, against a per-layer limit.
///
/// The instantaneous check: does this wire carry more current than its width
/// allows, right now, at nominal conditions. Distinct from
/// [`ElectromigrationTable`], which asks whether it survives ten years of it.
///
/// The limit is per layer because it is a property of the metallisation —
/// thickness, grain structure, liner — and the deck states it. What the rule
/// cannot get from the deck is the current, which is why it needs the solve and
/// therefore the intent.
#[derive(Debug, Default)]
pub struct EmCurrentDensityTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` and the parallel
    /// `max_density` and `max_current_per_cut` are row `i`'s per-layer limits.
    /// CSR.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut, not per width, exactly as in
    /// [`ElectromigrationTable::max_current_per_cut`]: a via array carries what
    /// its cut count allows and has no conductor width to divide by.
    ///
    /// Without this column an [`EdgeKind::Via`] edge would have to be compared
    /// as `|current| / cuts` — a [`Current`] — against `max_density`, a
    /// [`CurrentDensity`], which is a dimensional error and not a verdict. A
    /// via on a layer the row limits is checked against this and never against
    /// `max_density`.
    ///
    /// [`EdgeKind::Via`]: crate::power::EdgeKind::Via
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,
}

/// Lifetime under sustained current, with temperature derating.
///
/// Black's equation, reduced to what a DC signoff can state: the allowed
/// current scales by an Arrhenius factor between the edge's temperature and the
/// temperature the foundry limit was characterised at, and a segment short
/// enough to be Blech-immortal is exempt.
#[derive(Debug, Default)]
pub struct ElectromigrationTable {
    pub head: RuleHead,
    /// Per-layer limits, CSR, as in [`EmCurrentDensityTable`]. Characterised at
    /// [`ElectromigrationTable::reference_temperature`], which is why that field is not optional.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
    pub max_density: Vec<Qty<CurrentDensity, { prefix::BASE }>>,
    /// Via limits are per cut, not per width: a via array carries what its cut
    /// count allows, and the width of the metal above it is irrelevant.
    pub max_current_per_cut: Vec<Qty<Current, { prefix::MICRO }>>,

    /// The Blech product `J · L`, above which a segment is not immortal.
    ///
    /// With [`CurrentDensity`] defined as current per unit *width*, this
    /// product has the dimension of current — the literature's A/cm assumes
    /// current per unit *area*. Same physics, stated in this tree's units, and
    /// written down here because the two differ by a thickness and a reader
    /// comparing against a foundry document needs to know which is which.
    pub blech_limit: Vec<Qty<Current, { prefix::MICRO }>>,

    /// Arrhenius parameters, per row.
    ///
    /// Absolute, in kelvin. Black's equation needs `1/T`, which is meaningless
    /// on the Celsius scale — it divides by zero at 0 °C and changes sign
    /// below it. Decks state Celsius; `gpurify_units::celsius` converts once at
    /// the deck boundary so no arithmetic here ever sees the offset.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// `n` in Black's equation. Two for void nucleation, one for growth.
    pub current_exponent: Vec<f64>,
}

/// Worst-pair effective resistance, per net.
///
/// **Transform.** One row of [`NetNetworks`] per net that has one, probed by
/// [`effective_resistance_into`] into a `scratch` buffer, worst pair taken, one
/// compare. Nets are independent, so this is the tasker pattern and partitions
/// by row.
///
/// A net with fewer than two attach points has no row in `networks` and is not
/// examined — there is no pair to measure, so reporting it as clean would be a
/// claim about nothing.
///
/// `measured` is a [`Resistance`], `limit` is `max_resistance`, sense
/// [`Maximum`]. The violation names both attach polygons, so a viewer shows the
/// two ends of the offending run.
///
/// `examined` is the number of nets probed.
///
/// [`effective_resistance_into`]: crate::power::effective_resistance_into
/// [`Maximum`]: gpurify_report::LimitSense::Maximum
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
    // Split borrow: the probe writes its pair list and its linear-solve
    // workspace in the same call, and both live in the one shared `Scratch`.
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
            // Fail closed. A network this crate could not probe is not a net
            // that measured within its limit, and the whole row says so.
            if effective_resistance_into(networks, net, solve, probes).is_err() {
                outcome = Outcome::Refused;
                break;
            }
            examined += 1;

            // A pair split across components has no interconnect path and is
            // absent from the probe list, so a row with no pair at all has
            // nothing to compare. The branch predicts: a connected net is the
            // norm and a disconnected one is a topology finding, not this
            // rule's.
            let Some(&first) = probes.first() else {
                continue;
            };
            // The worst pair, as a branchless max: the comparison selects a
            // whole triple rather than jumping over it. A strict left fold in
            // ascending probe order, so among equal resistances the earliest
            // probe wins on every run — the tie-break is the report's
            // determinism, not an accident of iteration.
            let mut worst = first;
            for &probe in &probes[1..] {
                worst = [worst, probe][usize::from(probe.2.raw() > worst.2.raw())];
            }
            let measured = Measurement::Resistance(worst.2);

            // The taken side writes eight columns. On a design being signed
            // off almost every net is inside its limit, so skipping it is
            // exactly what the branch is for.
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
///
/// **Decision plus one push.** The three limits [`check_ir_drop`] applies
/// differ only in which pair of numbers they compare, so the comparison, the
/// coordinate and the shape are written once here rather than three times at
/// the call site — which is what stops one of the three quietly reporting a
/// different node's position.
fn report_node(
    out: &mut Violations,
    grid: &PowerGrid,
    node: usize,
    head: (StrId, Severity),
    measured: Qty<Voltage, { prefix::MILLI }>,
    limit: Qty<Voltage, { prefix::MILLI }>,
) {
    let (measured, limit) = (Measurement::Voltage(measured), Measurement::Voltage(limit));
    // The taken side writes eight columns, and on a design being signed off
    // the overwhelming majority of nodes sit inside their limit.
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
        // One shape: a node taps one polygon, and there is no second end to a
        // voltage the way there is to a resistance.
        shapes: (grid.node_poly[node], None),
    });
}

/// Node voltages against the drop each net is allowed.
///
/// **Transform, intent-gated.** One pass over the solution's node column; each
/// node's verdict is its own drop against its net's [`NetLimits`], so the pass
/// is a kernel over nodes.
///
/// Three independent limits, each reported separately when it is stated and
/// **not** reported at all when it is not: absolute drop, drop as a fraction of
/// the domain's nominal, and overvoltage. A net with none of the three is out of
/// scope: its nodes are not compared, and they do not contribute to `examined`.
/// A design that limited nothing therefore gets a run row with `examined == 0`,
/// which reads as "this rule ran and had nothing to check" and is a different
/// claim from clean — the same convention as
/// [`check_em_current_density`] on a deck that limits no layer.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when `power` is `None` or
/// [`IntentMap::is_usable`] is false. Not a silent empty result, ever.
///
/// `examined` is the number of nodes on nets with at least one stated limit.
///
/// [`NetLimits`]: gpurify_ingest::intent::NetLimits
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

    // The gate is a property of the run, not of a rule row, so it is decided
    // once above the loop and every row reads the same answer.
    // The gate is a property of the run, not of a rule row, so it is spent once
    // above the loop. Every row still records a run — a silent early return is
    // the empty clean result this crate exists to prevent.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "the solution's columns do not match the grid it claims to have solved"
    );

    // The dense `NetId`-keyed limit column, the same shape `check_branches`
    // builds for its layers, in place of one `IntentMap::limits_of` binary
    // search per node. Two loads and no branch, over a column with a node per
    // conductor tap on the chip.
    //
    // `limit_row_of_net[n]` is one plus the row of `intent.limit` that states
    // net `n`'s limits, and `0` is "this net stated none" — which indexes the
    // all-`None` sentinel `limits[0]`, so an unlimited net and a limited one
    // take the same path. That is why the sentinel is prepended rather than the
    // row index being decremented: `checked_sub(1)` would put a data-dependent
    // branch back in the node body.
    //
    // Sized by the highest limited net, so a node on a net above that is out of
    // scope by construction and `get` says so without a second column. Built
    // once above the row loop, not once per row: design intent is a uniform of
    // the whole transform, and every rule row reads the same answer.
    // `u32` rows, not `u16`: a `NetId` is a `u32` and a wrapped row index is a
    // wrong limit rather than a missing one.
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
            // `get` on a net above the highest limited one — and on
            // `NetId::NONE`, which indexes nothing — answers the same `0`,
            // which is a cmov rather than a second column.
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
            // `|`, not `||`: each side is a tag test, so this is one `or`
            // rather than two short-circuits, and it is what `examined`
            // counts — a node on a net that stated nothing is out of scope.
            let stated = limits.max_drop.is_some()
                | limits.max_drop_fraction.is_some()
                | limits.max_overvoltage.is_some();
            examined += u64::from(stated);

            let head = (id, severity);
            let drop = solved.solution.node_drop[node];
            // Magnitude: a fraction of a ground rail's nominal is a fraction
            // of its distance from zero, and a signed nominal would flip the
            // limit's sense on the ground side of the pair.
            let nominal = grid.node_nominal[node].raw().abs();

            // Three independent limits, each reported only where it is stated.
            // The three branches are on design intent, which is per net and so
            // constant across every node of a supply: the predictor has them
            // after the first node.
            if let Some(limit) = limits.max_drop {
                report_node(out, grid, node, head, drop, limit);
            }
            if let Some(fraction) = limits.max_drop_fraction {
                report_node(out, grid, node, head, drop, Qty::new(nominal * fraction));
            }
            // Overvoltage points the other way: a node *above* nominal, which
            // is a negative drop.
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
///
/// Three or four parallel slices that always travel together, so this is the
/// argument list of [`check_branches`] written down once rather than a bundle
/// hiding anything: every field is `pub(self)` data the caller sliced itself.
struct LayerLimits<'a> {
    /// The layers this row limits. An edge on any other layer is out of scope.
    layer: &'a [LayerId],
    max_density: &'a [Qty<CurrentDensity, { prefix::BASE }>],
    max_current_per_cut: &'a [Qty<Current, { prefix::MICRO }>],
    /// Blech-immortality product per layer, or **empty** for a rule with no
    /// lifetime to exempt a segment from. The instantaneous current-density
    /// check is that rule: a wire either carries more than its width allows
    /// right now or it does not, and no length makes it not so.
    blech: &'a [Qty<Current, { prefix::MICRO }>],
}

/// The current one edge may carry, from whichever limit its kind is stated
/// against.
///
/// **Decision** — small data in, one value out, pure. This is the dimensional
/// split both branch rules share: a metal segment's limit is a density times
/// its conductor width, a via's is a per-cut current times its cut count.
/// Both come out a [`Current`], which is what makes them comparable against
/// the branch current the solve produced — and a [`CurrentDensity`] is not,
/// because [`Measurement`] has no variant for one.
///
/// A zero width or a zero cut count yields a zero limit, so any current at all
/// violates it. That is the fail-closed direction; the `|I| / W` form the doc
/// comments state is the same inequality rearranged, and it divides by zero.
fn allowed_current(
    kind: EdgeKind,
    width: Dbu,
    grid: Grid,
    max_density: Qty<CurrentDensity, { prefix::BASE }>,
    max_current_per_cut: Qty<Current, { prefix::MICRO }>,
) -> Qty<Current, { prefix::MICRO }> {
    // A closed two-variant enum whose arms are three arithmetic operations
    // each, so this if-converts rather than jumping. Splitting the edge column
    // into one table per kind is `power::extract_into`'s layout decision, not
    // this rule's.
    match kind {
        // `A/m * m = A`, on base values: `units::arith` carries no
        // `CurrentDensity * Length` operator, and adding one is a signature
        // change this phase does not make.
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
/// **Transform, gatherer.** Caller owns `out`, appended to. Shared by
/// [`check_em_current_density`] and [`check_electromigration`], which differ in
/// exactly two things: `derate`, which is unity for the instantaneous check,
/// and [`LayerLimits::blech`], which is empty for it.
///
/// Returns `examined`: edges on a limited layer that the Blech exemption did
/// not remove.
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

    // The dense `LayerId`-keyed limit column: `limit_of_layer[l]` is one plus
    // the row of `limits.layer` that limits layer `l`, and `0` is "this row
    // does not limit that layer". One indexed load per edge in place of a
    // linear scan of the layer list — which cost the whole list on every edge
    // that was *out* of scope, the common case on a deck limiting one layer of
    // ten, over a column with an edge per conductor segment on the chip.
    //
    // Built once per `check_branches` call, which is once per rule row: the
    // allocation is amortised over the whole edge column, not paid per edge.
    // Sized by the highest layer this row limits, so an edge above that is out
    // of scope by construction and `get` says so without a second column.
    // `u32` rows, not `u16`: a row may name the same layer more times than the
    // `LayerId` space is wide, and a wrapped row index is a wrong limit rather
    // than a missing one.
    let dense_len = limits
        .layer
        .iter()
        .map(|layer| layer.idx() + 1)
        .max()
        .unwrap_or(0);
    let mut limit_of_layer = vec![0u32; dense_len];
    // Reverse, so the earliest mention of a repeated layer is the one left
    // standing — the row the linear `position` used to return. A rule row
    // limits a handful of layers, and this runs once per rule row.
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

    // The per-edge work that is kernel-shaped — the dense layer lookup, the
    // Blech product, `allowed_current` — is branchless arithmetic over the
    // edge's own columns, and stays that way inside this loop.
    for edge in 0..power.edge_count() {
        // Out of scope: this row states no limit for the edge's layer. Left as
        // a branch on purpose — the taken side is a division, a derated
        // compare and possibly an eight-column push, and skipping expensive
        // work is what a branch is for. `get` on a layer above the highest one
        // limited answers the same `0`, which is a cmov, not a second scan.
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
        // current's own unit, which is the dimension the column is stated in.
        // A zero width makes the product infinite, which is not immortal.
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
        let slenderness = length.raw() as f64 / width.raw() as f64;
        let blech_product = current.raw() * slenderness;
        // `get` on an empty column is `None`, which is how the instantaneous
        // check says it has no immortality to grant. The bound it tests is a
        // uniform of this loop, so the predictor owns it after the first edge.
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
        // Two branches, both earning their place: an immortal segment is one
        // the mechanism does not apply to rather than one that was waived, and
        // the push behind the second writes eight columns on a design where
        // almost every branch is inside its limit.
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
            // The edge's layer, not either endpoint's: the limit that was
            // exceeded is the one stated for the conductor carrying the
            // current.
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
/// **Transform, intent-gated.** One pass over the solution's branch column.
///
/// The compare is per [`EdgeKind`], and the two kinds are not commensurable:
///
/// - **Metal** — `|current| / grid.to_length(edge_width)` against `max_density`.
///   The division is the units crate's `Current / Length` operator, so the
///   dimension is checked by the compiler rather than by a comment.
/// - **Via** — `|current| / cuts` against `max_current_per_cut`. A cut count is
///   dimensionless, so this is a [`Current`] and `max_density` is not a limit it
///   can be held against.
///
/// `grid` is the run's manufacturing grid, and it is a parameter because
/// `edge_width` is a [`Dbu`] — a grid index — while `max_density` is amps per
/// metre. [`Grid::to_length`] is the only conversion between them, and neither
/// [`Solved`] nor [`IntentMap`] carries a grid. Without it the limit's stated
/// unit is not computable here and the rule's absolute verdict has no oracle.
///
/// An edge on a layer the row does not limit is skipped and not counted in
/// `examined`. A deck that limits no layer therefore produces a run row with
/// `examined == 0`, which reads as "this rule ran and had nothing to check" and
/// is a different claim from clean.
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

    // The gate is a property of the run, not of a rule row, so it is spent once
    // above the loop. Every row still records a run — a silent early return is
    // the empty clean result this crate exists to prevent.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "the solution's columns do not match the grid it claims to have solved"
    );

    for row in 0..rows {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        let span = table.layer_start[row] as usize..table.layer_start[row + 1] as usize;
        debug_assert!(span.end <= table.layer.len(), "row {row}'s CSR span runs past its column");
        let limits = LayerLimits {
            layer: &table.layer[span.clone()],
            max_density: &table.max_density[span.clone()],
            max_current_per_cut: &table.max_current_per_cut[span],
            // No lifetime, so no immortality: a wire either carries more than
            // its width allows right now or it does not.
            blech: &[],
        };

        let examined = check_branches(solved, grid, (id, severity), &limits, 1.0, out);
        record_run(runs, out, before, id, Outcome::Ran, examined);
    }
}

/// Black's temperature derating: how much of a limit characterised at
/// `reference` survives at `operating`.
///
/// **Decision** — four numbers in, one out, pure. Holding `MTTF = A J^-n
/// exp(Ea / kT)` equal at the two temperatures gives
/// `J(T) = J(T_ref) * exp( Ea / (n k) * (1/T - 1/T_ref) )`, so a hotter
/// operating point derates the allowed current *down*. That direction is what a
/// sign error inverts, and an inverted derating passes every branch it should
/// have caught.
///
/// `None` for a parameter set that has no Arrhenius factor at all — which the
/// caller reports as [`Outcome::Refused`] and never as a derating of one. Both
/// temperatures must be absolute and strictly positive: `1 / T` is meaningless
/// on the Celsius scale, so a deck value that never went through
/// [`gpurify_units::celsius`] arrives here as a small or negative number and is
/// refused rather than silently derated.
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
    // An infinite derating is an infinite allowed current, and an infinite
    // allowed current passes every branch silently. Zero is the other end of
    // the same expression and stays: it fails every branch, which is closed.
    debug_assert!(derate >= 0.0, "exp is never negative");
    derate.is_finite().then_some(derate)
}

/// Branch currents against a temperature-derated lifetime limit.
///
/// **Transform, intent-gated.** As [`check_em_current_density`], including its
/// `grid` and its per-kind compare, with the limit scaled by the Arrhenius
/// factor between `operating_temperature` and the row's
/// `reference_temperature`, and with Blech-immortal segments exempted before
/// the compare rather than after — an exempt segment is not a violation that
/// was waived, it is a segment the mechanism does not apply to, and the two
/// read differently in a report.
///
/// `operating_temperature` is the applied temperature the derating is computed
/// at, absolute, and it is a parameter because nothing else in the inputs
/// carries one: [`PowerGrid`] has no temperature column and [`IntentMap`] has
/// no operating point. `reference_temperature` is the characterisation point,
/// which is a different number, and deriving one from the other is the
/// fail-open shape where the derating silently becomes unity.
///
/// ponytail: one temperature for the whole run — no thermal solve, no
/// self-heating, so every edge derates identically. That is what a DC signoff
/// can state, and it errs *open*: a self-heated wire runs hotter than the
/// applied point and so derates further than this computes, which passes
/// branches a thermal solve would fail.
///
/// How far open, because Black's exponent makes the gap much larger than a
/// reader estimates from "one temperature for the whole run". The factor is
/// `exp(Ea / (n·k) · (1/T − 1/T_ref))`, so running at `T_applied` when the
/// conductor is really at `T_actual` over-states the allowed current by
/// `exp(Ea / (n·k) · (1/T_applied − 1/T_actual))` — for copper at
/// `Ea = 0.9 eV`, off an 85 °C applied point:
///
/// | `T_actual − T_applied` | `n = 1` | `n = 2` |
/// |---|---|---|
/// | +5 K — the self-heat budget a foundry rule typically states | 1.5× | 1.2× |
/// | +10 K | 2.2× | 1.5× |
/// | +40 K — 85 °C applied against a 125 °C junction | 19× | 4.3× |
///
/// The last row is the other half of the same gap and it is not in this file:
/// `engine::run::sign_off_temperature` hard-codes 85 °C, because no deck and no
/// `RunOptions` field declares a corner. The two compound rather than
/// alternate, and they point the same way — a corner below the real junction
/// and an unmodelled self-heat both make `T` too low, both raise the derating,
/// both over-state the allowed current. A part run at 125 °C with a 5 K
/// self-heat sees their product.
///
/// The same Arrhenius factor *without* the `1/n` governs
/// [`check_reliability`]'s predicted lifetime, so that rule is steeper still:
/// 19× at `Ea = 0.9 eV` over the same 40 K. [`check_em_current_density`] is not
/// wrong by any of these factors, because it derates by nothing — it inherits
/// whatever corner the deck characterised `max_density` at, and cannot say
/// which one that was. [`check_ir_drop`] and [`check_p2p_resistance`] are
/// temperature-sensitive too, but mildly and through a different term:
/// [`PowerGrid::edge_resistance`] is sheet resistance times squares with no TCR
/// factor, and copper is about 12 % more resistive at 125 °C than at 85 °C, so
/// those two read fail-open by ~1.12× rather than by ~19×.
///
/// Upgrade is a per-edge temperature column on [`PowerGrid`], written by
/// [`extract_into`] from a thermal model — a new column and a new writer, both
/// outside this file and both frozen this phase. The cheaper rung, since two of
/// the three factors are already here: a `thermal_resistance` K/W column on
/// [`ElectromigrationTable`] parallel to `max_density`, with the per-edge point
/// being `operating_temperature + I²R·θ` from the `branch_current` and
/// `edge_resistance` columns `check_branches` already reads. Both rungs and
/// the 85 °C corner are filed in `docs/SIGNATURE_DEFECTS.md`. Only the source
/// of this value changes; nothing below it does.
///
/// A derating factor that overflows to infinity is [`Refused`], not a pass. An
/// infinite allowed current passes every branch silently, which is the
/// fail-open shape this crate is built to refuse.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when there is no solve.
///
/// `examined` is the number of non-exempt edges on limited layers.
///
/// [`PowerGrid`]: crate::power::PowerGrid
/// [`PowerGrid::edge_resistance`]: crate::power::PowerGrid::edge_resistance
/// [`extract_into`]: crate::power::extract_into
/// [`check_reliability`]: crate::rules::reliability::check_reliability
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

    // The gate is a property of the run, not of a rule row, so it is spent once
    // above the loop. Every row still records a run — a silent early return is
    // the empty clean result this crate exists to prevent.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "the solution's columns do not match the grid it claims to have solved"
    );

    for row in 0..rows {
        let before = out.len();
        let (id, severity) = (table.head.rule[row], table.head.severity[row]);
        // Refused before anything is examined, and reported as such: an
        // unusable Arrhenius parameter leaves no derating, and no derating is
        // an undated limit that passes every branch it should have caught.
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
