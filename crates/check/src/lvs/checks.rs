//! LVS rows for the report: the layout-only checks, which need no reference
//! netlist, and the mapping of a comparison's discrepancies to violations.
//!
//! Data in: the extracted tables and the unreduced layout graph. Data out: five
//! run rows and their violations, and a sixth when the deck states device
//! parameter ranges.

use crate::erc::first_vertex;
use crate::lvs::controls::must_connect;
use crate::lvs::graph::{narrow, spice_param_name, Graph};
use crate::lvs::verdict::Discrepancy;
use crate::report::{record_run, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use crate::topology::device::{DeviceMeasure, DeviceParam};
use crate::topology::{DeviceId, NetId, NetTable, PortTable};
use crate::Design;
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{LvsControls, LvsCount, LvsLimit, LvsRange};
use gpurify_ingest::{StrId, StrTable};

/// Every rule id LVS reports under, in interning order: one per [`Discrepancy`]
/// variant but the last, then the five check rows, then the parameter-range
/// row, then the last variant's and the short-path row, each added after the
/// rows it follows. Each is a
/// row of the check catalog (`docs/check-catalog.tsv`), which a test keeps in
/// step with this list.
///
/// The first six and the last are defined on the [`Discrepancy`] variant that
/// raises them (`lvs.unpaired_device` is [`Discrepancy::UnpairedDevice`],
/// `lvs.model_mismatch` [`Discrepancy::ModelMismatch`], and so on), the five
/// after the first six under [`check_layout`], and `lvs.param_range` under
/// [`check_param_ranges`], `lvs.short_path` with `lvs.net_seed_conflict`
/// ([`check_net_seed_conflicts`]), `lvs.unpaired_instance` under
/// [`record_unpaired_instances`], and `lvs.device_count` under
/// [`check_device_counts`]. The crate's
/// [rule reference](crate#layout-against-schematic) maps each to its
/// [catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
/// rows.
pub const RULE_IDS: [&str; 16] = [
    "lvs.unpaired_device",
    "lvs.unpaired_net",
    "lvs.terminal_mismatch",
    "lvs.parameter_mismatch",
    "lvs.undeclared_param",
    "lvs.class_imbalance",
    "lvs.floating_net",
    "lvs.label_conflict",
    "lvs.net_seed_conflict",
    "lvs.terminal_net",
    "lvs.terminal_count",
    "lvs.param_range",
    "lvs.model_mismatch",
    "lvs.short_path",
    "lvs.unpaired_instance",
    "lvs.device_count",
];

/// Intern every LVS rule id; the report looks them up in a table it only borrows.
///
/// Call it on the run's table before [`check_layout`] or
/// [`record_discrepancies`] writes a row: a row written before carries
/// `StrId(u32::MAX)`, which `StrTable::resolve` panics on when the report is
/// printed. Interning twice is harmless.
pub fn intern_rule_ids(strings: &mut StrTable) {
    for name in RULE_IDS {
        strings.intern(name);
    }
}

/// An id [`intern_rule_ids`] missed is `u32::MAX`, which `resolve` panics on
/// rather than misattributing the row.
fn rule_id(strings: &StrTable, name: &str) -> StrId {
    strings.get(name).unwrap_or(StrId(u32::MAX))
}

/// An LVS finding has no layer, place or shape: past-the-end sentinels.
const NOWHERE: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};
const NO_LAYER: LayerId = LayerId(u16::MAX);
const NO_SHAPE: PolyId = PolyId(u32::MAX);

/// Run the layout-only checks on the unreduced layout graph.
///
/// `layout` must be [`from_layout`](crate::lvs::graph::from_layout) of the
/// same `design` and `ports`. Records five [`RuleRun`]s, in the order below,
/// and a sixth, `lvs.short_path`, right after `lvs.net_seed_conflict` when a
/// net carries two names, and appends their violations to `out`. Every violation is an error.
/// A row on a shape is located at the shape's first vertex, on its layer;
/// a row on none (a hand-built graph's structural fault) has no layer and no
/// location (both are sentinels), and its shape is `PolyId(u32::MAX)`.
///
/// # Rows
///
/// - `lvs.floating_net`: a net that no device terminal lands on, other than a
///   net with a port label or one made only of global-layer shapes (the
///   substrate). Shape: the net's lowest polygon, located at its first
///   vertex on its layer. Measured 0 against a limit of 1 terminal. Examines
///   every net. Catalog: LVS-006.
/// - `lvs.label_conflict`: one label text on several nets. That is an open,
///   since a label never joins shapes by itself. One row per pair of
///   consecutive such nets in net order, so a label on `n` nets gives
///   `n - 1` rows. Shapes: the lowest polygon carrying the label on each of
///   the two nets, so the two labels are found from the row; the location is
///   the first vertex of the first, on its layer. Measured 2 against a limit
///   of 1. Examines every net. A label `controls` makes must-connect (`lvs
///   connect_implicit`, `lvs connect_explicit`) is a warning, as `KLayout`
///   raises one for top cells, "for which it is assumed that this
///   connection is made later". Catalog: LVS-001, LVS-002.
/// - `lvs.net_seed_conflict`: several label texts on one net, a short between
///   named nets. One row per pair of consecutive names on the net in
///   [`StrId`] order, so `n` names give `n - 1` rows. Shapes: the lowest
///   polygon carrying each of the two names, so the two labels are found
///   from the row; the location is the first vertex of the first, on its
///   layer. Measured 2 against a limit of 1. Examines every binding of a
///   name to a net. Catalog: LVS-001, LVS-005. Where it finds one, the
///   short's path follows as `lvs.short_path`
///   ([`check_net_seed_conflicts`]).
/// - `lvs.terminal_net`: a device marker no recogniser could bind
///   ([`DeviceTable::refused`]): a terminal position with no shape of its
///   own under it (a terminal missing, or drawn twice with its twin
///   missing), or more distinct nets under it than the recogniser has
///   positions on that layer (two gates under one implant). Shape: the marker,
///   located at its first vertex on its layer. Measured the terminals bound
///   against the count listed. Also a terminal of `layout` on no net, or on a
///   net past its net table, which a hand-built graph can hold: measured the
///   net count against the count the terminal would need. Examines every
///   terminal and every refused marker. Catalog: LVS-004.
/// - `lvs.terminal_count`: a device whose terminal count its kind does not
///   allow: MOS 3 or 4 (bulk optional), BJT 3, resistor, capacitor and diode
///   2. The deck does not fix a recogniser's layer count, so this is where a
///   wrong one shows. Measured the count against the kind's full count.
///   Examines every device, or records [`Outcome::Refused`] when
///   `device_terminal_start` does not hold one run per device. Catalog:
///   LVS-004.
///
/// # Limits
///
/// - Parameter ranges are [`check_param_ranges`]'s, a row recorded only when
///   the deck states one, and per-model device counts
///   [`check_device_counts`]'s (catalog LVS-068).
///
/// # Panics
///
/// Panics if a device terminal names a net past `design.nets`, or a port
/// binding or a refused marker a polygon past `design.store`.
///
/// [`DeviceTable::refused`]: crate::topology::DeviceTable::refused
pub fn check_layout(
    layout: &Graph,
    design: Design<'_>,
    ports: &PortTable,
    (strings, controls): (&StrTable, &LvsControls),
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let id = |name| rule_id(strings, name);
    check_floating_nets(design, ports, id("lvs.floating_net"), out, runs);
    let joined = |name| must_connect(name, strings, controls);
    check_label_conflicts(
        design,
        ports,
        (id("lvs.label_conflict"), &joined),
        out,
        runs,
    );
    check_net_seed_conflicts(design, ports, strings, out, runs);
    check_topology(
        layout,
        design,
        (id("lvs.terminal_net"), id("lvs.terminal_count")),
        out,
        runs,
    );
}

/// The `lvs.param_range` row: every layout device of a model an `lvs range`
/// row names, its measured parameter held to the row's bounds (catalog
/// LVS-068), as a foundry states a device's legal size (GF App. A's
/// parameter ranges, IHP's per-device rules, Magic's device parameter
/// limits). A value at a bound is legal. Records nothing when `ranges` is
/// empty, since then no deck asked; otherwise one [`RuleRun`] that examined
/// one device per row naming its model.
///
/// Each violation is an error on the device's marker, located at its first
/// vertex on its layer, measured against the bound it breaks: a length or an
/// area exactly, a count as a count, and a diffusion a transistor shares
/// with others (its share, a fraction of a database unit) as a ratio of
/// database units. A device of a ranged model on which the parameter was not
/// measured (a source drawn in pieces, say) cannot be held to the bound, and
/// the run is then [`Outcome::Refused`], its other rows kept.
///
/// # Panics
///
/// Panics if a device's marker is past `design.store`.
pub fn check_param_ranges(
    design: Design<'_>,
    ranges: &[LvsRange],
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if ranges.is_empty() {
        return;
    }
    let rule = rule_id(strings, "lvs.param_range");
    let before = out.len();
    let devices = design.devices;
    let (mut examined, mut unmeasured) = (0u64, false);
    for device in 0..devices.len() {
        for range in ranges
            .iter()
            .filter(|row| row.model == devices.model[device])
        {
            examined += 1;
            let measure = measured_param(strings, range.param).and_then(|param| {
                devices
                    .params_of(DeviceId(narrow(device)))
                    .iter()
                    .find(|&&(stated, _)| stated == param)
                    .map(|&(_, measure)| measure)
            });
            let Some(measure) = measure else {
                unmeasured = true;
                continue;
            };
            for (bound, least) in [(range.min, true), (range.max, false)] {
                let Some(bound) = bound else { continue };
                match out_of_bounds(measure, bound, least) {
                    Ok(Some((measured, limit))) => {
                        let row = Violation {
                            measured,
                            limit,
                            ..graph_violation(rule, (devices.marker[device], None), 0, 0)
                        };
                        out.push(on_first_shape(design.store, row));
                    }
                    Ok(None) => {}
                    Err(Incomparable) => unmeasured = true,
                }
            }
        }
    }
    let outcome = if unmeasured {
        Outcome::Refused
    } else {
        Outcome::Ran
    };
    record_run(runs, out, before, rule, outcome, examined);
}

/// The `lvs.device_count` row: the number of layout devices of each model
/// an `lvs count` row names, held to the row's bounds (catalog LVS-068), as
/// a foundry limits a device per chip: IHP SG13G2's recommended rules allow
/// at most 4000 `npn13G2` emitters on a chip, and 800 each of `npn13G2L`
/// and `npn13G2V`. A count at a bound is legal. Records nothing when
/// `counts` is empty; otherwise one [`RuleRun`] that examined one model per
/// row.
///
/// A count over its maximum is an error on the marker of the first device
/// past it (the `max + 1`-th of the model, in device order), measured the
/// count against the maximum; one under its minimum is an error on the
/// model's first device, or with no layer, location or shape when the
/// layout has none, measured the count against the minimum. A device is
/// one recognised marker: a multi-emitter bipolar counts once, since no
/// emitter count is extracted (catalog LVS-064).
///
/// # Panics
///
/// Panics if a device's marker is past `design.store`.
pub fn check_device_counts(
    design: Design<'_>,
    counts: &[LvsCount],
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if counts.is_empty() {
        return;
    }
    let rule = rule_id(strings, "lvs.device_count");
    let before = out.len();
    let devices = design.devices;
    for row in counts {
        let of_model: Vec<usize> = (0..devices.len())
            .filter(|&device| devices.model[device] == row.model)
            .collect();
        let n = narrow(of_model.len());
        if let Some(max) = row.max.filter(|&max| n > max) {
            let marker = devices.marker[of_model[max as usize]];
            let found = graph_violation(rule, (marker, None), n, max);
            out.push(on_first_shape(design.store, found));
        }
        if let Some(min) = row.min.filter(|&min| n < min) {
            let found = graph_violation(rule, (NO_SHAPE, None), n, min);
            out.push(match of_model.first() {
                Some(&first) => on_first_shape(
                    design.store,
                    Violation {
                        shapes: (devices.marker[first], None),
                        ..found
                    },
                ),
                None => found,
            });
        }
    }
    record_run(runs, out, before, rule, Outcome::Ran, counts.len() as u64);
}

/// The measured parameter an `lvs range` row's name stands for.
fn measured_param(strings: &StrTable, name: StrId) -> Option<DeviceParam> {
    const MEASURED: [DeviceParam; 11] = [
        DeviceParam::Width,
        DeviceParam::Length,
        DeviceParam::Area,
        DeviceParam::Perimeter,
        DeviceParam::Fingers,
        DeviceParam::SourceArea,
        DeviceParam::DrainArea,
        DeviceParam::SourcePerimeter,
        DeviceParam::DrainPerimeter,
        DeviceParam::EmitterArea,
        DeviceParam::EmitterPerimeter,
    ];
    let name = strings.resolve(name);
    MEASURED
        .into_iter()
        .find(|&param| spice_param_name(param) == name)
}

/// Whether `measure` breaks `bound`, the least legal value when `least`, the
/// greatest otherwise: `Ok(Some((measured, limit)))` as the row reports
/// them when it does, `Ok(None)` when it does not, and `Err(Incomparable)`
/// when the two are of different kinds. A share of `ways` is compared
/// exactly, its bound scaled by `ways`.
fn out_of_bounds(
    measure: DeviceMeasure,
    bound: LvsLimit,
    least: bool,
) -> Result<Option<(Measurement, Measurement)>, Incomparable> {
    let breaks = |value: i128, limit: i128| if least { value < limit } else { value > limit };
    #[expect(
        clippy::cast_precision_loss,
        reason = "a shared diffusion is reported, not compared, as a ratio"
    )]
    let report = match (measure, bound) {
        (DeviceMeasure::Length(value), LvsLimit::Length(limit)) => {
            breaks(i128::from(value.raw()), i128::from(limit.raw()))
                .then_some((Measurement::Length(value), Measurement::Length(limit)))
        }
        (DeviceMeasure::Area(value), LvsLimit::Area(limit)) => breaks(value.raw(), limit.raw())
            .then_some((Measurement::Area(value), Measurement::Area(limit))),
        (DeviceMeasure::Count(value), LvsLimit::Count(limit)) => {
            breaks(i128::from(value), i128::from(limit))
                .then_some((Measurement::Count(value), Measurement::Count(limit)))
        }
        (DeviceMeasure::LengthShare(value, ways), LvsLimit::Length(limit)) => breaks(
            i128::from(value.raw()),
            i128::from(limit.raw()) * i128::from(ways),
        )
        .then(|| {
            (
                Measurement::Ratio(value.raw() as f64 / f64::from(ways)),
                Measurement::Ratio(limit.raw() as f64),
            )
        }),
        (DeviceMeasure::AreaShare(value, ways), LvsLimit::Area(limit)) => {
            breaks(value.raw(), limit.raw() * i128::from(ways)).then(|| {
                (
                    Measurement::Ratio(value.raw() as f64 / f64::from(ways)),
                    Measurement::Ratio(limit.raw() as f64),
                )
            })
        }
        _ => return Err(Incomparable),
    };
    Ok(report)
}

/// A measure and a bound of different kinds, a length against an area.
struct Incomparable;

/// One error row per discrepancy, which is how a mismatch fails the run.
///
/// Each row reports under its variant's id in [`RULE_IDS`], with no layer,
/// location or shape. Measured and limit are 1 against 0, except
/// `lvs.class_imbalance` (the layout's node count against the reference's)
/// and `lvs.parameter_mismatch` (the layout value against the reference
/// value, when both are finite). Records no [`RuleRun`]: the comparison is
/// accounted for by its verdict, not per id.
pub fn record_discrepancies(found: &[Discrepancy], strings: &StrTable, out: &mut Violations) {
    for discrepancy in found {
        let (name, measured, limit) = match *discrepancy {
            Discrepancy::UnpairedDevice { .. } => ("lvs.unpaired_device", 1, 0),
            Discrepancy::UnpairedNet { .. } => ("lvs.unpaired_net", 1, 0),
            Discrepancy::TerminalMismatch { .. } => ("lvs.terminal_mismatch", 1, 0),
            Discrepancy::ParameterMismatch { .. } => ("lvs.parameter_mismatch", 1, 0),
            Discrepancy::UndeclaredParam { .. } => ("lvs.undeclared_param", 1, 0),
            Discrepancy::ModelMismatch { .. } => ("lvs.model_mismatch", 1, 0),
            Discrepancy::ClassImbalance {
                layout_nodes,
                ref_nodes,
            } => ("lvs.class_imbalance", layout_nodes, ref_nodes),
        };
        let mut row = graph_violation(rule_id(strings, name), (NO_SHAPE, None), measured, limit);
        // Both values, when they are finite; a non-finite one reports as the rest do.
        if let Discrepancy::ParameterMismatch {
            layout_value,
            ref_value,
            ..
        } = *discrepancy
        {
            if layout_value.is_finite() && ref_value.is_finite() {
                row.measured = Measurement::Ratio(layout_value);
                row.limit = Measurement::Ratio(ref_value);
            }
        }
        out.push(row);
    }
}

/// One instance of the reference a mismatch left without a partner: every
/// device it placed that the comparison kept is unpaired, as `KLayout`
/// reports a subcircuit with no counterpart (catalog LVS-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnpairedInstance {
    /// The row of the flattened reference's
    /// [`placements`](gpurify_ingest::netlist::Netlist::placements).
    pub placement: u32,
    /// How many devices it placed, all unpaired.
    pub devices: u32,
}

/// The instances of the reference whose every device the comparison kept is
/// unpaired, each the outermost such: an instance inside a reported one is
/// not reported again. `found` is a mismatch's discrepancies,
/// `reference_rows` [`Traced::reference_rows`](crate::lvs::Traced::reference_rows)
/// of the same comparison, and `placements` the flattened reference's,
/// whose device rows are the reference graph's
/// ([`from_reference`](crate::lvs::graph::from_reference) keeps the
/// netlist's order). An instance placing no device the comparison kept is
/// never reported: nothing of it could pair.
///
/// The flat comparison decides the verdict; this only names, for a
/// mismatch it found, the instances it left whole and unmatched, so it can
/// never turn a match into a mismatch or the other way round.
#[must_use]
pub fn unpaired_instances(
    found: &[Discrepancy],
    reference_rows: &[Vec<u32>],
    placements: &[gpurify_ingest::netlist::Placement],
) -> Vec<UnpairedInstance> {
    let rows = reference_rows
        .iter()
        .flatten()
        .map(|&row| row as usize + 1)
        .max()
        .unwrap_or(0)
        .max(
            placements
                .iter()
                .map(|p| p.devices.end as usize)
                .max()
                .unwrap_or(0),
        );
    let (mut kept, mut unpaired) = (vec![false; rows], vec![false; rows]);
    for &row in reference_rows.iter().flatten() {
        kept[row as usize] = true;
    }
    for discrepancy in found {
        if let Discrepancy::UnpairedDevice {
            side: crate::lvs::verdict::Side::Reference,
            device,
            ..
        } = *discrepancy
        {
            for &row in reference_rows.get(device as usize).into_iter().flatten() {
                unpaired[row as usize] = true;
            }
        }
    }
    let mut out = Vec::new();
    let mut covered = 0u32;
    for (at, placement) in placements.iter().enumerate() {
        let range = placement.devices.start as usize..placement.devices.end as usize;
        if placement.devices.start < covered {
            continue;
        }
        let ours = range.clone().filter(|&row| kept[row]).count();
        if ours > 0 && range.clone().all(|row| !kept[row] || unpaired[row]) {
            out.push(UnpairedInstance {
                placement: narrow(at),
                devices: narrow(ours),
            });
            covered = placement.devices.end;
        }
    }
    out
}

/// One error row `lvs.unpaired_instance` per instance [`unpaired_instances`]
/// found, measured its device count against 0, with no layer, location or
/// shape: the instance is the reference's, and the report names it by its
/// path and cell beside the row. Records no [`RuleRun`], as
/// [`record_discrepancies`] records none.
pub fn record_unpaired_instances(
    instances: &[UnpairedInstance],
    strings: &StrTable,
    out: &mut Violations,
) {
    for instance in instances {
        out.push(graph_violation(
            rule_id(strings, "lvs.unpaired_instance"),
            (NO_SHAPE, None),
            instance.devices,
            0,
        ));
    }
}

/// Legal terminal counts per device kind, as a bitmask indexed by count. Rows past
/// `Inductor` admit nothing, so an unknown kind fails closed.
const LEGAL_WIDTHS: [u32; 8] = [
    (1 << 3) | (1 << 4), // Mos: gate, source, drain, and optionally bulk
    1 << 3,              // Bjt
    1 << 2,              // Resistor
    1 << 2,              // Capacitor
    1 << 2,              // Diode
    1 << 2,              // Inductor
    0,
    0,
];

/// The full terminal count each kind is reported against.
const FULL_WIDTHS: [u32; 8] = [4, 3, 2, 2, 2, 2, 0, 0];

fn graph_violation(
    rule: StrId,
    shapes: (PolyId, Option<PolyId>),
    measured: u32,
    limit: u32,
) -> Violation {
    Violation {
        rule,
        layer: NO_LAYER,
        severity: Severity::Error,
        at: NOWHERE,
        shapes,
        measured: Measurement::Count(measured),
        limit: Measurement::Count(limit),
    }
}

/// `row` located on its first shape: at that shape's first vertex, on its
/// layer.
fn on_first_shape(store: &GeometryStore, row: Violation) -> Violation {
    let shape = row.shapes.0;
    Violation {
        layer: store.poly_layer(shape),
        at: first_vertex(store, shape),
        ..row
    }
}

/// Nets with no device terminal on them; a named (port) net is not floating,
/// nor is the substrate alone (a global-layer net: always there, it floats
/// only in the model). Panics when a device terminal names a net past `nets`.
fn check_floating_nets(
    design: Design<'_>,
    ports: &PortTable,
    rule: StrId,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (nets, devices) = (design.nets, design.devices);
    let before = out.len();
    let net_count = narrow(nets.net_count());

    // Net `n` holds its lowest polygon while still a candidate, `NO_SHAPE` once
    // ruled out.
    let mut lowest: Vec<PolyId> = (0..net_count)
        .map(|row| {
            let net = NetId(row);
            let named =
                u32::from(ports.name_of(net).is_some() || nets.is_global_only(net)).wrapping_neg();
            PolyId(first_poly(nets, net).0 | named)
        })
        .collect();
    for &net in &devices.terminal_net {
        lowest[net.idx()] = NO_SHAPE;
    }

    for &poly in lowest.iter().filter(|&&poly| poly != NO_SHAPE) {
        let row = graph_violation(rule, (poly, None), 0, 1);
        out.push(on_first_shape(design.store, row));
    }
    record_run(runs, out, before, rule, Outcome::Ran, u64::from(net_count));
}

/// One label resolving to two nets. Reported rather than resolved.
fn check_label_conflicts(
    design: Design<'_>,
    ports: &PortTable,
    (rule, must_connect): (StrId, &dyn Fn(StrId) -> bool),
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(design.nets.net_count());

    // Every binding, so a name a short hides behind another is still seen.
    let (names, named) = ports.bindings_by_name();
    for at in 1..names.len() {
        if names[at] == names[at - 1] {
            let shapes = (
                labelled(ports, named[at - 1], names[at]),
                Some(labelled(ports, named[at], names[at])),
            );
            let mut row = graph_violation(rule, shapes, 2, 1);
            if must_connect(names[at]) {
                row.severity = Severity::Warning;
            }
            out.push(on_first_shape(design.store, row));
        }
    }
    record_run(runs, out, before, rule, Outcome::Ran, u64::from(net_count));
}

/// The `lvs.net_seed_conflict` row of [`check_layout`] alone: one
/// [`RuleRun`], and a violation per pair of names on one net, as described
/// there. Where it finds any, an `lvs.short_path` row follows: for each such
/// pair, the fewest polygons joining the two labelled shapes
/// ([`NetTable::path`](crate::topology::NetTable::path)), one error per step
/// between consecutive polygons of the path, its two shapes those polygons,
/// located at the first's first vertex on its layer, measured the step's
/// number against the path's step count; two labels on one polygon are one
/// row on it, measured 1 against 1. This is where the short runs, as
/// Calibre's `LVS ISOLATE SHORTS` and ICV's `ShortFinder` trace it (catalog
/// LVS-005). The row examines one pair per conflict, and is refused when a
/// pair's path cannot be traced. No row is recorded when no net carries two
/// names, so a run without a short reports nothing more.
///
/// For a run that reports labelled shorts without LVS's other layout rows:
/// the `gpurify` engine calls it when [`check_layout`] does not run and a
/// net carries two names, so a short between named nets fails every run.
///
/// # Panics
///
/// Panics if a port binds a polygon past `design.store`.
pub fn check_net_seed_conflicts(
    design: Design<'_>,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rule = rule_id(strings, "lvs.net_seed_conflict");
    let before = out.len();
    let (nets, _, polys) = ports.bindings();
    let mut shorts = Vec::new();
    for at in 1..nets.len() {
        if nets[at] == nets[at - 1] {
            let row = graph_violation(rule, (polys[at - 1], Some(polys[at])), 2, 1);
            out.push(on_first_shape(design.store, row));
            shorts.push((polys[at - 1], polys[at]));
        }
    }
    record_run(runs, out, before, rule, Outcome::Ran, ports.len() as u64);
    if shorts.is_empty() {
        return;
    }
    let rule = rule_id(strings, "lvs.short_path");
    let before = out.len();
    let mut outcome = Outcome::Ran;
    for &(from, to) in &shorts {
        let Some(path) = design.nets.path(from, to) else {
            outcome = Outcome::Refused;
            continue;
        };
        let steps = narrow(path.len() - 1);
        if steps == 0 {
            let row = graph_violation(rule, (from, None), 1, 1);
            out.push(on_first_shape(design.store, row));
        }
        for (step, pair) in (1u32..).zip(path.windows(2)) {
            let row = graph_violation(rule, (pair[0], Some(pair[1])), step, steps);
            out.push(on_first_shape(design.store, row));
        }
    }
    record_run(runs, out, before, rule, outcome, shorts.len() as u64);
}

/// Structural sanity of the extracted graph: a terminal on no net, a device with
/// the wrong terminal count for its kind. A graph with devices but no terminal
/// CSR is `Refused` rather than reported clean.
fn check_topology(
    graph: &Graph,
    design: Design<'_>,
    (terminal_net, terminal_count): (StrId, StrId),
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let devices = graph.device_kind.len();
    let net_count = narrow(graph.net_name.len());

    // `NetId::NONE` is `u32::MAX`, so "no net" and "past the table" are one test;
    // the limit saturates so it never wraps to zero.
    let before = out.len();
    for &net in graph.terminal_net.iter().filter(|&&net| net >= net_count) {
        out.push(graph_violation(
            terminal_net,
            (NO_SHAPE, None),
            net_count,
            net.saturating_add(1),
        ));
    }
    // A marker recognition refused never reaches the graph: it is reported
    // here, on the marker, rather than missing silently.
    let refused = &design.devices.refused;
    for &(marker, bound, listed) in refused {
        let row = graph_violation(terminal_net, (marker, None), bound, listed);
        out.push(on_first_shape(design.store, row));
    }
    record_run(
        runs,
        out,
        before,
        terminal_net,
        Outcome::Ran,
        (graph.terminal_net.len() + refused.len()) as u64,
    );

    let before = out.len();
    let width: Vec<u32> = graph
        .device_terminal_start
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect();
    if width.len() != devices {
        record_run(runs, out, before, terminal_count, Outcome::Refused, 0);
        return;
    }
    for (&kind, &count) in graph.device_kind.iter().zip(&width) {
        // A count past 31 clamps onto bit 31, which no kind sets.
        if (LEGAL_WIDTHS[(kind as usize) & 7] >> count.min(31)) & 1 == 0 {
            out.push(graph_violation(
                terminal_count,
                (NO_SHAPE, None),
                count,
                FULL_WIDTHS[(kind as usize) & 7],
            ));
        }
    }
    record_run(
        runs,
        out,
        before,
        terminal_count,
        Outcome::Ran,
        devices as u64,
    );
}

/// The lowest polygon carrying label `name` on `net`, which `ports` binds.
fn labelled(ports: &PortTable, net: NetId, name: StrId) -> PolyId {
    let (nets, names, polys) = ports.bindings();
    let from = nets.partition_point(|&bound| bound < net);
    let to = nets.partition_point(|&bound| bound <= net);
    polys[from + names[from..to].partition_point(|&bound| bound < name)]
}

/// The lowest polygon of a net, or [`NO_SHAPE`] for a net carrying none.
fn first_poly(nets: &NetTable, net: NetId) -> PolyId {
    nets.polys_of(net).first().copied().unwrap_or(NO_SHAPE)
}
