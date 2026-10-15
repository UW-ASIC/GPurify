//! Supply, substrate and pad integrity: topological but geometry-aware, and
//! independent of design intent (a supply short is an n-tie and a p-tie on one
//! conductor, provable from the deck's tap markers), except a gate tied to a
//! rail and the ESD path, which need to know which nets are the rails.
//!
//! Data in: the store, nets, devices, [`NetFacts`], the design intent's
//! supplies. Data out: violations and one run per row.

use crate::erc::facts::{IntentMap, NetFacts, RoleMask};
use crate::erc::power::{feed_shape, Process};
use crate::erc::ruleset::RuleHead;
use crate::erc::{
    device_id, first_vertex, push_net_violations, record_run, skip_rows, Design, Scratch,
};
use crate::report::{Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{extract_nets_into, DeviceId, NetId, PortTable, TerminalRole};
use gpurify_geom::ops::{isqrt, point_seg_dist2, winding_of, Point, Seg, Winding};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, RingRef};
use gpurify_geom::{Dbu, DbuArea, Qty};
use gpurify_ingest::deck::{Connectivity, DeviceKind};
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::StrId;

/// A supply short through one conductor: deck kind `supply_short`, written
/// `supply_short(tap_a, tap_b[, within])`.
///
/// A row flags every net that holds a polygon of `tap_a` and a polygon of
/// `tap_b`, such as an n-tap and a p-tap: one conductor ties together the two
/// supplies those taps bias. With `within`, a `tap_a` shape counts only when
/// its bounding-box centre lies in a `within` polygon: an n-tap biasing a
/// PMOS well, not a PNP's base contact, which carries a p-type net by design.
/// Needs no design intent.
///
/// Catalog: ERC-G4 in the [check catalog]. Defined by Calibre (public
/// material only); no standards body defines it. Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SupplyShortTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the first tap layer (the one `within` scopes).
    pub tap_a: Vec<LayerId>,
    /// Per row: the second tap layer.
    pub tap_b: Vec<LayerId>,
    /// Per row: the layer a `tap_a` shape must sit in to count, or `None` for
    /// every `tap_a` shape.
    pub within: Vec<Option<LayerId>>,
}

/// A net held together only by a high-resistance layer: deck kind
/// `soft_connection`, written `soft_connection(layers..)`.
///
/// The listed layers are soft: wells, substrate ties and the like, which
/// conduct too poorly to carry a signal or a supply. A row cuts the nets
/// again from the deck's connectivity with the soft layers taken out: no soft
/// conductor or global layer, and no via with a soft cut or a soft layer on
/// either side. Every net with a polygon on a soft layer whose other
/// polygons fall into more than one of those pieces is flagged: its pieces
/// are connected only through the soft layers. Shapes join only as the deck
/// declares, so a strap drawn over a piece without a via joins nothing.
/// Needs no design intent.
///
/// Catalog: LVS-003, ERC-G5 in the [check catalog]. Defined by
/// [KLayout `soft_connect`]; Calibre SOFTCHK and SCONNECT (public material
/// only); Magic `disconnect`. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [KLayout `soft_connect`]: https://www.klayout.de/doc-qt5/about/lvs_ref_netter.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SoftConnectionTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `soft[soft_start[i] .. soft_start[i + 1]]` are row `i`'s soft layers.
    pub soft_start: Vec<u32>,
    /// Soft layers, CSR by `soft_start`; at least one per row. A layer listed
    /// twice counts once.
    pub soft: Vec<LayerId>,
    /// The deck's connectivity, shared by every row: each row extracts it
    /// without its soft layers. [`RuleSet::from_deck`](crate::erc::RuleSet::from_deck)
    /// copies it from the deck's `connect` statements.
    pub connectivity: Connectivity,
}

/// Latch-up tap distance: deck kind `missing_tie`, written
/// `missing_tie(region, tap; max_distance: len)`.
///
/// A row flags every polygon of the `region` layer (the active area of one
/// device polarity, say) that has a point, anywhere in it and not only at a
/// vertex, further than `max_distance` from the nearest edge of a `tap`
/// polygon, holes included. Distance is Euclidean, compared exactly in
/// integers. A region with no tap on the layout is flagged. Needs no design
/// intent.
///
/// # Limits
///
/// A tap distance conditional on neighbouring well spacing is
/// [`ConditionalTieTable`]'s, a minimum tie area [`TieAreaTable`]'s. A point
/// inside a tap measures its
/// distance to the tap's edge, not zero, and a region polygon's hole is
/// measured as if filled (both over-report only).
///
/// Catalog: ERC-D1 in the [check catalog] (with the DRC kind
/// `max_distance_to_tap`). Defined by [GF180MCU] LU.1-LU.4; [IHP SG13G2]
/// LU.a and LU.b; [ASAP7] ACTIVE.LUP.1; [ESDA TR18.0-02] §3.1.1. Source tags
/// are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [ASAP7]: https://github.com/The-OpenROAD-Project/asap7_pdk_r1p7/blob/main/docs/asap7_drm_201207a.pdf
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
/// [`ConditionalTieTable`]: crate::erc::rules::latchup::ConditionalTieTable
/// [`TieAreaTable`]: crate::erc::rules::latchup::TieAreaTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MissingTieTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons must be tied.
    pub region: Vec<LayerId>,
    /// Per row: the tap layer.
    pub tap: Vec<LayerId>,
    /// Per row: the furthest a region point may be from a tap, database
    /// units. Positive from a deck.
    pub max_distance: Vec<Dbu>,
}

/// A gate tied straight to a rail: deck kind `tie_high_low`, written
/// `tie_high_low()`.
///
/// A row flags every rail, a supply the design intent declares (power or
/// ground), that reaches a transistor gate: a gate tied directly to a supply
/// instead of through a tie cell, which leaves the gate oxide exposed to
/// every transient on the rail. The rails decide, never which end of a
/// channel extraction calls the source. Every row flags the same nets; rows
/// differ only in id and severity. Needs design intent, for which nets are
/// the rails.
///
/// Catalog: ERC-G7 in the [check catalog]. Defined by Calibre's weak-sourcing
/// checks (public material only). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TieHighLowTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
}

/// Pad ESD clamp path: deck kind `esd_topological`, written
/// `esd_topological(pad; clamps: models)`.
///
/// A row flags a pad net with no chain of clamp devices to both a power and a
/// ground supply. A pad net is any net with a polygon on the `pad` layer. The
/// path is a clamp from the pad to a declared supply, then any chain of clamps
/// between supplies (rail clamps). A clamp is a device of a listed model,
/// through any of its terminals, except a diode between a supply and the pad
/// (or a signal) wired forward-biased: its anode held above its cathode, the
/// pad sitting between ground and every power supply (`reverse_biased`).
/// Such a diode conducts in operation and is no clamp. A signal net other than the
/// pad is not a path. Needs design intent, for which nets are the rails.
///
/// # Limits
///
/// Only the path's existence is checked; [`EsdPathTable`] measures it under
/// a forced current. A transistor clamp is taken as wired whatever its gate
/// is tied to, and a diode between two supplies whichever way round.
///
/// [`EsdPathTable`]: crate::erc::rules::esd::EsdPathTable
///
/// Catalog: ERC-C1 in the [check catalog]. Defined by [ESDA TR18.0-01]
/// §4.5.2-4.5.4; [Khazhinsky 2012]. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdTopologicalTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Marker layer whose polygons are pads.
    pub pad: Vec<LayerId>,
    /// Clamp device models per row, CSR.
    pub clamp_start: Vec<u32>,
    /// Clamp models, CSR by `clamp_start`; at least one per row.
    pub clamp: Vec<StrId>,
}

/// How many of the two rail kinds (power, ground) `pad` reaches through
/// devices of the `clamps` models ([`clamp_reach_into`]). `seen` and `stack`
/// are scratch.
pub(crate) fn clamp_rails(
    design: Design<'_>,
    intent: &IntentMap,
    clamps: &[StrId],
    pad: NetId,
    seen: &mut Vec<bool>,
    stack: &mut Vec<NetId>,
) -> u32 {
    let mut reached = Vec::new();
    clamp_reach_into(design, intent, clamps, pad, seen, stack, &mut reached);
    let has = |role| {
        reached.iter().any(|&net| {
            intent
                .supply_net
                .binary_search(&net)
                .is_ok_and(|row| intent.supply_role[row] == role)
        })
    };
    u32::from(has(SupplyRole::Power)) + u32::from(has(SupplyRole::Ground))
}

/// Every net `pad` reaches through devices of the `clamps` models, into
/// `reached` (cleared): `pad` first, then each declared supply in visit order.
/// The path is a clamp from the pad to a supply, then any chain of clamps
/// between supplies (rail clamps); another signal net is not a path, and a
/// diode clamp wired forward-biased carries nothing ([`reverse_biased`]).
/// `seen` (indexed by net: every net touched, signal nets included) and
/// `stack` are scratch.
pub(crate) fn clamp_reach_into(
    design: Design<'_>,
    intent: &IntentMap,
    clamps: &[StrId],
    pad: NetId,
    seen: &mut Vec<bool>,
    stack: &mut Vec<NetId>,
    reached: &mut Vec<NetId>,
) {
    let devices = design.devices;
    // ponytail: O(nets) reset per pad net; pads are few.
    seen.clear();
    seen.resize(design.nets.net_count(), false);
    stack.clear();
    reached.clear();
    stack.push(pad);
    seen[pad.idx()] = true;
    while let Some(net) = stack.pop() {
        if net != pad && intent.supply_net.binary_search(&net).is_err() {
            continue;
        }
        reached.push(net);
        for &device in devices.devices_on(net) {
            if !clamps.contains(&devices.model[device.0 as usize])
                || !reverse_biased(design, intent, device)
            {
                continue;
            }
            for &next in devices.terminals_of(device).0 {
                if next != NetId::NONE && !seen[next.idx()] {
                    seen[next.idx()] = true;
                    stack.push(next);
                }
            }
        }
    }
}

/// False for a pad diode its declared supplies forward-bias, which conducts
/// in operation and is no clamp: a diode between a supply and another net (a
/// pad, a signal) whose anode (`Pin(0)`) sits above its cathode (`Pin(1)`),
/// the other net sitting strictly between ground and every power supply. So
/// an anode on a power supply, or a cathode on a ground supply, is wired the
/// wrong way round. A diode between two supplies is taken as wired: a deck
/// may model a rail clamp (IHP's `nmoscl`) as a two-pin device whose first
/// pin is the power side, and anti-parallel pairs between grounds run both
/// ways. A diode between two other nets, and any device that is not a diode,
/// are taken as wired.
pub(crate) fn reverse_biased(design: Design<'_>, intent: &IntentMap, device: DeviceId) -> bool {
    let devices = design.devices;
    if devices.kind[device.0 as usize] != DeviceKind::Diode {
        return true;
    }
    let (on, roles) = devices.terminals_of(device);
    let pin = |k: u8| {
        on.iter()
            .zip(roles)
            .find(|&(_, &role)| role == TerminalRole::Pin(k))
            .map(|(&net, _)| intent.nominal_voltage(net).map(Qty::raw))
    };
    match (pin(0), pin(1)) {
        (Some(Some(anode)), Some(None)) => anode <= 0.0,
        (Some(None), Some(Some(cathode))) => cathode > 0.0,
        _ => true,
    }
}

/// One bit-or of `bit` per polygon on `layers` into its net's slot of
/// `marks` (sized `nets + 1`; `NetId::NONE` lands in the trash slot). Skipped
/// on an unextracted design, where `net_of` would panic.
fn mark_nets(design: Design<'_>, layer: LayerId, bit: u32, marks: &mut [u32]) {
    mark_nets_within(design, layer, None, bit, marks);
}

/// [`mark_nets`], counting only polygons of `layer` whose bounding-box centre
/// lies in a polygon of `within` (every polygon when `None`).
// ponytail: centre-in-polygon stands in for containment; taps are small
// convex shapes inside their well. A tap straddling a well edge is decided
// by its centre; an exact inside test if that ever matters.
fn mark_nets_within(
    design: Design<'_>,
    layer: LayerId,
    within: Option<LayerId>,
    bit: u32,
    marks: &mut [u32],
) {
    let nets = marks.len() - 1;
    if nets == 0 {
        return;
    }
    let inside = |poly: PolyId| {
        let Some(scope) = within else { return true };
        let b = design.store.poly_bbox(poly);
        let centre = crate::erc::centre(b);
        design.store.polys_on_layer(scope).any(|s| {
            let s = PolyId(s);
            design.store.poly_bbox(s).overlaps(b) && design.store.poly_contains_point(s, centre)
        })
    };
    for poly in design.store.polys_on_layer(layer) {
        if inside(PolyId(poly)) {
            let slot = design.nets.net_of(PolyId(poly)).idx().min(nets);
            marks[slot] |= bit;
        }
    }
}

/// The nets (ascending) whose mark equals `want`, ignoring the trash slot.
fn nets_marked(marks: &[u32], want: u32) -> Vec<u32> {
    (0u32..)
        .zip(&marks[..marks.len() - 1])
        .filter(|&(_, &mark)| mark == want)
        .map(|(net, _)| net)
        .collect()
}

/// Low- and high-voltage features on one net: deck kind `mixed_tag`, written
/// `mixed_tag(L, tag)`.
///
/// A merged figure of the conductor layer `L` is tagged when it shares area
/// with `tag` (an n-well under sky130's `hvi`, a high-voltage n-well) and
/// untagged otherwise. A row flags every untagged figure whose net also
/// holds a tagged figure: a low-voltage well tied to a high-voltage one.
/// Nets joined through a resistor count as one net, as hvnwell.10 asks ("for
/// the purposes of this check, short the connectivity through resistors").
/// A figure's net is its lowest-numbered drawn polygon's. Needs no design
/// intent.
///
/// # Limits
///
/// The tag is a layer: sky130's exemption of a high-voltage n-well whose
/// net carries the text tag `lv_net` is not read. A figure that touches the
/// tag only along an edge or at a corner is untagged.
///
/// Catalog: ERC-F10 in the [check catalog]. Defined by [SKY130] hvnwell.10
/// ("LVnwell and HnWell should not be on the same net"). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MixedTagTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the conductor layer whose figures are classed.
    pub layer: Vec<LayerId>,
    /// Per row: the tag layer that marks a figure high-voltage.
    pub tag: Vec<LayerId>,
}

/// Runs every [`MixedTagTable`] row.
///
/// `examined` counts the figures of `L` on a net. A violation sits at the
/// first vertex of the untagged figure's lowest drawn polygon, on `L`,
/// measuring the count of tagged figures on its net against 0, and names a
/// tagged figure's polygon as its second shape. Every row runs; a row is
/// refused when a layer will not validate or merge.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_mixed_tag(
    design: Design<'_>,
    table: &MixedTagTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Nets joined through a resistor are one group.
    let devices = design.devices;
    let mut edges: Vec<(u32, u32)> = Vec::new();
    for device in 0..devices.len() {
        if devices.kind[device] != gpurify_ingest::deck::DeviceKind::Resistor {
            continue;
        }
        let id = device_id(device);
        let pins: Vec<u32> = devices
            .terminals_of(id)
            .0
            .iter()
            .filter(|&&net| net != NetId::NONE)
            .map(|net| net.0)
            .collect();
        edges.extend(pins.windows(2).map(|pair| (pair[0], pair[1])));
    }
    let count = u32::try_from(design.nets.net_count()).expect("a NetId is a u32");
    let mut group = Vec::new();
    gpurify_geom::connectivity::components_into(count, &edges, &mut group);

    // A figure on no net (none was extracted) has no group and is not judged.
    let group_of = |poly: PolyId| {
        if count == 0 {
            return None;
        }
        let net = design.nets.net_of(poly);
        (net != NetId::NONE).then(|| group[net.idx()].0)
    };
    let mut scratch = crate::drc::Scratch::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let layer = table.layer[row];
        let figures = crate::drc::rules::presence::tagged_figures(
            design.store,
            layer,
            table.tag[row],
            &mut scratch,
        );
        let Some(figures) = figures else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };
        let mut tagged: Vec<(u32, PolyId)> = figures
            .iter()
            .filter(|figure| figure.1)
            .filter_map(|&(poly, _)| Some((group_of(poly)?, poly)))
            .collect();
        tagged.sort_unstable();
        let mut examined = 0u64;
        for &(poly, is_tagged) in &figures {
            let Some(mine) = group_of(poly) else {
                continue;
            };
            examined += 1;
            if is_tagged {
                continue;
            }
            let on_net =
                tagged.partition_point(|t| t.0 < mine)..tagged.partition_point(|t| t.0 <= mine);
            if on_net.is_empty() {
                continue;
            }
            out.push(Violation {
                rule,
                layer,
                severity: table.head.severity[row],
                at: first_vertex(design.store, poly),
                measured: Measurement::Count(
                    u32::try_from(on_net.len()).expect("a figure count fits a u32"),
                ),
                limit: Measurement::Count(0),
                shapes: (poly, Some(tagged[on_net.start].1)),
            });
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`SupplyShortTable`] row.
///
/// `examined` counts the polygons on `tap_a` and `tap_b`, all of them, inside
/// `within` or not. A violation sits at the first vertex of the net's
/// lowest-numbered polygon, on that polygon's layer, measuring the count 2
/// (tap kinds on the net) against 1. Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_supply_short(
    design: Design<'_>,
    table: &SupplyShortTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let nets = design.nets.net_count();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let (tap_a, tap_b) = (table.tap_a[row], table.tap_b[row]);

        scratch.net_marks.clear();
        scratch.net_marks.resize(nets + 1, 0);
        let within = table.within.get(row).copied().flatten();
        mark_nets_within(design, tap_a, within, 1, &mut scratch.net_marks);
        mark_nets(design, tap_b, 2, &mut scratch.net_marks);
        let (a_rows, b_rows) = (
            design.store.polys_on_layer(tap_a),
            design.store.polys_on_layer(tap_b),
        );
        let examined = u64::from(a_rows.end - a_rows.start) + u64::from(b_rows.end - b_rows.start);

        push_net_violations(
            design,
            &nets_marked(&scratch.net_marks, 3),
            rule,
            table.head.severity[row],
            Measurement::Count(2),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`SoftConnectionTable`] row.
///
/// `examined` counts the nets with a polygon on a soft layer. A violation sits
/// at the first vertex of the net's lowest-numbered remaining polygon, on its
/// layer, and names a polygon in another group, one shape on each side of the
/// bridge. It measures the count 2 against 1, however many groups there are.
/// Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_soft_connection(
    design: Design<'_>,
    table: &SoftConnectionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let nets = design.nets.net_count();
    let mut is_soft: Vec<bool> = Vec::new();
    let mut pieces = std::mem::take(&mut scratch.staged_nets);

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let span = table.soft_start[row] as usize..table.soft_start[row + 1] as usize;

        // A layer named twice is marked once.
        is_soft.clear();
        is_soft.resize(design.store.layer_count(), false);
        scratch.net_marks.clear();
        scratch.net_marks.resize(nets + 1, 0);
        for &layer in &table.soft[span] {
            if !is_soft[layer.idx()] {
                is_soft[layer.idx()] = true;
                mark_nets(design, layer, 1, &mut scratch.net_marks);
            }
        }
        let soft_nets = nets_marked(&scratch.net_marks, 1);

        // What is left without the resistive bodies, joined only as declared.
        let soft = |layer: LayerId| is_soft[layer.idx()];
        let all = &table.connectivity;
        let (via_cut, via_connects) = all
            .via_cut
            .iter()
            .zip(&all.via_connects)
            .filter(|&(&cut, &(a, b))| !(soft(cut) || soft(a) || soft(b)))
            .map(|(&cut, &joins)| (cut, joins))
            .unzip();
        let hard = Connectivity {
            conductors: all
                .conductors
                .iter()
                .copied()
                .filter(|&l| !soft(l))
                .collect(),
            via_cut,
            via_connects,
            global: all.global.iter().copied().filter(|&l| !soft(l)).collect(),
            ..all.clone()
        };
        extract_nets_into(design.store, &hard, &mut pieces);

        for &net in &soft_nets {
            // The lowest polygon off the soft layers, and the lowest one in
            // another piece.
            let mut near: Option<(PolyId, NetId)> = None;
            let mut far = None;
            for &poly in design.nets.polys_of(NetId(net)) {
                let piece = pieces.net_of(poly);
                if soft(design.store.poly_layer(poly)) || piece == NetId::NONE {
                    continue;
                }
                match near {
                    None => near = Some((poly, piece)),
                    Some((_, first)) if piece != first => {
                        far = Some(poly);
                        break;
                    }
                    Some(_) => {}
                }
            }
            let (Some((first_poly, _)), Some(far)) = (near, far) else {
                continue;
            };
            out.push(Violation {
                rule,
                layer: design.store.poly_layer(first_poly),
                severity: table.head.severity[row],
                at: first_vertex(design.store, first_poly),
                measured: Measurement::Count(2),
                limit: Measurement::Count(1),
                shapes: (first_poly, Some(far)),
            });
        }

        let examined = u64::try_from(soft_nets.len()).expect("a net count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
    scratch.staged_nets = pieces;
}

/// Runs every [`MissingTieTable`] row.
///
/// `examined` counts the region polygons. A violation sits at that furthest
/// point, on the region layer, measuring its distance (rounded down to a
/// database unit; `MAX_ABS_DBU` with no tap at all) against `max_distance`. A
/// row is refused when its tap layer will not validate, never read as empty.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_missing_tie(
    design: Design<'_>,
    table: &MissingTieTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let limit = table.max_distance[row];
        let examined = untied_points(
            design.store,
            (table.region[row], table.tap[row]),
            limit,
            &mut scratch.layer_b,
            |poly, at, worst| {
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(poly),
                    severity: table.head.severity[row],
                    at,
                    measured: Measurement::Length(isqrt(worst)),
                    limit: Measurement::Length(limit),
                    shapes: (poly, None),
                });
            },
        );
        // A tap layer that will not validate is refused, never read as empty.
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// Every outer row on `region` whose furthest point from the `tap` layer
/// (every point of the polygon, not only its vertices; distance to the taps'
/// edges, holes included) is more than `limit`: `each(row, point, distance²)`.
/// A hole row (clockwise) is not a region of its own, and its polygon is
/// measured as if filled. Returns the outer row count, or `None` when the tap
/// layer will not validate. A region with no tap at all measures
/// `MAX_ABS_DBU`.
pub(crate) fn untied_points(
    store: &GeometryStore,
    layers: (LayerId, LayerId),
    limit: Dbu,
    tap_layer: &mut ValidatedLayer,
    mut each: impl FnMut(PolyId, Point, DbuArea),
) -> Option<u64> {
    untied_points_by(
        store,
        layers,
        |_| Some(limit),
        tap_layer,
        |poly, at, worst, _| each(poly, at, worst),
    )
}

/// [`untied_points`] with each region polygon's own limit from `limit_of`,
/// `None` leaving the polygon out (not counted); `each` also receives the
/// limit the polygon was held to.
pub(crate) fn untied_points_by(
    store: &GeometryStore,
    (region, tap): (LayerId, LayerId),
    mut limit_of: impl FnMut(PolyId) -> Option<Dbu>,
    tap_layer: &mut ValidatedLayer,
    mut each: impl FnMut(PolyId, Point, DbuArea, Dbu),
) -> Option<u64> {
    validate_layer_into(store, tap, tap_layer).ok()?;

    // Holes too: a ring-shaped tap ties along its inner boundary.
    let mut taps: Vec<Seg> = Vec::new();
    for idx in 0..tap_layer.len() {
        let idx = u32::try_from(idx).expect("a validated layer's polygons fit a u32");
        let poly = tap_layer.get(idx);
        push_ring_edges(poly.outer(), &mut taps);
        for hole in poly.holes() {
            push_ring_edges(hole, &mut taps);
        }
    }
    // Coincident edges measure alike; keyed undirected because abutting
    // taps run a shared edge in opposite directions.
    taps.sort_unstable_by_key(undirected);
    taps.dedup_by_key(|s| undirected(s));
    let mut grid = TapGrid::default();
    TapGrid::build_into(&taps, &mut grid);
    let mut stack: Vec<Cell> = Vec::new();

    let mut examined = 0u64;
    for poly in store.polys_on_layer(region) {
        let poly = PolyId(poly);
        let (xs, ys) = store.poly_verts(poly);
        if winding_of(xs, ys) == Some(Winding::Clockwise) {
            continue;
        }
        let Some(limit) = limit_of(poly) else {
            continue;
        };
        let limit2 = limit.mul_wide(limit);
        examined += 1;
        let Some((&x0, &y0)) = xs.first().zip(ys.first()) else {
            continue;
        };
        // No taps at all: the sentinel, whose root is `MAX_ABS_DBU`.
        let (at, worst) = if taps.is_empty() {
            (Point { x: x0, y: y0 }, NO_TAP_IN_RANGE)
        } else {
            // `limit2` is the search's floor, so a region under the limit
            // prunes without descending.
            furthest_from_taps(xs, ys, store.poly_bbox(poly), limit2, &grid, &mut stack)
        };
        if worst > limit2 {
            each(poly, at, worst, limit);
        }
    }
    Some(examined)
}

/// Runs every [`TieHighLowTable`] row.
///
/// `examined` counts nets with a gate terminal. A violation sits at the first
/// vertex of the rail's lowest-numbered polygon, on its layer, measuring the
/// count of tie cells between the rail and its gates, 0, against 1. Every
/// row is skipped when no design intent was given or it declares no supply
/// this layout has.
pub fn check_tie_high_low(
    design: Design<'_>,
    facts: &NetFacts,
    intent: &IntentMap,
    table: &TieHighLowTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let examined = facts
        .role
        .iter()
        .filter(|mask| mask.contains(RoleMask::GATE))
        .count() as u64;
    let flagged: Vec<u32> = intent
        .supply_net
        .iter()
        .filter(|net| {
            facts
                .role
                .get(net.idx())
                .is_some_and(|mask| mask.contains(RoleMask::GATE))
        })
        .map(|net| net.0)
        .collect();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`EsdTopologicalTable`] row.
///
/// `examined` counts distinct pad nets. A violation sits at the first vertex
/// of the net's lowest-numbered polygon, on its layer, measuring the rail
/// kinds reached (0 or 1) against 2. Every row is skipped without usable
/// intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_topological(
    design: Design<'_>,
    intent: &IntentMap,
    table: &EsdTopologicalTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let nets = design.nets.net_count();
    let mut on_a_pad: Vec<u32> = Vec::new();
    let (mut seen, mut stack) = (Vec::new(), Vec::new());
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let clamps =
            &table.clamp[table.clamp_start[row] as usize..table.clamp_start[row + 1] as usize];
        on_a_pad.clear();
        on_a_pad.resize(nets + 1, 0);
        mark_nets(design, table.pad[row], 1, &mut on_a_pad);
        let pad_nets = nets_marked(&on_a_pad, 1);
        for &net in &pad_nets {
            let rails = clamp_rails(design, intent, clamps, NetId(net), &mut seen, &mut stack);
            if rails < 2 {
                push_net_violations(
                    design,
                    &[net],
                    rule,
                    table.head.severity[row],
                    Measurement::Count(rails),
                    Measurement::Count(2),
                    out,
                );
            }
        }
        let examined = u64::try_from(pad_nets.len()).expect("a net count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// One segment's endpoints in ascending order — its identity ignoring which way
/// round it was drawn.
fn undirected(s: &Seg) -> (i64, i64, i64, i64) {
    let (p, q) = ((s.a.x.raw(), s.a.y.raw()), (s.b.x.raw(), s.b.y.raw()));
    let (lo, hi) = (p.min(q), p.max(q));
    (lo.0, lo.1, hi.0, hi.1)
}

/// Append one ring's closed edges to a segment column.
fn push_ring_edges(ring: RingRef<'_>, out: &mut Vec<Seg>) {
    let (xs, ys) = ring.coords();
    out.reserve(xs.len());
    for vertex in 0..xs.len() {
        out.push(ring_edge(xs, ys, vertex));
    }
}

/// The closed edge from vertex `i` of a ring to the next one, wrapping.
#[inline]
pub(crate) fn ring_edge(xs: &[Dbu], ys: &[Dbu], i: usize) -> Seg {
    let next = (i + 1) - xs.len() * usize::from(i + 1 == xs.len());
    Seg {
        a: Point { x: xs[i], y: ys[i] },
        b: Point {
            x: xs[next],
            y: ys[next],
        },
    }
}

/// Whether a point lies in a ring, boundary included (the missing-tie maximum
/// often sits on an edge). Even-odd ray cast toward +x, exact in `i128`.
/// Deliberately not folded with `topology::inside_ring`, which excludes the
/// boundary.
pub(crate) fn point_in_region(xs: &[Dbu], ys: &[Dbu], p: Point) -> bool {
    if xs.len() < 3 {
        return false;
    }

    let zero = DbuArea::new(0);
    let mut inside = false;
    for i in 0..xs.len() {
        let edge = ring_edge(xs, ys, i);
        if point_seg_dist2(p, edge) == zero {
            return true;
        }

        // Half-open crossing rule, then the side test.
        let dy = i128::from(edge.b.y.raw() - edge.a.y.raw());
        let dx = i128::from(edge.b.x.raw() - edge.a.x.raw());
        let lhs = i128::from(p.x.raw() - edge.a.x.raw()) * dy;
        let rhs = i128::from(p.y.raw() - edge.a.y.raw()) * dx;
        let straddles = (edge.a.y > p.y) != (edge.b.y > p.y);
        inside ^= straddles & ((lhs - rhs) * dy.signum() < 0);
    }
    inside
}

/// The square root of a non-negative area, rounded up: an upper bound rounded
/// down (as `ops::isqrt` does) would prune away the maximum.
fn isqrt_ceil(area: i128) -> i64 {
    let root = area.isqrt();
    let root = root + i128::from(root * root != area);
    i64::try_from(root).expect("the root of an in-domain area is a length")
}

/// Target segments per [`TapGrid`] bucket. Tuned by measurement.
const BUCKET_TARGET: i64 = 16;

/// Whether no point of a cell can be further from a tap than the best found:
/// `sqrt(d2) + reach <= worst_root`, squared. `worst_root` is floored, so this
/// prunes slightly too rarely, never too often. The sign test is required.
#[inline]
fn prunes(worst_root: i64, reach: i64, d2: DbuArea) -> bool {
    let slack = i128::from(worst_root - reach);
    (slack >= 0) & (d2.raw() <= slack * slack)
}

/// A closed block of integer points in [`furthest_from_taps`]'s search.
#[derive(Debug, Clone, Copy)]
struct Cell {
    xlo: i64,
    ylo: i64,
    xhi: i64,
    yhi: i64,
    /// Index into [`TapGrid::segs`] of the tap nearest the parent's probe.
    hint: u32,
}

/// The nearest tap to some point: how far, and which one.
#[derive(Debug, Clone, Copy)]
struct Nearest {
    dist2: DbuArea,
    /// Index into [`TapGrid::segs`], or [`u32::MAX`] when nothing was scanned.
    tap: u32,
}

impl Nearest {
    const NONE: Self = Self {
        dist2: NO_TAP_IN_RANGE,
        tap: u32::MAX,
    };

    /// Keep whichever is nearer; the earlier wins a tie.
    #[inline]
    fn keep(&mut self, other: Self) {
        let mask = u32::from(other.dist2 < self.dist2).wrapping_neg();
        self.tap = (self.tap & !mask) | (other.tap & mask);
        self.dist2 = self.dist2.min(other.dist2);
    }
}

/// A uniform grid over one row's tap edges. A segment is filed under every
/// cell its bounding box overlaps, which makes the ring search's stop sound.
#[derive(Debug)]
struct TapGrid {
    origin: Point,
    cell: i64,
    nx: i64,
    ny: i64,
    /// `start[b] .. start[b + 1]` indexes `segs`.
    start: Vec<u32>,
    segs: Vec<Seg>,
    /// Build scratch.
    extents: Vec<i64>,
    cursor: Vec<u32>,
}

impl Default for TapGrid {
    fn default() -> Self {
        Self {
            origin: Point {
                x: Dbu::new_unchecked(0),
                y: Dbu::new_unchecked(0),
            },
            cell: 1,
            nx: 0,
            ny: 0,
            start: Vec::new(),
            segs: Vec::new(),
            extents: Vec::new(),
            cursor: Vec::new(),
        }
    }
}

impl TapGrid {
    /// Build over one row's tap edges; an empty column leaves an empty grid
    /// that must not be probed.
    fn build_into(taps: &[Seg], out: &mut Self) {
        out.start.clear();
        out.segs.clear();
        out.cursor.clear();
        out.cell = 1;
        out.nx = 0;
        out.ny = 0;
        out.origin = Point {
            x: Dbu::new_unchecked(0),
            y: Dbu::new_unchecked(0),
        };
        if taps.is_empty() {
            return;
        }

        let mut extent = Bbox::EMPTY;
        for s in taps {
            extent = extent.include(s.a.x, s.a.y).include(s.b.x, s.b.y);
        }
        let span_x = extent.xhi.raw() - extent.xlo.raw() + 1;
        let span_y = extent.yhi.raw() - extent.ylo.raw() + 1;

        // Cell: the median segment extent, widened until there are about
        // `taps.len() / BUCKET_TARGET` buckets.
        out.extents.clear();
        out.extents.reserve(taps.len());
        out.extents.extend(taps.iter().map(|s| {
            (s.b.x.raw() - s.a.x.raw())
                .abs()
                .max((s.b.y.raw() - s.a.y.raw()).abs())
        }));
        let mid = out.extents.len() / 2;
        out.extents.select_nth_unstable(mid);
        let side = (i64::try_from(taps.len()).expect("a tap edge count fits an i64")
            / BUCKET_TARGET)
            .isqrt()
            .max(1);
        let cell = out.extents[mid]
            .max(1)
            .max((span_x + side - 1) / side)
            .max((span_y + side - 1) / side);

        out.cell = cell;
        out.origin = Point {
            x: extent.xlo,
            y: extent.ylo,
        };
        out.nx = (span_x + cell - 1) / cell;
        out.ny = (span_y + cell - 1) / cell;

        let buckets = usize::try_from(out.nx * out.ny).expect("a bucket count fits a usize");
        out.start.clear();
        out.start.resize(buckets + 1, 0);

        // A counting sort: scatter-accumulate, prefix sum, scatter.
        for seg in taps {
            let (x0, y0, x1, y1) = out.cells_of(*seg);
            for cy in y0..=y1 {
                for cx in x0..=x1 {
                    let b = out.bucket(cx, cy);
                    out.start[b + 1] += 1;
                }
            }
        }
        for b in 0..buckets {
            out.start[b + 1] += out.start[b];
        }
        let total =
            usize::try_from(out.start[buckets]).expect("a filed-segment count fits a usize");
        out.segs.clear();
        out.segs
            .resize(total, *taps.first().expect("the column is not empty"));
        out.cursor.clear();
        out.cursor.extend_from_slice(&out.start[..buckets]);
        for seg in taps {
            let (x0, y0, x1, y1) = out.cells_of(*seg);
            for cy in y0..=y1 {
                for cx in x0..=x1 {
                    let b = out.bucket(cx, cy);
                    let at = usize::try_from(out.cursor[b]).expect("a write cursor fits a usize");
                    out.segs[at] = *seg;
                    out.cursor[b] += 1;
                }
            }
        }
    }

    /// The flat bucket index of one in-range cell.
    #[inline]
    fn bucket(&self, cx: i64, cy: i64) -> usize {
        usize::try_from(cy * self.nx + cx).expect("a cell inside the grid has a non-negative index")
    }

    /// The inclusive cell range one segment's bounding box covers, clamped.
    #[inline]
    fn cells_of(&self, seg: Seg) -> (i64, i64, i64, i64) {
        let (x0, x1) = (
            seg.a.x.raw().min(seg.b.x.raw()),
            seg.a.x.raw().max(seg.b.x.raw()),
        );
        let (y0, y1) = (
            seg.a.y.raw().min(seg.b.y.raw()),
            seg.a.y.raw().max(seg.b.y.raw()),
        );
        (
            self.axis_x(x0).clamp(0, self.nx - 1),
            self.axis_y(y0).clamp(0, self.ny - 1),
            self.axis_x(x1).clamp(0, self.nx - 1),
            self.axis_y(y1).clamp(0, self.ny - 1),
        )
    }

    #[inline]
    fn axis_x(&self, x: i64) -> i64 {
        (x - self.origin.x.raw()).div_euclid(self.cell)
    }

    #[inline]
    fn axis_y(&self, y: i64) -> i64 {
        (y - self.origin.y.raw()).div_euclid(self.cell)
    }

    /// One filed tap edge.
    #[inline]
    fn tap(&self, at: u32) -> Seg {
        self.segs[usize::try_from(at).expect("a filed-segment index fits a usize")]
    }

    /// The nearest tap in one cell, or [`Nearest::NONE`] when it is empty.
    #[inline]
    fn nybucket(&self, cx: i64, cy: i64, p: Point) -> Nearest {
        let b = self.bucket(cx, cy);
        let (lo, hi) = (
            usize::try_from(self.start[b]).expect("a bucket offset fits a usize"),
            usize::try_from(self.start[b + 1]).expect("a bucket offset fits a usize"),
        );
        let bucket = &self.segs[lo..hi];
        let mut best = Nearest::NONE;
        for (tap, &seg) in (self.start[b]..).zip(bucket) {
            best.keep(Nearest {
                dist2: point_seg_dist2(p, seg),
                tap,
            });
        }
        best
    }

    /// The nearest tap edge to `p`, exactly: rings of cells outward from `p`'s
    /// cell until nothing unscanned (at least `r * cell` away) can be nearer.
    fn nearest2(&self, p: Point) -> Nearest {
        let (px, py) = (self.axis_x(p.x.raw()), self.axis_y(p.y.raw()));
        let rmax = px
            .abs()
            .max((px - (self.nx - 1)).abs())
            .max(py.abs())
            .max((py - (self.ny - 1)).abs());

        let mut best = Nearest::NONE;
        let mut r = 0;
        while r <= rmax {
            let (x0, x1) = (px - r, px + r);
            let (y0, y1) = (py - r, py + r);
            for cy in y0.max(0)..=y1.min(self.ny - 1) {
                // Top and bottom rows whole; the rows between, their two ends.
                if (cy == y0) | (cy == y1) {
                    for cx in x0.max(0)..=x1.min(self.nx - 1) {
                        best.keep(self.nybucket(cx, cy, p));
                    }
                } else {
                    if (0..self.nx).contains(&x0) {
                        best.keep(self.nybucket(x0, cy, p));
                    }
                    if (0..self.nx).contains(&x1) && x1 != x0 {
                        best.keep(self.nybucket(x1, cy, p));
                    }
                }
            }

            let gap = i128::from(r) * i128::from(self.cell);
            if best.dist2.raw() <= gap * gap {
                break;
            }
            r += 1;
        }

        best
    }
}

/// The point of a region polygon furthest from any tap, and that distance
/// squared: exact whenever it exceeds `floor`, otherwise `floor` itself.
///
/// Branch and bound over the region's integer points (vertices alone miss the
/// maximum), seeded from the vertices. A cell is pruned when its probe's
/// distance plus its reach cannot beat the best; each cell inherits its
/// parent's nearest tap as a cheap upper bound, and only the exact query
/// writes `worst`.
fn furthest_from_taps(
    xs: &[Dbu],
    ys: &[Dbu],
    bbox: Bbox,
    floor: DbuArea,
    grid: &TapGrid,
    stack: &mut Vec<Cell>,
) -> (Point, DbuArea) {
    // Vertices are in the region, so need no containment test.
    let mut best = Nearest {
        dist2: DbuArea::new(-1),
        tap: 0,
    };
    let mut at = Point { x: xs[0], y: ys[0] };
    for vertex in 0..xs.len() {
        let here = Point {
            x: xs[vertex],
            y: ys[vertex],
        };
        let found = grid.nearest2(here);
        if found.dist2 > best.dist2 {
            best = found;
            at = here;
        }
    }

    // Starting at the floor prunes a region under it without descending; `at`
    // is read only when `worst` ends above the floor.
    let mut worst = best.dist2.max(floor);
    let mut worst_root = isqrt(worst).raw();

    stack.clear();
    stack.push(Cell {
        xlo: bbox.xlo.raw(),
        ylo: bbox.ylo.raw(),
        xhi: bbox.xhi.raw(),
        yhi: bbox.yhi.raw(),
        hint: best.tap,
    });
    while let Some(cell) = stack.pop() {
        let cx = cell.xlo + (cell.xhi - cell.xlo) / 2;
        let cy = cell.ylo + (cell.yhi - cell.ylo) / 2;
        let here = Point {
            x: Dbu::new_unchecked(cx),
            y: Dbu::new_unchecked(cy),
        };

        // The inherited tap is a real tap: an upper bound.
        let mut probe = Nearest {
            dist2: point_seg_dist2(here, grid.tap(cell.hint)),
            tap: cell.hint,
        };

        let rx = i128::from((cell.xhi - cx).max(cx - cell.xlo));
        let ry = i128::from((cell.yhi - cy).max(cy - cell.ylo));
        let reach = isqrt_ceil(rx * rx + ry * ry);

        if !prunes(worst_root, reach, probe.dist2) {
            let exact = grid.nearest2(here);
            probe = exact;

            if exact.dist2 > worst && point_in_region(xs, ys, here) {
                worst = exact.dist2;
                worst_root = isqrt(worst).raw();
                at = here;
            }
        }

        // Exact whenever the first test failed, so survival ignores the hint.
        if prunes(worst_root, reach, probe.dist2) {
            continue;
        }

        // A single point was just probed and cannot split.
        let splits_x = cx < cell.xhi;
        let splits_y = cy < cell.yhi;
        if !splits_x && !splits_y {
            continue;
        }

        stack.push(Cell {
            xlo: cell.xlo,
            ylo: cell.ylo,
            xhi: cx,
            yhi: cy,
            hint: probe.tap,
        });
        if splits_x {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cell.ylo,
                xhi: cell.xhi,
                yhi: cy,
                hint: probe.tap,
            });
        }
        if splits_y {
            stack.push(Cell {
                xlo: cell.xlo,
                ylo: cy + 1,
                xhi: cx,
                yhi: cell.yhi,
                hint: probe.tap,
            });
        }
        if splits_x && splits_y {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cy + 1,
                xhi: cell.xhi,
                yhi: cell.yhi,
                hint: probe.tap,
            });
        }
    }

    (at, worst)
}

/// "No tap in range": the largest area `ops::isqrt` accepts, so an untapped
/// region measures `MAX_ABS_DBU` and is reported.
const NO_TAP_IN_RANGE: DbuArea = DbuArea::new(1i128 << 80);

/// A floating piece of a supply: deck kind `floating_supply`, written
/// `floating_supply()`.
///
/// A declared supply is one logical net, but a layout can leave its shapes in
/// pieces that carry its name and touch nothing else of it: a stripe not
/// strapped to the grid, a cell rail cut off from it. The grid is fed where
/// the supply enters, the centre of its highest, then widest, shape over
/// every piece ([`extract_into`](crate::erc::power::extract_into)'s feed
/// point); every other piece is floating. A row flags each, at its lowest
/// polygon. This is [OpenROAD `check_power_grid`]: it walks the supply's
/// grid from one top-layer node and reports every shape the walk does not
/// reach as unconnected (PSM-38), with the instance pins on them (PSM-39);
/// here a piece is a connected component of the extracted net, and the
/// device terminals on a floating piece are those pins. The IR-drop and
/// current rules feed each piece by itself, so without this row a floating
/// piece reads as a healthy rail. Needs design intent, for which names are
/// supplies.
///
/// # Limits
///
/// A piece is found by its label: a stripe that carries no label of the
/// supply is a net of its own, which [`UnconnectedPinTable`] reports when no
/// device reaches it.
///
/// Catalog: ERC-E9 in the [check catalog]. Defined by
/// [OpenROAD `check_power_grid`]. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [OpenROAD `check_power_grid`]: https://openroad.readthedocs.io/en/latest/main/src/psm/README.html
/// [`UnconnectedPinTable`]: crate::erc::rules::topology::UnconnectedPinTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FloatingSupplyTable {
    /// Rule id and severity per row. Rows differ only in id and severity.
    pub head: RuleHead,
}

/// Runs every [`FloatingSupplyTable`] row.
///
/// `examined` counts the pieces of the declared supplies. A violation sits
/// at the first vertex of a floating piece's lowest-numbered polygon, on its
/// layer, measuring its connections to the fed piece, 0, against 1. Every
/// row is skipped when no design intent was given or it declares no supply
/// this layout has.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_floating_supply(
    design: Design<'_>,
    ports: &PortTable,
    intent: &IntentMap,
    process: Process<'_>,
    table: &FloatingSupplyTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let nets = design.nets;
    // Supply pieces grouped by name: `(name, net)`, ascending.
    let mut pieces: Vec<(StrId, NetId)> = intent
        .supply_net
        .iter()
        .filter_map(|&net| ports.name_of(net).map(|name| (name, net)))
        .collect();
    pieces.sort_unstable();
    pieces.dedup();
    let mut floating: Vec<u32> = Vec::new();
    let mut shapes: Vec<PolyId> = Vec::new();
    let mut owner: Vec<NetId> = Vec::new();
    for group in pieces.chunk_by(|a, b| a.0 == b.0) {
        if group.len() < 2 {
            continue;
        }
        shapes.clear();
        owner.clear();
        for &(_, net) in group {
            for &poly in nets.polys_of(net) {
                if !nets.holes.is_hole(poly) {
                    shapes.push(poly);
                    owner.push(net);
                }
            }
        }
        if shapes.is_empty() {
            continue;
        }
        let fed = owner[feed_shape(design.store, process, &shapes)];
        floating.extend(group.iter().filter(|p| p.1 != fed).map(|p| p.1 .0));
    }
    floating.sort_unstable();
    let examined = pieces.len() as u64;
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        push_net_violations(
            design,
            &floating,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

#[cfg(test)]
mod tests {
    use super::{furthest_from_taps, isqrt_ceil, point_in_region, Cell, TapGrid};
    use gpurify_geom::ops::{point_seg_dist2, Point, Seg};
    use gpurify_geom::{Bbox, Dbu, DbuArea};

    fn pt(x: i64, y: i64) -> Point {
        Point {
            x: Dbu::new_unchecked(x),
            y: Dbu::new_unchecked(y),
        }
    }

    fn ring(points: &[(i64, i64)]) -> (Vec<Dbu>, Vec<Dbu>) {
        points
            .iter()
            .map(|&(x, y)| (Dbu::new_unchecked(x), Dbu::new_unchecked(y)))
            .unzip()
    }

    /// A xorshift draw in `lo ..= hi`.
    fn draws(seed: u64) -> impl FnMut(i64, i64) -> i64 {
        let mut state = seed;
        move |lo, hi| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let span = u64::try_from(hi - lo + 1).expect("a non-empty range");
            lo + i64::try_from(state % span).expect("a draw below the span fits an i64")
        }
    }

    /// The nearest tap by an exhaustive scan.
    fn brute_nearest(taps: &[Seg], p: Point) -> DbuArea {
        taps.iter()
            .map(|&s| point_seg_dist2(p, s))
            .min()
            .expect("a non-empty column")
    }

    /// Random horizontal, vertical and sloped tap edges over a `span` square.
    fn random_taps(draw: &mut impl FnMut(i64, i64) -> i64, count: usize, span: i64) -> Vec<Seg> {
        (0..count)
            .map(|k| {
                let (x, y) = (draw(-span, span), draw(-span, span));
                let len = draw(0, span / 4 + 1);
                let b = match k % 3 {
                    0 => pt(x + len, y),
                    1 => pt(x, y - len),
                    _ => pt(x + len, y + draw(-len, len)),
                };
                Seg { a: pt(x, y), b }
            })
            .collect()
    }

    /// The ring search finds the nearest tap edge exactly, from inside the
    /// grid and far outside it, over grids of one bucket and of many (more
    /// than `BUCKET_TARGET` edges a bucket), and names a filed edge at that
    /// distance; each edge is filed once per cell its box covers.
    ///
    /// Oracle: differential against an exhaustive scan of every tap edge.
    #[test]
    fn the_tap_grid_ring_search_agrees_with_an_exhaustive_scan() {
        let mut draw = draws(0x9E37_79B9_7F4A_7C15);
        for count in [1usize, 2, 5, 17, 60, 400] {
            for span in [3i64, 50, 2000] {
                let taps = random_taps(&mut draw, count, span);
                let mut grid = TapGrid::default();
                TapGrid::build_into(&taps, &mut grid);
                let filed: usize = taps
                    .iter()
                    .map(|&s| {
                        let (x0, y0, x1, y1) = grid.cells_of(s);
                        usize::try_from((x1 - x0 + 1) * (y1 - y0 + 1)).expect("a cell count")
                    })
                    .sum();
                assert_eq!(grid.segs.len(), filed, "each edge once per cell it covers");
                for _ in 0..80 {
                    let p = pt(draw(-3 * span, 3 * span), draw(-3 * span, 3 * span));
                    let found = grid.nearest2(p);
                    assert_eq!(
                        found.dist2,
                        brute_nearest(&taps, p),
                        "{count} taps over {span}: {p:?}"
                    );
                    assert_eq!(point_seg_dist2(p, grid.tap(found.tap)), found.dist2);
                }
            }
        }
    }

    /// Rebuilding a grid over another column forgets the first one.
    ///
    /// Oracle: law: a build is a function of its column alone, so a grid
    /// built over `a` then `b` answers as one built over `b` only: the
    /// nearest point of the edge `(500,500)-(500,900)` to the origin is its
    /// end, 500² + 500² away.
    #[test]
    fn a_rebuilt_tap_grid_answers_for_its_new_column_only() {
        let a = [Seg {
            a: pt(0, 0),
            b: pt(10, 0),
        }];
        let b = [Seg {
            a: pt(500, 500),
            b: pt(500, 900),
        }];
        let mut grid = TapGrid::default();
        TapGrid::build_into(&a, &mut grid);
        TapGrid::build_into(&b, &mut grid);
        assert_eq!(grid.nearest2(pt(0, 0)).dist2, DbuArea::new(500 * 500 * 2));
        assert_eq!(grid.segs.len(), 1);
    }

    /// The furthest integer point of a region from every tap edge, by
    /// visiting every integer point of its box.
    fn brute_furthest(xs: &[Dbu], ys: &[Dbu], bbox: Bbox, taps: &[Seg]) -> DbuArea {
        let mut worst = DbuArea::new(-1);
        for x in bbox.xlo.raw()..=bbox.xhi.raw() {
            for y in bbox.ylo.raw()..=bbox.yhi.raw() {
                let p = pt(x, y);
                if point_in_region(xs, ys, p) {
                    worst = worst.max(brute_nearest(taps, p));
                }
            }
        }
        worst
    }

    /// Branch and bound finds the furthest point of a region from the taps
    /// exactly whenever it beats the floor, reports a point of the region at
    /// that distance, and answers the floor itself when nothing beats it.
    ///
    /// Oracle: differential against an exhaustive scan of every integer
    /// point of the region (rectangles, an L and a U), with taps inside,
    /// beside and far from it.
    #[test]
    fn the_furthest_point_from_the_taps_agrees_with_an_exhaustive_scan() {
        let mut draw = draws(0x2545_F491_4F6C_DD1D);
        let regions: [&[(i64, i64)]; 4] = [
            &[(0, 0), (40, 0), (40, 30), (0, 30)],
            &[(0, 0), (1, 0), (1, 57), (0, 57)],
            &[(0, 0), (50, 0), (50, 10), (10, 10), (10, 45), (0, 45)],
            &[
                (0, 0),
                (60, 0),
                (60, 40),
                (45, 40),
                (45, 12),
                (15, 12),
                (15, 40),
                (0, 40),
            ],
        ];
        let mut stack: Vec<Cell> = Vec::new();
        for region in regions {
            let (xs, ys) = ring(region);
            let bbox = region.iter().fold(Bbox::EMPTY, |b, &(x, y)| {
                b.include(Dbu::new_unchecked(x), Dbu::new_unchecked(y))
            });
            for count in [1usize, 3, 20, 90] {
                let taps = random_taps(&mut draw, count, 80);
                let mut grid = TapGrid::default();
                TapGrid::build_into(&taps, &mut grid);
                let want = brute_furthest(&xs, &ys, bbox, &taps);
                for floor in [DbuArea::new(0), want, DbuArea::new(want.raw() + 1)] {
                    let (at, worst) = furthest_from_taps(&xs, &ys, bbox, floor, &grid, &mut stack);
                    assert_eq!(
                        worst,
                        want.max(floor),
                        "{region:?}, {count} taps, floor {floor:?}"
                    );
                    if want > floor {
                        assert!(
                            point_in_region(&xs, &ys, at),
                            "{at:?} is outside {region:?}"
                        );
                        assert_eq!(brute_nearest(&taps, at), want, "{at:?} is not that far");
                    }
                }
            }
        }
    }

    /// Membership, boundary included, of a rectangle, an L, and a
    /// triangle with a sloped edge, at every integer point around them.
    ///
    /// Oracle: closed form: the rectangle is `0 <= x <= 20, 0 <= y <= 10`;
    /// the L is that rectangle with `x > 8, y > 4` cut away; the triangle
    /// `(0,0) (12,0) (0,12)` is `x >= 0, y >= 0, x + y <= 12`, either way
    /// round. Fewer than three vertices is no region.
    #[test]
    fn point_in_region_is_the_closed_set_of_each_shape() {
        let rect = ring(&[(0, 0), (20, 0), (20, 10), (0, 10)]);
        let l = ring(&[(0, 0), (20, 0), (20, 4), (8, 4), (8, 10), (0, 10)]);
        let tri = ring(&[(0, 0), (12, 0), (0, 12)]);
        let tri_cw = ring(&[(0, 0), (0, 12), (12, 0)]);
        for x in -3..=23 {
            for y in -3..=14 {
                let p = pt(x, y);
                let in_rect = (0..=20).contains(&x) && (0..=10).contains(&y);
                assert_eq!(
                    point_in_region(&rect.0, &rect.1, p),
                    in_rect,
                    "rect {x},{y}"
                );
                let in_l = in_rect && !(x > 8 && y > 4);
                assert_eq!(point_in_region(&l.0, &l.1, p), in_l, "L {x},{y}");
                let in_tri = x >= 0 && y >= 0 && x + y <= 12;
                assert_eq!(point_in_region(&tri.0, &tri.1, p), in_tri, "tri {x},{y}");
                assert_eq!(
                    point_in_region(&tri_cw.0, &tri_cw.1, p),
                    in_tri,
                    "cw {x},{y}"
                );
            }
        }
        let two = ring(&[(0, 0), (5, 5)]);
        assert!(!point_in_region(&two.0, &two.1, pt(0, 0)));
    }

    /// `isqrt_ceil(a)` is the least `r` with `r² >= a`.
    ///
    /// Oracle: the definition, `(r - 1)² < a <= r²`, over every area to
    /// 10 000 and at a large perfect square and its neighbours.
    #[test]
    fn isqrt_ceil_is_the_least_root_whose_square_covers_the_area() {
        assert_eq!(isqrt_ceil(0), 0);
        for a in (1..=10_000i128).chain([(1 << 60) - 1, 1 << 60, (1 << 60) + 1]) {
            let r = i128::from(isqrt_ceil(a));
            assert!((r - 1) * (r - 1) < a && a <= r * r, "{a} -> {r}");
        }
    }
}
