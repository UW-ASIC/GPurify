//! Latch-up rules beyond the tap distance of `missing_tie`: what a guard ring
//! is tied to, whether one surrounds what it must, how much tie a well has
//! for its channels, which diodes can inject, and tap distances that tighten
//! as a well's neighbours, or an injecting pad junction, close in.
//!
//! Data in: the store, nets, the design intent's supplies. Data out:
//! violations and one run per row.

use crate::drc::rules::{owners_of, LayerRects, SortedRects};
use crate::erc::facts::IntentMap;
use crate::erc::rules::domain::{device_id, push_device};
use crate::erc::rules::reliability::{encloses, narrow_rings};
use crate::erc::rules::supply::{point_in_region, ring_edge, untied_points_by};
use crate::erc::ruleset::RuleHead;
use crate::erc::voltage::NetVoltage;
use crate::erc::{first_vertex, record_run, skip_rows, Design, Scratch};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, SkipReason, Violation, Violations};
use crate::topology::{NetId, TerminalRole};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::{isqrt, point_seg_dist2, seg_seg_dist2, winding_of, Point, Winding};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{prefix, Bbox, GeometryStore, LayerId, PolyId, Qty, ValidatedLayer, Voltage};
use gpurify_geom::{Dbu, DbuArea};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::StrId;

/// A guard ring tied to the rail its type needs: deck kind
/// `guard_ring_bias`, written `guard_ring_bias(ring; power: true | false)`.
///
/// An n-type ring (n-taps in an n-well, `power: true`) collects the
/// electrons a junction injects into the substrate and must sit at the most
/// positive supply: its net must be a declared power supply held at the
/// highest voltage any declared supply is held at. A p-type ring (p-taps in
/// the substrate, `power: false`) collects holes and must sit at the lowest
/// potential: its net must be a declared ground. A row flags every polygon of
/// `ring` on any other net, an undeclared one included. Taps are rings in
/// this sense too, so a row on a tap layer checks GF180MCU's well-tap rules.
/// `ring` must be a conducting layer, whose polygons carry nets. Needs design
/// intent, for which nets are the rails.
///
/// # Limits
///
/// "Most positive" is the highest declared supply of the whole design, not
/// of the ring's own domain.
///
/// Catalog: ERC-D3, ERC-D6 in the [check catalog]. Defined by [GF180MCU]
/// §14.3.4 (the rails of a double guard ring), LU.9 and
/// LU.10 (well taps to the respective highest and lowest potential), IO.1
/// (a2) ("Nwell guard ring shall be connected to the most positive supply")
/// and IO.3 (a2) ("PCOMP guard ring shall be connected to the lowest
/// potential"). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct GuardRingBiasTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons are rings (or taps) of one type.
    pub ring: Vec<LayerId>,
    /// Per row: `true` for an n-type ring (the most positive supply),
    /// `false` for a p-type ring (a ground).
    pub power: Vec<bool>,
}

/// Runs every [`GuardRingBiasTable`] row over every ring polygon.
///
/// `examined` counts ring polygons, holes not counted. A violation sits at
/// the ring polygon's first vertex, on the ring layer. A ring on a supply of
/// the wrong voltage measures that supply's voltage in mV against the one it
/// needs (the highest supply's for an n-type ring, which it is below; 0 V
/// for a p-type ring, which it is above); a ring on no declared supply
/// measures the count of supplies it is on, 0, against 1. Every row is
/// skipped without usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_guard_ring_bias(
    design: Design<'_>,
    intent: &IntentMap,
    table: &GuardRingBiasTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let (store, nets) = (design.store, design.nets);
    let highest = (0..intent.supply_net.len())
        .filter(|&row| intent.supply_role[row] == SupplyRole::Power)
        .map(|row| intent.held_at(row).raw())
        .fold(f64::NEG_INFINITY, f64::max);
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let ring_layer = table.ring[row];
        let mut examined = 0u64;
        for poly in store.polys_on_layer(ring_layer) {
            let ring = PolyId(poly);
            if nets.holes.is_hole(ring) {
                continue;
            }
            examined += 1;
            let net = nets.net_of(ring);
            // `NetId::NONE` is no supply.
            let supply = intent
                .supply(net)
                .map(|(role, _)| (role, intent.nominal_voltage(net).map_or(0.0, Qty::raw)));
            let volts = |mv: f64| Measurement::Voltage(Qty::<Voltage, { prefix::MILLI }>::new(mv));
            // With no power supply declared, an n-type ring has none to sit at.
            let finding = match (table.power[row], supply) {
                (true, Some((_, held))) if highest.is_finite() => {
                    Some((volts(held), volts(highest), LimitSense::Minimum))
                }
                (false, Some((SupplyRole::Ground, _))) => None,
                (false, Some((SupplyRole::Power, held))) => {
                    Some((volts(held), volts(0.0), LimitSense::Maximum))
                }
                _ => Some((
                    Measurement::Count(0),
                    Measurement::Count(1),
                    LimitSense::Minimum,
                )),
            };
            if let Some((measured, limit, sense)) = finding {
                if measured.violates(limit, sense) {
                    out.push(Violation {
                        rule,
                        layer: ring_layer,
                        severity,
                        at: first_vertex(store, ring),
                        measured,
                        limit,
                        shapes: (ring, None),
                    });
                }
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Tie area against the channel area that injects substrate current: deck
/// kind `tie_area`, written `tie_area(region, contact, channel; min_ratio:
/// frac)`.
///
/// Within each figure of the merged `region` layer (a well, or a guard
/// ring), the area of `contact` (the tap contacts) over the area of
/// `channel` (where substrate current is generated: the gates, poly over
/// active) must be at least `min_ratio`. GF180MCU LU.7 asks for 3% of tap
/// contact area to the channel area generating substrate current; IO.2 and
/// IO.4 ask for 5% of contact area to a guard ring's active area, which is
/// the ring written as both `region` and `channel`. Overlapping shapes count
/// once, and only what lies inside the figure counts. A figure with no
/// channel area injects nothing and is not examined. Needs no design intent.
///
/// Catalog: ERC-D1b in the [check catalog]. Defined by [GF180MCU] LU.7, IO.2
/// and IO.4; [ESDA TR18.0-02] Annex A. Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TieAreaTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose merged figures are each checked.
    pub region: Vec<LayerId>,
    /// Per row: the tie (tap contact) layer.
    pub contact: Vec<LayerId>,
    /// Per row: the layer of what injects substrate current.
    pub channel: Vec<LayerId>,
    /// Per row: the least contact area per channel area, a fraction.
    pub min_ratio: Vec<f64>,
}

/// `layer` validated and merged into disjoint figures, through `drawn`;
/// `None` when it will not validate or merge.
fn merged_into(
    store: &GeometryStore,
    layer: LayerId,
    drawn: &mut ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Option<()> {
    validate_layer_into(store, layer, drawn).ok()?;
    union_into(drawn, &ValidatedLayer::default(), out).ok()
}

/// Every rectangle of `layer` merged, disjoint, for clipped-area sums; `None`
/// when it will not validate or merge.
fn area_index(store: &GeometryStore, layer: LayerId) -> Option<SortedRects<()>> {
    let (mut drawn, mut figures) = (ValidatedLayer::default(), ValidatedLayer::default());
    merged_into(store, layer, &mut drawn, &mut figures)?;
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(&figures, &mut rects, &mut start);
    Some(SortedRects::new(
        rects.into_iter().map(|r| (r, ())).collect(),
    ))
}

/// The area of `index` inside the disjoint rectangles `figure`, exactly.
fn area_within(index: &SortedRects<()>, figure: &[Bbox]) -> i128 {
    figure
        .iter()
        .flat_map(|&r| index.overlapping(r))
        .map(|(piece, ())| piece.area().raw())
        .sum()
}

/// Runs every [`TieAreaTable`] row over every merged region figure.
///
/// `examined` counts figures with channel area. A violation sits at the
/// first vertex of the lowest drawn polygon under the figure, on the region
/// layer, measuring the contact-to-channel ratio against `min_ratio`. A row
/// is refused when one of its layers will not validate or merge.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
#[allow(clippy::cast_precision_loss, reason = "an area ratio, a fraction")]
pub fn check_tie_area(
    design: Design<'_>,
    table: &TieAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let store = design.store;
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let region = table.region[row];
        let indexed = (
            area_index(store, table.contact[row]),
            area_index(store, table.channel[row]),
        );
        let (Some(contact), Some(channel), Some(())) = (
            indexed.0,
            indexed.1,
            merged_into(store, region, &mut scratch.layer_a, &mut scratch.layer_b),
        ) else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };
        let mut drawn = LayerRects::default();
        drawn.build(store, region, &scratch.layer_a);
        let owners = owners_of(&scratch.layer_b, &drawn);
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(&scratch.layer_b, &mut rects, &mut start);
        let limit = Measurement::Ratio(table.min_ratio[row]);
        let mut examined = 0u64;
        for (figure, span) in start.windows(2).enumerate() {
            let pieces = &rects[span[0] as usize..span[1] as usize];
            let injecting = area_within(&channel, pieces);
            if injecting == 0 {
                continue;
            }
            examined += 1;
            let tied = area_within(&contact, pieces);
            let measured = Measurement::Ratio(tied as f64 / injecting as f64);
            let owner = owners[figure];
            if owner != PolyId(u32::MAX) && measured.violates(limit, LimitSense::Minimum) {
                out.push(Violation {
                    rule,
                    layer: region,
                    severity,
                    at: first_vertex(store, owner),
                    measured,
                    limit,
                    shapes: (owner, None),
                });
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// A target a guard ring surrounds: deck kind `guard_ring`, written
/// `guard_ring(target, ring; max_space: len | none, min_width: len | none,
/// pad: layer | none, near: layer | none, within: len | none)`.
///
/// Every selected polygon of `target` must lie in a hole of one figure of the
/// merged `ring` layer, a closed ring round it: the target's whole outline in
/// the hole, and no corner of the hole inside the target. With `max_space`,
/// the ring's inner edge is no further than that from the target on any side:
/// the largest of the four gaps between the target's box and the box of the
/// innermost hole round it. With `min_width`, that ring is no narrower than
/// that anywhere, measured as `width` measures it. Every target is selected,
/// unless one of two conditions leaves it out: with `pad`, only a target on a
/// net that holds a polygon of `pad` (a diffusion directly connected to an
/// I/O pad; `target` must then conduct); with `near` and `within`, only a
/// target with a polygon of `near` no further than `within` from it. With
/// `clear`, the ring must directly surround the target: the innermost hole
/// round it may hold no area of the `clear` layer outside the target itself.
/// Needs no design intent.
///
/// So GF180MCU IO.1 (a2) and IO.2 are `guard_ring(ncomp_in_psub, nwell_ring;
/// max_space: 15um, min_width: 2um, pad: pad, ..)`, IO.3 (a2) and IO.4 the
/// same for p-diffusion in an n-well, LU.5 `guard_ring(nat, psub_ring; near:
/// nwell, within: 50um, clear: ncomp_or_nwell, ..)` ("NAT layer shall be
/// directly surrounded by PCOMP substrate guard ring. (No other NCOMP, NWELL
/// in between the NAT and PCOMP guard ring)", `ncomp_or_nwell` a derived
/// `ncomp or nwell`), and §14.3.3's forward-biased diodes, once
/// marked, `guard_ring(marked_diode, nwell_ring; ..)`. §14.3.4's double
/// guard ring round high-voltage devices is two rows, `guard_ring(hv,
/// nwell_ring; ..)` and `guard_ring(hv, psub_ring; ..)`, with
/// [`GuardRingBiasTable`] tying each ring to its rail.
///
/// # Limits
///
/// The space is box to box: exact for a rectangular target in a rectangular
/// hole, over-reported for other shapes. The hole `clear` reads is the hole's
/// box less its ring: exact unless another hole of the same ring figure lies
/// in that box, which can only over-report.
///
/// Catalog: ERC-D2, ERC-D6, ERC-D7, ERC-D8 in the [check catalog]. Defined
/// by
/// [GF180MCU] IO.1-IO.4, LU.5, §14.3.3 and §14.3.4 (a double guard ring
/// between high- and low-voltage devices); [IHP SG13G2] §7.2.1;
/// [ESDA TR18.0-02] §3.1.2. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
#[derive(Debug, Default, Clone, PartialEq)]
pub struct GuardRingTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons must be surrounded.
    pub target: Vec<LayerId>,
    /// Per row: the ring layer, merged.
    pub ring: Vec<LayerId>,
    /// Per row: the largest gap from a target to its ring, database units.
    pub max_space: Vec<Option<Dbu>>,
    /// Per row: the narrowest a surrounding ring may be, database units.
    pub min_width: Vec<Option<Dbu>>,
    /// Per row: the pad layer whose nets select targets; `None` selects all.
    pub pad: Vec<Option<LayerId>>,
    /// Per row: the layer, and the distance, a target must be near to be
    /// selected; `None` selects all.
    pub near: Vec<Option<(LayerId, Dbu)>>,
    /// Per row: the layer that may have no area between a target and its
    /// ring; `None` leaves the hole unread.
    pub clear: Vec<Option<LayerId>>,
}

/// What a `clear` row reads: the `clear` layer's merged rectangles labelled
/// by figure, every ring figure's rectangles, and the target layer's drawn
/// rectangles.
struct ClearIndex {
    clear: SortedRects<u32>,
    ring_rects: Vec<Bbox>,
    ring_start: Vec<u32>,
    targets: LayerRects,
    first_target: u32,
}

impl ClearIndex {
    /// `None` when the clear or target layer will not validate or merge.
    fn new(
        store: &GeometryStore,
        clear: LayerId,
        target: LayerId,
        rings: &ValidatedLayer,
    ) -> Option<Self> {
        let (mut drawn, mut merged) = (ValidatedLayer::default(), ValidatedLayer::default());
        merged_into(store, clear, &mut drawn, &mut merged)?;
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(&merged, &mut rects, &mut start);
        let labelled = start
            .windows(2)
            .zip(0u32..)
            .flat_map(|(span, f)| {
                rects[span[0] as usize..span[1] as usize]
                    .iter()
                    .map(move |&r| (r, f))
            })
            .collect();
        let (mut ring_rects, mut ring_start) = (Vec::new(), Vec::new());
        decompose_into(rings, &mut ring_rects, &mut ring_start);
        validate_layer_into(store, target, &mut drawn).ok()?;
        let mut targets = LayerRects::default();
        targets.build(store, target, &drawn);
        Some(ClearIndex {
            clear: SortedRects::new(labelled),
            ring_rects,
            ring_start,
            targets,
            first_target: store.polys_on_layer(target).start,
        })
    }

    /// The `clear` figures with area in `hole` (a box of ring figure
    /// `figure`) off that figure and off `target`: the hole's area, less the
    /// ring's within the box, less the target's, which lies in the hole.
    fn between(&self, hole: Bbox, figure: usize, target: PolyId) -> u32 {
        let mut area: Vec<(u32, i128)> = Vec::new();
        let mut add = |r: Bbox, sign: i128| {
            for (piece, f) in self.clear.overlapping(r) {
                let a = sign * piece.area().raw();
                match area.iter_mut().find(|e| e.0 == f) {
                    Some(e) => e.1 += a,
                    None => area.push((f, a)),
                }
            }
        };
        add(hole, 1);
        let span = self.ring_start[figure] as usize..self.ring_start[figure + 1] as usize;
        for &r in &self.ring_rects[span] {
            if let Some(r) = r.intersection(hole) {
                add(r, -1);
            }
        }
        let poly = self.targets.poly_of_row[(target.0 - self.first_target) as usize];
        for &r in self.targets.of(poly) {
            add(r, -1);
        }
        u32::try_from(area.iter().filter(|e| e.1 > 0).count()).expect("figures fit a u32")
    }
}

/// The counter-clockwise rows of `layer`: its polygons, not their holes.
fn outers(store: &GeometryStore, layer: LayerId) -> impl Iterator<Item = PolyId> + '_ {
    store.polys_on_layer(layer).map(PolyId).filter(|&poly| {
        let (xs, ys) = store.poly_verts(poly);
        winding_of(xs, ys) != Some(Winding::Clockwise)
    })
}

/// Squared distance between two polygons' outlines, zero when they touch or
/// one lies in the other.
pub(crate) fn poly_dist2(store: &GeometryStore, a: PolyId, b: PolyId) -> DbuArea {
    let ((ax, ay), (bx, by)) = (store.poly_verts(a), store.poly_verts(b));
    let first = |xs: &[Dbu], ys: &[Dbu]| Point { x: xs[0], y: ys[0] };
    if point_in_region(bx, by, first(ax, ay)) || point_in_region(ax, ay, first(bx, by)) {
        return DbuArea::new(0);
    }
    let mut best = DbuArea::new(i128::MAX);
    for i in 0..ax.len() {
        let edge = ring_edge(ax, ay, i);
        for j in 0..bx.len() {
            best = best.min(seg_seg_dist2(edge, ring_edge(bx, by, j)));
        }
    }
    best
}

/// Whether the hole `(hx, hy)` surrounds the polygon `(tx, ty)`: every vertex
/// of the polygon in or on the hole, and no vertex of the hole strictly
/// inside the polygon (a rectilinear hole's corner poking in).
fn surrounds(hole: (&[Dbu], &[Dbu]), target: (&[Dbu], &[Dbu])) -> bool {
    let ((hx, hy), (tx, ty)) = (hole, target);
    let zero = DbuArea::new(0);
    let on_target =
        |p: Point| (0..tx.len()).any(|i| point_seg_dist2(p, ring_edge(tx, ty, i)) == zero);
    (0..tx.len()).all(|i| point_in_region(hx, hy, Point { x: tx[i], y: ty[i] }))
        && (0..hx.len()).all(|i| {
            let p = Point { x: hx[i], y: hy[i] };
            !point_in_region(tx, ty, p) || on_target(p)
        })
}

/// The box of a ring's columns.
fn ring_box(xs: &[Dbu], ys: &[Dbu]) -> Bbox {
    xs.iter()
        .zip(ys)
        .fold(Bbox::EMPTY, |b, (&x, &y)| b.include(x, y))
}

/// Runs every [`GuardRingTable`] row over every selected target.
///
/// `examined` counts selected targets. A target no ring surrounds is a
/// violation at its first vertex, on the target layer, measuring the count of
/// rings round it, 0, against 1; one too far from its ring measures the
/// largest gap against `max_space`; one whose hole holds `clear` area measures
/// the count of `clear` figures with area there against 0. A surrounding ring narrower than
/// `min_width` is one violation at the first vertex of the lowest drawn
/// polygon under it, on the ring layer, measuring its narrowest band. A row
/// is refused when its ring, `clear` or target layer will not validate or
/// merge.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_guard_ring(
    design: Design<'_>,
    table: &GuardRingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (store, nets) = (design.store, design.nets);
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let (target_layer, ring_layer) = (table.target[row], table.ring[row]);
        // Below one unit no band is narrower: nothing is reported.
        let floor = table.min_width[row].unwrap_or(Dbu::new_unchecked(1));
        let Some(narrow) = narrow_rings(design, ring_layer, floor, scratch) else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };
        let mut drawn = LayerRects::default();
        drawn.build(store, ring_layer, &scratch.layer_a);
        let owners = owners_of(&scratch.layer_b, &drawn);
        let figures = &scratch.layer_b;
        let selected: Option<Vec<NetId>> = table.pad[row].map(|pad| pad_nets(design, pad));
        let near: Option<(Vec<PolyId>, Dbu)> =
            table.near[row].map(|(layer, within)| (outers(store, layer).collect(), within));
        let clear = match table.clear[row] {
            None => None,
            Some(layer) => {
                let Some(index) = ClearIndex::new(store, layer, target_layer, &scratch.layer_b)
                else {
                    record_run(runs, out, before, rule, Outcome::Refused, 0);
                    continue;
                };
                Some(index)
            }
        };
        let mut reported: Vec<usize> = Vec::new();
        let mut examined = 0u64;
        for target in outers(store, target_layer) {
            if let Some(pads) = &selected {
                if pads.is_empty() || pads.binary_search(&nets.net_of(target)).is_err() {
                    continue;
                }
            }
            if let Some((polys, within)) = &near {
                let reach = within.mul_wide(*within);
                let tb = store.poly_bbox(target);
                let close = polys.iter().any(|&p| {
                    store.poly_bbox(p).within(tb, *within) && poly_dist2(store, target, p) <= reach
                });
                if !close {
                    continue;
                }
            }
            examined += 1;
            let (tx, ty) = store.poly_verts(target);
            let tb = store.poly_bbox(target);
            // The innermost hole round the target.
            let mut best: Option<(usize, Bbox)> = None;
            for f in 0..figures.len() {
                let figure = figures.get(u32::try_from(f).expect("a figure index is a u32"));
                if !figure.bbox().contains(tb) {
                    continue;
                }
                for hole in figure.holes() {
                    let (hx, hy) = hole.coords();
                    let hb = ring_box(hx, hy);
                    let inner = best.is_none_or(|(_, b)| hb.area() < b.area());
                    if inner && hb.contains(tb) && surrounds((hx, hy), (tx, ty)) {
                        best = Some((f, hb));
                    }
                }
            }
            let at = first_vertex(store, target);
            let mut push = |layer, at, shape, measured, limit| {
                out.push(Violation {
                    rule,
                    layer,
                    severity,
                    at,
                    measured,
                    limit,
                    shapes: (shape, None),
                });
            };
            let Some((figure, hole)) = best else {
                push(
                    target_layer,
                    at,
                    target,
                    Measurement::Count(0),
                    Measurement::Count(1),
                );
                continue;
            };
            if let Some(index) = &clear {
                let between = index.between(hole, figure, target);
                if between > 0 {
                    push(
                        target_layer,
                        at,
                        target,
                        Measurement::Count(between),
                        Measurement::Count(0),
                    );
                }
            }
            if let Some(max_space) = table.max_space[row] {
                let gap = (tb.xlo - hole.xlo)
                    .max(hole.xhi - tb.xhi)
                    .max(tb.ylo - hole.ylo)
                    .max(hole.yhi - tb.yhi);
                let (measured, limit) = (Measurement::Length(gap), Measurement::Length(max_space));
                if measured.violates(limit, LimitSense::Maximum) {
                    push(target_layer, at, target, measured, limit);
                }
            }
            let owner = owners[figure];
            let band = narrow.binary_search_by_key(&owner, |&(o, _)| o);
            if let (Some(min_width), Ok(k), false) =
                (table.min_width[row], band, reported.contains(&figure))
            {
                reported.push(figure);
                let ring_at = first_vertex(store, owner);
                push(
                    ring_layer,
                    ring_at,
                    owner,
                    Measurement::Length(narrow[k].1),
                    Measurement::Length(min_width),
                );
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// A diode that can be forward-biased, marked for the I/O latch-up rules:
/// deck kind `forward_diode`, written `forward_diode(marker; models:
/// models)`.
///
/// A diode of a listed model whose anode can rise above its cathode (the
/// highest voltage the declared supplies give its anode's net, through device
/// channels, above the lowest they give its cathode's: [`NetVoltage`]) is
/// forward-biased in some state of the circuit, and a forward-biased junction
/// injects the carriers that trigger latch-up. GF180MCU §14.3.3: such a
/// diode "must be marked by `Latchup_MK` layer and it shall be surrounded by
/// N+/Nwell guard rings". A row flags such a diode whose marker polygon no
/// one polygon of `marker` covers; [`GuardRingTable`] checks the rings round
/// the marked ones. A diode whose anode or cathode no supply reaches is not
/// examined. Needs design intent.
///
/// # Limits
///
/// Voltages reach a net through every channel whatever its gate, so a diode
/// can be flagged as forward-biased in a state the circuit never enters.
///
/// Catalog: ERC-D8 in the [check catalog]. Defined by [GF180MCU] §14.3.2
/// (a) and §14.3.3. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ForwardDiodeTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the marker layer (`Latchup_MK`) a forward-biased diode must
    /// lie under.
    pub marker: Vec<LayerId>,
    /// Diode models per row, CSR.
    pub model_start: Vec<u32>,
    /// Diode models, CSR by `model_start`; at least one per row.
    pub model: Vec<StrId>,
}

/// Runs every [`ForwardDiodeTable`] row over every diode of its models.
///
/// `examined` counts diodes whose anode and cathode some supply reaches. A
/// violation sits at the first vertex of the diode's marker, on the marker
/// layer, measuring the largest forward bias, mV, against 0. Every row is
/// skipped without usable intent, and refused when its marker layer will not
/// validate.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_forward_diode(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ForwardDiodeTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let (store, devices) = (design.store, design.devices);
    let mut layer = ValidatedLayer::default();
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let models =
            &table.model[table.model_start[row] as usize..table.model_start[row + 1] as usize];
        if validate_layer_into(store, table.marker[row], &mut layer).is_err() {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        decompose_into(&layer, &mut rects, &mut start);
        let limit = Measurement::Voltage(Qty::new(0.0));
        let mut examined = 0u64;
        for index in 0..devices.len() {
            if devices.kind[index] != DeviceKind::Diode || !models.contains(&devices.model[index]) {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(index));
            let pin = |k: u8| {
                roles
                    .iter()
                    .position(|&role| role == TerminalRole::Pin(k))
                    .map_or(NetId::NONE, |at| nets[at])
            };
            let (anode, cathode) = (pin(0), pin(1));
            if !(voltage.known(anode) && voltage.known(cathode)) {
                continue;
            }
            examined += 1;
            let forward = voltage.hi[anode.idx()] - voltage.lo[cathode.idx()];
            let measured = Measurement::Voltage(Qty::new(forward));
            let marked = encloses(&rects, &start, store.poly_bbox(devices.marker[index]));
            if !marked && measured.violates(limit, LimitSense::Maximum) {
                push_device(design, index, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// A tap distance that tightens as a neighbouring well closes in: deck kind
/// `conditional_tie`, written `conditional_tie(region, tap, well, other;
/// within: len, spacing: [len, ..], max_distance: [len, ..])`.
///
/// For each polygon of `region` (PCOMP inside an n-well, say), `x` is the
/// least distance from a polygon of `other` (NCOMP outside the n-well) that
/// lies within `within` of the region to any polygon of `well`: how close
/// the parasitic bipolar's other junction sits to the well. The `spacing`
/// thresholds, ascending, split `x` into bands, and the region is held to the
/// band's tap distance as `missing_tie` measures it: below the first
/// threshold `max_distance[0]`, from the first to below the second
/// `max_distance[1]`, and so on, with one more limit than thresholds. With no
/// `other` polygon within `within`, the last (loosest) limit applies. Needs no
/// design intent.
///
/// GF180MCU LU.1-LU.4 are four rows of it: for example LU.4 (PCOMP in an
/// n-well, `y` the space from the n-well to NCOMP outside it within 50 µm)
/// is `conditional_tie(pcomp_in_nwell, nwell_tap, nwell, ncomp_outside_nwell;
/// within: 50um, spacing: [1um, 2um], max_distance: [15um, 30um, 50um])` for
/// LV devices.
///
/// # Limits
///
/// `x` is measured to any `well` polygon, not only the one holding the
/// region, which can only pick a tighter band.
///
/// Catalog: ERC-D1a in the [check catalog]. Defined by [GF180MCU] LU.1-LU.4.
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ConditionalTieTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons must be tied.
    pub region: Vec<LayerId>,
    /// Per row: the tap layer.
    pub tap: Vec<LayerId>,
    /// Per row: the well the neighbour's space is measured to.
    pub well: Vec<LayerId>,
    /// Per row: the neighbouring junctions.
    pub other: Vec<LayerId>,
    /// Per row: how near a region a neighbour counts, database units.
    pub within: Vec<Dbu>,
    /// Thresholds per row, CSR.
    pub spacing_start: Vec<u32>,
    /// Band thresholds, ascending, CSR by `spacing_start`.
    pub spacing: Vec<Dbu>,
    /// Limits per row, CSR; one more per row than `spacing`.
    pub max_distance_start: Vec<u32>,
    /// Each band's tap distance, CSR by `max_distance_start`.
    pub max_distance: Vec<Dbu>,
}

/// Runs every [`ConditionalTieTable`] row over every region polygon.
///
/// `examined` counts region polygons. A violation sits at the region's
/// furthest point from a tap, on the region layer, measuring that distance
/// (rounded down to a database unit) against its band's limit. A row is
/// refused when its tap layer will not validate.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_conditional_tie(
    design: Design<'_>,
    table: &ConditionalTieTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let store = design.store;
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let span = |start: &[u32]| start[row] as usize..start[row + 1] as usize;
        let spacing = &table.spacing[span(&table.spacing_start)];
        let limits = &table.max_distance[span(&table.max_distance_start)];
        let within = table.within[row];
        let within2 = within.mul_wide(within);
        let others: Vec<PolyId> = outers(store, table.other[row]).collect();
        let wells: Vec<PolyId> = outers(store, table.well[row]).collect();
        // ponytail: every neighbour against every well per region; a spatial
        // index if layouts grow large.
        let limit_of = |region: PolyId| {
            let rb = store.poly_bbox(region);
            let nearest = others
                .iter()
                .filter(|&&o| {
                    store.poly_bbox(o).within(rb, within) && poly_dist2(store, region, o) <= within2
                })
                .flat_map(|&o| wells.iter().map(move |&w| poly_dist2(store, o, w)))
                .min();
            let band = nearest.map_or(spacing.len(), |x| {
                spacing.iter().filter(|t| t.mul_wide(**t) <= x).count()
            });
            Some(limits[band])
        };
        let examined = untied_points_by(
            store,
            (table.region[row], table.tap[row]),
            limit_of,
            &mut scratch.layer_b,
            |poly, at, worst, limit| {
                out.push(Violation {
                    rule,
                    layer: store.poly_layer(poly),
                    severity,
                    at,
                    measured: Measurement::Length(isqrt(worst)),
                    limit: Measurement::Length(limit),
                    shapes: (poly, None),
                });
            },
        );
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// The pad nets: every net that holds a polygon of `pad`, ascending; none on
/// a design never extracted, where no polygon has a net to ask for.
pub(crate) fn pad_nets(design: Design<'_>, pad: LayerId) -> Vec<NetId> {
    if design.nets.net_count() == 0 {
        return Vec::new();
    }
    let mut on: Vec<NetId> = design
        .store
        .polys_on_layer(pad)
        .map(|poly| design.nets.net_of(PolyId(poly)))
        .filter(|&net| net != NetId::NONE)
        .collect();
    on.sort_unstable();
    on.dedup();
    on
}

/// A victim near an injecting junction, held to a tighter tap distance: deck
/// kind `latchup_victim`, written `latchup_victim(aggressor, region, tap;
/// within: len, max_distance: len, pad: layer | none, bias: layer | none,
/// forward: above | below | none)`.
///
/// An aggressor is a junction that can inject carriers into the substrate: a
/// polygon of `aggressor`, and with `pad` only one on a net that holds a
/// polygon of `pad` (a diffusion directly connected to an I/O pad, which an
/// off-chip load drives above the supply or below ground). A victim is a
/// polygon of `region` within `within` of an aggressor, whatever its own net,
/// and must have every point within `max_distance` of a `tap`, measured as
/// `missing_tie` measures it. A region farther from every aggressor is not
/// examined. Needs no design intent.
///
/// GF180MCU IO.1 (b): "Within 15um from the edge of the NCOMP connected to
/// I/O pad (marked by `Latchup_MK`): Max Nwell tap distance to PCOMP inside
/// Nwell (irrespective of its direct connection to Pad)" 2 µm, is
/// `latchup_victim(ncomp, pcomp_in_nwell, nwell_tap; within: 15um,
/// max_distance: 2um, pad: pad)`; IO.3 (b) is 10 µm and 5 µm the other way
/// round.
///
/// With `bias` and `forward`, an aggressor is chosen by voltage as well: a
/// junction can inject only when the voltages the intent propagates can
/// forward-bias it against the polygon of `bias` it lies in, the well or
/// substrate tie under it. `forward: above` (a P+ diffusion in an N-well)
/// takes an aggressor whose net can rise above the lowest voltage the
/// bias polygon's net sits at, `below` (an N+ diffusion in the substrate)
/// one whose net can fall below the highest. GF180MCU §14.3.2: "I/O
/// regions are more susceptible to latch-up because of over voltage (P+
/// COMP potential exceeding Vdd) and under voltage (N+ COMP potential below
/// Ground)"; the open CVC checker's "minimum source voltage for an n-mosfet
/// is less than its maximum bulk voltage". An aggressor on a net no supply
/// reaches, or in no bias polygon, is not chosen. A row with `bias` needs
/// design intent and is skipped without it.
///
/// # Limits
///
/// The whole victim polygon is held to the limit, not only its part within
/// `within`. Voltages are [`NetVoltage`]'s: the declared supplies'
/// spans through channels, so an injection from off-chip (a pad driven
/// past the rails) is the `pad` selection's, not the voltage's.
///
/// Catalog: ERC-D5 in the [check catalog]. Defined by [ESDA TR18.0-02]
/// §2.2.3 (voltage-aware aggressors and victims; its table of contents);
/// [GF180MCU] §14.3.2, IO.1 (b) and IO.3 (b); [CVC] (forward-biased
/// junctions from propagated minimum and maximum voltages); Calibre PERC
/// (public material only). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [CVC]: https://woset-workshop.github.io/PDFs/2020/a05.pdf
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LatchupVictimTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the injecting junctions.
    pub aggressor: Vec<LayerId>,
    /// Per row: the layer whose polygons near an aggressor are victims.
    pub region: Vec<LayerId>,
    /// Per row: the tap layer.
    pub tap: Vec<LayerId>,
    /// Per row: how near an aggressor a region is a victim, database units.
    pub within: Vec<Dbu>,
    /// Per row: a victim's tap distance, database units.
    pub max_distance: Vec<Dbu>,
    /// Per row: the pad layer whose nets select aggressors; `None` takes
    /// every aggressor polygon.
    pub pad: Vec<Option<LayerId>>,
    /// Per row: the layer an aggressor's junction sits in (its well or tie),
    /// and whether the junction injects when its net rises above that
    /// polygon's (`true`, a P+ in an N-well) or falls below it (an N+ in the
    /// substrate); `None` takes every aggressor polygon.
    pub bias: Vec<Option<(LayerId, bool)>>,
}

/// Runs every [`LatchupVictimTable`] row over every region polygon.
///
/// `examined` counts victims. A violation sits at the victim's furthest point
/// from a tap, on the region layer, measuring that distance (rounded down to
/// a database unit) against `max_distance`. A row is refused when its tap
/// layer will not validate.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_latchup_victim(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &LatchupVictimTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (store, nets) = (design.store, design.nets);
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        if table.bias[row].is_some() && !intent.is_usable() {
            let skipped = Outcome::Skipped(SkipReason::NoDesignIntent);
            record_run(runs, out, before, rule, skipped, 0);
            continue;
        }
        let pads = table.pad[row].map(|pad| pad_nets(design, pad));
        // The bias polygon an aggressor lies in, and whether its net can
        // forward-bias the junction against that polygon's.
        let injects = |poly: PolyId| -> bool {
            let Some((layer, above)) = table.bias[row] else {
                return true;
            };
            let net = nets.net_of(poly);
            if !voltage.known(net) {
                return false;
            }
            let (px, py) = store.poly_verts(poly);
            let pb = store.poly_bbox(poly);
            outers(store, layer).any(|bias| {
                let (bx, by) = store.poly_verts(bias);
                let well = nets.net_of(bias);
                store.poly_bbox(bias).contains(pb)
                    && surrounds((bx, by), (px, py))
                    && voltage.known(well)
                    && if above {
                        voltage.hi[net.idx()] > voltage.lo[well.idx()]
                    } else {
                        voltage.lo[net.idx()] < voltage.hi[well.idx()]
                    }
            })
        };
        let aggressors: Vec<PolyId> = outers(store, table.aggressor[row])
            .filter(|&poly| {
                pads.as_ref().is_none_or(|pads| {
                    !pads.is_empty() && pads.binary_search(&nets.net_of(poly)).is_ok()
                })
            })
            .filter(|&poly| injects(poly))
            .collect();
        let (within, limit) = (table.within[row], table.max_distance[row]);
        let within2 = within.mul_wide(within);
        let limit_of = |region: PolyId| {
            let rb = store.poly_bbox(region);
            aggressors
                .iter()
                .any(|&a| {
                    store.poly_bbox(a).within(rb, within) && poly_dist2(store, region, a) <= within2
                })
                .then_some(limit)
        };
        let examined = untied_points_by(
            store,
            (table.region[row], table.tap[row]),
            limit_of,
            &mut scratch.layer_b,
            |poly, at, worst, limit| {
                out.push(Violation {
                    rule,
                    layer: store.poly_layer(poly),
                    severity,
                    at,
                    measured: Measurement::Length(isqrt(worst)),
                    limit: Measurement::Length(limit),
                    shapes: (poly, None),
                });
            },
        );
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
    }
}
