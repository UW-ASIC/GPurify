//! Connectivity + device extraction from layout geometry.

use super::types::*;
use crate::backend::Backend;
use crate::geometry::*;
use crate::params::Deck;
use std::collections::{HashMap, HashSet};

// ponytail: `#[verify_kernel]` (macro + cubecl) removed; these are the plain
// per-element predicate bodies, unchanged. The cross_pairs sweep below runs
// them in a CPU loop. GPU dispatch is staged for phase-2 vulkano.
// `bbox_overlap` had no CPU caller (macro-only) and was dropped.

/// Exact rect-pair positive-area overlap: 1 iff the two rects overlap with
/// positive area (open intervals).
fn rect_overlap(
    a_x0: i32,
    a_y0: i32,
    a_x1: i32,
    a_y1: i32,
    b_x0: i32,
    b_y0: i32,
    b_x1: i32,
    b_y1: i32,
) -> u32 {
    let mut x0 = a_x0;
    if b_x0 > x0 {
        x0 = b_x0;
    }
    let mut y0 = a_y0;
    if b_y0 > y0 {
        y0 = b_y0;
    }
    let mut x1 = a_x1;
    if b_x1 < x1 {
        x1 = b_x1;
    }
    let mut y1 = a_y1;
    if b_y1 < y1 {
        y1 = b_y1;
    }
    let mut f = 0u32;
    if x1 > x0 && y1 > y0 {
        f = 1u32;
    }
    f
}

/// Exact rect-pair touch: 1 iff the two rects touch or overlap (closed
/// intervals).
fn rect_touch(
    a_x0: i32,
    a_y0: i32,
    a_x1: i32,
    a_y1: i32,
    b_x0: i32,
    b_y0: i32,
    b_x1: i32,
    b_y1: i32,
) -> u32 {
    let mut f = 1u32;
    if a_x1 < b_x0 || b_x1 < a_x0 || a_y1 < b_y0 || b_y1 < a_y0 {
        f = 0u32;
    }
    f
}

/// CPU `cross_pairs` driver: for each descriptor `(a0,a1,b0,b1)`, flag 1 iff
/// some rect `a in a0..a1` and `b in b0..b1` satisfy `pred(a, b) != 0`.
/// Replaces the macro-generated `<name>_kernel::run` for the two predicates
/// above (identical result).
fn cross_pairs_flags(
    rx0: &[i32],
    ry0: &[i32],
    rx1: &[i32],
    ry1: &[i32],
    descs: &[(u32, u32, u32, u32)],
    pred: fn(i32, i32, i32, i32, i32, i32, i32, i32) -> u32,
) -> Vec<u32> {
    descs
        .iter()
        .map(|&(a0, a1, b0, b1)| {
            for a in a0..a1 {
                let ai = a as usize;
                for b in b0..b1 {
                    let bi = b as usize;
                    if pred(
                        rx0[ai], ry0[ai], rx1[ai], ry1[ai], rx0[bi], ry0[bi], rx1[bi], ry1[bi],
                    ) != 0
                    {
                        return 1u32;
                    }
                }
            }
            0u32
        })
        .collect()
}

use crate::geometry::rects::decompose_rectilinear;
use gdsverify_core::connectivity::host_union_find;

/// Exact rect predicate over candidate pairs. For each pair, decomposes both
/// polygons into rects and checks if any rect-pair overlaps (or touches, for
/// intra-layer when intra_touch is set). Returns per-pair flags: 1 = connect,
/// 0 = no geometric contact.
// ponytail: `_backend` kept in the signature (callers thread it); the sweep is
// CPU-only now. GPU rect-predicate dispatch is staged for phase-2 vulkano.
fn rect_predicate_flags(
    store: &GeometryStore,
    nodes: &[Node],
    cands: &[(u32, u32)],
    intra_touch: bool,
    _backend: Backend,
) -> Option<Vec<u32>> {
    if cands.len() < (1 << 14) {
        return None;
    }

    // Collect unique polys referenced by candidate nodes; decompose each.
    let mut poly_rects: HashMap<u32, (u32, u32)> = HashMap::new();
    let mut rx0 = Vec::new();
    let mut ry0 = Vec::new();
    let mut rx1 = Vec::new();
    let mut ry1 = Vec::new();

    let mut ensure_decomposed = |poly: PolyId| -> Option<(u32, u32)> {
        if let Some(&range) = poly_rects.get(&poly.0) {
            return Some(range);
        }
        let rects = decompose_rectilinear(store, poly).ok()?;
        let start = rx0.len() as u32;
        for r in &rects {
            rx0.push(r.x0);
            ry0.push(r.y0);
            rx1.push(r.x1);
            ry1.push(r.y1);
        }
        let range = (start, rx0.len() as u32);
        poly_rects.insert(poly.0, range);
        Some(range)
    };

    // Pre-decompose all referenced polys
    for &(i, j) in cands {
        ensure_decomposed(nodes[i as usize].poly)?;
        ensure_decomposed(nodes[j as usize].poly)?;
    }

    // Split candidates into overlap vs touch groups, build cross_pairs descriptors
    let mut overlap_descs: Vec<(u32, u32, u32, u32)> = Vec::new();
    let mut overlap_cand_idx: Vec<usize> = Vec::new();
    let mut touch_descs: Vec<(u32, u32, u32, u32)> = Vec::new();
    let mut touch_cand_idx: Vec<usize> = Vec::new();

    for (ci, &(i, j)) in cands.iter().enumerate() {
        let (i, j) = (i as usize, j as usize);
        let (a0, a1) = poly_rects[&nodes[i].poly.0];
        let (b0, b1) = poly_rects[&nodes[j].poly.0];
        if a0 == a1 || b0 == b1 {
            continue;
        }
        if intra_touch && nodes[i].layer == nodes[j].layer {
            touch_descs.push((a0, a1, b0, b1));
            touch_cand_idx.push(ci);
        } else {
            overlap_descs.push((a0, a1, b0, b1));
            overlap_cand_idx.push(ci);
        }
    }

    let mut flags = vec![0u32; cands.len()];

    if !overlap_descs.is_empty() {
        let of = cross_pairs_flags(&rx0, &ry0, &rx1, &ry1, &overlap_descs, rect_overlap);
        for (k, &ci) in overlap_cand_idx.iter().enumerate() {
            flags[ci] = of[k];
        }
    }
    if !touch_descs.is_empty() {
        let tf = cross_pairs_flags(&rx0, &ry0, &rx1, &ry1, &touch_descs, rect_touch);
        for (k, &ci) in touch_cand_idx.iter().enumerate() {
            flags[ci] = tf[k];
        }
    }
    Some(flags)
}

// --- internal types ---

struct Node {
    bbox: Bbox,
    layer: LayerId,
    is_diff_seg: bool,
    /// Electrical region represented by this node.  Ordinary conductor nodes
    /// use the polygon's full bbox as the clip; split diffusion nodes use the
    /// original diffusion polygon clipped to one source/drain segment.  Keeping
    /// the source polygon here lets the sweep-line remain a bbox prefilter while
    /// the final connectivity decision uses the real rectilinear geometry.
    poly: PolyId,
    clip: Bbox,
}

struct GateSpan {
    gate: u32,
    lo: i32,
    hi: i32,
}

struct DiffSplit {
    diff: u32,
    axis_x: bool,
    seg_nodes: Vec<u32>,
    seg_spans: Vec<(i32, i32)>,
    gates: Vec<GateSpan>,
}

// --- helpers ---

/// Sweep-line enumeration of node pairs whose bboxes touch or overlap (closed
/// test — a superset of both positive-area overlap and boundary contact, which
/// the caller re-applies to the exact polygon regions). Sorts along the axis with the larger bbox-min
/// spread so the look-ahead window stays small: O(m log m + K) vs all-pairs O(m²).
/// Returns pairs as (lo, hi) node indices.
fn node_candidate_pairs(nodes: &[Node]) -> Vec<(u32, u32)> {
    let (mut xlo, mut xhi, mut ylo, mut yhi) = (i32::MAX, i32::MIN, i32::MAX, i32::MIN);
    for n in nodes {
        xlo = xlo.min(n.bbox.xmin);
        xhi = xhi.max(n.bbox.xmin);
        ylo = ylo.min(n.bbox.ymin);
        yhi = yhi.max(n.bbox.ymin);
    }
    let sweep_x = xhi.saturating_sub(xlo) >= yhi.saturating_sub(ylo);
    // (sweep_min, sweep_max, node)
    let mut items: Vec<(i32, i32, u32)> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let b = &n.bbox;
            if sweep_x {
                (b.xmin, b.xmax, i as u32)
            } else {
                (b.ymin, b.ymax, i as u32)
            }
        })
        .collect();
    items.sort_unstable_by_key(|it| it.0);
    let mut out = Vec::new();
    for i in 0..items.len() {
        let (_, hi_i, ni) = items[i];
        for &(_, _, nj) in items[i + 1..].iter().take_while(|it| it.0 <= hi_i) {
            let (ba, bb) = (&nodes[ni as usize].bbox, &nodes[nj as usize].bbox);
            let other_near = if sweep_x {
                ba.ymin <= bb.ymax && bb.ymin <= ba.ymax
            } else {
                ba.xmin <= bb.xmax && bb.xmin <= ba.xmax
            };
            if other_near {
                out.push((ni.min(nj), ni.max(nj)));
            }
        }
    }
    out
}

#[derive(Clone, Copy)]
pub(super) struct PolyRegion {
    poly: PolyId,
    clip: Bbox,
}

pub(super) fn full_region(store: &GeometryStore, poly: PolyId) -> PolyRegion {
    PolyRegion {
        poly,
        clip: store.poly_bbox[poly.0 as usize],
    }
}

fn is_rectilinear(store: &GeometryStore, poly: PolyId) -> bool {
    store.edges_of(poly).all(|e| e.x0 == e.x1 || e.y0 == e.y1)
}

/// Validate geometry on connectivity-relevant layers. Hard errors on degenerate
/// or self-intersecting polygons. Non-rectilinear polygons are collected into
/// `non_rect_polys` and a diagnostic warning is emitted; connectivity will use
/// their bounding box as an approximation.
fn validate_rectilinear_layers(
    store: &GeometryStore,
    deck: &Deck,
    layers: &HashSet<LayerId>,
    non_rect_polys: &mut HashSet<u32>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let mut ordered: Vec<LayerId> = layers.iter().copied().collect();
    ordered.sort_unstable();
    for layer in ordered {
        for poly in store.polys_on_layer(layer) {
            let (s, e) = store.poly_range(poly);
            if e - s < 4 {
                return Err(format!(
                    "polygon {} on '{}' has fewer than four vertices; exact rectilinear LVS cannot process it",
                    poly.0, deck.layers.name(layer),
                ));
            }
            for edge in store.edges_of(poly) {
                if edge.x0 == edge.x1 && edge.y0 == edge.y1 {
                    return Err(format!(
                        "polygon {} on '{}' has a zero-length edge; exact rectilinear LVS cannot process it",
                        poly.0, deck.layers.name(layer),
                    ));
                }
            }
            if !is_rectilinear(store, poly) {
                // ponytail: bbox fallback for non-rectilinear; upgrade to exact
                // all-angle predicates if false-short rate matters.
                non_rect_polys.insert(poly.0);
                warnings.push(format!(
                    "polygon {} on '{}' is non-rectilinear; using bounding-box approximation for connectivity",
                    poly.0, deck.layers.name(layer),
                ));
                continue;
            }
            if store.area(poly) == 0 || poly_self_intersects(store, poly) {
                return Err(format!(
                    "polygon {} on '{}' is degenerate or self-intersecting; LVS extraction stopped",
                    poly.0,
                    deck.layers.name(layer),
                ));
            }
        }
    }
    Ok(())
}

/// Interior y-intervals of a rectilinear polygon at a vertical scan coordinate
/// represented as twice-x.  Callers only pass odd `x2`, so the scan never lies
/// on a polygon vertex and the even/odd pairing is exact.
fn interior_intervals_at_x2(store: &GeometryStore, region: PolyRegion, x2: i64) -> Vec<(i32, i32)> {
    if x2 <= 2 * region.clip.xmin as i64 || x2 >= 2 * region.clip.xmax as i64 {
        return Vec::new();
    }
    let mut crossings = Vec::new();
    for edge in store.edges_of(region.poly) {
        if edge.y0 != edge.y1 {
            continue;
        }
        let lo2 = 2 * edge.x0.min(edge.x1) as i64;
        let hi2 = 2 * edge.x0.max(edge.x1) as i64;
        if lo2 < x2 && x2 < hi2 {
            crossings.push(edge.y0);
        }
    }
    crossings.sort_unstable();
    let mut out = Vec::with_capacity(crossings.len() / 2);
    for ys in crossings.chunks_exact(2) {
        let lo = ys[0].max(region.clip.ymin);
        let hi = ys[1].min(region.clip.ymax);
        if lo < hi {
            out.push((lo, hi));
        }
    }
    out
}

fn intersect_interval_sets(a: &[(i32, i32)], b: &[(i32, i32)]) -> Vec<(i32, i32)> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        let lo = a[i].0.max(b[j].0);
        let hi = a[i].1.min(b[j].1);
        if lo < hi {
            out.push((lo, hi));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// Exact positive intersection area for simple rectilinear polygon regions.
/// Coordinate compression creates x-slabs on which every polygon's vertical
/// cross-section is constant, then intersects the y-interval sets.  `i128`
/// prevents overflow for the full i32 coordinate range.
pub(super) fn rectilinear_intersection_area(store: &GeometryStore, regions: &[PolyRegion]) -> i128 {
    if regions.is_empty() || regions.iter().any(|r| !is_rectilinear(store, r.poly)) {
        return 0;
    }
    let mut xs = Vec::new();
    for region in regions {
        xs.push(region.clip.xmin);
        xs.push(region.clip.xmax);
        let (s, e) = store.poly_range(region.poly);
        xs.extend_from_slice(&store.verts_x[s..e]);
    }
    xs.sort_unstable();
    xs.dedup();

    let mut area = 0i128;
    for pair in xs.windows(2) {
        let (x0, x1) = (pair[0], pair[1]);
        if x0 >= x1 {
            continue;
        }
        let x2 = x0 as i64 + x1 as i64;
        let mut common = interior_intervals_at_x2(store, regions[0], x2);
        for &region in &regions[1..] {
            if common.is_empty() {
                break;
            }
            let next = interior_intervals_at_x2(store, region, x2);
            common = intersect_interval_sets(&common, &next);
        }
        let covered_y: i128 = common.iter().map(|&(lo, hi)| hi as i128 - lo as i128).sum();
        area += (x1 as i128 - x0 as i128) * covered_y;
    }
    area
}

fn merge_closed_intervals(mut intervals: Vec<(i32, i32)>) -> Vec<(i32, i32)> {
    intervals.sort_unstable();
    let mut out: Vec<(i32, i32)> = Vec::new();
    for (lo, hi) in intervals {
        if lo > hi {
            continue;
        }
        if let Some(last) = out.last_mut() {
            if lo <= last.1 {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        out.push((lo, hi));
    }
    out
}

/// Closed vertical slice of a clipped rectilinear polygon at integer `x`.
/// The closure is the union of the immediately-left/right interiors and any
/// vertical boundary segment at x.  This distinguishes legal boundary contact
/// from mere bbox contact without introducing floating point tolerances.
fn closed_intervals_at_x(store: &GeometryStore, region: PolyRegion, x: i32) -> Vec<(i32, i32)> {
    if x < region.clip.xmin || x > region.clip.xmax {
        return Vec::new();
    }
    let mut intervals = Vec::new();
    for x2 in [2 * x as i64 - 1, 2 * x as i64 + 1] {
        intervals.extend(interior_intervals_at_x2(store, region, x2));
    }
    for edge in store.edges_of(region.poly) {
        if edge.x0 == edge.x1 && edge.x0 == x {
            let lo = edge.y0.min(edge.y1).max(region.clip.ymin);
            let hi = edge.y0.max(edge.y1).min(region.clip.ymax);
            if lo <= hi {
                intervals.push((lo, hi));
            }
        }
    }
    merge_closed_intervals(intervals)
}

fn closed_interval_sets_intersect(a: &[(i32, i32)], b: &[(i32, i32)]) -> bool {
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].0.max(b[j].0) <= a[i].1.min(b[j].1) {
            return true;
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    false
}

fn rectilinear_regions_touch(store: &GeometryStore, a: PolyRegion, b: PolyRegion) -> bool {
    if rectilinear_intersection_area(store, &[a, b]) > 0 {
        return true;
    }
    if !is_rectilinear(store, a.poly) || !is_rectilinear(store, b.poly) {
        return false;
    }
    let mut xs = vec![a.clip.xmin, a.clip.xmax, b.clip.xmin, b.clip.xmax];
    for region in [a, b] {
        let (s, e) = store.poly_range(region.poly);
        xs.extend_from_slice(&store.verts_x[s..e]);
    }
    xs.sort_unstable();
    xs.dedup();
    xs.into_iter().any(|x| {
        let ai = closed_intervals_at_x(store, a, x);
        let bi = closed_intervals_at_x(store, b, x);
        closed_interval_sets_intersect(&ai, &bi)
    })
}

pub(super) fn poly_poly_overlap(store: &GeometryStore, a: PolyId, b: PolyId) -> bool {
    let ba = store.poly_bbox[a.0 as usize];
    let bb = store.poly_bbox[b.0 as usize];
    if !ba.overlaps(&bb) {
        return false;
    }
    rectilinear_intersection_area(store, &[full_region(store, a), full_region(store, b)]) > 0
}

/// Resolve connectivity from PDK config. Returns error if no conductors configured.
fn resolve_connectivity(deck: &Deck) -> Result<(Vec<LayerId>, Vec<LayerId>), String> {
    if deck.connectivity.conductors.is_empty() {
        return Err("no conductors configured in connectivity schema".into());
    }
    let vias = deck.connectivity.vias.iter().map(|(v, _)| *v).collect();
    Ok((deck.connectivity.conductors.clone(), vias))
}

// --- device type resolution ---

/// Result of matching a MOS rule: device kind, flavor, and the index of the matched rule.
struct MosMatch {
    kind: DeviceKind,
    flavor: DeviceFlavor,
    rule_idx: usize,
}

/// `Ok(None)` means the crossing is a BJT base over its emitter/collector
/// (a bjt rule's type_marker covers it) and must not extract as MOS.
fn pick_type_and_flavor(
    store: &GeometryStore,
    deck: &Deck,
    gate: PolyId,
    channel: PolyId,
) -> Result<Option<MosMatch>, String> {
    if deck.devices.mos_rules.is_empty() {
        return Err("found gate crossing but no MOS rules to classify device".into());
    }
    let gate_layer = store.poly_layer[gate.0 as usize];
    let channel_layer = store.poly_layer[channel.0 as usize];
    let mut matches = Vec::new();
    for (ri, rule) in deck.devices.mos_rules.iter().enumerate() {
        if rule.gate_layer != gate_layer || rule.channel_layer != channel_layer {
            continue;
        }
        let implant_overlaps = store
            .polys_on_layer(rule.type_implant)
            .into_iter()
            .any(|p| {
                rectilinear_intersection_area(
                    store,
                    &[
                        full_region(store, p),
                        full_region(store, gate),
                        full_region(store, channel),
                    ],
                ) > 0
            });
        if !implant_overlaps {
            continue;
        }
        let kind = match rule.device_type.as_str() {
            "pmos" => DeviceKind::Pmos,
            "nmos" => DeviceKind::Nmos,
            other => {
                return Err(format!(
                    "MOS rule '{}' has unsupported device type '{}' during extraction",
                    rule.name, other,
                ))
            }
        };
        let mut flavors = HashSet::new();
        for &(marker_layer, ref flavor_name) in &rule.flavor_markers {
            let marker_overlaps = store.polys_on_layer(marker_layer).into_iter().any(|p| {
                rectilinear_intersection_area(
                    store,
                    &[
                        full_region(store, p),
                        full_region(store, gate),
                        full_region(store, channel),
                    ],
                ) > 0
            });
            if marker_overlaps {
                let flavor = match flavor_name.as_str() {
                    "hvt" | "Hvt" | "HVT" => DeviceFlavor::Hvt,
                    "lvt" | "Lvt" | "LVT" => DeviceFlavor::Lvt,
                    other => {
                        return Err(format!(
                            "MOS rule '{}' has unsupported flavor '{}' during extraction",
                            rule.name, other,
                        ))
                    }
                };
                flavors.insert(flavor);
            }
        }
        if flavors.len() > 1 {
            return Err(format!(
                "gate polygon {} crossing channel polygon {} matches multiple flavor markers for MOS rule '{}'",
                gate.0, channel.0, rule.name,
            ));
        }
        matches.push(MosMatch {
            kind,
            flavor: flavors
                .iter()
                .next()
                .copied()
                .unwrap_or(DeviceFlavor::Standard),
            rule_idx: ri,
        });
    }
    match matches.len() {
        0 => {
            let bjt_marked = deck.devices.bjt_rules.iter().any(|rule| {
                store.polys_on_layer(rule.type_marker).into_iter().any(|m| {
                    rectilinear_intersection_area(
                        store,
                        &[
                            full_region(store, m),
                            full_region(store, gate),
                            full_region(store, channel),
                        ],
                    ) > 0
                })
            });
            if bjt_marked {
                return Ok(None);
            }
            Err(format!(
                "gate polygon {} crossing channel polygon {} has no matching MOS type implant",
                gate.0, channel.0,
            ))
        }
        1 => Ok(Some(matches.pop().expect("one match"))),
        _ => {
            let names: Vec<&str> = matches
                .iter()
                .map(|m| deck.devices.mos_rules[m.rule_idx].name.as_str())
                .collect();
            Err(format!(
                "gate polygon {} crossing channel polygon {} ambiguously matches MOS rules {:?}",
                gate.0, channel.0, names,
            ))
        }
    }
}

// --- two-terminal device extraction ---

fn extract_two_terminal_devices(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> Vec<TwoTerminalDevice> {
    let mut out = Vec::new();

    for rule in &deck.devices.resistor_rules {
        let gate_layers: Vec<LayerId> = deck
            .devices
            .mos_rules
            .iter()
            .map(|r| r.gate_layer)
            .collect();
        for body in store.polys_on_layer(rule.body_layer) {
            let bb = store.poly_bbox[body.0 as usize];
            let has_marker = store
                .polys_on_layer(rule.marker_layer)
                .any(|m| poly_poly_overlap(store, m, body));
            if !has_marker {
                continue;
            }
            let is_gate = gate_layers.iter().any(|&gl| {
                store
                    .polys_on_layer(gl)
                    .any(|g| poly_poly_overlap(store, body, g))
            });
            if is_gate {
                continue;
            }
            let mut terminals: Vec<(u32, i32)> = Vec::new();
            let long_axis_x = bb.width() >= bb.height();
            for tc in store.polys_on_layer(rule.terminal_layer) {
                let tb = store.poly_bbox[tc.0 as usize];
                if !tb.overlaps(&bb) || !poly_poly_overlap(store, tc, body) {
                    continue;
                }
                let net = net_of_poly[tc.0 as usize];
                if net == u32::MAX {
                    continue;
                }
                let pos = if long_axis_x {
                    (tb.xmin + tb.xmax) / 2
                } else {
                    (tb.ymin + tb.ymax) / 2
                };
                terminals.push((net, pos));
            }
            if terminals.len() < 2 {
                continue;
            }
            terminals.sort_by_key(|&(_, p)| p);
            let ta = terminals.first().unwrap().0;
            let tb_net = terminals.last().unwrap().0;
            let value = deck.pex.get(&rule.body_layer).map_or(0.0, |p| {
                let (l, w) = if long_axis_x {
                    (bb.width() as f64, bb.height() as f64)
                } else {
                    (bb.height() as f64, bb.width() as f64)
                };
                if w > 0.0 {
                    p.sheet_res_ohm_sq * l / w
                } else {
                    0.0
                }
            });
            out.push(TwoTerminalDevice {
                kind: TwoTerminalKind::Resistor,
                name: rule.name.clone(),
                terminal_a: ta,
                terminal_b: tb_net,
                value,
            });
        }
    }

    for rule in &deck.devices.diode_rules {
        for anode in store.polys_on_layer(rule.anode_layer) {
            let ab = store.poly_bbox[anode.0 as usize];
            for cathode in store.polys_on_layer(rule.cathode_layer) {
                let cb = store.poly_bbox[cathode.0 as usize];
                if !ab.overlaps(&cb) || !poly_poly_overlap(store, anode, cathode) {
                    continue;
                }
                let has_implant = store.polys_on_layer(rule.implant_layer).any(|imp| {
                    rectilinear_intersection_area(
                        store,
                        &[
                            full_region(store, imp),
                            full_region(store, anode),
                            full_region(store, cathode),
                        ],
                    ) > 0
                });
                if !has_implant {
                    continue;
                }
                let a_net = net_of_poly[anode.0 as usize];
                let c_net = net_of_poly[cathode.0 as usize];
                if a_net == u32::MAX || c_net == u32::MAX {
                    continue;
                }
                out.push(TwoTerminalDevice {
                    kind: TwoTerminalKind::Diode,
                    name: rule.name.clone(),
                    terminal_a: a_net,
                    terminal_b: c_net,
                    value: 0.0,
                });
            }
        }
    }

    for rule in &deck.devices.cap_rules {
        for top in store.polys_on_layer(rule.top_layer) {
            let tb = store.poly_bbox[top.0 as usize];
            for bot in store.polys_on_layer(rule.bottom_layer) {
                let bb = store.poly_bbox[bot.0 as usize];
                if !tb.overlaps(&bb) {
                    continue;
                }
                let overlap_area = rectilinear_intersection_area(
                    store,
                    &[full_region(store, top), full_region(store, bot)],
                );
                if overlap_area <= 0 {
                    continue;
                }
                if let Some(marker_l) = rule.marker_layer {
                    let has_marker = store.polys_on_layer(marker_l).any(|m| {
                        rectilinear_intersection_area(
                            store,
                            &[
                                full_region(store, m),
                                full_region(store, top),
                                full_region(store, bot),
                            ],
                        ) > 0
                    });
                    if !has_marker {
                        continue;
                    }
                }
                let t_net = net_of_poly[top.0 as usize];
                let b_net = net_of_poly[bot.0 as usize];
                if t_net == u32::MAX || b_net == u32::MAX {
                    continue;
                }
                let dbu_um = deck.dbu_nm / 1000.0;
                let area_um2 = overlap_area as f64 * dbu_um * dbu_um;
                let cap_per_area = deck
                    .pex
                    .get(&rule.top_layer)
                    .map_or(0.0, |p| p.interlayer_cap_af_um2);
                let value = area_um2 * cap_per_area;
                out.push(TwoTerminalDevice {
                    kind: TwoTerminalKind::Capacitor,
                    name: rule.name.clone(),
                    terminal_a: t_net,
                    terminal_b: b_net,
                    value,
                });
            }
        }
    }

    out
}

// --- BJT device extraction ---

fn extract_bjt_devices(store: &GeometryStore, deck: &Deck, net_of_poly: &[u32]) -> Vec<BjtDevice> {
    let mut out = Vec::new();
    // One device per distinct (rule, kind, e, b, c) net tuple: multi-poly nets
    // (striped emitters, ring collectors) match many triples for one device.
    let mut seen: HashSet<(String, DeviceKind, u32, u32, u32)> = HashSet::new();
    for rule in &deck.devices.bjt_rules {
        let kind = match rule.device_type.as_str() {
            "pnp" => DeviceKind::Pnp,
            _ => DeviceKind::Npn,
        };
        for emitter in store.polys_on_layer(rule.emitter_layer) {
            let eb = store.poly_bbox[emitter.0 as usize];
            for base in store.polys_on_layer(rule.base_layer) {
                let bb = store.poly_bbox[base.0 as usize];
                if !eb.overlaps(&bb) || !poly_poly_overlap(store, emitter, base) {
                    continue;
                }
                for collector in store.polys_on_layer(rule.collector_layer) {
                    if collector == emitter {
                        continue;
                    }
                    let cb = store.poly_bbox[collector.0 as usize];
                    if !bb.overlaps(&cb) || !poly_poly_overlap(store, base, collector) {
                        continue;
                    }
                    // The type marker must cover the actual emitter/base device
                    // region, not merely overlap its bounding box.
                    let has_marker = store.polys_on_layer(rule.type_marker).any(|m| {
                        rectilinear_intersection_area(
                            store,
                            &[
                                full_region(store, m),
                                full_region(store, emitter),
                                full_region(store, base),
                            ],
                        ) > 0
                    });
                    if !has_marker {
                        continue;
                    }
                    let e_net = net_of_poly[emitter.0 as usize];
                    let b_net = net_of_poly[base.0 as usize];
                    let c_net = net_of_poly[collector.0 as usize];
                    if e_net == u32::MAX || b_net == u32::MAX || c_net == u32::MAX {
                        continue;
                    }
                    // A diff shape on the emitter's net is part of the emitter
                    // (striped emitter), not a collector. Genuinely shorted
                    // devices then surface as a count mismatch — conservative.
                    if c_net == e_net {
                        continue;
                    }
                    if !seen.insert((rule.name.clone(), kind.clone(), e_net, b_net, c_net)) {
                        continue;
                    }
                    out.push(BjtDevice {
                        kind: kind.clone(),
                        collector: c_net,
                        base: b_net,
                        emitter: e_net,
                        name: rule.name.clone(),
                    });
                }
            }
        }
    }
    out
}

// --- netlist reduction ---

fn parallel_reduce(devices: Vec<Device>) -> Vec<Device> {
    // S/D are symmetric, but body, class and L are not.  Devices with unlike
    // lengths do not have an exact single-device parallel equivalent.
    let mut index: HashMap<
        (
            DeviceKind,
            DeviceFlavor,
            u32,
            u32,
            u32,
            u32,
            i32,
            Option<String>,
        ),
        usize,
    > = HashMap::new();
    let mut out: Vec<Device> = Vec::new();
    for mut d in devices {
        if d.source > d.drain {
            std::mem::swap(&mut d.source, &mut d.drain);
        }
        let key = (
            d.kind.clone(),
            d.flavor,
            d.gate,
            d.source,
            d.drain,
            d.body,
            d.l,
            d.device_class.clone(),
        );
        if let Some(&idx) = index.get(&key) {
            if let Some(width) = out[idx].w.checked_add(d.w) {
                out[idx].w = width;
                continue;
            }
        }
        index.insert(key, out.len());
        out.push(d);
    }
    out
}

fn compatible_in_series(a: &Device, b: &Device) -> bool {
    a.kind == b.kind
        && a.flavor == b.flavor
        && a.device_class == b.device_class
        && a.gate == b.gate
        && a.body == b.body
        && a.w == b.w
}

fn other_sd_terminal(d: &Device, shared: u32) -> Option<u32> {
    match (d.source == shared, d.drain == shared) {
        (true, false) => Some(d.drain),
        (false, true) => Some(d.source),
        _ => None,
    }
}

fn series_reduce_once(ext: &mut ExtractedNetlist, protected_nets: &HashSet<u32>) -> bool {
    let mut sd_incidence: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut forbidden = protected_nets.clone();
    for (idx, d) in ext.devices.iter().enumerate() {
        sd_incidence.entry(d.source).or_default().push(idx);
        sd_incidence.entry(d.drain).or_default().push(idx);
        forbidden.insert(d.gate);
        // The raw extraction core uses u32::MAX as an unambiguous unresolved
        // body marker. The legacy public adapter converts it to its historical
        // zero sentinel only at the API boundary.
        if d.body != u32::MAX {
            forbidden.insert(d.body);
        }
    }
    for d in &ext.two_terminal {
        forbidden.insert(d.terminal_a);
        forbidden.insert(d.terminal_b);
    }
    for d in &ext.bjt_devices {
        forbidden.insert(d.collector);
        forbidden.insert(d.base);
        forbidden.insert(d.emitter);
    }

    let mut candidates: Vec<u32> = sd_incidence.keys().copied().collect();
    candidates.sort_unstable();
    for shared in candidates {
        if forbidden.contains(&shared) {
            continue;
        }
        let incidence = &sd_incidence[&shared];
        // Exactly two S/D incidences on distinct devices: no branch, port,
        // self-loop, or third device may disappear during normalization.
        if incidence.len() != 2 || incidence[0] == incidence[1] {
            continue;
        }
        let (i, j) = (incidence[0], incidence[1]);
        let (a, b) = (&ext.devices[i], &ext.devices[j]);
        if !compatible_in_series(a, b) {
            continue;
        }
        let (Some(a_outer), Some(b_outer)) =
            (other_sd_terminal(a, shared), other_sd_terminal(b, shared))
        else {
            continue;
        };
        if a_outer == b_outer {
            continue;
        }
        let Some(length) = a.l.checked_add(b.l) else {
            continue;
        };

        let merged = Device {
            kind: a.kind.clone(),
            gate: a.gate,
            source: a_outer,
            drain: b_outer,
            body: a.body,
            flavor: a.flavor,
            w: a.w,
            l: length,
            device_class: a.device_class.clone(),
            ..Default::default()
        };
        let (lo, hi) = (i.min(j), i.max(j));
        ext.devices.remove(hi);
        ext.devices.remove(lo);
        ext.devices.push(merged);
        return true;
    }
    false
}

fn reduce_netlist_with_protected(ext: &mut ExtractedNetlist, protected_nets: &HashSet<u32>) {
    loop {
        let before = ext.devices.len();
        ext.devices = parallel_reduce(std::mem::take(&mut ext.devices));
        let series_merged = series_reduce_once(ext, protected_nets);
        if !series_merged && ext.devices.len() == before {
            break;
        }
    }
    let mut used_set = HashSet::new();
    for d in &ext.devices {
        used_set.insert(d.gate);
        used_set.insert(d.source);
        used_set.insert(d.drain);
    }
    ext.used_nets = used_set.len();
}

pub fn reduce_netlist(ext: &mut ExtractedNetlist) {
    reduce_netlist_with_protected(ext, &HashSet::new());
}

// --- main extraction pipeline ---

pub fn extract_netlist(
    store: &GeometryStore,
    deck: &Deck,
) -> Result<ExtractedNetlist, crate::LvsError> {
    extract_netlist_opts(
        store,
        deck,
        &ExtractOpts {
            cut_required: deck.lvs_cut_required,
            ..Default::default()
        },
        Backend::Cpu,
    )
}

pub fn extract_netlist_opts(
    store: &GeometryStore,
    deck: &Deck,
    opts: &ExtractOpts,
    backend: Backend,
) -> Result<ExtractedNetlist, crate::LvsError> {
    let mut extracted = extract_raw(store, deck, opts, backend, true)?.netlist;
    for device in &mut extracted.devices {
        if device.body == u32::MAX {
            device.body = 0;
        }
    }
    Ok(extracted)
}

/// Full extraction result before the legacy body=0 conversion. Callers that
/// need raw body terminals or device-recognition sources use this directly.
pub struct ExtractResult {
    pub netlist: ExtractedNetlist,
    pub sources: Vec<DeviceRecognitionSource>,
}

/// Production extraction: raw body terminals (`u32::MAX` = unresolved),
/// optional legacy reduction, and device-recognition source provenance.
pub fn extract_raw(
    store: &GeometryStore,
    deck: &Deck,
    opts: &ExtractOpts,
    backend: Backend,
    apply_legacy_reduction: bool,
) -> Result<ExtractResult, String> {
    extract_pipeline(store, deck, opts, backend, apply_legacy_reduction)
}

fn extract_pipeline(
    store: &GeometryStore,
    deck: &Deck,
    opts: &ExtractOpts,
    backend: Backend,
    apply_legacy_reduction: bool,
) -> Result<ExtractResult, String> {
    let n = store.poly_count();
    let (conductors, vias) = resolve_connectivity(deck)?;
    let is_conn = |l: LayerId| conductors.contains(&l) || vias.contains(&l);

    // Derive gate layers and channel layers from MOS rules (no hardcoded "poly"/"diff")
    let mut gate_layers: Vec<LayerId> = deck
        .devices
        .mos_rules
        .iter()
        .map(|r| r.gate_layer)
        .collect();
    gate_layers.sort_unstable();
    gate_layers.dedup();
    let mut channel_layers: Vec<LayerId> = deck
        .devices
        .mos_rules
        .iter()
        .map(|r| r.channel_layer)
        .collect();
    channel_layers.sort_unstable();
    channel_layers.dedup();

    let mut exact_layers: HashSet<LayerId> = conductors.iter().copied().collect();
    exact_layers.extend(vias.iter().copied());
    for rule in &deck.devices.mos_rules {
        exact_layers.extend([rule.gate_layer, rule.channel_layer, rule.type_implant]);
        exact_layers.extend(rule.flavor_markers.iter().map(|(layer, _)| *layer));
        if let Some(layer) = rule.well_layer {
            exact_layers.insert(layer);
        }
    }
    for rule in &deck.devices.resistor_rules {
        exact_layers.extend([rule.body_layer, rule.marker_layer, rule.terminal_layer]);
    }
    for rule in &deck.devices.diode_rules {
        exact_layers.extend([rule.anode_layer, rule.cathode_layer, rule.implant_layer]);
    }
    for rule in &deck.devices.cap_rules {
        exact_layers.extend([rule.top_layer, rule.bottom_layer]);
        if let Some(layer) = rule.marker_layer {
            exact_layers.insert(layer);
        }
    }
    for rule in &deck.devices.bjt_rules {
        exact_layers.extend([
            rule.collector_layer,
            rule.base_layer,
            rule.emitter_layer,
            rule.type_marker,
        ]);
    }
    let mut non_rect_polys: HashSet<u32> = HashSet::new();
    let mut non_rect_warnings: Vec<String> = Vec::new();
    validate_rectilinear_layers(
        store,
        deck,
        &exact_layers,
        &mut non_rect_polys,
        &mut non_rect_warnings,
    )?;
    for w in &non_rect_warnings {
        eprintln!("[lvs-warn] {w}");
    }

    // Build connectivity nodes
    let mut nodes: Vec<Node> = Vec::new();
    let mut node_of_poly: Vec<u32> = vec![u32::MAX; n];
    let mut first_seg_of_poly: Vec<u32> = vec![u32::MAX; n];
    let mut splits: Vec<DiffSplit> = Vec::new();

    for i in 0..n as u32 {
        let li = store.poly_layer[i as usize];
        if channel_layers.contains(&li) {
            continue;
        }
        if !is_conn(li) {
            continue;
        }
        node_of_poly[i as usize] = nodes.len() as u32;
        let bbox = store.poly_bbox[i as usize];
        nodes.push(Node {
            bbox,
            layer: li,
            is_diff_seg: false,
            poly: PolyId(i),
            clip: bbox,
        });
    }

    // Split each channel-layer polygon at its gate crossings
    for &ch_l in &channel_layers {
        for d in store.polys_on_layer(ch_l) {
            let db = store.poly_bbox[d.0 as usize];
            let gates_all: Vec<u32> = gate_layers
                .iter()
                .flat_map(|&gl| {
                    store
                        .polys_on_layer(gl)
                        .into_iter()
                        .filter(|&g| poly_poly_overlap(store, g, d))
                        .map(|g| g.0)
                })
                .collect();

            let crosses_vertically = |g: u32| {
                let gb = store.poly_bbox[g as usize];
                (gb.ymin <= db.ymin && gb.ymax >= db.ymax) || gb.height() >= db.height()
            };
            let n_vert = gates_all.iter().filter(|&&g| crosses_vertically(g)).count();
            let axis_x = n_vert * 2 >= gates_all.len();
            let (d_lo, d_hi) = if axis_x {
                (db.xmin, db.xmax)
            } else {
                (db.ymin, db.ymax)
            };
            let mut gspans: Vec<GateSpan> = gates_all
                .iter()
                .copied()
                .filter(|&g| crosses_vertically(g) == axis_x)
                .map(|g| {
                    let gb = store.poly_bbox[g as usize];
                    let (lo, hi) = if axis_x {
                        (gb.xmin.max(d_lo), gb.xmax.min(d_hi))
                    } else {
                        (gb.ymin.max(d_lo), gb.ymax.min(d_hi))
                    };
                    GateSpan { gate: g, lo, hi }
                })
                .collect();
            gspans.sort_by_key(|s| (s.lo, s.hi));

            let mut seg_spans: Vec<(i32, i32)> = Vec::new();
            let mut cursor = d_lo;
            for s in &gspans {
                if s.lo > cursor {
                    seg_spans.push((cursor, s.lo));
                }
                cursor = cursor.max(s.hi);
            }
            if d_hi > cursor {
                seg_spans.push((cursor, d_hi));
            }

            let mut seg_nodes = Vec::with_capacity(seg_spans.len());
            for &(lo, hi) in &seg_spans {
                let bb = if axis_x {
                    Bbox {
                        xmin: lo,
                        xmax: hi,
                        ymin: db.ymin,
                        ymax: db.ymax,
                    }
                } else {
                    Bbox {
                        xmin: db.xmin,
                        xmax: db.xmax,
                        ymin: lo,
                        ymax: hi,
                    }
                };
                seg_nodes.push(nodes.len() as u32);
                nodes.push(Node {
                    bbox: bb,
                    layer: ch_l,
                    is_diff_seg: true,
                    poly: d,
                    clip: bb,
                });
            }
            if let Some(&f) = seg_nodes.first() {
                first_seg_of_poly[d.0 as usize] = f;
            }
            splits.push(DiffSplit {
                diff: d.0,
                axis_x,
                seg_nodes,
                seg_spans,
                gates: gspans,
            });
        }
    }

    // Union-find over nodes
    let intra_touch = deck.intra_layer_touch;
    let can_union = |a: &Node, b: &Node| -> bool {
        let gate_pair = (gate_layers.contains(&a.layer) && b.is_diff_seg)
            || (gate_layers.contains(&b.layer) && a.is_diff_seg);
        if gate_pair {
            return false;
        }
        if a.layer == b.layer {
            return true;
        }
        let bridges = |via: &Node, other: &Node| -> bool {
            for &(vid, ref connects) in &deck.connectivity.vias {
                if via.layer == vid {
                    return connects.contains(&other.layer)
                        || (other.is_diff_seg
                            && connects
                                .iter()
                                .any(|&c| channel_layers.contains(&c) || c == other.layer));
                }
            }
            false
        };
        if bridges(a, b) || bridges(b, a) {
            return true;
        }
        if opts.cut_required {
            return false;
        }

        // Backward-compatible schema fallback: old decks sometimes supplied
        // only a conductor list and explicitly requested cut-less extraction.
        // With no via declarations there is no layer-pair graph to consult, so
        // retain overlap connectivity for those decks only.  As soon as the PDK
        // declares any via relation, the bounded adjacency rule below applies.
        if deck.connectivity.vias.is_empty() {
            return true;
        }

        // Explicit compatibility mode: an omitted cut may directly join only
        // conductor layers that a declared via is allowed to bridge.  The old
        // fallback joined *every* pair of overlapping conductor layers, making
        // unrelated layers electrical shorts.  Requiring co-membership in one
        // via declaration preserves legacy cut-less fixtures without inventing
        // connectivity absent from the PDK.
        deck.connectivity.vias.iter().any(|(_, connects)| {
            let a_decl = connects.contains(&a.layer)
                || (a.is_diff_seg && connects.iter().any(|c| channel_layers.contains(c)));
            let b_decl = connects.contains(&b.layer)
                || (b.is_diff_seg && connects.iter().any(|c| channel_layers.contains(c)));
            a_decl && b_decl
        })
    };

    let m = nodes.len();

    // Sweep-line candidate enumeration: O(m log m + K) bbox-touching pairs
    // instead of the previous all-pairs O(m²) scan. Closed intervals — touching
    // pairs are included, so the candidate set is a superset of both overlap
    // predicates below; each pair still gets the exact predicate. Union order
    // differs from the old scan but the partition (and therefore net ids,
    // assigned by ascending node index afterwards) is identical.
    let cands = node_candidate_pairs(&nodes);

    // Exact geometry predicates: rect decomposition via cross_pairs kernel when
    // profitable (>= 2^14 candidates), else per-pair CPU rectilinear predicates.
    // ponytail: rect predicates are exact for unclipped rects. Clipped diffusion
    // segments still need per-pair CPU fallback (clip bbox != poly bbox).
    let rect_flags = rect_predicate_flags(store, &nodes, &cands, intra_touch, backend);

    // GPU bbox-overlap PAIR prefilter (positive-area / open-interval, matching
    // the original `bbox_overlap` kernel). One dispatch over all candidate node
    // clip-bboxes: `out[k] = overlap(box[a], box[b])`. Used only as a *reject*
    // filter for the inter-layer positive-area decision, where an empty
    // positive-area bbox intersection guarantees no rect-pair overlaps — so a
    // GPU flag of 0 lets us skip the exact predicate. Panic-contained; `None`
    // (no device / off) leaves the CPU path untouched.
    let bbox_flags: Option<Vec<u32>> = {
        #[cfg(feature = "gpu")]
        {
            if backend == Backend::Gpu && gdsverify_backend::gpu::context().is_some() {
                let (mut bx0, mut by0, mut bx1, mut by1) = (
                    Vec::with_capacity(nodes.len()),
                    Vec::with_capacity(nodes.len()),
                    Vec::with_capacity(nodes.len()),
                    Vec::with_capacity(nodes.len()),
                );
                for n in &nodes {
                    bx0.push(n.clip.xmin);
                    by0.push(n.clip.ymin);
                    bx1.push(n.clip.xmax);
                    by1.push(n.clip.ymax);
                }
                let pa: Vec<u32> = cands.iter().map(|&(i, _)| i).collect();
                let pb: Vec<u32> = cands.iter().map(|&(_, j)| j).collect();
                crate::gpu_overlap::bbox_overlap_pairs_gpu(&bx0, &by0, &bx1, &by1, &pa, &pb)
            } else {
                None
            }
        }
        #[cfg(not(feature = "gpu"))]
        {
            None
        }
    };

    // Collect connectivity edges.
    let mut edges: Vec<(u32, u32)> = Vec::new();
    for (pair_idx, &(i, j)) in cands.iter().enumerate() {
        let (i, j) = (i as usize, j as usize);

        // GPU reject: for the inter-layer positive-area case on unclipped rect
        // nodes, an empty bbox intersection means the exact predicate is 0 too.
        if let Some(flags) = &bbox_flags {
            let unclipped = nodes[i].clip == nodes[i].bbox && nodes[j].clip == nodes[j].bbox;
            let inter_positive = !(intra_touch && nodes[i].layer == nodes[j].layer);
            let rect_pair = !non_rect_polys.contains(&nodes[i].poly.0)
                && !non_rect_polys.contains(&nodes[j].poly.0);
            if unclipped && inter_positive && rect_pair && flags[pair_idx] == 0 {
                continue;
            }
        }

        let either_non_rect =
            non_rect_polys.contains(&nodes[i].poly.0) || non_rect_polys.contains(&nodes[j].poly.0);

        let overlaps = if either_non_rect {
            // ponytail: bbox fallback for non-rectilinear polygons. May produce
            // false shorts; upgrade to exact all-angle predicates if needed.
            let (a, b) = (&nodes[i].clip, &nodes[j].clip);
            if intra_touch && nodes[i].layer == nodes[j].layer {
                a.xmin <= b.xmax && b.xmin <= a.xmax && a.ymin <= b.ymax && b.ymin <= a.ymax
            } else {
                a.overlaps(b)
            }
        } else if let Some(flags) = &rect_flags {
            if nodes[i].clip == nodes[i].bbox && nodes[j].clip == nodes[j].bbox {
                // Unclipped nodes: rect decomposition is exact
                flags[pair_idx] != 0
            } else {
                // Clipped diffusion segments: fall back to exact CPU predicate
                let a = PolyRegion {
                    poly: nodes[i].poly,
                    clip: nodes[i].clip,
                };
                let b = PolyRegion {
                    poly: nodes[j].poly,
                    clip: nodes[j].clip,
                };
                if intra_touch && nodes[i].layer == nodes[j].layer {
                    rectilinear_regions_touch(store, a, b)
                } else {
                    rectilinear_intersection_area(store, &[a, b]) > 0
                }
            }
        } else {
            let a = PolyRegion {
                poly: nodes[i].poly,
                clip: nodes[i].clip,
            };
            let b = PolyRegion {
                poly: nodes[j].poly,
                clip: nodes[j].clip,
            };
            if intra_touch && nodes[i].layer == nodes[j].layer {
                rectilinear_regions_touch(store, a, b)
            } else {
                rectilinear_intersection_area(store, &[a, b]) > 0
            }
        };
        if !overlaps {
            continue;
        }
        if !can_union(&nodes[i], &nodes[j]) {
            continue;
        }
        edges.push((i as u32, j as u32));
    }

    // Compute connected components via host union-find.
    // ponytail: session/cubecl GPU FastSV path removed; the GPU connectivity
    // path is staged for phase-2 vulkano. Host UF is exact for all sizes.
    let component_labels = host_union_find(&edges, m);

    // Assign compact net ids (first-occurrence of root in ascending node order)
    let mut root_to_net: HashMap<u32, u32> = HashMap::new();
    let mut net_of_node = vec![u32::MAX; m];
    for i in 0..m as u32 {
        let r = component_labels[i as usize];
        let next = root_to_net.len() as u32;
        net_of_node[i as usize] = *root_to_net.entry(r).or_insert(next);
    }
    let net_count = root_to_net.len();

    let mut net_of_poly = vec![u32::MAX; n];
    for i in 0..n {
        if node_of_poly[i] != u32::MAX {
            net_of_poly[i] = net_of_node[node_of_poly[i] as usize];
        } else if first_seg_of_poly[i] != u32::MAX {
            net_of_poly[i] = net_of_node[first_seg_of_poly[i] as usize];
        }
    }

    // Device extraction
    let mut devices = Vec::new();
    let mut device_sources = Vec::new();
    for sp in &splits {
        let db = store.poly_bbox[sp.diff as usize];
        for gs in &sp.gates {
            let gate_net = net_of_poly[gs.gate as usize];
            if gate_net == u32::MAX {
                continue;
            }
            let mut src: Option<u32> = None;
            let mut drn: Option<u32> = None;
            for (k, &(s0, s1)) in sp.seg_spans.iter().enumerate() {
                if s1 <= gs.lo {
                    src = Some(sp.seg_nodes[k]);
                }
                if drn.is_none() && s0 >= gs.hi {
                    drn = Some(sp.seg_nodes[k]);
                }
            }
            if let (Some(s), Some(dd)) = (src, drn) {
                let gb = store.poly_bbox[gs.gate as usize];
                let Some(mos_match) =
                    pick_type_and_flavor(store, deck, PolyId(gs.gate), PolyId(sp.diff))?
                else {
                    // BJT base crossing its emitter/collector — not a MOS.
                    continue;
                };
                let matched_rule = &deck.devices.mos_rules[mos_match.rule_idx];
                let l = gs.hi - gs.lo;
                let w = if sp.axis_x {
                    db.ymax.min(gb.ymax) - db.ymin.max(gb.ymin)
                } else {
                    db.xmax.min(gb.xmax) - db.xmin.max(gb.xmin)
                };
                // Phase 3A: body/well extraction
                let well_polygon = if let Some(well_layer) = matched_rule.well_layer {
                    store
                        .polys_on_layer(well_layer)
                        .into_iter()
                        .find(|&wp| {
                            rectilinear_intersection_area(
                                store,
                                &[
                                    full_region(store, wp),
                                    full_region(store, PolyId(gs.gate)),
                                    full_region(store, PolyId(sp.diff)),
                                ],
                            ) > 0
                        })
                        .map(|wp| wp.0)
                } else {
                    None
                };
                let body = well_polygon
                    .map(|polygon| net_of_poly[polygon as usize])
                    .unwrap_or(u32::MAX);
                // Phase 3C: DMOS class tag
                let device_class = matched_rule.device_class.clone();
                devices.push(Device {
                    kind: mos_match.kind,
                    gate: gate_net,
                    source: net_of_node[s as usize],
                    drain: net_of_node[dd as usize],
                    body,
                    flavor: mos_match.flavor,
                    w,
                    l,
                    device_class,
                    well_provenance: well_polygon,
                    ..Default::default()
                });
                device_sources.push(DeviceRecognitionSource {
                    gate_polygon: gs.gate,
                    channel_polygon: sp.diff,
                    well_polygon,
                    rule_id: matched_rule.name.clone(),
                });
            }
        }
    }

    // L4.3: AD/AS/PD/PS — source/drain diffusion area and perimeter.
    // For each MOS device, find all diffusion-layer polygons on the source/drain
    // nets and sum bbox area/perimeter.
    // ponytail: O(devices * polys) scan; spatial index if device count is large.
    {
        // Build net → diffusion polygon list once
        let mut net_diff_polys: HashMap<u32, Vec<u32>> = HashMap::new();
        for &ch_l in &channel_layers {
            for poly in store.polys_on_layer(ch_l) {
                let net = net_of_poly[poly.0 as usize];
                if net != u32::MAX {
                    net_diff_polys.entry(net).or_default().push(poly.0);
                }
            }
        }
        for d in devices.iter_mut() {
            // Drain diffusion (AD/PD)
            if let Some(polys) = net_diff_polys.get(&d.drain) {
                for &pi in polys {
                    let bb = store.poly_bbox[pi as usize];
                    let w = bb.width_i64();
                    let h = bb.height_i64();
                    d.ad += w * h;
                    d.pd += 2 * (w + h);
                }
            }
            // Source diffusion (AS/PS)
            if let Some(polys) = net_diff_polys.get(&d.source) {
                for &pi in polys {
                    let bb = store.poly_bbox[pi as usize];
                    let w = bb.width_i64();
                    let h = bb.height_i64();
                    d.as_ += w * h;
                    d.ps += 2 * (w + h);
                }
            }
        }
    }

    // Phase 4B: Global net merging — force all polygons labelled with a global net name
    // to share a single net ID.
    if !deck.global_nets.is_empty() && !store.net_labels.is_empty() {
        for global_name in &deck.global_nets {
            let mut matching_nets: Vec<u32> = Vec::new();
            for (poly_idx, label) in &store.net_labels {
                if label == global_name {
                    let net = net_of_poly[*poly_idx as usize];
                    if net != u32::MAX {
                        matching_nets.push(net);
                    }
                }
            }
            matching_nets.sort_unstable();
            matching_nets.dedup();
            if matching_nets.len() > 1 {
                let canonical = matching_nets[0];
                for &other in &matching_nets[1..] {
                    if other != canonical {
                        // Remap all occurrences of `other` to `canonical`
                        for np in net_of_poly.iter_mut() {
                            if *np == other {
                                *np = canonical;
                            }
                        }
                        // MOS devices were recognized before global-net merging.
                        // Keep their already-extracted terminals consistent with
                        // the remapped polygon connectivity.
                        for d in devices.iter_mut() {
                            if d.gate == other {
                                d.gate = canonical;
                            }
                            if d.source == other {
                                d.source = canonical;
                            }
                            if d.drain == other {
                                d.drain = canonical;
                            }
                            if d.body == other {
                                d.body = canonical;
                            }
                        }
                    }
                }
            }
        }
    }

    let two_terminal = extract_two_terminal_devices(store, deck, &net_of_poly);
    // L4.3: The richer devices::extract_resistors/capacitors/diodes() are
    // available for callers that need geometry properties (sheet_rho, segments,
    // perimeter). The pipeline uses extract_two_terminal_devices() which
    // already processes the same deck rules into TwoTerminalDevice records.
    // ponytail: no merge — same rules, same results; merge when the richer
    // records carry properties that TwoTerminalDevice cannot express.

    // Phase 3B: BJT device extraction
    let bjt_devices = extract_bjt_devices(store, deck, &net_of_poly);

    let mut used = HashSet::new();
    for d in &devices {
        used.insert(d.gate);
        used.insert(d.source);
        used.insert(d.drain);
    }

    // Label conflict detection
    let mut label_conflicts: Vec<String> = Vec::new();
    if !store.net_labels.is_empty() {
        let mut net_to_label: HashMap<u32, &str> = HashMap::new();
        for (poly_idx, label) in &store.net_labels {
            let net = net_of_poly[*poly_idx as usize];
            if net == u32::MAX {
                continue;
            }
            if let Some(existing) = net_to_label.get(&net) {
                if *existing != label.as_str() {
                    label_conflicts.push(format!(
                        "net {} has conflicting labels: '{}' vs '{}'",
                        net, existing, label
                    ));
                }
            } else {
                net_to_label.insert(net, label.as_str());
            }
        }
    }

    // Build net_names from polygon labels and text elements.
    // ponytail: first-label-wins for conflicts; upgrade to explicit conflict
    // resolution if multi-label semantics are needed.
    let mut net_names: HashMap<u32, String> = HashMap::new();
    for (poly_idx, label) in &store.net_labels {
        let net = net_of_poly[*poly_idx as usize];
        if net != u32::MAX {
            net_names.entry(net).or_insert_with(|| label.clone());
        }
    }
    // Associate text elements with the net of the containing polygon.
    for ti in 0..store.text_count() {
        let tx = store.text_x[ti];
        let ty = store.text_y[ti];
        // Find any polygon whose bbox contains this text position.
        // ponytail: linear scan over polys; spatial index if text count grows.
        let mut best_net = None;
        for (pi, &net) in net_of_poly.iter().enumerate() {
            if net == u32::MAX {
                continue;
            }
            let bb = &store.poly_bbox[pi];
            if tx >= bb.xmin && tx <= bb.xmax && ty >= bb.ymin && ty <= bb.ymax {
                best_net = Some(net);
                break;
            }
        }
        if let Some(net) = best_net {
            net_names
                .entry(net)
                .or_insert_with(|| store.text_string[ti].clone());
        }
    }

    if std::env::var("PNR_DEBUG_LVS_RAW").is_ok() {
        for d in &devices {
            eprintln!(
                "[lvs-raw] {:?} g={} s={} d={} b={} w={} l={}",
                d.kind, d.gate, d.source, d.drain, d.body, d.w, d.l
            );
        }
    }
    // Any named layout net is externally observable and therefore cannot be
    // removed as an internal series node.  This includes global-net labels
    // after the remapping above.
    let protected_nets: HashSet<u32> = store
        .net_labels
        .keys()
        .filter_map(|&poly| net_of_poly.get(poly as usize).copied())
        .filter(|&net| net != u32::MAX)
        .collect();
    let mut ext = ExtractedNetlist {
        devices,
        net_count,
        used_nets: used.len(),
        net_of_poly,
        label_conflicts,
        two_terminal,
        bjt_devices,
        floating_nets: Vec::new(),
        net_names,
    };
    if apply_legacy_reduction {
        reduce_netlist_with_protected(&mut ext, &protected_nets);
        // A reduced device may represent several recognized polygon pairs.
        device_sources.clear();
    }

    // Phase 4C: Floating net detection — nets with polygons but no device terminal connections
    {
        let mut terminal_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            terminal_nets.insert(d.gate);
            terminal_nets.insert(d.source);
            terminal_nets.insert(d.drain);
            if d.body != u32::MAX {
                terminal_nets.insert(d.body);
            }
        }
        for d in &ext.two_terminal {
            terminal_nets.insert(d.terminal_a);
            terminal_nets.insert(d.terminal_b);
        }
        for d in &ext.bjt_devices {
            terminal_nets.insert(d.collector);
            terminal_nets.insert(d.base);
            terminal_nets.insert(d.emitter);
        }
        // Count polygons per net and find label for each net
        let mut net_poly_count: HashMap<u32, usize> = HashMap::new();
        let mut net_label: HashMap<u32, String> = HashMap::new();
        for (i, &net) in ext.net_of_poly.iter().enumerate() {
            if net == u32::MAX {
                continue;
            }
            *net_poly_count.entry(net).or_default() += 1;
            if let Some(label) = store.net_labels.get(&(i as u32)) {
                net_label.entry(net).or_insert_with(|| label.clone());
            }
        }
        for (&net, &count) in &net_poly_count {
            if !terminal_nets.contains(&net) {
                ext.floating_nets.push(FloatingNet {
                    net_id: net,
                    label: net_label.get(&net).cloned(),
                    polygon_count: count,
                });
            }
        }
    }

    Ok(ExtractResult {
        netlist: ext,
        sources: device_sources,
    })
}

#[cfg(test)]
mod reduction_tests {
    use super::*;

    fn mos(source: u32, drain: u32, w: i32, l: i32) -> Device {
        Device {
            kind: DeviceKind::Nmos,
            gate: 10,
            source,
            drain,
            body: 20,
            flavor: DeviceFlavor::Standard,
            w,
            l,
            device_class: Some("core".into()),
            ..Default::default()
        }
    }

    fn netlist(devices: Vec<Device>) -> ExtractedNetlist {
        ExtractedNetlist {
            devices,
            bjt_devices: Vec::new(),
            net_count: 32,
            used_nets: 0,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        }
    }

    #[test]
    fn series_reduction_repeats_to_fixpoint() {
        let mut ext = netlist(vec![
            mos(1, 2, 100, 40),
            mos(2, 3, 100, 50),
            mos(3, 4, 100, 60),
        ]);
        reduce_netlist(&mut ext);
        assert_eq!(ext.devices.len(), 1);
        let d = &ext.devices[0];
        assert_eq!((d.source, d.drain), (1, 4));
        assert_eq!((d.w, d.l), (100, 150));
    }

    #[test]
    fn series_reduction_rejects_incompatible_or_branched_devices() {
        let mut unequal_width = netlist(vec![mos(1, 2, 100, 40), mos(2, 3, 120, 50)]);
        reduce_netlist(&mut unequal_width);
        assert_eq!(unequal_width.devices.len(), 2);

        let mut unlike_body = mos(2, 3, 100, 50);
        unlike_body.body = 21;
        let mut body = netlist(vec![mos(1, 2, 100, 40), unlike_body]);
        reduce_netlist(&mut body);
        assert_eq!(body.devices.len(), 2);

        let mut unlike_class = mos(2, 3, 100, 50);
        unlike_class.device_class = Some("io".into());
        let mut class = netlist(vec![mos(1, 2, 100, 40), unlike_class]);
        reduce_netlist(&mut class);
        assert_eq!(class.devices.len(), 2);

        let mut branch = netlist(vec![
            mos(1, 2, 100, 40),
            mos(2, 3, 100, 50),
            mos(2, 4, 100, 60),
        ]);
        reduce_netlist(&mut branch);
        assert_eq!(
            branch.devices.len(),
            3,
            "degree-three net must not disappear"
        );
    }

    #[test]
    fn series_reduction_protects_observable_nets() {
        let mut gate_tied = netlist(vec![mos(1, 10, 100, 40), mos(10, 3, 100, 50)]);
        reduce_netlist(&mut gate_tied);
        assert_eq!(
            gate_tied.devices.len(),
            2,
            "gate-connected net is observable"
        );

        let mut labeled = netlist(vec![mos(1, 2, 100, 40), mos(2, 3, 100, 50)]);
        reduce_netlist_with_protected(&mut labeled, &HashSet::from([2]));
        assert_eq!(
            labeled.devices.len(),
            2,
            "labeled/global net must be protected"
        );

        let mut passive = netlist(vec![mos(1, 2, 100, 40), mos(2, 3, 100, 50)]);
        passive.two_terminal.push(TwoTerminalDevice {
            kind: TwoTerminalKind::Resistor,
            name: "tap".into(),
            terminal_a: 2,
            terminal_b: 5,
            value: 1.0,
        });
        reduce_netlist(&mut passive);
        assert_eq!(
            passive.devices.len(),
            2,
            "passive-connected net is external"
        );
    }

    #[test]
    fn parallel_reduction_requires_same_body_and_length() {
        let mut same = netlist(vec![mos(1, 2, 100, 40), mos(2, 1, 120, 40)]);
        reduce_netlist(&mut same);
        assert_eq!(same.devices.len(), 1);
        assert_eq!(same.devices[0].w, 220);

        let mut other_l = netlist(vec![mos(1, 2, 100, 40), mos(1, 2, 120, 50)]);
        reduce_netlist(&mut other_l);
        assert_eq!(other_l.devices.len(), 2);

        let mut body_device = mos(1, 2, 120, 40);
        body_device.body = 21;
        let mut other_body = netlist(vec![mos(1, 2, 100, 40), body_device]);
        reduce_netlist(&mut other_body);
        assert_eq!(other_body.devices.len(), 2);
    }
}

#[cfg(test)]
mod net_names_tests {
    use super::*;
    use crate::geometry::GeometryStore;
    use crate::params::{ConnectivityConfig, Deck, DeviceConfig, ErcParams, LayerDef, LayerTable};

    fn simple_deck() -> Deck {
        let defs = [("met1", 7, 0)]
            .into_iter()
            .map(|(n, l, d)| {
                (
                    n.to_string(),
                    LayerDef {
                        layer: l,
                        datatype: d,
                    },
                )
            })
            .collect();
        let layers = LayerTable::from_defs(&defs);
        let met1 = layers.id("met1").unwrap();
        Deck {
            layers,
            connectivity: ConnectivityConfig {
                conductors: vec![met1],
                vias: Vec::new(),
            },
            devices: DeviceConfig::default(),
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            w_tolerance: crate::schema::PropertyTolerance::default(),
            l_tolerance: crate::schema::PropertyTolerance::default(),
            fail_on_floating: false,
            erc: ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    #[test]
    fn net_names_from_polygon_labels() {
        let deck = simple_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        let a = st.add_rect(met1, 0, 0, 100, 100);
        let b = st.add_rect(met1, 200, 0, 100, 100);
        st.net_labels.insert(a.0, "VDD".into());
        st.net_labels.insert(b.0, "VSS".into());

        let ext = extract_netlist(&st, &deck).unwrap();
        let net_a = ext.net_of_poly[a.0 as usize];
        let net_b = ext.net_of_poly[b.0 as usize];
        assert_eq!(ext.net_names.get(&net_a), Some(&"VDD".to_string()));
        assert_eq!(ext.net_names.get(&net_b), Some(&"VSS".to_string()));
    }

    #[test]
    fn net_names_from_text_elements() {
        let deck = simple_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        let a = st.add_rect(met1, 0, 0, 100, 100);
        // Text at center of polygon a
        st.add_text(7, 0, 50, 50, "SIG".into());

        let ext = extract_netlist(&st, &deck).unwrap();
        let net_a = ext.net_of_poly[a.0 as usize];
        assert_eq!(ext.net_names.get(&net_a), Some(&"SIG".to_string()));
    }

    #[test]
    fn net_names_polygon_label_wins_over_text() {
        let deck = simple_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        let a = st.add_rect(met1, 0, 0, 100, 100);
        st.net_labels.insert(a.0, "LABEL".into());
        st.add_text(7, 0, 50, 50, "TEXT".into());

        let ext = extract_netlist(&st, &deck).unwrap();
        let net_a = ext.net_of_poly[a.0 as usize];
        // Polygon label inserted first, so it wins first-writer
        assert_eq!(ext.net_names.get(&net_a), Some(&"LABEL".to_string()));
    }

    #[test]
    fn non_rectilinear_bbox_connectivity() {
        let deck = simple_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        // Trapezoid polygon (non-rectilinear)
        let trap = st.add_polygon(met1, &[(0, 0), (100, 0), (80, 100), (0, 100)]);
        // Rect that overlaps the trapezoid's bbox
        let rect = st.add_rect(met1, 50, 50, 100, 100);

        // ponytail: bbox fallback means these connect (bbox overlap)
        let ext = extract_netlist(&st, &deck).unwrap();
        assert_eq!(
            ext.net_of_poly[trap.0 as usize], ext.net_of_poly[rect.0 as usize],
            "non-rectilinear polygon should connect via bbox approximation"
        );
    }

    #[test]
    fn well_provenance_tracked() {
        let defs = [
            ("nwell", 1, 0),
            ("diff", 2, 0),
            ("poly", 3, 0),
            ("nsdm", 4, 0),
        ]
        .into_iter()
        .map(|(n, l, d)| {
            (
                n.to_string(),
                LayerDef {
                    layer: l,
                    datatype: d,
                },
            )
        })
        .collect();
        let layers = LayerTable::from_defs(&defs);
        let nwell = layers.id("nwell").unwrap();
        let diff = layers.id("diff").unwrap();
        let poly = layers.id("poly").unwrap();
        let nsdm = layers.id("nsdm").unwrap();
        let deck = Deck {
            layers,
            connectivity: ConnectivityConfig {
                conductors: vec![nwell, diff, poly],
                vias: Vec::new(),
            },
            devices: DeviceConfig {
                mos_rules: vec![crate::params::MosRule {
                    name: "nch".into(),
                    gate_layer: poly,
                    channel_layer: diff,
                    type_implant: nsdm,
                    device_type: "nmos".into(),
                    flavor_markers: Vec::new(),
                    well_layer: Some(nwell),
                    device_class: None,
                }],
                ..Default::default()
            },
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            w_tolerance: crate::schema::PropertyTolerance::default(),
            l_tolerance: crate::schema::PropertyTolerance::default(),
            fail_on_floating: false,
            erc: ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        };
        let mut st = GeometryStore::new();
        let wp = st.add_rect(nwell, -100, -100, 1200, 400);
        st.add_rect(diff, 0, 0, 1000, 200);
        st.add_rect(poly, 400, -50, 60, 300);
        st.add_rect(nsdm, -50, -50, 1100, 300);

        let ext = crate::extract::extract_raw(
            &st,
            &deck,
            &ExtractOpts {
                cut_required: false,
                ..Default::default()
            },
            crate::backend::Backend::Cpu,
            false,
        )
        .unwrap();
        assert_eq!(ext.netlist.devices.len(), 1);
        assert_eq!(ext.netlist.devices[0].well_provenance, Some(wp.0));
    }
}

#[cfg(test)]
mod bjt_extract_tests {
    use super::*;
    use crate::geometry::GeometryStore;
    use crate::params::{ConnectivityConfig, Deck, DeviceConfig, ErcParams, LayerDef, LayerTable};

    // diff serves as both emitter and collector layer, like a real vertical
    // BJT recognition deck — exercises the emitter==collector exclusions.
    fn bjt_deck() -> Deck {
        let defs = [("diff", 1, 0), ("pbase", 2, 0), ("npnid", 3, 0)]
            .into_iter()
            .map(|(n, l, d)| {
                (
                    n.to_string(),
                    LayerDef {
                        layer: l,
                        datatype: d,
                    },
                )
            })
            .collect();
        let layers = LayerTable::from_defs(&defs);
        let diff = layers.id("diff").unwrap();
        let pbase = layers.id("pbase").unwrap();
        let npnid = layers.id("npnid").unwrap();
        Deck {
            layers,
            connectivity: ConnectivityConfig {
                conductors: vec![diff, pbase],
                vias: Vec::new(),
            },
            devices: DeviceConfig {
                bjt_rules: vec![crate::params::BjtRule {
                    name: "npn".into(),
                    collector_layer: diff,
                    base_layer: pbase,
                    emitter_layer: diff,
                    type_marker: npnid,
                    device_type: "npn".into(),
                }],
                ..Default::default()
            },
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            w_tolerance: crate::schema::PropertyTolerance::default(),
            l_tolerance: crate::schema::PropertyTolerance::default(),
            fail_on_floating: false,
            erc: ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    #[test]
    fn single_bjt_extracts_once() {
        let deck = bjt_deck();
        let diff = deck.layers.id("diff").unwrap();
        let pbase = deck.layers.id("pbase").unwrap();
        let npnid = deck.layers.id("npnid").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 100, 100); // emitter, net 0
        st.add_rect(pbase, 0, 0, 300, 100); // base, net 1
        st.add_rect(diff, 200, 0, 100, 100); // collector, net 2 — no emitter contact
        st.add_rect(npnid, 0, 0, 100, 100); // marker over emitter∩base
        let net_of_poly = vec![0, 1, 2, u32::MAX];

        let out = extract_bjt_devices(&st, &deck, &net_of_poly);
        assert_eq!(out.len(), 1);
        let d = &out[0];
        assert_eq!(d.kind, DeviceKind::Npn);
        assert_eq!((d.emitter, d.base, d.collector), (0, 1, 2));
    }

    #[test]
    fn striped_emitter_extracts_once() {
        let deck = bjt_deck();
        let diff = deck.layers.id("diff").unwrap();
        let pbase = deck.layers.id("pbase").unwrap();
        let npnid = deck.layers.id("npnid").unwrap();
        let mut st = GeometryStore::new();
        // Three emitter stripes electrically on one net.
        st.add_rect(diff, 0, 0, 40, 100);
        st.add_rect(diff, 60, 0, 40, 100);
        st.add_rect(diff, 120, 0, 40, 100);
        st.add_rect(pbase, 0, 0, 400, 100); // base, net 1
        st.add_rect(diff, 300, 0, 100, 100); // collector, net 2
        st.add_rect(npnid, 0, 0, 160, 100); // marker over stripes∩base
        let net_of_poly = vec![0, 0, 0, 1, 2, u32::MAX];

        let out = extract_bjt_devices(&st, &deck, &net_of_poly);
        assert_eq!(out.len(), 1, "one device per (e,b,c) net tuple");
        assert_eq!((out[0].emitter, out[0].base, out[0].collector), (0, 1, 2));
    }

    #[test]
    fn no_marker_no_device() {
        let deck = bjt_deck();
        let diff = deck.layers.id("diff").unwrap();
        let pbase = deck.layers.id("pbase").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 100, 100);
        st.add_rect(pbase, 0, 0, 300, 100);
        st.add_rect(diff, 200, 0, 100, 100);
        let net_of_poly = vec![0, 1, 2];

        let out = extract_bjt_devices(&st, &deck, &net_of_poly);
        assert!(out.is_empty());
    }

    #[test]
    fn collector_on_emitter_net_rejected() {
        let deck = bjt_deck();
        let diff = deck.layers.id("diff").unwrap();
        let pbase = deck.layers.id("pbase").unwrap();
        let npnid = deck.layers.id("npnid").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 100, 100); // emitter
        st.add_rect(pbase, 0, 0, 300, 100); // base
        st.add_rect(diff, 200, 0, 100, 100); // "collector" shorted to emitter
        st.add_rect(npnid, 0, 0, 100, 100);
        let net_of_poly = vec![0, 1, 0, u32::MAX];

        let out = extract_bjt_devices(&st, &deck, &net_of_poly);
        assert!(out.is_empty(), "shorted e/c must not extract");
    }

    // Deck with both a MOS rule (gate=poly over channel=diff) and a BJT rule
    // whose base is drawn in poly crossing the emitter diff — the layout that
    // used to hard-error MOS extraction with "no matching MOS type implant".
    fn bjt_mos_deck() -> Deck {
        let defs = [
            ("diff", 1, 0),
            ("poly", 2, 0),
            ("nsdm", 3, 0),
            ("npnid", 4, 0),
            ("ctub", 5, 0),
            ("licon", 6, 0),
        ]
        .into_iter()
        .map(|(n, l, d)| {
            (
                n.to_string(),
                LayerDef {
                    layer: l,
                    datatype: d,
                },
            )
        })
        .collect();
        let layers = LayerTable::from_defs(&defs);
        let diff = layers.id("diff").unwrap();
        let poly = layers.id("poly").unwrap();
        let nsdm = layers.id("nsdm").unwrap();
        let npnid = layers.id("npnid").unwrap();
        let ctub = layers.id("ctub").unwrap();
        let licon = layers.id("licon").unwrap();
        Deck {
            layers,
            connectivity: ConnectivityConfig {
                conductors: vec![diff, poly, ctub],
                // Non-empty via list disables the cut-less overlap fallback,
                // so base poly over collector ctub does not short b/c.
                vias: vec![(licon, Vec::new())],
            },
            devices: DeviceConfig {
                mos_rules: vec![crate::params::MosRule {
                    name: "nch".into(),
                    gate_layer: poly,
                    channel_layer: diff,
                    type_implant: nsdm,
                    device_type: "nmos".into(),
                    flavor_markers: Vec::new(),
                    well_layer: None,
                    device_class: None,
                }],
                bjt_rules: vec![crate::params::BjtRule {
                    name: "npn".into(),
                    collector_layer: ctub,
                    base_layer: poly,
                    emitter_layer: diff,
                    type_marker: npnid,
                    device_type: "npn".into(),
                }],
                ..Default::default()
            },
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            w_tolerance: crate::schema::PropertyTolerance::default(),
            l_tolerance: crate::schema::PropertyTolerance::default(),
            fail_on_floating: false,
            erc: ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    #[test]
    fn marked_base_crossing_skips_mos_and_extracts_bjt() {
        let deck = bjt_mos_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let npnid = deck.layers.id("npnid").unwrap();
        let ctub = deck.layers.id("ctub").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 100, 100); // emitter
        st.add_rect(poly, 30, -20, 40, 300); // base bar fully crossing emitter
        st.add_rect(ctub, 20, 150, 120, 80); // collector under the bar's far end
        st.add_rect(npnid, 0, 0, 100, 100); // marker over emitter∩base

        let ext = extract_netlist(&st, &deck).unwrap();
        assert!(ext.devices.is_empty(), "marked crossing must not be a MOS");
        assert_eq!(ext.bjt_devices.len(), 1);
        let d = &ext.bjt_devices[0];
        assert!(d.emitter != d.base && d.base != d.collector && d.emitter != d.collector);
    }

    #[test]
    fn unmarked_crossing_without_implant_still_errors() {
        let deck = bjt_mos_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 100, 100);
        st.add_rect(poly, 30, -20, 40, 300); // crossing, no implant, no marker

        let err = extract_netlist(&st, &deck).err().expect("must error");
        assert!(
            err.to_string().contains("no matching MOS type implant"),
            "unexpected error: {err}"
        );
    }
}
