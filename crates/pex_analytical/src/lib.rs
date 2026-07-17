//! PEX — analytical (pattern-based, 2.5D) parasitic extraction. No field solver.
//!
//! Models (per the research):
//!   * Resistance:   R = Rs * L / W     (sheet resistance times number of squares)
//!   * Area cap:     C_area = Ca * A     (parallel-plate to substrate, A in um^2)
//!   * Fringe cap:   C_fringe = Cf * P   (edge/fringe to ground, P = perimeter in um)
//!   * Coupling cap: C_c = Ck * Lp * (Sref / S)   (lateral, parallel-run-length model,
//!                   scaled inversely with spacing relative to the reference spacing)
//!
//! Each analytical formula maps to a geometric relationship:
//!   - resistance      -> a single conductor polygon's perimeter/area-equivalent L/W
//!   - area+fringe     -> every conductor polygon's exact area & perimeter
//!   - coupling        -> two same-layer polygons facing each other (parallel run length)

pub mod device_parasitics;
pub mod dspf;
pub mod graph;
pub mod inductance;
pub mod process_stack;
pub mod reduce;
pub mod spef;

// Re-exports so internal `crate::*` paths resolve after workspace split
pub use gdsverify_backend as backend;
pub use gdsverify_backend::rule;
pub use gdsverify_backend::session;
pub use gdsverify_core::geometry;
pub use gdsverify_core::params;

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::{Deck, LayerTable, PexLayerParams};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Parasitic {
    Resistance {
        layer: String,
        ohm: f64,
        length_nm: i32,
        width_nm: i32,
        #[serde(default)]
        source_polygon: Option<u32>,
        #[serde(default)]
        corner: Option<String>,
    },
    ViaResistance {
        layer: String,
        ohm: f64,
        #[serde(default)]
        source_polygon: Option<u32>,
        #[serde(default)]
        corner: Option<String>,
    },
    AreaCap {
        layer: String,
        /// Total ground capacitance (`area_af + fringe_af`).
        af: f64,
        /// Parallel-plate contribution, in attofarads.
        area_af: f64,
        /// Edge/fringe contribution, in attofarads.
        fringe_af: f64,
        area_um2: f64,
        perimeter_um: f64,
        #[serde(default)]
        source_polygon: Option<u32>,
        #[serde(default)]
        corner: Option<String>,
    },
    CouplingCap {
        layer: String,
        af: f64,
        spacing_nm: i32,
        run_length_um: f64,
        #[serde(default)]
        source_polygon: Option<u32>,
        #[serde(default)]
        corner: Option<String>,
    },
    InterlayerCap {
        layer_a: String,
        layer_b: String,
        af: f64,
        overlap_area_um2: f64,
        #[serde(default)]
        source_polygon: Option<u32>,
        #[serde(default)]
        corner: Option<String>,
    },
    /// The analytical extractor refused geometry it cannot model faithfully. Diagnostics
    /// live in the result (rather than silently producing zero R/C) so signoff callers can
    /// fail closed using [`PexReport::is_complete`].
    ExtractionDiagnostic {
        layer: String,
        polygon: u32,
        model: String,
        message: String,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PexReport {
    pub parasitics: Vec<Parasitic>,
}

impl PexReport {
    pub fn total_resistance(&self, layer: &str) -> f64 {
        self.parasitics
            .iter()
            .filter_map(|p| match p {
                Parasitic::Resistance { layer: l, ohm, .. }
                | Parasitic::ViaResistance { layer: l, ohm, .. }
                    if l == layer =>
                {
                    Some(*ohm)
                }
                _ => None,
            })
            .sum()
    }
    pub fn total_cap(&self) -> f64 {
        self.parasitics
            .iter()
            .map(|p| match p {
                Parasitic::AreaCap { af, .. }
                | Parasitic::CouplingCap { af, .. }
                | Parasitic::InterlayerCap { af, .. } => *af,
                Parasitic::Resistance { .. }
                | Parasitic::ViaResistance { .. }
                | Parasitic::ExtractionDiagnostic { .. } => 0.0,
            })
            .sum()
    }
    pub fn resistances(&self) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::Resistance { .. }))
            .collect()
    }
    pub fn area_caps(&self) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::AreaCap { .. }))
            .collect()
    }
    pub fn coupling_caps(&self) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::CouplingCap { .. }))
            .collect()
    }
    pub fn via_resistances(&self) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::ViaResistance { .. }))
            .collect()
    }
    pub fn interlayer_caps(&self) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::InterlayerCap { .. }))
            .collect()
    }

    pub fn diagnostics(&self) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::ExtractionDiagnostic { .. }))
            .collect()
    }

    /// True only when all encountered geometry was supported by the analytical model.
    pub fn is_complete(&self) -> bool {
        self.diagnostics().is_empty()
    }

    /// Fringe-to-total ground-cap ratio for characterization. Returns 0.0 if no ground cap.
    /// Both numerator and denominator are capacitances in attofarads.
    pub fn fringe_ratio(&self) -> f64 {
        let mut total = 0.0_f64;
        let mut fringe_total = 0.0_f64;
        for p in &self.parasitics {
            if let Parasitic::AreaCap { af, fringe_af, .. } = p {
                total += *af;
                fringe_total += *fringe_af;
            }
        }
        if total == 0.0 {
            0.0
        } else {
            fringe_total / total
        }
    }

    /// Count the number of coupling cap pairs (for bus/interdigitated analysis).
    pub fn bus_coupling_pairs(&self) -> usize {
        self.parasitics
            .iter()
            .filter(|p| matches!(p, Parasitic::CouplingCap { .. }))
            .count()
    }

    /// Sum coupling-cap contributions from floating (unconnected) polygons.
    /// Since `PexReport` does not carry polygon attribution, this delegates to
    /// `run_pex_by_net` results: pass the by-net map and it returns the cap_af
    /// accrued to the sentinel net `u32::MAX` (polygons not on any device net).
    pub fn floating_metal_cap(
        &self,
        by_net: &std::collections::HashMap<u32, NetParasitics>,
    ) -> f64 {
        by_net.get(&u32::MAX).map_or(0.0, |np| np.cap_af)
    }

    /// Filter for resistance parasitics where length/width > threshold (high aspect ratio).
    pub fn high_ar_polygons(&self, threshold: f64) -> Vec<&Parasitic> {
        self.parasitics
            .iter()
            .filter(|p| {
                if let Parasitic::Resistance {
                    length_nm,
                    width_nm,
                    ..
                } = p
                {
                    *width_nm > 0 && (*length_nm as f64 / *width_nm as f64) > threshold
                } else {
                    false
                }
            })
            .collect()
    }
}

// --- Rule plumbing: one extractor per file in rules/, globbed at build time --

/// Everything a PEX rule reads besides its own per-layer params.
#[derive(Clone, Copy)]
pub struct PexCtx<'a> {
    pub store: &'a GeometryStore,
    pub layers: &'a LayerTable,
    /// One device session per run: rules upload shared columns once and keep
    /// intermediate results on device; reads are the only sync points.
    pub session: &'a crate::session::Session,
}

/// A PEX rule with the finding type fixed.
pub type BoxedRule = Box<dyn for<'a> crate::rule::Rule<PexCtx<'a>, Finding = Attributed>>;

pub mod rules {
    /// One factory per rule file: instantiate the rule for a (layer, params)
    /// deck entry, or `None` when the params disable it.
    pub type Factory =
        fn(crate::geometry::LayerId, &crate::params::PexLayerParams) -> Option<super::BoxedRule>;
    include!(concat!(env!("OUT_DIR"), "/pex_rules.rs"));
}

const NM_PER_UM: f64 = 1000.0;

/// A parasitic together with the polygon(s) it came from: `[poly, u32::MAX]` for the
/// single-polygon extractors (R, area/fringe C), `[poly_a, poly_b]` for coupling C.
pub type Attributed = (Parasitic, [u32; 2]);

fn extract_all(store: &GeometryStore, deck: &Deck, backend: Backend) -> Vec<Attributed> {
    let mut rule_set: Vec<BoxedRule> = Vec::new();
    for (&lid, params) in &deck.pex {
        for factory in rules::FACTORIES {
            if let Some(rule) = factory(lid, params) {
                rule_set.push(rule);
            }
        }
    }
    // GPU absence is a hard error from the session — handle the fallback
    // here, audibly, instead of silently degrading.
    let session = crate::session::Session::new(backend).unwrap_or_else(|_| {
        crate::session::warn_no_gpu("pex");
        crate::session::Session::cpu()
    });
    let ctx = PexCtx {
        store,
        layers: &deck.layers,
        session: &session,
    };
    let mut out = crate::rule::run_rules(&rule_set, &ctx, backend);
    extract_interlayer_cap(store, deck, &mut out);
    out
}

pub fn run_pex(store: &GeometryStore, deck: &Deck) -> PexReport {
    let parasitics = extract_all(store, deck, Backend::Cpu)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    PexReport { parasitics }
}

/// Forced-backend PEX: same as `run_pex` but with explicit backend + telemetry.
pub fn run_pex_backend(
    store: &GeometryStore,
    deck: &Deck,
    backend: Backend,
) -> Result<(PexReport, crate::backend::BackendTelemetry), String> {
    let session = crate::session::Session::new(backend).map_err(|e| e.to_string())?;
    let parasitics = extract_all(store, deck, backend)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    Ok((PexReport { parasitics }, session.telemetry()))
}

/// Aggregate parasitics of one extracted net (see [`run_pex_by_net`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetParasitics {
    pub r_ohm: f64,
    pub cap_af: f64,
}

/// Per-net PEX: same extractors as [`run_pex`], but each parasitic is attributed to the
/// extracted net(s) of its source polygon(s) via `net_of_poly` (as produced by
/// `ExtractedNetlist::net_of_poly`). Unattributed/floating geometry is retained
/// under the sentinel net `u32::MAX`, so [`PexReport::floating_metal_cap`] can
/// report it rather than silently losing it.
///
/// * Resistance and area/fringe cap accrue to the polygon's net.
/// * Coupling cap accrues in FULL to BOTH nets (conservative for budget checks); pairs on
///   the same net are skipped — same-net coupling is not a parasitic to budget.
///
/// This compatibility entry point returns numeric values even when another polygon produced
/// an extraction diagnostic. Signoff callers should use [`run_pex_by_net_checked`] to fail
/// closed on unsupported geometry.
pub fn run_pex_by_net(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> std::collections::HashMap<u32, NetParasitics> {
    aggregate_by_net(extract_all(store, deck, Backend::Cpu), net_of_poly)
}

/// Fail-closed per-net PEX. Returns all extraction diagnostics instead of a partial numeric
/// map when any configured R/C model encounters unsupported geometry.
pub fn run_pex_by_net_checked(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> Result<std::collections::HashMap<u32, NetParasitics>, Vec<Parasitic>> {
    let extracted = extract_all(store, deck, Backend::Cpu);
    let diagnostics: Vec<Parasitic> = extracted
        .iter()
        .filter_map(|(parasitic, _)| {
            matches!(parasitic, Parasitic::ExtractionDiagnostic { .. }).then(|| parasitic.clone())
        })
        .collect();
    if diagnostics.is_empty() {
        Ok(aggregate_by_net(extracted, net_of_poly))
    } else {
        Err(diagnostics)
    }
}

fn aggregate_by_net(
    extracted: Vec<Attributed>,
    net_of_poly: &[u32],
) -> std::collections::HashMap<u32, NetParasitics> {
    let net = |p: u32| -> u32 { net_of_poly.get(p as usize).copied().unwrap_or(u32::MAX) };
    let mut out: std::collections::HashMap<u32, NetParasitics> = std::collections::HashMap::new();
    for (par, polys) in extracted {
        match par {
            Parasitic::Resistance { ohm, .. } | Parasitic::ViaResistance { ohm, .. } => {
                let n = net(polys[0]);
                out.entry(n).or_default().r_ohm += ohm;
            }
            Parasitic::AreaCap { af, .. } => {
                let n = net(polys[0]);
                out.entry(n).or_default().cap_af += af;
            }
            Parasitic::CouplingCap { af, .. } | Parasitic::InterlayerCap { af, .. } => {
                let (na, nb) = (net(polys[0]), net(polys[1]));
                if na == nb {
                    continue;
                } // same-net coupling: not a parasitic to budget
                out.entry(na).or_default().cap_af += af;
                out.entry(nb).or_default().cap_af += af;
            }
            Parasitic::ExtractionDiagnostic { .. } => {}
        }
    }
    out
}

/// Build a PEX graph from layout geometry, deck, and net assignment.
///
/// ponytail: one node per polygon (no segmentation at via landings yet).
/// Segment when distributed RC accuracy matters — for now the lumped model
/// matches the existing `run_pex` fidelity.
pub fn build_pex_graph(store: &GeometryStore, deck: &Deck, net_of_poly: &[u32]) -> graph::PexGraph {
    let extracted = extract_all(store, deck, Backend::Cpu);
    let mut g = graph::PexGraph::new();
    let mut poly_to_node: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut next_id = 0_u32;

    // Create a node per polygon that appears in the extraction results.
    for (par, polys) in &extracted {
        for &pid in polys {
            if pid == u32::MAX {
                continue;
            }
            poly_to_node.entry(pid).or_insert_with(|| {
                let id = next_id;
                next_id += 1;
                let net_id = net_of_poly.get(pid as usize).copied().unwrap_or(u32::MAX);
                let bbox = store.poly_bbox[pid as usize];
                let cx = (bbox.xmin as i64 + bbox.xmax as i64) / 2;
                let cy = (bbox.ymin as i64 + bbox.ymax as i64) / 2;
                let layer = store.poly_layer[pid as usize];
                g.add_node(graph::PexNode {
                    id,
                    net_id,
                    layer,
                    poly: PolyId(pid),
                    segment: None,
                    x: cx as i32,
                    y: cy as i32,
                    terminal: None,
                    substrate_cap_af: 0.0,
                });
                id
            });
        }
        // Populate ground cap from area caps
        if let Parasitic::AreaCap { af, .. } = par {
            if let Some(&nid) = poly_to_node.get(&polys[0]) {
                g.ground_caps.push((nid, *af));
            }
        }
    }

    // Add resistance edges and coupling caps
    for (par, polys) in &extracted {
        match par {
            Parasitic::Resistance { ohm, .. } | Parasitic::ViaResistance { ohm, .. } => {
                if let Some(&nid) = poly_to_node.get(&polys[0]) {
                    // ponytail: self-edge for lumped R; becomes a real edge once
                    // polygons are segmented into sub-nodes.
                    let _ = (nid, ohm);
                }
            }
            Parasitic::CouplingCap { af, .. } | Parasitic::InterlayerCap { af, .. } => {
                if let (Some(&na), Some(&nb)) =
                    (poly_to_node.get(&polys[0]), poly_to_node.get(&polys[1]))
                {
                    g.coupling_caps.push((na, nb, *af));
                }
            }
            _ => {}
        }
    }

    g
}

/// Run PEX extraction for multiple process corners.
///
/// ponytail: applies overrides by cloning + patching the deck per corner.
/// Returns one `PexReport` per corner name.
pub fn run_pex_multi_corner(
    store: &GeometryStore,
    deck: &Deck,
    corners: &[process_stack::ProcessCorner],
) -> std::collections::HashMap<String, PexReport> {
    let mut results = std::collections::HashMap::new();
    for corner in corners {
        let mut patched_pex = deck.pex.clone();
        for (&lid, params) in &mut patched_pex {
            let layer_name = deck.layers.name(lid);
            if let Some(ovr) = corner.overrides.get(layer_name) {
                if let Some(v) = ovr.sheet_res_ohm_sq {
                    params.sheet_res_ohm_sq = v;
                }
                if let Some(v) = ovr.area_cap_af_um2 {
                    params.area_cap_af_um2 = v;
                }
                if let Some(v) = ovr.fringe_cap_af_um {
                    params.fringe_cap_af_um = v;
                }
                if let Some(v) = ovr.coupling_cap_af_um {
                    params.coupling_cap_af_um = v;
                }
            }
        }
        // ponytail: builds a patched Deck by cloning all fields. Deck doesn't
        // derive Clone, so we reconstruct with only the PEX map changed.
        // The extract_all path only reads deck.pex and deck.layers, so we
        // pass through extract_all's per-layer loop manually.
        let mut rule_set: Vec<BoxedRule> = Vec::new();
        for (&lid, params) in &patched_pex {
            for factory in rules::FACTORIES {
                if let Some(rule) = factory(lid, params) {
                    rule_set.push(rule);
                }
            }
        }
        let session = crate::session::Session::new(Backend::Cpu).unwrap_or_else(|_| {
            crate::session::warn_no_gpu("pex");
            crate::session::Session::cpu()
        });
        let ctx = PexCtx {
            store,
            layers: &deck.layers,
            session: &session,
        };
        let mut out = crate::rule::run_rules(&rule_set, &ctx, Backend::Cpu);
        extract_interlayer_cap(store, deck, &mut out);
        let parasitics = out.into_iter().map(|(p, _)| p).collect();
        results.insert(corner.name.clone(), PexReport { parasitics });
    }
    results
}

#[derive(Debug, Clone, Copy)]
struct RectilinearMetrics {
    area_nm2: f64,
    perimeter_nm: f64,
    equivalent_length_nm: f64,
    equivalent_width_nm: f64,
}

/// Measure a simple Manhattan polygon without substituting its bounding box.
///
/// The equivalent rectangle is the rectangle with the same area and perimeter as the
/// polygon. Its dimensions are the roots of `t² - (P/2)t + A = 0`. This is exact for a
/// rectangle and for ideal constant-width orthogonal traces (including bends). Indentations
/// increase perimeter and therefore conservatively increase the estimated number of squares.
fn rectilinear_metrics(store: &GeometryStore, poly: PolyId) -> Result<RectilinearMetrics, String> {
    let (start, end) = store.poly_range(poly);
    let count = end - start;
    if count < 4 {
        return Err(format!(
            "polygon has {count} vertices; at least four are required"
        ));
    }
    if crate::geometry::poly_self_intersects(store, poly) {
        return Err("self-intersecting polygon is unsupported".into());
    }

    let mut area2 = 0_i128;
    let mut perimeter_nm = 0_f64;
    for i in 0..count {
        let (x0, y0) = store.poly_vertex(start, i);
        let (x1, y1) = store.poly_vertex(start, (i + 1) % count);
        let dx = x1 as i64 - x0 as i64;
        let dy = y1 as i64 - y0 as i64;
        if dx == 0 && dy == 0 {
            return Err(format!("zero-length edge at vertex {i}"));
        }
        if dx != 0 && dy != 0 {
            return Err(format!("non-Manhattan edge at vertex {i}"));
        }
        perimeter_nm += (dx.abs() + dy.abs()) as f64;
        area2 += x0 as i128 * y1 as i128 - x1 as i128 * y0 as i128;
    }
    let area_nm2 = area2.abs() as f64 / 2.0;
    if !area_nm2.is_finite() || area_nm2 <= 0.0 || perimeter_nm <= 0.0 {
        return Err("polygon has zero or non-finite area/perimeter".into());
    }

    let semiperimeter = perimeter_nm / 2.0;
    let raw_discriminant = semiperimeter * semiperimeter - 4.0 * area_nm2;
    let tolerance = semiperimeter * semiperimeter * 1e-12;
    if raw_discriminant < -tolerance {
        return Err("area/perimeter cannot form a rectilinear equivalent rectangle".into());
    }
    let root = raw_discriminant.max(0.0).sqrt();
    let equivalent_length_nm = (semiperimeter + root) / 2.0;
    let equivalent_width_nm = (semiperimeter - root) / 2.0;
    if equivalent_width_nm <= 0.0 || !equivalent_length_nm.is_finite() {
        return Err("polygon has no positive equivalent conductor width".into());
    }
    Ok(RectilinearMetrics {
        area_nm2,
        perimeter_nm,
        equivalent_length_nm,
        equivalent_width_nm,
    })
}

fn report_dimension_nm(value: f64) -> i32 {
    value.round().clamp(1.0, i32::MAX as f64) as i32
}

fn extraction_diagnostic(
    lt: &LayerTable,
    layer: LayerId,
    poly: PolyId,
    model: &str,
    message: String,
) -> Attributed {
    (
        Parasitic::ExtractionDiagnostic {
            layer: lt.name(layer).into(),
            polygon: poly.0,
            model: model.into(),
            message,
        },
        [poly.0, u32::MAX],
    )
}

/// Inter-layer coupling capacitance between wires on DIFFERENT metal layers that cross
/// over/under each other. C = interlayer_cap_af_um2 * overlap_area_um2 for each polygon
/// pair that overlaps in the x-y plane.
fn extract_interlayer_cap(store: &GeometryStore, deck: &Deck, out: &mut Vec<Attributed>) {
    let pex_layers: Vec<(LayerId, &PexLayerParams)> =
        deck.pex.iter().map(|(&lid, p)| (lid, p)).collect();
    let n = pex_layers.len();
    for i in 0..n {
        for j in (i + 1)..n {
            let (lid_a, params_a) = pex_layers[i];
            let (lid_b, params_b) = pex_layers[j];
            // Use the average of both layers' interlayer_cap coefficients (or whichever is nonzero).
            let coeff = if params_a.interlayer_cap_af_um2 != 0.0
                && params_b.interlayer_cap_af_um2 != 0.0
            {
                (params_a.interlayer_cap_af_um2 + params_b.interlayer_cap_af_um2) / 2.0
            } else {
                params_a.interlayer_cap_af_um2 + params_b.interlayer_cap_af_um2 // one is 0.0
            };
            if coeff == 0.0 {
                continue;
            }
            let polys_a: Vec<PolyId> = store.polys_on_layer(lid_a).collect();
            let polys_b: Vec<PolyId> = store.polys_on_layer(lid_b).collect();
            // overlap requires bbox intersection: x-sweep candidates, not all pairs
            for (pa, pb) in crate::geometry::candidate_pairs(store, &polys_a, Some(&polys_b), 0) {
                let ba = store.poly_bbox[pa.0 as usize];
                let bb = store.poly_bbox[pb.0 as usize];
                // Compute x-y overlap area (bbox intersection).
                let ox = (ba.xmax.min(bb.xmax) - ba.xmin.max(bb.xmin)).max(0);
                let oy = (ba.ymax.min(bb.ymax) - ba.ymin.max(bb.ymin)).max(0);
                if ox <= 0 || oy <= 0 {
                    continue;
                }
                let overlap_area_um2 = (ox as f64 / NM_PER_UM) * (oy as f64 / NM_PER_UM);
                let af = coeff * overlap_area_um2;
                out.push((
                    Parasitic::InterlayerCap {
                        layer_a: deck.layers.name(lid_a).into(),
                        layer_b: deck.layers.name(lid_b).into(),
                        af,
                        overlap_area_um2,
                        source_polygon: None,
                        corner: None,
                    },
                    [pa.0, pb.0],
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_deck() -> Deck {
        Deck::from_json(
            r#"{
            "layers": { "met1": { "layer": 68, "datatype": 20 } },
            "drc": {},
            "pex": { "met1": {
                "sheet_res_ohm_sq": 0.1,
                "area_cap_af_um2": 25.0,
                "fringe_cap_af_um": 40.0,
                "coupling_cap_af_um": 100.0,
                "coupling_ref_spacing_nm": 200
            } }
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn per_net_attribution() {
        let deck = test_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(met1, 0, 0, 2000, 200); // wire A: 10 squares -> 1.0 ohm
        st.add_rect(met1, 0, 400, 2000, 200); // wire B: parallel, 200nm gap

        // Every conductor gets R and ground C. For either wire:
        // area C = 25 * 0.4 = 10 aF; fringe C = 40 * 4.4 = 176 aF.
        const GROUND_CAP: f64 = 186.0;

        // distinct nets: R and ground C per net, full coupling to both
        let by_net = run_pex_by_net(&st, &deck, &[0, 1]);
        let a = by_net[&0];
        let b = by_net[&1];
        assert!((a.r_ohm - 1.0).abs() < 1e-9);
        assert!((b.r_ohm - 1.0).abs() < 1e-9);
        // coupling: 100 aF/um * 2.0 um * (200/200) = 200 aF, added to BOTH nets
        assert!((a.cap_af - (GROUND_CAP + 200.0)).abs() < 1e-9);
        assert!((b.cap_af - (GROUND_CAP + 200.0)).abs() < 1e-9);

        // same net: coupling skipped; resistance and ground capacitance accumulate
        let by_net = run_pex_by_net(&st, &deck, &[0, 0]);
        let a = by_net[&0];
        assert!((a.r_ohm - 2.0).abs() < 1e-9);
        assert!((a.cap_af - 2.0 * GROUND_CAP).abs() < 1e-9);

        // Both analytical contributions exist on both conductor polygons.
        let report = run_pex(&st, &deck);
        assert!((report.total_resistance("met1") - 2.0).abs() < 1e-9);
        assert_eq!(report.resistances().len(), 2);
        assert_eq!(report.area_caps().len(), 2);
        assert!(report.is_complete());

        // Floating attribution is retained under the sentinel net.  This used
        // to be silently skipped, making floating_metal_cap always return zero.
        let floating = run_pex_by_net(&st, &deck, &[u32::MAX, 1]);
        assert!((report.floating_metal_cap(&floating) - (GROUND_CAP + 200.0)).abs() < 1e-9);
    }

    #[test]
    fn exact_concave_area_perimeter_and_equivalent_resistance() {
        let deck = test_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        // Constant-width L: area 0.19 um², perimeter 4.0 um. The equivalent rectangle
        // is 1900 x 100 nm, so the estimate is exactly 19 squares.
        st.add_polygon(
            met1,
            &[
                (0, 0),
                (1000, 0),
                (1000, 100),
                (100, 100),
                (100, 1000),
                (0, 1000),
            ],
        );

        let report = run_pex(&st, &deck);
        assert!(report.is_complete());
        assert!((report.total_resistance("met1") - 1.9).abs() < 1e-9);
        let cap = report.area_caps()[0];
        match cap {
            Parasitic::AreaCap {
                af,
                area_af,
                fringe_af,
                area_um2,
                perimeter_um,
                ..
            } => {
                assert!((*area_um2 - 0.19).abs() < 1e-12);
                assert!((*perimeter_um - 4.0).abs() < 1e-12);
                assert!((*area_af - 4.75).abs() < 1e-12);
                assert!((*fringe_af - 160.0).abs() < 1e-12);
                assert!((*af - 164.75).abs() < 1e-12);
                assert!((report.fringe_ratio() - 160.0 / 164.75).abs() < 1e-12);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn square_conductor_receives_both_resistance_and_capacitance() {
        let deck = test_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(met1, 0, 0, 1000, 1000);

        let report = run_pex(&st, &deck);
        assert!((report.total_resistance("met1") - 0.1).abs() < 1e-12);
        assert_eq!(report.area_caps().len(), 1);
        assert!((report.total_cap() - 185.0).abs() < 1e-12);
        assert!((report.fringe_ratio() - 160.0 / 185.0).abs() < 1e-12);
    }

    #[test]
    fn unconfigured_fill_and_shielding_heuristics_do_not_change_capacitance() {
        let deck = Deck::from_json(
            r#"{
            "layers": {
                "met1": { "layer": 68, "datatype": 20 },
                "met2": { "layer": 69, "datatype": 20 }
            },
            "drc": {},
            "pex": {
                "met1": {
                    "sheet_res_ohm_sq": 0.1,
                    "area_cap_af_um2": 25.0,
                    "fringe_cap_af_um": 40.0,
                    "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 200
                },
                "met2": {
                    "sheet_res_ohm_sq": 0.08,
                    "area_cap_af_um2": 15.0,
                    "fringe_cap_af_um": 30.0,
                    "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 200
                }
            }
        }"#,
        )
        .unwrap();
        let met1 = deck.layers.id("met1").unwrap();
        let met2 = deck.layers.id("met2").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(met1, 0, 0, 2000, 2000); // old code treated this as a met2 shield
        st.add_rect(met2, 500, 500, 1000, 1000);
        st.add_rect(met1, 3000, 0, 90, 90); // old code inferred dummy fill

        let report = run_pex(&st, &deck);
        let mut met1_small = None;
        let mut met2_plate = None;
        for cap in report.area_caps() {
            if let Parasitic::AreaCap {
                layer,
                af,
                area_um2,
                ..
            } = cap
            {
                if layer == "met1" && (*area_um2 - 0.0081).abs() < 1e-12 {
                    met1_small = Some(*af);
                }
                if layer == "met2" {
                    met2_plate = Some(*af);
                }
            }
        }
        assert!((met1_small.unwrap() - 14.6025).abs() < 1e-12);
        assert!((met2_plate.unwrap() - 135.0).abs() < 1e-12);
    }

    #[test]
    fn unsupported_geometry_is_reported_instead_of_silently_zeroed() {
        let deck = test_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        st.add_polygon(met1, &[(0, 0), (1000, 0), (500, 500)]);

        let report = run_pex(&st, &deck);
        assert!(!report.is_complete());
        assert_eq!(report.diagnostics().len(), 2); // independent R and ground-C models
        assert!(report.resistances().is_empty());
        assert!(report.area_caps().is_empty());
        assert_eq!(
            run_pex_by_net_checked(&st, &deck, &[0]).unwrap_err().len(),
            2
        );
    }
}
