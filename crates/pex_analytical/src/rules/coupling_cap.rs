//! Lateral coupling capacitance between parallel same-layer wires that face each other.
//!
//! `C_c = Ck * Lp * (Sref / S)` — parallel-run-length model, scaled inversely with
//! spacing relative to the reference spacing.

use gdsverify_macros::verify_kernel;

// The cube dialect resolves `f32::min`/`f32::max` through prelude traits.
#[cfg(feature = "gpu")]
#[allow(unused_imports)]
use cubecl::prelude::*;

use crate::backend::Backend;
use crate::geometry::{LayerId, PolyId};
use crate::params::PexLayerParams;
use crate::{Attributed, Parasitic, PexCtx, NM_PER_UM};
use crate::rule::Rule;

// The old paired GPU kernel returned (run, gap) per bbox pair; the single-source
// `#[verify_kernel]` shape produces one output array, so the same body is split
// into two kernels. Encoding kept from the old kernel: gap = 0.0 means "not
// facing" — callers only accept run > 0 && gap > 0, and a facing pair with zero
// gap is touching, which they reject too. (cubecl's cube macro cannot expand
// const-const float arithmetic like `-1.0f32`, hence no negative sentinel.)

/// Parallel run length (nm) of a facing bbox pair; 0.0 if not facing.
#[verify_kernel(shape = pair)]
pub fn coupling_run(
    a_xmin: f32, a_ymin: f32, a_xmax: f32, a_ymax: f32,
    b_xmin: f32, b_ymin: f32, b_xmax: f32, b_ymax: f32,
) -> f32 {
    let mut run = 0.0f32;
    let mut gap = 0.0f32;
    let x_overlap = f32::min(a_xmax, b_xmax) - f32::max(a_xmin, b_xmin);
    if x_overlap > 0.0 {
        if a_ymax <= b_ymin {
            run = f32::max(x_overlap, 0.0);
            gap = f32::max(b_ymin - a_ymax, 0.0);
        } else if b_ymax <= a_ymin {
            run = f32::max(x_overlap, 0.0);
            gap = f32::max(a_ymin - b_ymax, 0.0);
        }
    }
    if gap <= 0.0 {
        let y_overlap = f32::min(a_ymax, b_ymax) - f32::max(a_ymin, b_ymin);
        if y_overlap > 0.0 {
            if a_xmax <= b_xmin {
                run = f32::max(y_overlap, 0.0);
            } else if b_xmax <= a_xmin {
                run = f32::max(y_overlap, 0.0);
            }
        }
    }
    run
}

/// Gap (nm) of a facing bbox pair; 0.0 if not facing (or touching).
#[verify_kernel(shape = pair)]
pub fn coupling_gap(
    a_xmin: f32, a_ymin: f32, a_xmax: f32, a_ymax: f32,
    b_xmin: f32, b_ymin: f32, b_xmax: f32, b_ymax: f32,
) -> f32 {
    let mut gap = 0.0f32;
    let x_overlap = f32::min(a_xmax, b_xmax) - f32::max(a_xmin, b_xmin);
    if x_overlap > 0.0 {
        if a_ymax <= b_ymin {
            gap = f32::max(b_ymin - a_ymax, 0.0);
        } else if b_ymax <= a_ymin {
            gap = f32::max(a_ymin - b_ymax, 0.0);
        }
    }
    if gap <= 0.0 {
        let y_overlap = f32::min(a_ymax, b_ymax) - f32::max(a_ymin, b_ymin);
        if y_overlap > 0.0 {
            if a_xmax <= b_xmin {
                gap = f32::max(b_xmin - a_xmax, 0.0);
            } else if b_xmax <= a_xmin {
                gap = f32::max(a_xmin - b_xmax, 0.0);
            }
        }
    }
    gap
}

pub struct CouplingCap {
    layer: LayerId,
    params: PexLayerParams,
}

impl<'a> Rule<PexCtx<'a>> for CouplingCap {
    type Finding = Attributed;
    fn id(&self) -> &str {
        "coupling_cap"
    }
    fn check(&self, ctx: &PexCtx<'a>, backend: Backend) -> Vec<Attributed> {
        let (store, lt, layer, p) = (ctx.store, ctx.layers, self.layer, &self.params);
        let mut out = Vec::new();
        let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
        let n = polys.len();
        let n_pairs = n * n.saturating_sub(1) / 2;

        // GPU path: compute run length + gap for all pairs in parallel (advisory —
        // any failure falls through to the exact CPU path).
        // Gate on the session's ACTUAL backend: with GPU requested but no
        // device, the session fell back to the CPU arena, where the exact
        // integer path below is both faster and the fail-closed contract.
        let _ = backend;
        if ctx.session.backend() == Backend::Gpu && n_pairs >= (1 << 18) {
            let xmins: Vec<f32> = polys
                .iter()
                .map(|q| store.poly_bbox[q.0 as usize].xmin as f32)
                .collect();
            let ymins: Vec<f32> = polys
                .iter()
                .map(|q| store.poly_bbox[q.0 as usize].ymin as f32)
                .collect();
            let xmaxs: Vec<f32> = polys
                .iter()
                .map(|q| store.poly_bbox[q.0 as usize].xmax as f32)
                .collect();
            let ymaxs: Vec<f32> = polys
                .iter()
                .map(|q| store.poly_bbox[q.0 as usize].ymax as f32)
                .collect();
            let mut pa = Vec::with_capacity(n_pairs);
            let mut pb = Vec::with_capacity(n_pairs);
            for i in 0..n {
                for j in (i + 1)..n {
                    pa.push(i as u32);
                    pb.push(j as u32);
                }
            }
            // Session execution: the bbox + pair columns are uploaded ONCE and
            // both kernels launch against the same device-resident buffers;
            // the first read is the only sync. `contained` degrades any device
            // failure to the exact CPU path below, like the one-shot API did.
            let s = ctx.session;
            let device = crate::session::contained(|| {
                let cxmin = s.upload(&xmins);
                let cymin = s.upload(&ymins);
                let cxmax = s.upload(&xmaxs);
                let cymax = s.upload(&ymaxs);
                let cpa = s.upload(&pa);
                let cpb = s.upload(&pb);
                let runs: crate::session::Col<f32> = s.launch(coupling_run_kernel::bind(
                    &cxmin, &cymin, &cxmax, &cymax, &cpa, &cpb,
                ));
                let gaps: crate::session::Col<f32> = s.launch(coupling_gap_kernel::bind(
                    &cxmin, &cymin, &cxmax, &cymax, &cpa, &cpb,
                ));
                (s.read(&runs), s.read(&gaps))
            });
            if let Some((runs, gaps)) = device {
                let mut idx = 0;
                for i in 0..n {
                    for j in (i + 1)..n {
                        let run_nm = runs[idx];
                        let gap_nm = gaps[idx];
                        idx += 1;
                        if run_nm > 0.0 && gap_nm > 0.0 {
                            let run_um = run_nm as f64 / NM_PER_UM;
                            let spacing = gap_nm as i32;
                            let scale = p.coupling_ref_spacing_nm / spacing as f64;
                            let af = p.coupling_cap_af_um * run_um * scale;
                            out.push((
                                Parasitic::CouplingCap {
                                    layer: lt.name(layer).into(),
                                    af,
                                    spacing_nm: spacing,
                                    run_length_um: run_um,
                                    source_polygon: None, corner: None,
                                },
                                [polys[i].0, polys[j].0],
                            ));
                        }
                    }
                }
                return out;
            }
        }

        // CPU fallback
        // ponytail: all-pairs — the 1/S model has no distance cutoff, so every pair
        // couples; add a coupling_max_spacing_nm deck param before sweep-pruning this.
        for i in 0..n {
            for j in (i + 1)..n {
                let a = store.poly_bbox[polys[i].0 as usize];
                let b = store.poly_bbox[polys[j].0 as usize];
                let x_overlap = a.xmax.min(b.xmax) - a.xmin.max(b.xmin);
                let y_gap = if a.ymax <= b.ymin {
                    b.ymin - a.ymax
                } else if b.ymax <= a.ymin {
                    a.ymin - b.ymax
                } else {
                    -1
                };
                if x_overlap > 0 && y_gap > 0 {
                    let run_um = x_overlap as f64 / NM_PER_UM;
                    let spacing = y_gap;
                    let scale = p.coupling_ref_spacing_nm / spacing as f64;
                    let af = p.coupling_cap_af_um * run_um * scale;
                    out.push((
                        Parasitic::CouplingCap {
                            layer: lt.name(layer).into(),
                            af,
                            spacing_nm: spacing,
                            run_length_um: run_um,
                            source_polygon: None, corner: None,
                        },
                        [polys[i].0, polys[j].0],
                    ));
                    continue;
                }
                let y_overlap = a.ymax.min(b.ymax) - a.ymin.max(b.ymin);
                let x_gap = if a.xmax <= b.xmin {
                    b.xmin - a.xmax
                } else if b.xmax <= a.xmin {
                    a.xmin - b.xmax
                } else {
                    -1
                };
                if y_overlap > 0 && x_gap > 0 {
                    let run_um = y_overlap as f64 / NM_PER_UM;
                    let spacing = x_gap;
                    let scale = p.coupling_ref_spacing_nm / spacing as f64;
                    let af = p.coupling_cap_af_um * run_um * scale;
                    out.push((
                        Parasitic::CouplingCap {
                            layer: lt.name(layer).into(),
                            af,
                            spacing_nm: spacing,
                            run_length_um: run_um,
                            source_polygon: None, corner: None,
                        },
                        [polys[i].0, polys[j].0],
                    ));
                }
            }
        }
        out
    }
}

fn factory(layer: LayerId, params: &PexLayerParams) -> Option<crate::BoxedRule> {
    // No coefficient gate: the old extractor emitted (zero-af) pairs even with
    // coupling_cap_af_um == 0, and bus_coupling_pairs counts entries.
    Some(Box::new(CouplingCap {
        layer,
        params: params.clone(),
    }))
}
pub static FACTORY: crate::rules::Factory = factory;
