//! Lateral coupling capacitance between parallel same-layer wires that face each other.
//!
//! `C_c = Ck * Lp * (Sref / S)` — parallel-run-length model, scaled inversely with
//! spacing relative to the reference spacing.

use crate::backend::Backend;
use crate::geometry::{LayerId, PolyId};
use crate::params::PexLayerParams;
use crate::analytical::{Attributed, Parasitic, PexCtx, NM_PER_UM};
use crate::rule::Rule;

// ponytail: the two kernels below used to run on the GPU via `#[verify_kernel]`
// (cubecl). The macro and cubecl are gone; they are now plain f32 functions and
// the "GPU" path is a plain CPU loop over the pairs (see the large-input branch
// in `check`). Encoding kept from the old kernel: gap = 0.0 means "not facing" —
// callers only accept run > 0 && gap > 0, and a facing pair with zero gap is
// touching, which they reject too.

/// Parallel run length (nm) of a facing bbox pair; 0.0 if not facing.
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

        // The old GPU path computed run length + gap for all pairs via the two
        // kernels above. cubecl is gone, so for large inputs we run the same two
        // functions in a plain CPU loop over the pairs. Results are identical to
        // the exact-integer fallback below. Kept as a distinct branch only to
        // exercise `coupling_run`/`coupling_gap`; either branch is correct.
        let _ = backend;
        if ctx.backend == Backend::Gpu && n_pairs >= (1 << 18) {
            for i in 0..n {
                let a = store.poly_bbox[polys[i].0 as usize];
                for j in (i + 1)..n {
                    let b = store.poly_bbox[polys[j].0 as usize];
                    let run_nm = coupling_run(
                        a.xmin as f32, a.ymin as f32, a.xmax as f32, a.ymax as f32,
                        b.xmin as f32, b.ymin as f32, b.xmax as f32, b.ymax as f32,
                    );
                    let gap_nm = coupling_gap(
                        a.xmin as f32, a.ymin as f32, a.xmax as f32, a.ymax as f32,
                        b.xmin as f32, b.ymin as f32, b.xmax as f32, b.ymax as f32,
                    );
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

        // CPU fallback (exact integer path)
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

fn factory(layer: LayerId, params: &PexLayerParams) -> Option<crate::analytical::BoxedRule> {
    // No coefficient gate: the old extractor emitted (zero-af) pairs even with
    // coupling_cap_af_um == 0, and bus_coupling_pairs counts entries.
    Some(Box::new(CouplingCap {
        layer,
        params: params.clone(),
    }))
}
pub static FACTORY: crate::analytical::rules::Factory = factory;
