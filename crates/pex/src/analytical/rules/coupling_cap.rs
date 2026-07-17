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

        // Large-input path: compute run length + gap for all pairs, then apply
        // the (host-side, f64) cap math. On a real GPU (Backend::Gpu + a usable
        // Vulkan device) this dispatches the pair kernel; otherwise it's the same
        // two functions in a plain CPU loop over the pairs. Both are numerically
        // identical to the exact-integer fallback below; either is correct.
        let _ = backend;
        if ctx.backend == Backend::Gpu && n_pairs >= (1 << 18) {
            let xmin: Vec<f32> = polys.iter().map(|q| store.poly_bbox[q.0 as usize].xmin as f32).collect();
            let ymin: Vec<f32> = polys.iter().map(|q| store.poly_bbox[q.0 as usize].ymin as f32).collect();
            let xmax: Vec<f32> = polys.iter().map(|q| store.poly_bbox[q.0 as usize].xmax as f32).collect();
            let ymax: Vec<f32> = polys.iter().map(|q| store.poly_bbox[q.0 as usize].ymax as f32).collect();
            let mut pa = Vec::with_capacity(n_pairs);
            let mut pb = Vec::with_capacity(n_pairs);
            for i in 0..n {
                for j in (i + 1)..n {
                    pa.push(i as u32);
                    pb.push(j as u32);
                }
            }

            // GPU first (panic-contained inside gpu::coupling_pairs), CPU loop otherwise.
            #[cfg(feature = "gpu")]
            let device = gpu::coupling_pairs(&xmin, &ymin, &xmax, &ymax, &pa, &pb);
            #[cfg(not(feature = "gpu"))]
            let device: Option<(Vec<f32>, Vec<f32>)> = None;

            let (runs, gaps) = device.unwrap_or_else(|| {
                let mut runs = Vec::with_capacity(n_pairs);
                let mut gaps = Vec::with_capacity(n_pairs);
                for k in 0..n_pairs {
                    let (ia, ib) = (pa[k] as usize, pb[k] as usize);
                    runs.push(coupling_run(
                        xmin[ia], ymin[ia], xmax[ia], ymax[ia],
                        xmin[ib], ymin[ib], xmax[ib], ymax[ib],
                    ));
                    gaps.push(coupling_gap(
                        xmin[ia], ymin[ia], xmax[ia], ymax[ia],
                        xmin[ib], ymin[ib], xmax[ib], ymax[ib],
                    ));
                }
                (runs, gaps)
            });

            for k in 0..n_pairs {
                let (run_nm, gap_nm) = (runs[k], gaps[k]);
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
                        [polys[pa[k] as usize].0, polys[pb[k] as usize].0],
                    ));
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

/// GPU pair kernel: `out[i] = coupling(col[pairs_a[i]], col[pairs_b[i]])` for
/// run length and gap. Single dispatch, panic-contained. Returns `None` when no
/// device is available (caller falls back to the CPU loop).
#[cfg(feature = "gpu")]
mod gpu {
    use gdsverify_backend::gpu;
    use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
    use vulkano::pipeline::{Pipeline, PipelineBindPoint};

    // GLSL translation of `coupling_run` / `coupling_gap`. Both are computed per
    // pair in one dispatch; the branch structure mirrors the Rust bodies exactly
    // (same f32 min/max, same facing/gap tests, same 0.0 "not facing" sentinel).
    mod shader {
        vulkano_shaders::shader! {
            ty: "compute",
            src: r"
                #version 460
                layout(local_size_x = 64) in;
                layout(set = 0, binding = 0) readonly buffer Xmin { float xmin[]; };
                layout(set = 0, binding = 1) readonly buffer Ymin { float ymin[]; };
                layout(set = 0, binding = 2) readonly buffer Xmax { float xmax[]; };
                layout(set = 0, binding = 3) readonly buffer Ymax { float ymax[]; };
                layout(set = 0, binding = 4) readonly buffer Pa { uint pa[]; };
                layout(set = 0, binding = 5) readonly buffer Pb { uint pb[]; };
                layout(set = 0, binding = 6) writeonly buffer Runs { float runs[]; };
                layout(set = 0, binding = 7) writeonly buffer Gaps { float gaps[]; };
                layout(push_constant) uniform Params { uint len; };
                void main() {
                    uint i = gl_GlobalInvocationID.x;
                    if (i >= len) return;
                    uint ia = pa[i];
                    uint ib = pb[i];
                    float a_xmin = xmin[ia], a_ymin = ymin[ia], a_xmax = xmax[ia], a_ymax = ymax[ia];
                    float b_xmin = xmin[ib], b_ymin = ymin[ib], b_xmax = xmax[ib], b_ymax = ymax[ib];

                    // coupling_run
                    float run = 0.0;
                    float rgap = 0.0;
                    float x_overlap = min(a_xmax, b_xmax) - max(a_xmin, b_xmin);
                    if (x_overlap > 0.0) {
                        if (a_ymax <= b_ymin) {
                            run = max(x_overlap, 0.0);
                            rgap = max(b_ymin - a_ymax, 0.0);
                        } else if (b_ymax <= a_ymin) {
                            run = max(x_overlap, 0.0);
                            rgap = max(a_ymin - b_ymax, 0.0);
                        }
                    }
                    if (rgap <= 0.0) {
                        float y_overlap = min(a_ymax, b_ymax) - max(a_ymin, b_ymin);
                        if (y_overlap > 0.0) {
                            if (a_xmax <= b_xmin) {
                                run = max(y_overlap, 0.0);
                            } else if (b_xmax <= a_xmin) {
                                run = max(y_overlap, 0.0);
                            }
                        }
                    }

                    // coupling_gap
                    float gap = 0.0;
                    if (x_overlap > 0.0) {
                        if (a_ymax <= b_ymin) {
                            gap = max(b_ymin - a_ymax, 0.0);
                        } else if (b_ymax <= a_ymin) {
                            gap = max(a_ymin - b_ymax, 0.0);
                        }
                    }
                    if (gap <= 0.0) {
                        float y_overlap = min(a_ymax, b_ymax) - max(a_ymin, b_ymin);
                        if (y_overlap > 0.0) {
                            if (a_xmax <= b_xmin) {
                                gap = max(b_xmin - a_xmax, 0.0);
                            } else if (b_xmax <= a_xmin) {
                                gap = max(a_xmin - b_xmax, 0.0);
                            }
                        }
                    }

                    runs[i] = run;
                    gaps[i] = gap;
                }
            ",
        }
    }

    pub fn coupling_pairs(
        xmin: &[f32], ymin: &[f32], xmax: &[f32], ymax: &[f32],
        pa: &[u32], pb: &[u32],
    ) -> Option<(Vec<f32>, Vec<f32>)> {
        let ctx = gpu::context()?;
        // AssertUnwindSafe: `ctx` (device/allocators) is only read here; a device
        // panic mid-dispatch leaves nothing shared in a torn state — we discard
        // the whole attempt and fall back to the CPU loop.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let n = pa.len();
            let cxmin = ctx.upload(xmin);
            let cymin = ctx.upload(ymin);
            let cxmax = ctx.upload(xmax);
            let cymax = ctx.upload(ymax);
            let cpa = ctx.upload(pa);
            let cpb = ctx.upload(pb);
            let runs = ctx.output::<f32>(n);
            let gaps = ctx.output::<f32>(n);

            let module = shader::load(ctx.device().clone()).expect("load coupling shader");
            let pipeline = ctx.compute_pipeline(&module);
            let layout = pipeline.layout().clone();
            let set_layout = layout.set_layouts().first().expect("set layout").clone();
            let set = DescriptorSet::new(
                ctx.descriptors().clone(),
                set_layout,
                [
                    WriteDescriptorSet::buffer(0, cxmin),
                    WriteDescriptorSet::buffer(1, cymin),
                    WriteDescriptorSet::buffer(2, cxmax),
                    WriteDescriptorSet::buffer(3, cymax),
                    WriteDescriptorSet::buffer(4, cpa),
                    WriteDescriptorSet::buffer(5, cpb),
                    WriteDescriptorSet::buffer(6, runs.clone()),
                    WriteDescriptorSet::buffer(7, gaps.clone()),
                ],
                [],
            )
            .expect("descriptor set");

            let mut builder = ctx.command_builder();
            builder
                .bind_pipeline_compute(pipeline.clone())
                .unwrap()
                .bind_descriptor_sets(PipelineBindPoint::Compute, layout.clone(), 0, vec![set])
                .unwrap()
                .push_constants(layout, 0, shader::Params { len: n as u32 })
                .unwrap();
            let groups = (n as u32).div_ceil(64);
            unsafe {
                builder.dispatch([groups, 1, 1]).unwrap();
            }
            ctx.execute_and_wait(builder);

            let r = runs.read().expect("read runs").to_vec();
            let g = gaps.read().expect("read gaps").to_vec();
            (r, g)
        }))
        .ok()
    }
}

#[cfg(all(test, feature = "gpu"))]
mod gpu_tests {
    use super::{coupling_gap, coupling_run, gpu};

    #[test]
    fn gpu_pairs_equal_cpu() {
        if gdsverify_backend::gpu::context().is_none() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        }
        eprintln!(
            "gpu test on device: {}",
            gdsverify_backend::gpu::context().unwrap().device_name()
        );

        // Fixed geometry: a spread of bboxes exercising every branch (facing in y,
        // facing in x, overlapping, touching, not facing).
        let xmin = vec![0.0f32, 0.0, 5.0, 20.0, 0.0, 100.0];
        let ymin = vec![0.0f32, 20.0, 0.0, 0.0, 0.0, 100.0];
        let xmax = vec![10.0f32, 10.0, 15.0, 30.0, 10.0, 110.0];
        let ymax = vec![10.0f32, 30.0, 10.0, 10.0, 5.0, 110.0];
        let n = xmin.len();
        let (mut pa, mut pb) = (Vec::new(), Vec::new());
        for i in 0..n {
            for j in (i + 1)..n {
                pa.push(i as u32);
                pb.push(j as u32);
            }
        }

        let (runs, gaps) = gpu::coupling_pairs(&xmin, &ymin, &xmax, &ymax, &pa, &pb)
            .expect("gpu dispatch");

        for k in 0..pa.len() {
            let (ia, ib) = (pa[k] as usize, pb[k] as usize);
            let cpu_run = coupling_run(
                xmin[ia], ymin[ia], xmax[ia], ymax[ia],
                xmin[ib], ymin[ib], xmax[ib], ymax[ib],
            );
            let cpu_gap = coupling_gap(
                xmin[ia], ymin[ia], xmax[ia], ymax[ia],
                xmin[ib], ymin[ib], xmax[ib], ymax[ib],
            );
            assert_eq!(runs[k], cpu_run, "run mismatch at pair {k} ({ia},{ib})");
            assert_eq!(gaps[k], cpu_gap, "gap mismatch at pair {k} ({ia},{ib})");
        }
    }
}
