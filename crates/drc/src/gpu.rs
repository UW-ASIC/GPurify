//! GPU advisory prefilters for DRC map/pair rules (feature `gpu`).
//!
//! Every kernel here is an ADVISORY PREFILTER: it produces a per-item u32
//! candidate flag that is a **superset** of the CPU-exact hits (it may flag
//! extra items, never miss a real one). The exact CPU verdict then runs on the
//! flagged items, so the DrcReport is identical whether the GPU ran or not.
//!
//! All dispatch is panic-contained via [`gdsverify_backend::gpu::context`]; a
//! missing/broken device degrades to the pure-CPU path, never a crash.

use gdsverify_backend::gpu::context;
use gdsverify_core::geometry::Edge;
use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
use vulkano::pipeline::{Pipeline, PipelineBindPoint};

/// Below this element count the launch/readback overhead isn't worth it — the
/// CPU path handles it. ponytail: fixed threshold; tune if profiling says so.
pub const GPU_MIN_LINEAR_WORK: usize = 4096;

fn groups(len: usize) -> [u32; 3] {
    let g = (len as u32).div_ceil(64).max(1);
    [g, 1, 1]
}

// --- offgrid_flag: v % grid != 0 (exact integer, GPU flags authoritative) ----
mod offgrid_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        src: r"
            #version 460
            layout(local_size_x = 64) in;
            layout(set = 0, binding = 0) readonly buffer X { int x[]; };
            layout(set = 0, binding = 1) readonly buffer Y { int y[]; };
            layout(set = 0, binding = 2) writeonly buffer O { uint o[]; };
            layout(push_constant) uniform Params { uint len; int grid; };
            void main() {
                uint i = gl_GlobalInvocationID.x;
                if (i >= len) return;
                uint f = 0u;
                // GLSL % is undefined for negative operands; grid > 0 and
                // v % grid == 0 iff abs(v) % grid == 0, so normalize the sign.
                if ((abs(x[i]) % grid) != 0 || (abs(y[i]) % grid) != 0) f = 1u;
                o[i] = f;
            }
        ",
    }
}

/// Per-vertex flag: 1 iff off-grid. Exact integer remainder — the same verdict
/// as the CPU. Returns `None` if no GPU. Panic-contained.
#[must_use]
pub fn offgrid_flag(verts_x: &[i32], verts_y: &[i32], grid: i32) -> Option<Vec<u32>> {
    let ctx = context()?;
    let len = verts_x.len();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bx = ctx.upload(verts_x);
        let by = ctx.upload(verts_y);
        let out = ctx.output::<u32>(len);
        let module = offgrid_shader::load(ctx.device().clone()).expect("load offgrid");
        let pipeline = ctx.compute_pipeline(&module);
        let layout = pipeline.layout().clone();
        let set = DescriptorSet::new(
            ctx.descriptors().clone(),
            layout.set_layouts()[0].clone(),
            [
                WriteDescriptorSet::buffer(0, bx),
                WriteDescriptorSet::buffer(1, by),
                WriteDescriptorSet::buffer(2, out.clone()),
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
            .push_constants(
                layout,
                0,
                offgrid_shader::Params { len: len as u32, grid },
            )
            .unwrap();
        unsafe {
            builder.dispatch(groups(len)).unwrap();
        }
        ctx.execute_and_wait(builder);
        let r = out.read().expect("read output").to_vec();
        r
    }))
    .ok()
}

// --- angle_dev: min over allowed of |sin(edge - allowed)| ---------------------
mod angle_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        src: r"
            #version 460
            layout(local_size_x = 64) in;
            layout(set = 0, binding = 0) readonly buffer X0 { float x0[]; };
            layout(set = 0, binding = 1) readonly buffer Y0 { float y0[]; };
            layout(set = 0, binding = 2) readonly buffer X1 { float x1[]; };
            layout(set = 0, binding = 3) readonly buffer Y1 { float y1[]; };
            layout(set = 0, binding = 4) readonly buffer SN { float sn[]; };
            layout(set = 0, binding = 5) readonly buffer CS { float cs[]; };
            layout(set = 0, binding = 6) writeonly buffer O { float o[]; };
            layout(push_constant) uniform Params { uint len; uint n_ang; };
            void main() {
                uint i = gl_GlobalInvocationID.x;
                if (i >= len) return;
                float dx = x1[i] - x0[i];
                float dy = y1[i] - y0[i];
                float l = sqrt(dx * dx + dy * dy);
                float best = 1e30;
                for (uint a = 0u; a < n_ang; a++) {
                    float dev = 0.0;
                    if (l > 0.0) dev = abs(dx * sn[a] - dy * cs[a]) / l;
                    best = min(best, dev);
                }
                o[i] = best;
            }
        ",
    }
}

/// Per-edge min deviation `|sin(edge - allowed)|` over allowed angles. Advisory
/// f32 prefilter. Returns `None` if no GPU. Panic-contained.
#[must_use]
pub fn angle_dev(
    x0: &[f32],
    y0: &[f32],
    x1: &[f32],
    y1: &[f32],
    sins: &[f32],
    coss: &[f32],
) -> Option<Vec<f32>> {
    let ctx = context()?;
    let len = x0.len();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bx0 = ctx.upload(x0);
        let by0 = ctx.upload(y0);
        let bx1 = ctx.upload(x1);
        let by1 = ctx.upload(y1);
        let bsn = ctx.upload(sins);
        let bcs = ctx.upload(coss);
        let out = ctx.output::<f32>(len);
        let module = angle_shader::load(ctx.device().clone()).expect("load angle");
        let pipeline = ctx.compute_pipeline(&module);
        let layout = pipeline.layout().clone();
        let set = DescriptorSet::new(
            ctx.descriptors().clone(),
            layout.set_layouts()[0].clone(),
            [
                WriteDescriptorSet::buffer(0, bx0),
                WriteDescriptorSet::buffer(1, by0),
                WriteDescriptorSet::buffer(2, bx1),
                WriteDescriptorSet::buffer(3, by1),
                WriteDescriptorSet::buffer(4, bsn),
                WriteDescriptorSet::buffer(5, bcs),
                WriteDescriptorSet::buffer(6, out.clone()),
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
            .push_constants(
                layout,
                0,
                angle_shader::Params {
                    len: len as u32,
                    n_ang: sins.len() as u32,
                },
            )
            .unwrap();
        unsafe {
            builder.dispatch(groups(len)).unwrap();
        }
        ctx.execute_and_wait(builder);
        let r = out.read().expect("read output").to_vec();
        r
    }))
    .ok()
}

// --- edge_len2_approx: f32 squared edge length --------------------------------
mod edgelen_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        src: r"
            #version 460
            layout(local_size_x = 64) in;
            layout(set = 0, binding = 0) readonly buffer X0 { float x0[]; };
            layout(set = 0, binding = 1) readonly buffer Y0 { float y0[]; };
            layout(set = 0, binding = 2) readonly buffer X1 { float x1[]; };
            layout(set = 0, binding = 3) readonly buffer Y1 { float y1[]; };
            layout(set = 0, binding = 4) writeonly buffer O { float o[]; };
            layout(push_constant) uniform Params { uint len; };
            void main() {
                uint i = gl_GlobalInvocationID.x;
                if (i >= len) return;
                float dx = x1[i] - x0[i];
                float dy = y1[i] - y0[i];
                o[i] = dx * dx + dy * dy;
            }
        ",
    }
}

/// Per-edge f32 squared length. Advisory prefilter; the exact i128 length
/// decides. Returns `None` if no GPU. Panic-contained.
#[must_use]
pub fn edge_len2_approx(x0: &[f32], y0: &[f32], x1: &[f32], y1: &[f32]) -> Option<Vec<f32>> {
    let ctx = context()?;
    let len = x0.len();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bx0 = ctx.upload(x0);
        let by0 = ctx.upload(y0);
        let bx1 = ctx.upload(x1);
        let by1 = ctx.upload(y1);
        let out = ctx.output::<f32>(len);
        let module = edgelen_shader::load(ctx.device().clone()).expect("load edgelen");
        let pipeline = ctx.compute_pipeline(&module);
        let layout = pipeline.layout().clone();
        let set = DescriptorSet::new(
            ctx.descriptors().clone(),
            layout.set_layouts()[0].clone(),
            [
                WriteDescriptorSet::buffer(0, bx0),
                WriteDescriptorSet::buffer(1, by0),
                WriteDescriptorSet::buffer(2, bx1),
                WriteDescriptorSet::buffer(3, by1),
                WriteDescriptorSet::buffer(4, out.clone()),
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
            .push_constants(layout, 0, edgelen_shader::Params { len: len as u32 })
            .unwrap();
        unsafe {
            builder.dispatch(groups(len)).unwrap();
        }
        ctx.execute_and_wait(builder);
        let r = out.read().expect("read output").to_vec();
        r
    }))
    .ok()
}

/// Split a flat `&[Edge]` into the four f32 coordinate columns kernels want.
#[must_use]
pub fn edge_cols(edges: &[Edge]) -> (Vec<f32>, Vec<f32>, Vec<f32>, Vec<f32>) {
    let mut x0 = Vec::with_capacity(edges.len());
    let mut y0 = Vec::with_capacity(edges.len());
    let mut x1 = Vec::with_capacity(edges.len());
    let mut y1 = Vec::with_capacity(edges.len());
    for e in edges {
        x0.push(e.x0 as f32);
        y0.push(e.y0 as f32);
        x1.push(e.x1 as f32);
        y1.push(e.y1 as f32);
    }
    (x0, y0, x1, y1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn have_gpu() -> bool {
        context().is_some()
    }

    #[test]
    fn offgrid_gpu_equals_cpu() {
        if !have_gpu() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        }
        eprintln!("gpu test on device: {}", context().unwrap().device_name());
        let grid = 5i32;
        let xs: Vec<i32> = (0..5000).map(|i| i - 2500).collect();
        let ys: Vec<i32> = (0..5000).map(|i| (i * 3) - 100).collect();
        let got = offgrid_flag(&xs, &ys, grid).expect("gpu ran");
        for i in 0..xs.len() {
            let cpu = u32::from(xs[i] % grid != 0 || ys[i] % grid != 0);
            assert_eq!(got[i], cpu, "offgrid mismatch at {i}");
        }
    }

    #[test]
    fn edge_len2_superset_of_cpu_hits() {
        if !have_gpu() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        }
        // Build edges; CPU-exact hit = len2 in (0, min2). GPU keeps candidates
        // with approx < thr. Assert every CPU hit survives the prefilter.
        let min = 100i32;
        let min2 = (min as i64) * (min as i64);
        let thr = (min as f32) * (min as f32) * 1.05 + 4.0;
        let edges: Vec<Edge> = (0..5000)
            .map(|i| Edge {
                x0: 0,
                y0: 0,
                x1: (i % 200),
                y1: ((i * 7) % 200),
                poly: 0,
            })
            .collect();
        let (x0, y0, x1, y1) = edge_cols(&edges);
        let approx = edge_len2_approx(&x0, &y0, &x1, &y1).expect("gpu ran");
        for (i, e) in edges.iter().enumerate() {
            let l2 = e.len2_i128();
            let cpu_hit = l2 > 0 && l2 < i128::from(min2);
            let kept = approx[i] < thr;
            if cpu_hit {
                assert!(kept, "prefilter dropped a real hit at {i}: approx={}", approx[i]);
            }
        }
    }

    #[test]
    fn angle_dev_superset_of_cpu_hits() {
        if !have_gpu() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        }
        const SIN_04_DEG: f32 = 0.006_981_3;
        let allowed = [0i32, 45, 90, 135];
        let sins: Vec<f32> = allowed.iter().map(|&a| (a as f32).to_radians().sin()).collect();
        let coss: Vec<f32> = allowed.iter().map(|&a| (a as f32).to_radians().cos()).collect();
        let edges: Vec<Edge> = (0..5000)
            .map(|i| Edge {
                x0: 0,
                y0: 0,
                x1: 1000 + (i % 137),
                y1: (i * 11) % 300,
                poly: 0,
            })
            .collect();
        let (x0, y0, x1, y1) = edge_cols(&edges);
        let dev = angle_dev(&x0, &y0, &x1, &y1, &sins, &coss).expect("gpu ran");
        // Any edge the CPU would flag (not matching an allowed angle) must NOT
        // be prefiltered away, i.e. its dev must be >= SIN_04_DEG.
        for (i, e) in edges.iter().enumerate() {
            let ang = {
                let a = (e.dy() as f64).atan2(e.dx() as f64).to_degrees();
                let mut a = a % 180.0;
                if a < 0.0 {
                    a += 180.0;
                }
                a
            };
            let cpu_ok = allowed.iter().any(|&al| {
                let t = (al as f64) % 180.0;
                (ang - t).abs() < 0.5 || (ang - t - 180.0).abs() < 0.5
            });
            if !cpu_ok {
                assert!(
                    dev[i] >= SIN_04_DEG,
                    "prefilter dropped a violating edge at {i}: dev={}",
                    dev[i]
                );
            }
        }
    }
}
