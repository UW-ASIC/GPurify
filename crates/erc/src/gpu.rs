//! GPU advisory prefilters for ERC map rules (feature `gpu`).
//!
//! Same model as [`gdsverify_drc::gpu`]: each kernel produces a per-item u32
//! candidate flag that is a **superset** of the CPU-exact hits (it may flag
//! extra items, never miss a real one). The exact CPU verdict then runs on the
//! flagged items, so the `ErcReport` is identical whether the GPU ran or not.
//!
//! All dispatch is panic-contained via [`gdsverify_backend::gpu::context`]; a
//! missing/broken device degrades to the pure-CPU path, never a crash.

use gdsverify_backend::gpu::context;
use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
use vulkano::pipeline::{Pipeline, PipelineBindPoint};

/// Below this element count the launch/readback overhead isn't worth it — the
/// CPU path handles it. ponytail: fixed threshold; tune if profiling says so.
pub const GPU_MIN_LINEAR_WORK: usize = 4096;

fn groups(len: usize) -> [u32; 3] {
    let g = (len as u32).div_ceil(64).max(1);
    [g, 1, 1]
}

// --- em_narrow_flag: min(width, height) < min_width -------------------------
//
// Width/height are 32-bit spans (`xmax - xmin`), matching `Bbox::width`. On the
// pathological full-i32-range box the subtraction wraps, but that can only turn
// a genuinely WIDE box into a false "narrow" flag (never hide a narrow one), so
// the flag stays a valid superset; the CPU recomputes the exact `Bbox::width`
// on flagged items before emitting.
mod em_narrow_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        src: r"
            #version 460
            layout(local_size_x = 64) in;
            layout(set = 0, binding = 0) readonly buffer X0 { int xmin[]; };
            layout(set = 0, binding = 1) readonly buffer Y0 { int ymin[]; };
            layout(set = 0, binding = 2) readonly buffer X1 { int xmax[]; };
            layout(set = 0, binding = 3) readonly buffer Y1 { int ymax[]; };
            layout(set = 0, binding = 4) writeonly buffer O { uint o[]; };
            layout(push_constant) uniform Params { uint len; int min_width; };
            void main() {
                uint i = gl_GlobalInvocationID.x;
                if (i >= len) return;
                int w = xmax[i] - xmin[i];
                int h = ymax[i] - ymin[i];
                o[i] = (w < min_width || h < min_width) ? 1u : 0u;
            }
        ",
    }
}

/// Per-polygon flag: 1 iff `min(width, height) < min_width` (advisory superset).
/// Returns `None` if no GPU. Panic-contained.
#[must_use]
pub fn em_narrow_flags(
    xmin: &[i32],
    ymin: &[i32],
    xmax: &[i32],
    ymax: &[i32],
    min_width: i32,
) -> Option<Vec<u32>> {
    let ctx = context()?;
    let len = xmin.len();
    if len == 0 {
        return Some(Vec::new());
    }
    // AssertUnwindSafe: `ctx` is a shared read-only handle; a panic mid-dispatch
    // leaves no host state we observe (the result is discarded on `Err`).
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bx0 = ctx.upload(xmin);
        let by0 = ctx.upload(ymin);
        let bx1 = ctx.upload(xmax);
        let by1 = ctx.upload(ymax);
        let out = ctx.output::<u32>(len);

        let module = em_narrow_shader::load(ctx.device().clone()).expect("load em_narrow");
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
            .push_constants(
                layout,
                0,
                em_narrow_shader::Params {
                    len: len as u32,
                    min_width,
                },
            )
            .unwrap();
        unsafe {
            builder.dispatch(groups(len)).unwrap();
        }
        ctx.execute_and_wait(builder);
        let result = out.read().expect("read em_narrow output").to_vec();
        result
    }))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_em_narrow_matches_cpu() {
        if context().is_none() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        }
        // Cheap xorshift; no rng dependency.
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        let mut rng = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 32) as u32
        };
        let min_width = 140i32;
        let n = 1 << 14;
        let (mut xmin, mut ymin, mut xmax, mut ymax) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for _ in 0..n {
            let x = (rng() % 4000) as i32 - 2000;
            let y = (rng() % 4000) as i32 - 2000;
            let w = (rng() % 300) as i32; // straddles min_width
            let h = (rng() % 300) as i32;
            xmin.push(x);
            ymin.push(y);
            xmax.push(x + w);
            ymax.push(y + h);
        }
        let cpu: Vec<u32> = (0..n)
            .map(|i| {
                let w = xmax[i] - xmin[i];
                let h = ymax[i] - ymin[i];
                u32::from(w.min(h) < min_width)
            })
            .collect();
        let gpu = em_narrow_flags(&xmin, &ymin, &xmax, &ymax, min_width)
            .expect("gpu path returned None despite a device");
        assert_eq!(gpu, cpu, "GPU narrow flags must equal CPU flags");
    }
}
