//! GPU bbox/rect overlap PAIR kernel (Vulkano, AOT SPIR-V).
//!
//! One dispatch computes, for each candidate pair `i`,
//! `out[i] = bbox_overlap(box[pairs_a[i]], box[pairs_b[i]])` where the boxes
//! are stored column-wise (`x0,y0,x1,y1`). The predicate is the positive-area
//! (open-interval) overlap of the original CubeCL `bbox_overlap` kernel:
//! `1` iff the clamped intersection has strictly positive width and height.
//!
//! The whole path is `#[cfg(feature = "gpu")]`; the CPU build never sees it.
//! Every entry point is reached through [`gpu::context`], which is
//! panic-contained, so a device failure degrades to the caller's CPU path.

use gdsverify_backend::gpu;
use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
use vulkano::pipeline::{Pipeline, PipelineBindPoint};

// GLSL translation of the original `bbox_overlap` pair predicate. Boxes are
// four parallel i32 columns; each invocation handles one (a, b) pair index.
mod shader {
    vulkano_shaders::shader! {
        ty: "compute",
        src: r"
            #version 460
            layout(local_size_x = 256) in;
            layout(set = 0, binding = 0) readonly buffer X0 { int x0[]; };
            layout(set = 0, binding = 1) readonly buffer Y0 { int y0[]; };
            layout(set = 0, binding = 2) readonly buffer X1 { int x1[]; };
            layout(set = 0, binding = 3) readonly buffer Y1 { int y1[]; };
            layout(set = 0, binding = 4) readonly buffer A  { uint pa[]; };
            layout(set = 0, binding = 5) readonly buffer B  { uint pb[]; };
            layout(set = 0, binding = 6) writeonly buffer O { uint o[];  };
            layout(push_constant) uniform Params { uint len; };
            void main() {
                uint i = gl_GlobalInvocationID.x;
                if (i >= len) return;
                uint a = pa[i];
                uint b = pb[i];
                int ix0 = max(x0[a], x0[b]);
                int iy0 = max(y0[a], y0[b]);
                int ix1 = min(x1[a], x1[b]);
                int iy1 = min(y1[a], y1[b]);
                o[i] = (ix1 > ix0 && iy1 > iy0) ? 1u : 0u;
            }
        ",
    }
}

/// CPU reference for the same predicate — the single source of truth the GPU
/// path is checked against. Kept here (not in `extract`) so the test can hold
/// GPU and CPU side by side.
#[must_use]
pub fn bbox_overlap_cpu(
    x0: &[i32],
    y0: &[i32],
    x1: &[i32],
    y1: &[i32],
    pairs_a: &[u32],
    pairs_b: &[u32],
) -> Vec<u32> {
    pairs_a
        .iter()
        .zip(pairs_b)
        .map(|(&a, &b)| {
            let (a, b) = (a as usize, b as usize);
            let ix0 = x0[a].max(x0[b]);
            let iy0 = y0[a].max(y0[b]);
            let ix1 = x1[a].min(x1[b]);
            let iy1 = y1[a].min(y1[b]);
            u32::from(ix1 > ix0 && iy1 > iy0)
        })
        .collect()
}

/// Run the PAIR bbox-overlap kernel on the GPU. Returns `None` when no device
/// is available (caller falls back to [`bbox_overlap_cpu`]). Panic-contained:
/// any dispatch failure degrades to `None`.
#[must_use]
pub fn bbox_overlap_pairs_gpu(
    x0: &[i32],
    y0: &[i32],
    x1: &[i32],
    y1: &[i32],
    pairs_a: &[u32],
    pairs_b: &[u32],
) -> Option<Vec<u32>> {
    let ctx = gpu::context()?;
    let len = pairs_a.len();
    if len == 0 {
        return Some(Vec::new());
    }
    // AssertUnwindSafe: `ctx` is a shared read-only handle to allocators and
    // the device; a panic mid-dispatch leaves no half-written host state we
    // observe afterwards (we discard the result on `Err`).
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bx0 = ctx.upload(x0);
        let by0 = ctx.upload(y0);
        let bx1 = ctx.upload(x1);
        let by1 = ctx.upload(y1);
        let ba = ctx.upload(pairs_a);
        let bb = ctx.upload(pairs_b);
        let out = ctx.output::<u32>(len);

        let module = shader::load(ctx.device().clone()).expect("load overlap shader");
        let pipeline = ctx.compute_pipeline(&module);
        let layout = pipeline.layout().clone();
        let set_layout = layout.set_layouts().first().expect("set layout").clone();
        let set = DescriptorSet::new(
            ctx.descriptors().clone(),
            set_layout,
            [
                WriteDescriptorSet::buffer(0, bx0),
                WriteDescriptorSet::buffer(1, by0),
                WriteDescriptorSet::buffer(2, bx1),
                WriteDescriptorSet::buffer(3, by1),
                WriteDescriptorSet::buffer(4, ba),
                WriteDescriptorSet::buffer(5, bb),
                WriteDescriptorSet::buffer(6, out.clone()),
            ],
            [],
        )
        .expect("descriptor set");

        let groups = (len as u32).div_ceil(256);
        let mut builder = ctx.command_builder();
        builder
            .bind_pipeline_compute(pipeline.clone())
            .unwrap()
            .bind_descriptor_sets(PipelineBindPoint::Compute, layout.clone(), 0, vec![set])
            .unwrap()
            .push_constants(
                layout,
                0,
                shader::Params {
                    len: len as u32,
                },
            )
            .unwrap();
        unsafe {
            builder.dispatch([groups, 1, 1]).unwrap();
        }
        ctx.execute_and_wait(builder);
        let result = out.read().expect("read overlap output").to_vec();
        result
    }))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap xorshift so the test needs no rng dependency.
    fn rng(state: &mut u64) -> u32 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        (x >> 32) as u32
    }

    #[test]
    fn gpu_bbox_overlap_matches_cpu() {
        if gpu::context().is_none() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        }
        eprintln!(
            "gpu test on device: {}",
            gpu::context().unwrap().device_name()
        );

        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let n = 4096usize; // number of boxes
        let mut x0 = Vec::with_capacity(n);
        let mut y0 = Vec::with_capacity(n);
        let mut x1 = Vec::with_capacity(n);
        let mut y1 = Vec::with_capacity(n);
        for _ in 0..n {
            let bx = (rng(&mut s) % 2000) as i32 - 1000;
            let by = (rng(&mut s) % 2000) as i32 - 1000;
            let w = (rng(&mut s) % 200) as i32; // zero-width included → open-interval matters
            let h = (rng(&mut s) % 200) as i32;
            x0.push(bx);
            y0.push(by);
            x1.push(bx + w);
            y1.push(by + h);
        }
        let pairs = 1 << 15; // > 32k pairs, one dispatch
        let mut pa = Vec::with_capacity(pairs);
        let mut pb = Vec::with_capacity(pairs);
        for _ in 0..pairs {
            pa.push(rng(&mut s) % n as u32);
            pb.push(rng(&mut s) % n as u32);
        }

        let cpu = bbox_overlap_cpu(&x0, &y0, &x1, &y1, &pa, &pb);
        let gpu = bbox_overlap_pairs_gpu(&x0, &y0, &x1, &y1, &pa, &pb)
            .expect("gpu path returned None despite a device");
        assert_eq!(gpu, cpu, "GPU overlap flags must equal CPU flags");
    }
}
