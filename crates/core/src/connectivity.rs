//! Connected components over an edge list.
//!
//! Each node is labeled with the **minimum node index** in its component, so
//! two runs on the same graph give identical labels and two graphs with the
//! same partition give identical labels.
//!
//! On the CPU this is a weighted union-find with path halving — the direct,
//! cache-friendly way to do it. (The previous design ran a parallel
//! label-propagation, FastSV / ECL-CC, through a device session so the *same*
//! code could target the GPU via a transpiling macro. With hand-written GLSL
//! that shared path is gone: the GPU gets its own label-propagation kernels in
//! the `gpu` module, and the CPU gets the algorithm that is actually fastest on
//! a CPU.)

/// Weighted union-find that always roots a component at its smallest index, so
/// `find` yields the min-index label directly. Path halving keeps `find`
/// near-constant amortized.
struct MinUnionFind {
    parent: Vec<u32>,
}

impl MinUnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..u32::try_from(n).unwrap_or(u32::MAX)).collect(),
        }
    }

    fn find(&mut self, x: u32) -> u32 {
        let mut x = x;
        while self.parent[x as usize] != x {
            // Path halving: point each node to its grandparent.
            let grand = self.parent[self.parent[x as usize] as usize];
            self.parent[x as usize] = grand;
            x = grand;
        }
        x
    }

    /// Union `a` and `b`, keeping the smaller root so labels stay min-indexed.
    fn union(&mut self, a: u32, b: u32) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        let (lo, hi) = (ra.min(rb), ra.max(rb));
        self.parent[hi as usize] = lo;
    }

    /// Flatten every node to its (min-index) root.
    fn into_labels(mut self) -> Vec<u32> {
        for i in 0..self.parent.len() {
            let root = self.find(u32::try_from(i).unwrap_or(u32::MAX));
            self.parent[i] = root;
        }
        self.parent
    }
}

/// Component labels for `n` nodes over `edges`, each node labeled with the
/// minimum node index in its component.
///
/// Edges to out-of-range endpoints and self-loops are ignored. Isolated nodes
/// (including every node when `edges` is empty) are their own component.
#[must_use]
pub fn connected_components(edges: &[(u32, u32)], n: usize) -> Vec<u32> {
    let mut uf = MinUnionFind::new(n);
    for &(u, v) in edges {
        if (u as usize) < n && (v as usize) < n && u != v {
            uf.union(u, v);
        }
    }
    uf.into_labels()
}

/// Alias kept for callers that name the host union-find explicitly (LVS net
/// extraction). Identical semantics to [`connected_components`].
#[must_use]
pub fn host_union_find(edges: &[(u32, u32)], n: usize) -> Vec<u32> {
    connected_components(edges, n)
}

/// Connected components via the requested backend. Uses the GPU FastSV path
/// when `backend == Gpu` and it succeeds (a device exists and no failure),
/// otherwise the CPU union-find. Result is identical either way (min-index
/// component labels).
#[must_use]
pub fn connected_components_backend(
    backend: gdsverify_backend::Backend,
    edges: &[(u32, u32)],
    n: usize,
) -> Vec<u32> {
    #[cfg(feature = "gpu")]
    if backend == gdsverify_backend::Backend::Gpu {
        if let Some(labels) = connected_components_gpu(edges, n) {
            return labels;
        }
    }
    let _ = backend;
    connected_components(edges, n)
}

/// GPU FastSV connected components. Returns `None` if there is no usable device
/// or any GPU step fails (all failures are panic-contained via [`context`] and a
/// `catch_unwind` around the dispatch). On success, labels match
/// [`connected_components`] exactly.
#[cfg(feature = "gpu")]
#[must_use]
pub fn connected_components_gpu(edges: &[(u32, u32)], n: usize) -> Option<Vec<u32>> {
    gpu::fastsv(edges, n)
}

// ---------------------------------------------------------------------------
// GPU FastSV (hand-written GLSL, AOT SPIR-V via Vulkano)
// ---------------------------------------------------------------------------

#[cfg(feature = "gpu")]
mod gpu {
    use gdsverify_backend::gpu::context;
    use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
    use vulkano::pipeline::{Pipeline, PipelineBindPoint};

    // sc_gather: out[i] = f[f[i]] (the original pair-gather shortcut).
    mod sc_gather {
        vulkano_shaders::shader! {
            ty: "compute",
            src: r"
                #version 460
                layout(local_size_x = 64) in;
                layout(set = 0, binding = 0) readonly buffer F { uint f[]; };
                layout(set = 0, binding = 1) writeonly buffer O { uint o[]; };
                layout(push_constant) uniform Params { uint n; };
                void main() {
                    uint i = gl_GlobalInvocationID.x;
                    if (i >= n) return;
                    o[i] = f[f[i]];
                }
            ",
        }
    }

    // neighbor_min: segmented-min over CSR. out[i] = min(f[i], min over
    // neighbors j in [seg[i], seg[i+1]) of f[nbr[j]]).
    mod neighbor_min {
        vulkano_shaders::shader! {
            ty: "compute",
            src: r"
                #version 460
                layout(local_size_x = 64) in;
                layout(set = 0, binding = 0) readonly buffer F { uint f[]; };
                layout(set = 0, binding = 1) readonly buffer Nbr { uint nbr[]; };
                layout(set = 0, binding = 2) readonly buffer Seg { uint seg[]; };
                layout(set = 0, binding = 3) writeonly buffer O { uint o[]; };
                layout(push_constant) uniform Params { uint n; };
                void main() {
                    uint i = gl_GlobalInvocationID.x;
                    if (i >= n) return;
                    uint m = f[i];
                    uint s = seg[i];
                    uint e = seg[i + 1];
                    for (uint j = s; j < e; ++j) {
                        uint fv = f[nbr[j]];
                        if (fv < m) m = fv;
                    }
                    o[i] = m;
                }
            ",
        }
    }

    // combine: f_next[i] = min(f[i], sc[i], nb[i]).
    mod combine {
        vulkano_shaders::shader! {
            ty: "compute",
            src: r"
                #version 460
                layout(local_size_x = 64) in;
                layout(set = 0, binding = 0) readonly buffer F { uint f[]; };
                layout(set = 0, binding = 1) readonly buffer Sc { uint sc[]; };
                layout(set = 0, binding = 2) readonly buffer Nb { uint nb[]; };
                layout(set = 0, binding = 3) writeonly buffer O { uint o[]; };
                layout(push_constant) uniform Params { uint n; };
                void main() {
                    uint i = gl_GlobalInvocationID.x;
                    if (i >= n) return;
                    uint r = f[i];
                    if (sc[i] < r) r = sc[i];
                    if (nb[i] < r) r = nb[i];
                    o[i] = r;
                }
            ",
        }
    }

    /// Symmetric CSR from an edge list, matching the original host builder:
    /// self-loops and out-of-range endpoints dropped, each kept edge counted
    /// both directions. Returns `(neighbors, seg_start)` with `seg_start.len() == n+1`.
    fn build_csr(edges: &[(u32, u32)], n: usize) -> (Vec<u32>, Vec<u32>) {
        let mut deg = vec![0u32; n];
        for &(u, v) in edges {
            if u == v || u as usize >= n || v as usize >= n {
                continue;
            }
            deg[u as usize] += 1;
            deg[v as usize] += 1;
        }
        let mut seg_start = Vec::with_capacity(n + 1);
        seg_start.push(0u32);
        for &d in &deg {
            seg_start.push(seg_start.last().unwrap() + d);
        }
        let total = *seg_start.last().unwrap() as usize;
        let mut neighbors = vec![0u32; total];
        let mut cursor = seg_start[..n].to_vec();
        for &(u, v) in edges {
            if u == v || u as usize >= n || v as usize >= n {
                continue;
            }
            neighbors[cursor[u as usize] as usize] = v;
            cursor[u as usize] += 1;
            neighbors[cursor[v as usize] as usize] = u;
            cursor[v as usize] += 1;
        }
        (neighbors, seg_start)
    }

    /// GPU FastSV. `None` on no-device / any failure (panic-contained).
    pub fn fastsv(edges: &[(u32, u32)], n: usize) -> Option<Vec<u32>> {
        if n == 0 {
            return Some(Vec::new());
        }
        if edges.is_empty() {
            return Some((0..n as u32).collect());
        }
        let ctx = context()?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(ctx, edges, n))).ok()
    }

    fn run(
        ctx: &gdsverify_backend::gpu::GpuContext,
        edges: &[(u32, u32)],
        n: usize,
    ) -> Vec<u32> {
        let (neighbors, seg_start) = build_csr(edges, n);
        let identity: Vec<u32> = (0..n as u32).collect();

        // Immutable CSR inputs, uploaded once.
        let nbr_buf = ctx.upload(&neighbors);
        let seg_buf = ctx.upload(&seg_start);

        let sc_pipe = ctx.compute_pipeline(&sc_gather::load(ctx.device().clone()).unwrap());
        let nb_pipe = ctx.compute_pipeline(&neighbor_min::load(ctx.device().clone()).unwrap());
        let cb_pipe = ctx.compute_pipeline(&combine::load(ctx.device().clone()).unwrap());

        let groups = (n as u32).div_ceil(64);
        let max_rounds = (n.max(2) as f64).log2().ceil() as usize + 2;

        let mut f = identity;
        loop {
            f = rounds(
                ctx, &f, &nbr_buf, &seg_buf, &sc_pipe, &nb_pipe, &cb_pipe, n, groups, max_rounds,
            );
            // Host convergence check, identical to the original.
            let converged = f.iter().all(|&fi| f[fi as usize] == fi)
                && edges.iter().all(|&(u, v)| {
                    let (uu, vv) = (u as usize, v as usize);
                    uu >= n || vv >= n || f[uu] == f[vv]
                });
            if converged {
                break;
            }
        }

        // Chase to canonical roots on host (matches original).
        for i in 0..n {
            let mut r = f[i];
            while f[r as usize] != r {
                r = f[r as usize];
            }
            f[i] = r;
        }
        f
    }

    #[allow(clippy::too_many_arguments)]
    fn rounds(
        ctx: &gdsverify_backend::gpu::GpuContext,
        f_init: &[u32],
        nbr_buf: &vulkano::buffer::Subbuffer<[u32]>,
        seg_buf: &vulkano::buffer::Subbuffer<[u32]>,
        sc_pipe: &std::sync::Arc<vulkano::pipeline::ComputePipeline>,
        nb_pipe: &std::sync::Arc<vulkano::pipeline::ComputePipeline>,
        cb_pipe: &std::sync::Arc<vulkano::pipeline::ComputePipeline>,
        n: usize,
        groups: u32,
        max_rounds: usize,
    ) -> Vec<u32> {
        // Label buffer held resident across all rounds; three scratch outputs.
        let mut f_buf = ctx.upload(f_init);
        let sc_buf = ctx.output::<u32>(n);
        let nb_buf = ctx.output::<u32>(n);
        let next_buf = ctx.output::<u32>(n);

        for _ in 0..max_rounds {
            let mut b = ctx.command_builder();

            // 1. shortcut: sc[i] = f[f[i]]
            dispatch(
                &mut b, sc_pipe, ctx,
                [WriteDescriptorSet::buffer(0, f_buf.clone()),
                 WriteDescriptorSet::buffer(1, sc_buf.clone())],
                sc_gather::Params { n: n as u32 }, groups,
            );
            // 2. neighbor min: nb[i] = min(f[i], min_{j} f[nbr[j]])
            dispatch(
                &mut b, nb_pipe, ctx,
                [WriteDescriptorSet::buffer(0, f_buf.clone()),
                 WriteDescriptorSet::buffer(1, nbr_buf.clone()),
                 WriteDescriptorSet::buffer(2, seg_buf.clone()),
                 WriteDescriptorSet::buffer(3, nb_buf.clone())],
                neighbor_min::Params { n: n as u32 }, groups,
            );
            // 3. combine: next[i] = min(f[i], sc[i], nb[i])
            dispatch(
                &mut b, cb_pipe, ctx,
                [WriteDescriptorSet::buffer(0, f_buf.clone()),
                 WriteDescriptorSet::buffer(1, sc_buf.clone()),
                 WriteDescriptorSet::buffer(2, nb_buf.clone()),
                 WriteDescriptorSet::buffer(3, next_buf.clone())],
                combine::Params { n: n as u32 }, groups,
            );
            ctx.execute_and_wait(b);

            // next -> f for the following round (copy back into the resident buffer).
            let next = next_buf.read().unwrap().to_vec();
            f_buf = ctx.upload(&next);
        }
        let out = f_buf.read().unwrap().to_vec();
        out
    }

    fn dispatch<P: vulkano::buffer::BufferContents, const K: usize>(
        b: &mut vulkano::command_buffer::AutoCommandBufferBuilder<
            vulkano::command_buffer::PrimaryAutoCommandBuffer,
        >,
        pipe: &std::sync::Arc<vulkano::pipeline::ComputePipeline>,
        ctx: &gdsverify_backend::gpu::GpuContext,
        writes: [WriteDescriptorSet; K],
        params: P,
        groups: u32,
    ) {
        let layout = pipe.layout().clone();
        let set = DescriptorSet::new(
            ctx.descriptors().clone(),
            layout.set_layouts()[0].clone(),
            writes,
            [],
        )
        .unwrap();
        b.bind_pipeline_compute(pipe.clone())
            .unwrap()
            .bind_descriptor_sets(PipelineBindPoint::Compute, layout.clone(), 0, vec![set])
            .unwrap()
            .push_constants(layout, 0, params)
            .unwrap();
        unsafe {
            b.dispatch([groups, 1, 1]).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference union-find oracle (independent implementation).
    fn oracle(edges: &[(u32, u32)], n: usize) -> Vec<u32> {
        let mut parent: Vec<u32> = (0..n as u32).collect();
        fn find(p: &mut [u32], x: u32) -> u32 {
            let mut r = x;
            while p[r as usize] != r {
                p[r as usize] = p[p[r as usize] as usize];
                r = p[r as usize];
            }
            r
        }
        for &(u, v) in edges {
            if (u as usize) >= n || (v as usize) >= n {
                continue;
            }
            let (ru, rv) = (find(&mut parent, u), find(&mut parent, v));
            if ru != rv {
                let (lo, hi) = (ru.min(rv), ru.max(rv));
                parent[hi as usize] = lo;
            }
        }
        for i in 0..n {
            parent[i] = find(&mut parent, i as u32);
        }
        parent
    }

    /// Two labelings are equivalent iff they induce the same partition.
    fn partition_equiv(a: &[u32], b: &[u32]) -> bool {
        a.len() == b.len()
            && (0..a.len()).all(|i| {
                ((i + 1)..a.len()).all(|j| (a[i] == a[j]) == (b[i] == b[j]))
            })
    }

    #[test]
    fn empty_graph() {
        assert_eq!(connected_components(&[], 0), Vec::<u32>::new());
    }

    #[test]
    fn isolated_nodes() {
        assert_eq!(connected_components(&[], 5), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn line_graph_is_one_component_labeled_zero() {
        let edges = [(0, 1), (1, 2), (2, 3), (3, 4)];
        let r = connected_components(&edges, 5);
        assert!(partition_equiv(&r, &oracle(&edges, 5)));
        assert!(r.iter().all(|&v| v == 0));
    }

    #[test]
    fn star_graph_labels_center_min() {
        let edges = [(0, 1), (0, 2), (0, 3), (0, 4)];
        let r = connected_components(&edges, 5);
        assert!(r.iter().all(|&v| v == 0));
        assert!(partition_equiv(&r, &oracle(&edges, 5)));
    }

    #[test]
    fn duplicate_and_reversed_edges() {
        let edges = [(0, 1), (1, 0), (0, 1), (2, 3), (3, 2)];
        let r = connected_components(&edges, 4);
        assert!(partition_equiv(&r, &oracle(&edges, 4)));
    }

    #[test]
    fn self_loops_ignored() {
        let edges = [(0, 0), (1, 1), (2, 3)];
        let r = connected_components(&edges, 4);
        assert!(partition_equiv(&r, &oracle(&edges, 4)));
        assert_eq!(r, vec![0, 1, 2, 2]);
    }

    #[test]
    fn two_components() {
        let edges = [(0, 1), (1, 2), (3, 4)];
        let r = connected_components(&edges, 5);
        assert_eq!(r[0], r[1]);
        assert_eq!(r[1], r[2]);
        assert_eq!(r[3], r[4]);
        assert_ne!(r[0], r[3]);
        assert!(partition_equiv(&r, &oracle(&edges, 5)));
    }

    #[test]
    fn out_of_range_endpoints_ignored() {
        let edges = [(0, 1), (1, 99)];
        let r = connected_components(&edges, 3);
        assert_eq!(r, vec![0, 0, 2]);
    }

    #[test]
    fn random_graph_matches_oracle_and_is_deterministic() {
        let mut edges = Vec::new();
        let mut rng: u64 = 0xDEAD_BEEF;
        let mut next = || {
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((rng >> 32) % 200) as u32
        };
        for _ in 0..300 {
            edges.push((next(), next()));
        }
        let r1 = connected_components(&edges, 200);
        let r2 = connected_components(&edges, 200);
        assert_eq!(r1, r2);
        assert!(partition_equiv(&r1, &oracle(&edges, 200)));
    }

    // ---- GPU FastSV: must match the CPU union-find on every graph ----

    #[cfg(feature = "gpu")]
    fn gpu_or_skip(edges: &[(u32, u32)], n: usize) -> Option<Vec<u32>> {
        if gdsverify_backend::gpu::context().is_none() {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return None;
        }
        Some(super::connected_components_gpu(edges, n).expect("gpu path returned None with a device"))
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn gpu_matches_cpu_fixed_graphs() {
        if let Some(ctx) = gdsverify_backend::gpu::context() {
            eprintln!("gpu test on device: {}", ctx.device_name());
        }
        let cases: &[(&[(u32, u32)], usize)] = &[
            (&[], 5),
            (&[(0, 1), (1, 2), (2, 3), (3, 4)], 5),
            (&[(0, 1), (0, 2), (0, 3), (0, 4)], 5),
            (&[(0, 1), (1, 0), (0, 1), (2, 3), (3, 2)], 4),
            (&[(0, 0), (1, 1), (2, 3)], 4),
            (&[(0, 1), (1, 2), (3, 4)], 5),
        ];
        for &(edges, n) in cases {
            let Some(g) = gpu_or_skip(edges, n) else { return };
            assert_eq!(g, connected_components(edges, n), "n={n} edges={edges:?}");
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn gpu_matches_cpu_random_graphs() {
        let mut rng: u64 = 0xBADD_C0DE;
        let mut next = |m: u64| {
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((rng >> 32) % m) as u32
        };
        for &(n, e) in &[(50usize, 60usize), (200, 300), (1000, 1500)] {
            let edges: Vec<(u32, u32)> =
                (0..e).map(|_| (next(n as u64), next(n as u64))).collect();
            let Some(g) = gpu_or_skip(&edges, n) else { return };
            let cpu = connected_components(&edges, n);
            assert!(
                partition_equiv(&g, &cpu),
                "gpu/cpu differ n={n} e={e}\ngpu={g:?}\ncpu={cpu:?}"
            );
            assert_eq!(g, cpu, "min-index labels must be identical n={n}");
        }
    }
}
