//! Vulkano GPU backend — AOT SPIR-V shaders via vulkano-shaders.
//!
//! GLSL compute shaders in `src/gpu/shaders/` are compiled to SPIR-V at build time
//! by the `vulkano_shaders::shader!` macro. Pipeline creation at runtime loads
//! pre-compiled SPIR-V (~1ms startup vs ~550ms with CubeCL JIT).
//!
//! ## Precision
//! Kernels run in **f32**. The `ComputeBackend` trait operates on f64;
//! conversions happen at upload/download boundaries.

use crate::gpu::backend::{ComputeBackend, DeviceMatrix, GpuMatrixHandle, Precision};
use std::sync::Arc;
use vulkano::{
    buffer::{Buffer, BufferCreateInfo, BufferUsage, Subbuffer},
    command_buffer::{
        allocator::{StandardCommandBufferAllocator, StandardCommandBufferAllocatorCreateInfo},
        AutoCommandBufferBuilder, CommandBufferUsage, PrimaryCommandBufferAbstract,
    },
    descriptor_set::{
        allocator::StandardDescriptorSetAllocator, DescriptorSet, WriteDescriptorSet,
    },
    device::{
        physical::PhysicalDeviceType, Device, DeviceCreateInfo, DeviceExtensions, Queue,
        QueueCreateInfo, QueueFlags,
    },
    instance::{Instance, InstanceCreateFlags, InstanceCreateInfo},
    memory::allocator::{AllocationCreateInfo, MemoryTypeFilter, StandardMemoryAllocator},
    pipeline::{
        compute::ComputePipelineCreateInfo, layout::PipelineLayout, ComputePipeline, Pipeline,
        PipelineBindPoint, PipelineShaderStageCreateInfo,
    },
    sync::GpuFuture,
    VulkanLibrary,
};

// ---------------------------------------------------------------------------
// Shader modules — GLSL compiled to SPIR-V at build time
// ---------------------------------------------------------------------------

mod p2p_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        path: "src/gpu/shaders/p2p.glsl",
    }
}

mod gemv_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        path: "src/gpu/shaders/gemv.glsl",
    }
}

mod gemm_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        path: "src/gpu/shaders/gemm.glsl",
    }
}

mod axpy_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        path: "src/gpu/shaders/axpy.glsl",
    }
}

mod block_jacobi_shader {
    vulkano_shaders::shader! {
        ty: "compute",
        path: "src/gpu/shaders/block_jacobi.glsl",
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WORKGROUP_SIZE: u32 = 256;

fn div_ceil(n: u32, d: u32) -> u32 {
    (n + d - 1) / d
}

// ---------------------------------------------------------------------------
// GPU-resident matrix handle for persistent buffers
// ---------------------------------------------------------------------------

struct GpuResidentMatrix {
    buffer: Subbuffer<[f32]>,
}

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

/// GPU backend using Vulkano with AOT SPIR-V shaders.
#[allow(dead_code)] // ponytail: device/axpy/block_jacobi kept for future kernel dispatch
pub struct VulkanoBackend {
    device: Arc<Device>,
    queue: Arc<Queue>,
    p2p_pipeline: Arc<ComputePipeline>,
    gemv_pipeline: Arc<ComputePipeline>,
    gemm_pipeline: Arc<ComputePipeline>,
    axpy_pipeline: Arc<ComputePipeline>,
    block_jacobi_pipeline: Arc<ComputePipeline>,
    memory_allocator: Arc<StandardMemoryAllocator>,
    desc_allocator: Arc<StandardDescriptorSetAllocator>,
    cmd_allocator: Arc<StandardCommandBufferAllocator>,
}

impl VulkanoBackend {
    /// Create a backend on the best available GPU.
    /// Prefers discrete GPU, falls back to integrated, then any.
    pub fn new() -> Self {
        let library = VulkanLibrary::new().expect("failed to load Vulkan library");
        let instance = Instance::new(
            library,
            InstanceCreateInfo {
                flags: InstanceCreateFlags::ENUMERATE_PORTABILITY,
                ..Default::default()
            },
        )
        .expect("failed to create Vulkan instance");

        // Pick the best physical device with a compute queue.
        let (physical_device, queue_family_index) = instance
            .enumerate_physical_devices()
            .expect("failed to enumerate Vulkan devices")
            .filter_map(|pd| {
                let qf_idx = pd
                    .queue_family_properties()
                    .iter()
                    .position(|qf| qf.queue_flags.intersects(QueueFlags::COMPUTE));
                qf_idx.map(|i| (pd, i as u32))
            })
            .min_by_key(|(pd, _)| match pd.properties().device_type {
                PhysicalDeviceType::DiscreteGpu => 0,
                PhysicalDeviceType::IntegratedGpu => 1,
                PhysicalDeviceType::VirtualGpu => 2,
                PhysicalDeviceType::Cpu => 3,
                _ => 4,
            })
            .expect("no Vulkan device with compute support found");

        let (device, mut queues) = Device::new(
            physical_device,
            DeviceCreateInfo {
                queue_create_infos: vec![QueueCreateInfo {
                    queue_family_index,
                    ..Default::default()
                }],
                enabled_extensions: DeviceExtensions {
                    ..DeviceExtensions::empty()
                },
                ..Default::default()
            },
        )
        .expect("failed to create Vulkan device");

        let queue = queues.next().unwrap();

        // Load shader modules and create pipelines
        let p2p_pipeline = Self::make_pipeline(&device, p2p_shader::load(device.clone()).unwrap());
        let gemv_pipeline =
            Self::make_pipeline(&device, gemv_shader::load(device.clone()).unwrap());
        let gemm_pipeline =
            Self::make_pipeline(&device, gemm_shader::load(device.clone()).unwrap());
        let axpy_pipeline =
            Self::make_pipeline(&device, axpy_shader::load(device.clone()).unwrap());
        let block_jacobi_pipeline =
            Self::make_pipeline(&device, block_jacobi_shader::load(device.clone()).unwrap());

        let memory_allocator = Arc::new(StandardMemoryAllocator::new_default(device.clone()));
        let desc_allocator = Arc::new(StandardDescriptorSetAllocator::new(
            device.clone(),
            Default::default(),
        ));
        let cmd_allocator = Arc::new(StandardCommandBufferAllocator::new(
            device.clone(),
            StandardCommandBufferAllocatorCreateInfo::default(),
        ));

        VulkanoBackend {
            device,
            queue,
            p2p_pipeline,
            gemv_pipeline,
            gemm_pipeline,
            axpy_pipeline,
            block_jacobi_pipeline,
            memory_allocator,
            desc_allocator,
            cmd_allocator,
        }
    }

    fn make_pipeline(
        device: &Arc<Device>,
        shader_module: Arc<vulkano::shader::ShaderModule>,
    ) -> Arc<ComputePipeline> {
        let entry = shader_module.entry_point("main").unwrap();
        let stage = PipelineShaderStageCreateInfo::new(entry);
        let layout = PipelineLayout::new(
            device.clone(),
            vulkano::pipeline::layout::PipelineDescriptorSetLayoutCreateInfo::from_stages([&stage])
                .into_pipeline_layout_create_info(device.clone())
                .unwrap(),
        )
        .unwrap();
        ComputePipeline::new(
            device.clone(),
            None,
            ComputePipelineCreateInfo::stage_layout(stage, layout),
        )
        .unwrap()
    }

    /// Create a device-local + host-visible storage buffer from f32 data.
    fn create_storage_buffer(&self, data: &[f32]) -> Subbuffer<[f32]> {
        Buffer::from_iter(
            self.memory_allocator.clone(),
            BufferCreateInfo {
                usage: BufferUsage::STORAGE_BUFFER,
                ..Default::default()
            },
            AllocationCreateInfo {
                memory_type_filter: MemoryTypeFilter::PREFER_DEVICE
                    | MemoryTypeFilter::HOST_SEQUENTIAL_WRITE,
                ..Default::default()
            },
            data.iter().copied(),
        )
        .unwrap()
    }

    /// Create a storage buffer for output (readable from host).
    fn create_output_buffer(&self, len: usize) -> Subbuffer<[f32]> {
        Buffer::new_slice::<f32>(
            self.memory_allocator.clone(),
            BufferCreateInfo {
                usage: BufferUsage::STORAGE_BUFFER,
                ..Default::default()
            },
            AllocationCreateInfo {
                memory_type_filter: MemoryTypeFilter::PREFER_DEVICE
                    | MemoryTypeFilter::HOST_RANDOM_ACCESS,
                ..Default::default()
            },
            len as u64,
        )
        .unwrap()
    }

    /// Execute a command buffer and wait for completion.
    fn execute_and_wait(
        &self,
        builder: AutoCommandBufferBuilder<vulkano::command_buffer::PrimaryAutoCommandBuffer>,
    ) {
        let cb = builder.build().unwrap();
        cb.execute(self.queue.clone())
            .unwrap()
            .then_signal_fence_and_flush()
            .unwrap()
            .wait(None)
            .unwrap();
    }

    /// GPU P2P Laplace evaluation (f32).
    #[allow(clippy::too_many_arguments)]
    pub fn p2p_laplace(
        &self,
        tx: &[f32],
        ty: &[f32],
        tz: &[f32],
        sx: &[f32],
        sy: &[f32],
        sz: &[f32],
        sq: &[f32],
    ) -> Vec<f32> {
        let n_targets = tx.len() as u32;
        let n_sources = sx.len() as u32;

        let tx_buf = self.create_storage_buffer(tx);
        let ty_buf = self.create_storage_buffer(ty);
        let tz_buf = self.create_storage_buffer(tz);
        let sx_buf = self.create_storage_buffer(sx);
        let sy_buf = self.create_storage_buffer(sy);
        let sz_buf = self.create_storage_buffer(sz);
        let sq_buf = self.create_storage_buffer(sq);
        let phi_buf = self.create_output_buffer(tx.len());

        let layout = self.p2p_pipeline.layout().clone();
        let desc_layout = layout.set_layouts().first().unwrap().clone();
        let desc_set = DescriptorSet::new(
            self.desc_allocator.clone(),
            desc_layout,
            [
                WriteDescriptorSet::buffer(0, tx_buf),
                WriteDescriptorSet::buffer(1, ty_buf),
                WriteDescriptorSet::buffer(2, tz_buf),
                WriteDescriptorSet::buffer(3, sx_buf),
                WriteDescriptorSet::buffer(4, sy_buf),
                WriteDescriptorSet::buffer(5, sz_buf),
                WriteDescriptorSet::buffer(6, sq_buf),
                WriteDescriptorSet::buffer(7, phi_buf.clone()),
            ],
            [],
        )
        .unwrap();

        let mut builder = AutoCommandBufferBuilder::primary(
            self.cmd_allocator.clone(),
            self.queue.queue_family_index(),
            CommandBufferUsage::OneTimeSubmit,
        )
        .unwrap();

        builder
            .bind_pipeline_compute(self.p2p_pipeline.clone())
            .unwrap()
            .bind_descriptor_sets(
                PipelineBindPoint::Compute,
                layout.clone(),
                0,
                vec![desc_set],
            )
            .unwrap()
            .push_constants(
                layout,
                0,
                p2p_shader::Params {
                    n_targets,
                    n_sources,
                },
            )
            .unwrap();
        unsafe {
            builder
                .dispatch([div_ceil(n_targets, WORKGROUP_SIZE), 1, 1])
                .unwrap();
        }

        self.execute_and_wait(builder);
        let result = phi_buf.read().unwrap().to_vec();
        result
    }

    /// GPU GEMV (f32): y = A*x.
    pub fn gemv_f32_gpu(&self, a: &[f32], rows: usize, cols: usize, x: &[f32]) -> Vec<f32> {
        let a_buf = self.create_storage_buffer(a);
        let x_buf = self.create_storage_buffer(x);
        let y_buf = self.create_output_buffer(rows);

        self.dispatch_gemv(&a_buf, &x_buf, &y_buf, rows as u32, cols as u32);
        let result = y_buf.read().unwrap().to_vec();
        result
    }

    /// Dispatch GEMV using pre-existing buffers.
    fn dispatch_gemv(
        &self,
        a_buf: &Subbuffer<[f32]>,
        x_buf: &Subbuffer<[f32]>,
        y_buf: &Subbuffer<[f32]>,
        rows: u32,
        cols: u32,
    ) {
        let layout = self.gemv_pipeline.layout().clone();
        let desc_layout = layout.set_layouts().first().unwrap().clone();
        let desc_set = DescriptorSet::new(
            self.desc_allocator.clone(),
            desc_layout,
            [
                WriteDescriptorSet::buffer(0, a_buf.clone()),
                WriteDescriptorSet::buffer(1, x_buf.clone()),
                WriteDescriptorSet::buffer(2, y_buf.clone()),
            ],
            [],
        )
        .unwrap();

        let mut builder = AutoCommandBufferBuilder::primary(
            self.cmd_allocator.clone(),
            self.queue.queue_family_index(),
            CommandBufferUsage::OneTimeSubmit,
        )
        .unwrap();

        builder
            .bind_pipeline_compute(self.gemv_pipeline.clone())
            .unwrap()
            .bind_descriptor_sets(
                PipelineBindPoint::Compute,
                layout.clone(),
                0,
                vec![desc_set],
            )
            .unwrap()
            .push_constants(layout, 0, gemv_shader::Params { rows, cols })
            .unwrap();
        unsafe {
            builder
                .dispatch([div_ceil(rows, WORKGROUP_SIZE), 1, 1])
                .unwrap();
        }

        self.execute_and_wait(builder);
    }

    /// Dispatch GEMM (C = A·B) using pre-existing buffers.
    fn dispatch_gemm(
        &self,
        a_buf: &Subbuffer<[f32]>,
        b_buf: &Subbuffer<[f32]>,
        c_buf: &Subbuffer<[f32]>,
        m: u32,
        k: u32,
        n: u32,
    ) {
        let layout = self.gemm_pipeline.layout().clone();
        let desc_layout = layout.set_layouts().first().unwrap().clone();
        let desc_set = DescriptorSet::new(
            self.desc_allocator.clone(),
            desc_layout,
            [
                WriteDescriptorSet::buffer(0, a_buf.clone()),
                WriteDescriptorSet::buffer(1, b_buf.clone()),
                WriteDescriptorSet::buffer(2, c_buf.clone()),
            ],
            [],
        )
        .unwrap();

        let mut builder = AutoCommandBufferBuilder::primary(
            self.cmd_allocator.clone(),
            self.queue.queue_family_index(),
            CommandBufferUsage::OneTimeSubmit,
        )
        .unwrap();

        builder
            .bind_pipeline_compute(self.gemm_pipeline.clone())
            .unwrap()
            .bind_descriptor_sets(
                PipelineBindPoint::Compute,
                layout.clone(),
                0,
                vec![desc_set],
            )
            .unwrap()
            .push_constants(layout, 0, gemm_shader::Params { m, k_dim: k, n })
            .unwrap();
        unsafe {
            builder
                .dispatch([div_ceil(m * n, WORKGROUP_SIZE), 1, 1])
                .unwrap();
        }

        self.execute_and_wait(builder);
    }

    /// GPU GEMM (f32): C = A*B.
    pub fn gemm_f32_gpu(
        &self,
        a: &[f32],
        m: usize,
        k: usize,
        b: &[f32],
        n: usize,
    ) -> Vec<f32> {
        let a_buf = self.create_storage_buffer(a);
        let b_buf = self.create_storage_buffer(b);
        let c_buf = self.create_output_buffer(m * n);
        self.dispatch_gemm(&a_buf, &b_buf, &c_buf, m as u32, k as u32, n as u32);
        let result = c_buf.read().unwrap().to_vec();
        result
    }
}

// ---------------------------------------------------------------------------
// ComputeBackend impl — bridges f64 trait interface to f32 GPU kernels
// ---------------------------------------------------------------------------

impl ComputeBackend for VulkanoBackend {
    fn name(&self) -> &'static str {
        "vulkano"
    }

    fn precision(&self) -> Precision {
        // ponytail: GPU kernels run f32; the trait is f64 — we convert at boundaries.
        Precision::F32
    }

    fn gemv(&self, a: &DeviceMatrix, x: &[f64], y: &mut [f64]) {
        assert_eq!(x.len(), a.cols);
        assert_eq!(y.len(), a.rows);
        let a32: Vec<f32> = a.host.iter().map(|&v| v as f32).collect();
        let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
        let y32 = self.gemv_f32_gpu(&a32, a.rows, a.cols, &x32);
        for (yi, &v) in y.iter_mut().zip(y32.iter()) {
            *yi = v as f64;
        }
    }

    fn gemv_f32(&self, a: &DeviceMatrix, x: &[f64], y: &mut [f64]) {
        self.gemv(a, x, y);
    }

    fn upload_matrix(&self, a: &DeviceMatrix) -> GpuMatrixHandle {
        let a32: Vec<f32> = a.host.iter().map(|&v| v as f32).collect();
        let buffer = self.create_storage_buffer(&a32);
        let resident = GpuResidentMatrix { buffer };
        GpuMatrixHandle::new(a.rows, a.cols, resident)
    }

    fn gemv_with_handle(&self, handle: &GpuMatrixHandle, x: &[f64], y: &mut [f64]) {
        assert_eq!(x.len(), handle.cols);
        assert_eq!(y.len(), handle.rows);
        let resident = handle
            .downcast_ref::<GpuResidentMatrix>()
            .expect("VulkanoBackend GpuMatrixHandle");
        let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
        let x_buf = self.create_storage_buffer(&x32);
        let y_buf = self.create_output_buffer(handle.rows);

        self.dispatch_gemv(
            &resident.buffer,
            &x_buf,
            &y_buf,
            handle.rows as u32,
            handle.cols as u32,
        );
        let y32 = y_buf.read().unwrap();
        for (yi, &v) in y.iter_mut().zip(y32.iter()) {
            *yi = v as f64;
        }
    }

    fn gemm_with_handle(&self, handle: &GpuMatrixHandle, b: &[f64], ncols: usize) -> Vec<f64> {
        assert_eq!(b.len(), handle.cols * ncols);
        let resident = handle
            .downcast_ref::<GpuResidentMatrix>()
            .expect("VulkanoBackend GpuMatrixHandle");
        let b32: Vec<f32> = b.iter().map(|&v| v as f32).collect();
        let b_buf = self.create_storage_buffer(&b32);
        let c_buf = self.create_output_buffer(handle.rows * ncols);
        self.dispatch_gemm(
            &resident.buffer,
            &b_buf,
            &c_buf,
            handle.rows as u32,
            handle.cols as u32,
            ncols as u32,
        );
        let c32 = c_buf.read().unwrap();
        c32.iter().map(|&v| v as f64).collect()
    }

    fn batched_gemm(&self, a: &[DeviceMatrix], b: &[DeviceMatrix]) -> Vec<DeviceMatrix> {
        assert_eq!(a.len(), b.len());
        if a.is_empty() {
            return Vec::new();
        }
        // ponytail: per-batch dispatch. Fused batched kernel skipped — add when profiling shows
        // dispatch overhead dominates over kernel time for the typical M2L batch count.
        a.iter()
            .zip(b.iter())
            .map(|(ai, bi)| {
                assert_eq!(ai.cols, bi.rows);
                let (m, k, n) = (ai.rows, ai.cols, bi.cols);
                let a32: Vec<f32> = ai.host.iter().map(|&v| v as f32).collect();
                let b32: Vec<f32> = bi.host.iter().map(|&v| v as f32).collect();
                let c32 = self.gemm_f32_gpu(&a32, m, k, &b32, n);
                let c64: Vec<f64> = c32.iter().map(|&v| v as f64).collect();
                DeviceMatrix::from_rows(m, n, c64)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ponytail: GPU tests are #[ignore] — they need a real GPU + Vulkan driver.
    // Run with: cargo test -p quasiss-gpu --features gpu -- --ignored

    #[test]
    #[ignore = "requires GPU with Vulkan support"]
    fn vulkano_gemv() {
        let backend = VulkanoBackend::new();
        let a = DeviceMatrix::from_rows(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let x = [1.0, 0.0, -1.0];
        let mut y = [0.0; 2];
        backend.gemv(&a, &x, &mut y);
        assert!((y[0] - (-2.0)).abs() < 1e-5);
        assert!((y[1] - (-2.0)).abs() < 1e-5);
    }

    #[test]
    #[ignore = "requires GPU with Vulkan support"]
    fn vulkano_gemv_persistent() {
        let backend = VulkanoBackend::new();
        let a = DeviceMatrix::from_rows(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let handle = backend.upload_matrix(&a);

        let x = [1.0, 0.0, -1.0];
        let mut y = [0.0; 2];
        backend.gemv_with_handle(&handle, &x, &mut y);
        assert!((y[0] - (-2.0)).abs() < 1e-5);
        assert!((y[1] - (-2.0)).abs() < 1e-5);

        let x2 = [1.0, 1.0, 1.0];
        let mut y2 = [0.0; 2];
        backend.gemv_with_handle(&handle, &x2, &mut y2);
        assert!((y2[0] - 6.0).abs() < 1e-5);
        assert!((y2[1] - 15.0).abs() < 1e-5);
    }

    #[test]
    #[ignore = "requires GPU with Vulkan support"]
    fn vulkano_gemm_with_handle_matches_cpu() {
        use crate::gpu::backend::CpuBackend;
        let gpu = VulkanoBackend::new();
        let cpu = CpuBackend::default();
        let a = DeviceMatrix::from_rows(3, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0]);
        let b = vec![1.0, 2.0, 0.0, 1.0, -1.0, 0.5];
        let hg = gpu.upload_matrix(&a);
        let hc = cpu.upload_matrix(&a);
        let cg = gpu.gemm_with_handle(&hg, &b, 2);
        let cc = cpu.gemm_with_handle(&hc, &b, 2);
        for (g, c) in cg.iter().zip(&cc) {
            assert!((g - c).abs() < 1e-4, "gpu {g} vs cpu {c}");
        }
    }

    #[test]
    #[ignore = "requires GPU with Vulkan support"]
    fn vulkano_batched_gemm() {
        let backend = VulkanoBackend::new();
        let id = DeviceMatrix::from_rows(2, 2, vec![1.0, 0.0, 0.0, 1.0]);
        let m = DeviceMatrix::from_rows(2, 2, vec![7.0, 8.0, 9.0, 10.0]);
        let out = backend.batched_gemm(&[id], &[m]);
        for (got, want) in out[0].host.iter().zip([7.0, 8.0, 9.0, 10.0].iter()) {
            assert!((*got - want).abs() < 1e-5);
        }
    }

    #[test]
    #[ignore = "requires GPU with Vulkan support"]
    fn vulkano_p2p() {
        let backend = VulkanoBackend::new();
        let sx = vec![0.0f32, 1.0, 2.0];
        let sy = vec![0.0f32; 3];
        let sz = vec![0.0f32; 3];
        let sq = vec![1.0f32; 3];
        let tx = vec![0.5f32];
        let ty = vec![0.0f32];
        let tz = vec![0.0f32];
        let result = backend.p2p_laplace(&tx, &ty, &tz, &sx, &sy, &sz, &sq);
        // Expected: 1/0.5 + 1/0.5 + 1/1.5 = 2 + 2 + 0.6667 = 4.6667
        assert!((result[0] - 4.6667).abs() < 0.01);
    }
}
