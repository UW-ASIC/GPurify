//! Vulkano GPU context — shared device, queue, and allocators.
//!
//! This is the seam every engine's compute kernels build on. Engines own their
//! GLSL shaders (compiled to SPIR-V at build time by `vulkano_shaders::shader!`)
//! and their pipelines; this module owns the one process-wide device context
//! they all dispatch through.
//!
//! Context creation is lazy and **panic-contained**: a missing driver or a
//! broken device reads as "no GPU" ([`context`] returns `None`), never a crash
//! that aborts a verification run.
//!
//! Kernel dispatch (pipelines, descriptor sets, push constants) lands here in
//! phase 2, designed against the first concrete shader rather than guessed at.

use std::sync::{Arc, OnceLock};

use vulkano::{
    buffer::{Buffer, BufferContents, BufferCreateInfo, BufferUsage, Subbuffer},
    command_buffer::{
        allocator::{StandardCommandBufferAllocator, StandardCommandBufferAllocatorCreateInfo},
        AutoCommandBufferBuilder, CommandBufferUsage, PrimaryAutoCommandBuffer,
        PrimaryCommandBufferAbstract,
    },
    descriptor_set::allocator::StandardDescriptorSetAllocator,
    device::{
        physical::PhysicalDeviceType, Device, DeviceCreateInfo, Queue, QueueCreateInfo, QueueFlags,
    },
    instance::{Instance, InstanceCreateFlags, InstanceCreateInfo},
    memory::allocator::{AllocationCreateInfo, MemoryTypeFilter, StandardMemoryAllocator},
    pipeline::{
        compute::ComputePipelineCreateInfo,
        layout::{PipelineDescriptorSetLayoutCreateInfo, PipelineLayout},
        ComputePipeline, PipelineShaderStageCreateInfo,
    },
    shader::ShaderModule,
    sync::GpuFuture,
    VulkanLibrary,
};

/// Why a GPU context could not be created.
#[derive(Debug, thiserror::Error)]
pub enum GpuInitError {
    #[error("no Vulkan loader/driver on this system: {0}")]
    NoLibrary(String),
    #[error("could not create a Vulkan instance: {0}")]
    Instance(String),
    #[error("no Vulkan device with a compute queue")]
    NoComputeDevice,
    #[error("could not create the Vulkan device: {0}")]
    Device(String),
}

/// The process-wide Vulkan compute context: one device, one compute queue, and
/// the standard allocators kernels draw buffers and command buffers from.
pub struct GpuContext {
    device: Arc<Device>,
    queue: Arc<Queue>,
    memory: Arc<StandardMemoryAllocator>,
    descriptors: Arc<StandardDescriptorSetAllocator>,
    commands: Arc<StandardCommandBufferAllocator>,
    device_name: String,
}

impl GpuContext {
    /// Select the best available compute device and build the context.
    ///
    /// Prefers a discrete GPU, then integrated, then anything with a compute
    /// queue. Fails (rather than panics) when no usable device exists.
    ///
    /// # Errors
    /// Returns [`GpuInitError`] when the Vulkan loader, an instance, a
    /// compute-capable device, or the logical device cannot be created.
    pub fn new() -> Result<Self, GpuInitError> {
        let library =
            VulkanLibrary::new().map_err(|e| GpuInitError::NoLibrary(e.to_string()))?;
        let instance = Instance::new(
            library,
            InstanceCreateInfo {
                flags: InstanceCreateFlags::ENUMERATE_PORTABILITY,
                ..Default::default()
            },
        )
        .map_err(|e| GpuInitError::Instance(e.to_string()))?;

        let (physical, queue_family_index) = instance
            .enumerate_physical_devices()
            .map_err(|e| GpuInitError::Instance(e.to_string()))?
            .filter_map(|pd| {
                let qf = pd
                    .queue_family_properties()
                    .iter()
                    .position(|qf| qf.queue_flags.intersects(QueueFlags::COMPUTE));
                qf.map(|i| (pd, u32::try_from(i).unwrap_or(0)))
            })
            .min_by_key(|(pd, _)| match pd.properties().device_type {
                PhysicalDeviceType::DiscreteGpu => 0,
                PhysicalDeviceType::IntegratedGpu => 1,
                PhysicalDeviceType::VirtualGpu => 2,
                PhysicalDeviceType::Cpu => 3,
                _ => 4,
            })
            .ok_or(GpuInitError::NoComputeDevice)?;

        let device_name = physical.properties().device_name.clone();

        let (device, mut queues) = Device::new(
            physical,
            DeviceCreateInfo {
                queue_create_infos: vec![QueueCreateInfo {
                    queue_family_index,
                    ..Default::default()
                }],
                ..Default::default()
            },
        )
        .map_err(|e| GpuInitError::Device(e.to_string()))?;

        let queue = queues.next().ok_or(GpuInitError::NoComputeDevice)?;
        let memory = Arc::new(StandardMemoryAllocator::new_default(device.clone()));
        let descriptors = Arc::new(StandardDescriptorSetAllocator::new(
            device.clone(),
            Default::default(),
        ));
        let commands = Arc::new(StandardCommandBufferAllocator::new(
            device.clone(),
            StandardCommandBufferAllocatorCreateInfo::default(),
        ));

        Ok(Self {
            device,
            queue,
            memory,
            descriptors,
            commands,
            device_name,
        })
    }

    /// The logical device.
    #[must_use]
    pub fn device(&self) -> &Arc<Device> {
        &self.device
    }
    /// The compute queue.
    #[must_use]
    pub fn queue(&self) -> &Arc<Queue> {
        &self.queue
    }
    /// Allocator for storage/output buffers.
    #[must_use]
    pub fn memory(&self) -> &Arc<StandardMemoryAllocator> {
        &self.memory
    }
    /// Allocator for descriptor sets.
    #[must_use]
    pub fn descriptors(&self) -> &Arc<StandardDescriptorSetAllocator> {
        &self.descriptors
    }
    /// Allocator for command buffers.
    #[must_use]
    pub fn commands(&self) -> &Arc<StandardCommandBufferAllocator> {
        &self.commands
    }
    /// Human-readable name of the selected device (for telemetry).
    #[must_use]
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    // --- Kernel dispatch plumbing -----------------------------------------
    //
    // Engines own their GLSL shaders and assemble the descriptor set + push
    // constants (which are shader-specific) themselves; these helpers are the
    // shared, shader-agnostic building blocks. They panic on allocation failure
    // — every GPU entry point is reached through [`context`], which is
    // panic-contained, so a device OOM degrades to the CPU path, never aborts.

    /// Upload `data` to a device-local storage buffer (host writes it once, the
    /// device reads it). Use for immutable kernel inputs.
    #[must_use]
    pub fn upload<T: BufferContents + Copy>(&self, data: &[T]) -> Subbuffer<[T]> {
        Buffer::from_iter(
            self.memory.clone(),
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
        .expect("gpu storage buffer allocation")
    }

    /// Allocate a `len`-element storage buffer the host can read back. Use for
    /// kernel outputs; read it with `.read()` after [`Self::execute_and_wait`].
    #[must_use]
    pub fn output<T: BufferContents>(&self, len: usize) -> Subbuffer<[T]> {
        Buffer::new_slice::<T>(
            self.memory.clone(),
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
        .expect("gpu output buffer allocation")
    }

    /// Build a compute pipeline from a loaded shader module (entry point `main`).
    #[must_use]
    pub fn compute_pipeline(&self, module: &Arc<ShaderModule>) -> Arc<ComputePipeline> {
        let entry = module.entry_point("main").expect("shader entry point `main`");
        let stage = PipelineShaderStageCreateInfo::new(entry);
        let layout = PipelineLayout::new(
            self.device.clone(),
            PipelineDescriptorSetLayoutCreateInfo::from_stages([&stage])
                .into_pipeline_layout_create_info(self.device.clone())
                .expect("pipeline layout"),
        )
        .expect("pipeline layout create");
        ComputePipeline::new(
            self.device.clone(),
            None,
            ComputePipelineCreateInfo::stage_layout(stage, layout),
        )
        .expect("compute pipeline create")
    }

    /// Start a one-time-submit primary command buffer on the compute queue.
    #[must_use]
    pub fn command_builder(&self) -> AutoCommandBufferBuilder<PrimaryAutoCommandBuffer> {
        AutoCommandBufferBuilder::primary(
            self.commands.clone(),
            self.queue.queue_family_index(),
            CommandBufferUsage::OneTimeSubmit,
        )
        .expect("command buffer builder")
    }

    /// Submit a recorded command buffer and block until the device finishes.
    /// The single synchronization point of a kernel launch.
    pub fn execute_and_wait(&self, builder: AutoCommandBufferBuilder<PrimaryAutoCommandBuffer>) {
        builder
            .build()
            .expect("command buffer build")
            .execute(self.queue.clone())
            .expect("command buffer execute")
            .then_signal_fence_and_flush()
            .expect("fence and flush")
            .wait(None)
            .expect("device wait");
    }
}

/// The lazily-created, panic-contained process-wide context.
///
/// `None` means no usable GPU (feature off is handled at the crate root; here
/// it means no driver, no device, or a failed/ panicking init). The result is
/// memoized: one probe per process.
#[must_use]
pub fn context() -> Option<&'static GpuContext> {
    static CTX: OnceLock<Option<GpuContext>> = OnceLock::new();
    CTX.get_or_init(|| {
        std::panic::catch_unwind(GpuContext::new)
            .ok()
            .and_then(Result::ok)
    })
    .as_ref()
}

/// Is a Vulkan compute device usable right now?
#[must_use]
pub fn ready() -> bool {
    context().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
    use vulkano::pipeline::{Pipeline, PipelineBindPoint};

    // A trivial map kernel — the smallest end-to-end proof of the dispatch
    // plumbing: upload → bind → push-constant → dispatch → read back.
    mod scale_shader {
        vulkano_shaders::shader! {
            ty: "compute",
            src: r"
                #version 460
                layout(local_size_x = 64) in;
                layout(set = 0, binding = 0) readonly buffer X { float x[]; };
                layout(set = 0, binding = 1) writeonly buffer O { float o[]; };
                layout(push_constant) uniform Params { uint len; float a; };
                void main() {
                    uint i = gl_GlobalInvocationID.x;
                    if (i >= len) return;
                    o[i] = a * x[i];
                }
            ",
        }
    }

    #[test]
    fn map_kernel_runs_on_device() {
        let Some(ctx) = context() else {
            eprintln!("gpu test skipped: no usable Vulkan device");
            return;
        };
        eprintln!("gpu test on device: {}", ctx.device_name());

        let x = ctx.upload(&[1.0f32, 2.0, 3.0, 4.0, 5.0]);
        let out = ctx.output::<f32>(5);
        let module = scale_shader::load(ctx.device().clone()).expect("load shader");
        let pipeline = ctx.compute_pipeline(&module);
        let layout = pipeline.layout().clone();
        let set_layout = layout.set_layouts().first().expect("set layout").clone();
        let set = DescriptorSet::new(
            ctx.descriptors().clone(),
            set_layout,
            [
                WriteDescriptorSet::buffer(0, x),
                WriteDescriptorSet::buffer(1, out.clone()),
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
            .push_constants(layout, 0, scale_shader::Params { len: 5, a: 3.0 })
            .unwrap();
        unsafe {
            builder.dispatch([1, 1, 1]).unwrap();
        }
        ctx.execute_and_wait(builder);

        let got = out.read().expect("read output").to_vec();
        assert_eq!(got, vec![3.0, 6.0, 9.0, 12.0, 15.0]);
    }
}
