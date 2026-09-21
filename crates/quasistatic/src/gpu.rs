//! The `f32` device adapter.
//!
//! Six rules from `docs/GPU.md` that this adapter does not ship without; if any
//! fails, the CPU adapter is the answer and saying so is a complete result.
//!
//! 1. Buffers allocated once per solve, never inside the iteration loop.
//! 2. No host wait between dependent dispatches.
//! 3. One dispatch per matvec, not one per block.
//! 4. Accuracy bounded by a host `f64` residual, and the achieved value
//!    reported: `solve::refine` takes two operators and the accurate one is
//!    always the host `CpuMatVec`.
//! 5. Equality tests against the host adapter that actually run.
//! 6. A measured crossover, selected automatically and never by a flag.

use std::sync::Arc;

use vulkano::buffer::{Buffer, BufferCreateInfo, BufferUsage, Subbuffer};
use vulkano::command_buffer::allocator::{
    StandardCommandBufferAllocator, StandardCommandBufferAllocatorCreateInfo,
};
use vulkano::command_buffer::{
    AutoCommandBufferBuilder, CommandBufferUsage, PrimaryAutoCommandBuffer,
};
use vulkano::descriptor_set::allocator::{
    StandardDescriptorSetAllocator, StandardDescriptorSetAllocatorCreateInfo,
};
use vulkano::descriptor_set::{DescriptorSet, WriteDescriptorSet};
use vulkano::device::physical::PhysicalDevice;
use vulkano::device::{Device as VkDevice, DeviceCreateInfo, Queue, QueueCreateInfo, QueueFlags};
use vulkano::instance::{Instance, InstanceCreateFlags, InstanceCreateInfo};
use vulkano::memory::allocator::{AllocationCreateInfo, MemoryTypeFilter, StandardMemoryAllocator};
use vulkano::pipeline::compute::ComputePipelineCreateInfo;
use vulkano::pipeline::layout::PipelineDescriptorSetLayoutCreateInfo;
use vulkano::pipeline::{
    ComputePipeline, Pipeline, PipelineBindPoint, PipelineLayout, PipelineShaderStageCreateInfo,
};
use vulkano::shader::{ShaderModule, ShaderModuleCreateInfo};
use vulkano::sync::GpuFuture;
use vulkano::VulkanLibrary;

use super::matvec::FOUR_PI_EPS0;
use super::matvec::{Backend, MatVec};
use super::mesh::Mesh;

/// The compiled P2P Laplace kernel: ahead-of-time SPIR-V from
/// `shaders/p2p_laplace.comp`, committed beside it.
///
/// Committed rather than built by a build script because `vulkano-shaders` pulls
/// in `shaderc-sys`, which needs `libshaderc` or `cmake` — neither present
/// outside `nix develop`. Regeneration command in the shader's own header.
const P2P_LAPLACE_SPV: &[u8] = include_bytes!("../shaders/p2p_laplace.spv");

/// Threads per workgroup, and the `local_size_x` the shader was compiled for.
/// The two must agree, or a tail is left unwritten.
const WORKGROUP: u32 = 64;

/// A usable compute device. `None` means no device, or one that does not meet
/// the requirements, which is an ordinary outcome rather than an error.
#[derive(Debug)]
pub struct Device {
    /// The compute queue every dispatch is submitted on; it owns the logical
    /// device, which is why no separate handle is kept.
    queue: Arc<Queue>,
    pipeline: Arc<ComputePipeline>,
    memory: Arc<StandardMemoryAllocator>,
    descriptors: Arc<StandardDescriptorSetAllocator>,
    commands: Arc<StandardCommandBufferAllocator>,
    /// Panel count above which this device beat the host.
    crossover: usize,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeviceError {
    #[error("no compute device present")]
    NoDevice,
    #[error("device lacks a required feature: {0}")]
    MissingFeature(String),
    #[error("device has {available} bytes available, solve needs {needed}")]
    OutOfMemory { needed: u64, available: u64 },
    #[error("device lost during a solve")]
    Lost,
}

/// Why one physical device was passed over, or `None` if it is usable.
fn unusable(physical: &PhysicalDevice) -> Option<String> {
    let properties = physical.properties();
    let name = &properties.device_name;

    if properties.max_compute_work_group_invocations < WORKGROUP {
        return Some(format!(
            "{name} allows {} invocations per compute work group, and the P2P \
             Laplace kernel was compiled for {WORKGROUP}",
            properties.max_compute_work_group_invocations
        ));
    }
    if properties.max_compute_work_group_size[0] < WORKGROUP {
        return Some(format!(
            "{name} allows a compute work group {} wide on x, and the P2P \
             Laplace kernel was compiled for {WORKGROUP}",
            properties.max_compute_work_group_size[0]
        ));
    }
    // `shader_float64` is deliberately *not* required: the `f32` matvec inside
    // host `f64` refinement is the whole design.
    if !physical
        .queue_family_properties()
        .iter()
        .any(|family| family.queue_flags.intersects(QueueFlags::COMPUTE))
    {
        return Some(format!("{name} has no queue family with COMPUTE set"));
    }
    None
}

impl Device {
    /// Find a device meeting the requirements.
    ///
    /// `Ok(None)` is "no GPU here" — no loader, or zero physical devices — and
    /// is not a failure. `Err(MissingFeature)` is "a GPU is here and this is why
    /// it did not run".
    pub fn find() -> Result<Option<Self>, DeviceError> {
        // No loader at all: the probe succeeded, it found nothing.
        let Ok(library) = VulkanLibrary::new() else {
            return Ok(None);
        };
        let Ok(instance) = Instance::new(
            library,
            InstanceCreateInfo {
                flags: InstanceCreateFlags::ENUMERATE_PORTABILITY,
                ..Default::default()
            },
        ) else {
            return Ok(None);
        };
        let Ok(devices) = instance.enumerate_physical_devices() else {
            return Ok(None);
        };

        // The first complaint, kept so "a GPU is here and none of them would
        // run" is not silently downgraded to "no GPU here".
        let mut complaint = None;
        for physical in devices {
            match unusable(&physical) {
                Some(why) => complaint.get_or_insert(why),
                None => return Self::open(&physical).map(Some),
            };
        }
        match complaint {
            Some(why) => Err(DeviceError::MissingFeature(why)),
            None => Ok(None),
        }
    }

    /// Open a physical device that [`unusable`] already cleared.
    fn open(physical: &Arc<PhysicalDevice>) -> Result<Self, DeviceError> {
        let queue_family_index = physical
            .queue_family_properties()
            .iter()
            .position(|family| family.queue_flags.intersects(QueueFlags::COMPUTE))
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                DeviceError::MissingFeature(
                    "the compute queue family disappeared between the probe and the open"
                        .to_owned(),
                )
            })?;

        let (device, mut queues) = VkDevice::new(
            physical.clone(),
            DeviceCreateInfo {
                queue_create_infos: vec![QueueCreateInfo {
                    queue_family_index,
                    ..Default::default()
                }],
                ..Default::default()
            },
        )
        .map_err(|why| DeviceError::MissingFeature(format!("the device would not open: {why}")))?;
        let queue = queues
            .next()
            .ok_or_else(|| DeviceError::MissingFeature("no queue was created".to_owned()))?;

        let pipeline = Self::build_pipeline(&device)?;

        Ok(Self {
            memory: Arc::new(StandardMemoryAllocator::new_default(device.clone())),
            descriptors: Arc::new(StandardDescriptorSetAllocator::new(
                device.clone(),
                StandardDescriptorSetAllocatorCreateInfo::default(),
            )),
            commands: Arc::new(StandardCommandBufferAllocator::new(
                device,
                StandardCommandBufferAllocatorCreateInfo::default(),
            )),
            queue,
            pipeline,
            crossover: MEASURED_CROSSOVER,
        })
    }

    /// Compile [`P2P_LAPLACE_SPV`] into a compute pipeline.
    ///
    /// The descriptor set layout comes from the module's own reflection rather
    /// than being written out here, so the bindings cannot drift apart silently.
    fn build_pipeline(device: &Arc<VkDevice>) -> Result<Arc<ComputePipeline>, DeviceError> {
        let words = spirv_words(P2P_LAPLACE_SPV)
            .ok_or_else(|| DeviceError::MissingFeature(BAD_SPIRV.to_owned()))?;
        // SAFETY: the module is `include_bytes!` of a blob this repository
        // compiles from `shaders/p2p_laplace.comp` with `glslc`, so it is
        // well-formed SPIR-V for a compute stage. `ShaderModule::new` is unsafe
        // because vulkano cannot verify that of arbitrary bytes; the alternative
        // to trusting it here is trusting it at every call site.
        // `spirv_words` has already checked the magic number and the word
        // alignment, which are the two ways a wrong file reaches this line.
        let module =
            unsafe { ShaderModule::new(device.clone(), ShaderModuleCreateInfo::new(&words)) }
                .map_err(|why| {
                    DeviceError::MissingFeature(format!("the shader would not load: {why}"))
                })?;
        let entry = module.entry_point("main").ok_or_else(|| {
            DeviceError::MissingFeature("the shader declares no `main` entry point".to_owned())
        })?;

        let stage = PipelineShaderStageCreateInfo::new(entry);
        let layout = PipelineLayout::new(
            device.clone(),
            PipelineDescriptorSetLayoutCreateInfo::from_stages([&stage])
                .into_pipeline_layout_create_info(device.clone())
                .map_err(|why| {
                    DeviceError::MissingFeature(format!("the pipeline layout is not valid: {why}"))
                })?,
        )
        .map_err(|why| {
            DeviceError::MissingFeature(format!("the pipeline layout would not build: {why}"))
        })?;

        ComputePipeline::new(
            device.clone(),
            None,
            ComputePipelineCreateInfo::stage_layout(stage, layout),
        )
        .map_err(|why| {
            DeviceError::MissingFeature(format!("the compute pipeline would not build: {why}"))
        })
    }

    /// Panel count above which this device beat the host.
    pub fn crossover(&self) -> usize {
        debug_assert!(
            self.crossover > 0,
            "a measured crossover is the first panel count at which the device won"
        );
        self.crossover
    }
}

/// The panel count above which the device was measured to win.
///
/// Measured in `--release` by
/// `crates/quasistatic/tests/gpu.rs::the_crossover_is_measured_rather_than_assumed` on
/// an RTX 4060 Laptop against an i9-14900HX: host wins at 64 panels, device wins
/// 1.6× at 256 and 22× at 8192. 256 is the first *sampled* count at which the
/// device won; rounding down to an unmeasured size is the invention this
/// constant exists to avoid.
///
/// ponytail: one number for every device, measured on one part. The ceiling: a
/// part slower than this one is selected below its own crossover and loses
/// throughput; it does not lose accuracy, because `solve::refine`'s residual is
/// measured rather than assumed. Upgrade path: calibrate in [`Device::find`] and
/// store the measurement on the value — the field is already there, and `find`
/// is called once per run.
///
/// `> 0` is load-bearing and `matvec::select` asserts it: a crossover of zero
/// would select the device at every size including the empty problem.
const MEASURED_CROSSOVER: usize = 256;

const BAD_SPIRV: &str =
    "the committed SPIR-V is not a whole number of little-endian words beginning \
     with the SPIR-V magic; regenerate it with the command in the shader header";

/// The SPIR-V magic number, little-endian.
const SPIRV_MAGIC: u32 = 0x0723_0203;

/// Reinterpret a committed SPIR-V blob as the `u32` words vulkano wants.
///
/// `None` for anything that is not SPIR-V: a truncated or wrong-endian blob
/// reaching `ShaderModule::new` is undefined behaviour there.
fn spirv_words(bytes: &[u8]) -> Option<Vec<u32>> {
    if !bytes.len().is_multiple_of(4) || bytes.len() < 4 {
        return None;
    }
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .collect();
    (words[0] == SPIRV_MAGIC).then_some(words)
}

/// Device-resident `f32` matvec: panel data stays on the device for the solve's
/// lifetime and only the vectors cross the bus.
///
/// Multiplies in `f32`, which is safe only because [`super::solve::refine`]
/// wraps it in host `f64` refinement and the achieved residual is measured.
#[derive(Debug)]
pub struct GpuMatVec<'d> {
    device: &'d Device,
    /// Panels, and the `n` the shader is handed as a push constant.
    panels: usize,
    /// The two vectors, host-visible so a matvec is a write, a submit and a read
    /// rather than a staging copy either side.
    charge: Subbuffer<[f32]>,
    potential: Subbuffer<[f32]>,
    /// Recorded once in [`Self::upload`] and replayed by every
    /// [`MatVec::apply`], so nothing is allocated *or recorded* in the loop. It
    /// and the descriptor set hold the panel buffers alive, which is why those
    /// have no fields of their own.
    command: Arc<PrimaryAutoCommandBuffer>,
}

impl<'d> GpuMatVec<'d> {
    /// Upload a mesh and allocate every buffer the solve will use, so
    /// [`MatVec::apply`] allocates nothing.
    ///
    /// The panel table is built here rather than read from the mesh: the kernel
    /// wants a centroid, an effective radius and a coefficient, which is
    /// `CpuMatVec::build`'s reduction, narrowed to `f32`.
    ///
    /// Centres are stored relative to the mesh's own centroid. The kernel reads
    /// them only as differences, so a common translation cancels in the maths
    /// and catastrophically does not cancel in the narrowing: a layout at
    /// `x ≈ 1e-3` m with panels `1e-8` m apart loses five of `f32`'s seven
    /// digits before the kernel has done any arithmetic.
    pub fn upload(device: &'d Device, mesh: &Mesh) -> Result<Self, DeviceError> {
        debug_assert_eq!(
            mesh.panel.len(),
            mesh.epsilon.len(),
            "one permittivity per panel"
        );
        let panels = mesh.panel.len();
        if panels == 0 {
            // `Buffer::from_iter` refuses a zero-length slice, and `select`
            // never routes an empty problem here anyway.
            return Err(DeviceError::NoDevice);
        }

        // Sized before any of them is allocated, so the check below is against
        // the whole solve rather than whichever allocation failed first.
        let bytes = (panels as u64) * (4 * 4 + 4 + 4 + 4);
        let limit = u64::from(
            device
                .queue
                .device()
                .physical_device()
                .properties()
                .max_storage_buffer_range,
        );
        if bytes > limit {
            return Err(DeviceError::OutOfMemory {
                needed: bytes,
                available: limit,
            });
        }

        // Summed in `f64` in ascending panel order, so two uploads of one mesh
        // place the panels identically.
        let mut origin = [0.0_f64; 3];
        for panel in &mesh.panel {
            for (sum, &coordinate) in origin.iter_mut().zip(&panel.centre) {
                *sum += coordinate;
            }
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a panel count under 2^53 is exact in f64"
        )]
        let count = panels as f64;
        for slot in &mut origin {
            *slot /= count;
        }

        // Packed as the shader declares: a `vec4` of centroid and radius, and a
        // scalar coefficient.
        let posr = Buffer::from_iter(
            device.memory.clone(),
            BufferCreateInfo {
                usage: BufferUsage::STORAGE_BUFFER,
                ..Default::default()
            },
            AllocationCreateInfo {
                memory_type_filter: MemoryTypeFilter::PREFER_DEVICE
                    | MemoryTypeFilter::HOST_SEQUENTIAL_WRITE,
                ..Default::default()
            },
            mesh.panel.iter().map(|panel| {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "narrowing to f32 is the adapter; Backend::GpuF32 attributes it"
                )]
                [
                    (panel.centre[0] - origin[0]) as f32,
                    (panel.centre[1] - origin[1]) as f32,
                    (panel.centre[2] - origin[2]) as f32,
                    // `√A / (4 ln(1 + √2))`: the radius at which a point charge
                    // reproduces this panel's own centroid potential, and the
                    // softening that keeps the diagonal off zero.
                    (panel.area.sqrt() / super::matvec::SELF_POTENTIAL_SHAPE) as f32,
                ]
            }),
        )
        .map_err(allocation_refused)?;

        let coef = Buffer::from_iter(
            device.memory.clone(),
            BufferCreateInfo {
                usage: BufferUsage::STORAGE_BUFFER,
                ..Default::default()
            },
            AllocationCreateInfo {
                memory_type_filter: MemoryTypeFilter::PREFER_DEVICE
                    | MemoryTypeFilter::HOST_SEQUENTIAL_WRITE,
                ..Default::default()
            },
            mesh.epsilon.iter().map(|&epsilon| {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "narrowing to f32 is the adapter; Backend::GpuF32 attributes it"
                )]
                let coefficient = (1.0 / (FOUR_PI_EPS0 * epsilon)) as f32;
                coefficient
            }),
        )
        .map_err(allocation_refused)?;

        let charge = Buffer::from_iter(
            device.memory.clone(),
            BufferCreateInfo {
                usage: BufferUsage::STORAGE_BUFFER,
                ..Default::default()
            },
            AllocationCreateInfo {
                memory_type_filter: MemoryTypeFilter::PREFER_DEVICE
                    | MemoryTypeFilter::HOST_SEQUENTIAL_WRITE,
                ..Default::default()
            },
            std::iter::repeat_n(0.0_f32, panels),
        )
        .map_err(allocation_refused)?;

        // Read back every call, so host-visible on the *random access* filter:
        // a write-combined mapping reads at bus speed.
        let potential = Buffer::from_iter(
            device.memory.clone(),
            BufferCreateInfo {
                usage: BufferUsage::STORAGE_BUFFER,
                ..Default::default()
            },
            AllocationCreateInfo {
                memory_type_filter: MemoryTypeFilter::PREFER_HOST
                    | MemoryTypeFilter::HOST_RANDOM_ACCESS,
                ..Default::default()
            },
            std::iter::repeat_n(0.0_f32, panels),
        )
        .map_err(allocation_refused)?;

        let layout = device
            .pipeline
            .layout()
            .set_layouts()
            .first()
            .ok_or_else(|| {
                DeviceError::MissingFeature("the pipeline declares no descriptor set".to_owned())
            })?
            .clone();
        let descriptor = DescriptorSet::new(
            device.descriptors.clone(),
            layout,
            [
                WriteDescriptorSet::buffer(0, posr),
                WriteDescriptorSet::buffer(1, coef),
                WriteDescriptorSet::buffer(2, charge.clone()),
                WriteDescriptorSet::buffer(3, potential.clone()),
            ],
            [],
        )
        .map_err(|why| DeviceError::MissingFeature(format!("descriptor set: {why}")))?;

        let command = Self::record(device, &descriptor, panels)?;

        Ok(Self {
            device,
            panels,
            charge,
            potential,
            command,
        })
    }

    /// Record the one dispatch this solve replays, so `apply` neither allocates
    /// nor records.
    fn record(
        device: &Device,
        descriptor: &Arc<DescriptorSet>,
        panels: usize,
    ) -> Result<Arc<PrimaryAutoCommandBuffer>, DeviceError> {
        let n = u32::try_from(panels)
            .map_err(|_| DeviceError::MissingFeature("a panel count past u32".to_owned()))?;
        let groups = n.div_ceil(WORKGROUP);

        let mut builder = AutoCommandBufferBuilder::primary(
            device.commands.clone(),
            device.queue.queue_family_index(),
            // Replayed once per GMRES iteration, so not one-time-submit.
            CommandBufferUsage::MultipleSubmit,
        )
        .map_err(|why| DeviceError::MissingFeature(format!("command buffer: {why}")))?;

        builder
            .bind_pipeline_compute(device.pipeline.clone())
            .and_then(|builder| {
                builder.bind_descriptor_sets(
                    PipelineBindPoint::Compute,
                    device.pipeline.layout().clone(),
                    0,
                    descriptor.clone(),
                )
            })
            .and_then(|builder| builder.push_constants(device.pipeline.layout().clone(), 0, n))
            .map_err(|why| DeviceError::MissingFeature(format!("recording: {why}")))?;

        // SAFETY: `dispatch` is unsafe because vulkano cannot check that the
        // shader stays inside the buffers it was bound. It does: every buffer
        // in the descriptor set above is exactly `panels` elements long, the
        // push constant `n` is that same count, and the kernel's first
        // statement is `if (i >= push.n) return`, so the only invocations that
        // index anything are `0..panels`. `groups * WORKGROUP >= panels` by
        // `div_ceil`, and the excess is exactly what that guard drops.
        unsafe { builder.dispatch([groups, 1, 1]) }
            .map_err(|why| DeviceError::MissingFeature(format!("dispatch: {why}")))?;

        builder
            .build()
            .map_err(|why| DeviceError::MissingFeature(format!("command buffer build: {why}")))
    }
}

/// An allocation the driver refused, as a [`DeviceError::OutOfMemory`].
///
/// The needed and available figures are not recoverable from a vulkano
/// allocation error, so both are reported as zero rather than invented.
fn allocation_refused<E: std::fmt::Display>(why: E) -> DeviceError {
    debug_assert!(false, "the device refused an allocation: {why}");
    DeviceError::OutOfMemory {
        needed: 0,
        available: 0,
    }
}

impl MatVec for GpuMatVec<'_> {
    fn dim(&self) -> usize {
        self.panels
    }

    /// `y := A x`, with `x` narrowed to `f32` on upload and `y` widened back on
    /// readback.
    ///
    /// # Panics
    ///
    /// On a device lost mid-solve, and on a vector of the wrong length. Panics
    /// rather than returning quietly because `y` is fully overwritten by
    /// contract: returning without writing would hand GMRES the previous
    /// iteration's vector and let a solve "converge" on nothing.
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        assert_eq!(x.len(), self.panels, "one charge per panel");
        assert_eq!(y.len(), self.panels, "one potential per panel");

        {
            // The scope ends the mapping before the submit, which is what makes
            // the write visible to the device.
            let mut charge = self
                .charge
                .write()
                .expect("the charge buffer is host-visible and not in flight");
            for (slot, &value) in charge.iter_mut().zip(x) {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the f32 narrowing is the adapter's whole purpose; Backend::GpuF32 attributes it"
                )]
                {
                    *slot = value as f32;
                }
            }
        }

        // One submit and one fence, at the end: a wait after every dispatch
        // would make a 100-iteration GMRES 100 round trips.
        vulkano::sync::now(self.device.queue.device().clone())
            .then_execute(self.device.queue.clone(), self.command.clone())
            .expect("the command buffer was recorded for this queue family")
            .then_signal_fence_and_flush()
            .expect("the queue accepted the submission")
            .wait(None)
            .expect("the device completed the dispatch");

        let potential = self
            .potential
            .read()
            .expect("the potential buffer is host-visible and the fence has passed");
        for (slot, &value) in y.iter_mut().zip(potential.iter()) {
            *slot = f64::from(value);
        }

        debug_assert!(
            y.iter().all(|potential| potential.is_finite()),
            "the operator produced a non-finite potential"
        );
    }

    fn backend(&self) -> Backend {
        // Answerable without a device: an adapter that misnames itself makes
        // every attribution downstream a lie.
        Backend::GpuF32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ways a wrong file reaches the `unsafe` `ShaderModule::new`: a bad
    /// magic number, and a length that is not a whole number of words.
    #[test]
    fn the_committed_spirv_is_a_whole_number_of_words_beginning_with_the_magic() {
        assert_eq!(
            P2P_LAPLACE_SPV.len() % 4,
            0,
            "SPIR-V is a stream of 32-bit words"
        );
        let words = spirv_words(P2P_LAPLACE_SPV).expect("the committed blob is SPIR-V");
        assert_eq!(words[0], SPIRV_MAGIC);
        assert!(
            words.len() > 5,
            "a module with only a header declares no entry point"
        );
    }

    /// Anything that is not SPIR-V is refused rather than reinterpreted.
    #[test]
    fn a_blob_that_is_not_spirv_is_refused_rather_than_reinterpreted() {
        assert!(spirv_words(&[]).is_none(), "an empty file is not a module");
        assert!(
            spirv_words(&[0x03, 0x02, 0x23]).is_none(),
            "three bytes are not a whole word"
        );
        assert!(
            spirv_words(&[0xde, 0xad, 0xbe, 0xef]).is_none(),
            "a whole word that is not the magic is not SPIR-V"
        );
        assert!(
            spirv_words(&P2P_LAPLACE_SPV[..P2P_LAPLACE_SPV.len() - 4]).is_some(),
            "truncation by a whole word is not detectable here, and is not \
             claimed to be — the magic is all this checks"
        );
    }

    /// `WORKGROUP` is both what the shader was compiled for and what the
    /// dispatch rounds up by; recompiling at a different `local_size_x` changes
    /// this line.
    #[test]
    fn the_dispatch_covers_every_panel_and_no_more_than_one_group_of_slack() {
        for panels in [1_u32, 63, 64, 65, 127, 128, 4_097] {
            let groups = panels.div_ceil(WORKGROUP);
            let threads = groups * WORKGROUP;
            assert!(threads >= panels, "{panels} panels are not all covered");
            assert!(
                threads - panels < WORKGROUP,
                "{panels} panels dispatch {threads} threads, more than one group of slack"
            );
        }
    }
}
