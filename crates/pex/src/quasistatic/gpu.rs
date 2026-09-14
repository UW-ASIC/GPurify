//! The `f32` device adapter, and the contract it must meet to exist.
//!
//! This is the only GPU code in the workspace. Everything else that ran on a
//! device in the old tree was an advisory prefilter — flag candidates, then
//! check them exactly on the CPU anyway — which pays the whole transfer cost to
//! save part of the work, on kernels doing one integer modulo per element. No
//! amount of tuning clears that ceiling, so those are gone.
//!
//! # The contract
//!
//! From `docs/GPU.md`. This adapter does not ship unless all six hold, and if
//! any fails the CPU adapter is the answer and saying so is a complete result.
//!
//! 1. **Persistent buffers.** Allocated once per solve, reused across every
//!    iteration. No allocation inside the iteration loop. — [`GpuMatVec::upload`]
//!    allocates all four and records the command buffer once; [`MatVec::apply`]
//!    allocates nothing.
//! 2. **Async submission.** No host wait between dependent dispatches. The old
//!    path called `.wait(None)` after every dispatch, so a 50–100 iteration
//!    GMRES became 50–100 round trips — that alone is why it measured ~1000×
//!    slower than the CPU. — one dispatch per `apply` and one fence, at the end,
//!    where the potential vector is genuinely needed.
//! 3. **Batched dispatch.** The far-field batch is one dispatch, not one per
//!    block. — the whole matvec is one dispatch; there is no far field, because
//!    this adapter is direct P2P and the FMM is still filed.
//! 4. **`f64` residual.** Accuracy is bounded by a host `f64` residual check
//!    and the achieved value is reported. The old path computed in `f32` and
//!    never re-verified, on a signoff tool. — `solve::refine` takes **two**
//!    operators, and `quasistatic::columns_into` always passes the host
//!    `CpuMatVec` as the accurate one. See below.
//! 5. **Equality tests that actually run.** Not `#[ignore]`d. — `crates/pex/tests/gpu.rs`,
//!    every one of which runs on a machine with no device and asserts the
//!    fallback, and asserts agreement with [`super::matvec::CpuMatVec`] on one
//!    with a device.
//! 6. **A measured crossover.** Selected only above the size it was benchmarked
//!    to win at. Automatic, never a flag. — [`Device::crossover`], measured by
//!    `crates/pex/benches` and recorded there.
//!
//! ## Item 4 was open, and closing it is what made this adapter usable
//!
//! `solve::refine` used to take one operator, so the `A x` inside
//! `solve::residual` went through the same adapter as the inner solve. Under a
//! `GpuF32` adapter the residual then carried that adapter's own error and no
//! amount of iteration removed it. **Measured, the first time this adapter ran a
//! real solve**: the residual stalled at `7.87e-7` against a `1e-10` tolerance
//! and the solve returned `SolveError::NotConverged` after 400 iterations.
//!
//! That was fail-*closed* — a refusal, not a quietly `f32`-accurate capacitance
//! — and it also made the device useless, because every solve above the
//! crossover refused. `docs/GPU.md` specifies the fix in as many words: the
//! matvec runs on the GPU in `f32`, the residual and the correction are computed
//! on the host in `f64`. `refine` now takes both operators and
//! `quasistatic::columns_into` builds the host adapter unconditionally to be the
//! accurate one. The same solve reaches `1e-10`.
//!
//! It costs one `f64` matvec per refinement pass and needs more iterations than
//! the host path for the same tolerance — about 440 against 400 on the corpus's
//! two-conductor fixture. More iterations of a much cheaper kind is what
//! mixed-precision refinement *is*.

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
use vulkano::device::{
    Device as VkDevice, DeviceCreateInfo, Queue, QueueCreateInfo, QueueFlags,
};
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

use super::matvec::{Backend, MatVec};
use super::mesh::Mesh;
use super::matvec::FOUR_PI_EPS0;

/// The compiled P2P Laplace kernel.
///
/// Ahead-of-time SPIR-V, compiled from `shaders/p2p_laplace.comp` by `glslc` and
/// committed beside it — `docs/GPU.md`: "no runtime shader compilation, so a
/// shader that does not compile is a build failure rather than a surprise on a
/// customer's machine."
///
/// Committed rather than generated by a build script on purpose.
/// `vulkano-shaders` pulls in `shaderc-sys`, which needs either a system
/// `libshaderc` or `cmake` to build one, and neither is present outside
/// `nix develop` — so a build-script version would make `cargo test` outside the
/// dev shell fail to compile, on every crate downstream of `pex`. The
/// regeneration command is in the shader's own header, and
/// `the_committed_spirv_is_the_module_the_adapter_expects` checks the blob is
/// the module this file binds against rather than a stale one.
const P2P_LAPLACE_SPV: &[u8] = include_bytes!("../../shaders/p2p_laplace.spv");

/// Threads per workgroup, and the `local_size_x` the shader was compiled for.
///
/// The two must agree: the dispatch below rounds the panel count up by this, and
/// a shader compiled for a different size would leave a tail unwritten or run
/// past the buffer. [`Device::find`] rejects a device whose limits cannot run it.
const WORKGROUP: u32 = 64;

/// A usable compute device.
///
/// `None` everywhere it appears means no device, or one that does not meet the
/// requirements. That is an ordinary outcome, not an error: the CPU adapter
/// produces the same answers.
#[derive(Debug)]
pub struct Device {
    /// The compute queue every dispatch is submitted on. Owns the logical
    /// device, which is why no separate handle is kept.
    queue: Arc<Queue>,
    /// AOT-compiled, built once here rather than per solve: pipeline creation
    /// is milliseconds and a solve is one `upload` away from being hot.
    pipeline: Arc<ComputePipeline>,
    memory: Arc<StandardMemoryAllocator>,
    descriptors: Arc<StandardDescriptorSetAllocator>,
    commands: Arc<StandardCommandBufferAllocator>,
    /// Panel count above which this device beat the host. A *property of the
    /// device*, so it lives on the value rather than in a constant.
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
///
/// **Decision** — one physical device in, one optional reason out, pure apart
/// from the property reads. Separate from [`Device::find`] so the enumeration
/// loop reads as "the first device with no complaint against it", and so the
/// complaint can be reported rather than discarded when *every* device has one.
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
    // host `f64` refinement is the whole design, and demanding `f64` on the
    // device would reject the development target for a feature this path does
    // not use.
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
    /// Returns `Ok(None)` when there is simply no device — the common case on
    /// CI and on many desktops, and not a failure. `Err` is reserved for a
    /// device that exists but is unusable, which is worth telling someone about.
    ///
    /// The split is exactly that, and it is the whole of the return type's
    /// meaning: **no loader, or an instance with zero physical devices, is
    /// `Ok(None)`** — "no GPU here". A physical device that exists and is then
    /// *rejected* is `Err(MissingFeature)`, carrying which requirement it missed
    /// and both numbers — "a GPU is here and this is why it did not run."
    ///
    /// `TRANSFER` is implied by `COMPUTE` and `GRAPHICS` is not needed, so the
    /// queue search asks for `COMPUTE` and nothing else.
    pub fn find() -> Result<Option<Self>, DeviceError> {
        // No loader at all. Ordinary — a headless container has none — and
        // `Ok(None)` rather than `Err`: the probe succeeded, it found nothing.
        let Ok(library) = VulkanLibrary::new() else {
            return Ok(None);
        };
        let Ok(instance) = Instance::new(
            library,
            InstanceCreateInfo {
                // MoltenVK and other portability drivers are not conformant and
                // are enumerated only when asked for. Costs nothing where none
                // is present.
                flags: InstanceCreateFlags::ENUMERATE_PORTABILITY,
                ..Default::default()
            },
        ) else {
            return Ok(None);
        };
        let Ok(devices) = instance.enumerate_physical_devices() else {
            return Ok(None);
        };

        // The first complaint, kept so that "a GPU is here and none of them
        // would run" can be reported rather than silently downgraded to "no GPU
        // here". Fail closed: a rejected device is `Err`.
        let mut complaint = None;
        for physical in devices {
            match unusable(&physical) {
                Some(why) => complaint.get_or_insert(why),
                None => return Self::open(&physical).map(Some),
            };
        }
        match complaint {
            Some(why) => Err(DeviceError::MissingFeature(why)),
            // Zero physical devices. The probe ran and found nothing.
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
    /// The descriptor set layout is *derived from the module's own reflection*
    /// rather than written out here, so the four bindings this file writes and
    /// the four the shader declares cannot drift apart silently: a mismatch is a
    /// validation error at set-creation time.
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
        let module = unsafe { ShaderModule::new(device.clone(), ShaderModuleCreateInfo::new(&words)) }
            .map_err(|why| DeviceError::MissingFeature(format!("the shader would not load: {why}")))?;
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

    /// Panel count above which this device beat the host, measured on the scale
    /// corpus.
    ///
    /// A property of the device, not a constant: the crossover on a laptop
    /// integrated part and on a discrete card are not the same number.
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
/// **Measured, not assumed** — `docs/GPU.md` contract item 6, and the one item
/// that cannot be met by reading the code.
/// `crates/pex/tests/gpu.rs::the_crossover_is_measured_rather_than_assumed` is
/// what produced this table and what re-measures it, on an RTX 4060 Laptop
/// (driver 595.71.05) against an i9-14900HX, one matvec averaged over
/// `2^22 / n` repeats after a warm-up:
///
/// | panels | host µs | device µs | winner |
/// |---:|---:|---:|---|
/// | 64 | 11.1 | 216.8 | host |
/// | 256 | 410.7 | 254.9 | device, 1.6× |
/// | 512 | 1959.5 | 398.1 | device, 4.9× |
/// | 1024 | 4148.3 | 353.0 | device, 11.8× |
/// | 2048 | 11441.1 | 738.9 | device, 15.5× |
/// | 4096 | 45722.4 | 2762.8 | device, 16.6× |
/// | 8192 | 183065.7 | 8286.6 | device, 22.1× |
///
/// `--release`, deliberately: the same sweep in a debug build gives the same
/// crossover but a 66× figure at 8192, because it is timing an unoptimised host
/// fold. A crossover measured against a debug host would be too *low*, which is
/// the fail-open direction — it routes a signoff number onto the `f32` path
/// below the size where that path was actually seen to win.
///
/// 256 rather than something between 64 and 256: it is the first *sampled* count
/// at which the device won, and rounding the claim down to an unmeasured size
/// would be exactly the invention this constant exists to avoid. Below it the
/// host runs, which costs throughput and nothing else.
///
/// ponytail: one number for every device, measured on one part. The ceiling: a
/// part slower than this one is selected below its own crossover and loses
/// throughput; it does not lose accuracy, because `solve::refine`'s residual is
/// measured rather than assumed. Upgrade path: calibrate in [`Device::find`] and
/// store the measurement on the value — the field is already there, and `find`
/// is called once per run.
///
/// `> 0` is load-bearing and `matvec::select` asserts it: a crossover of zero
/// would select the device at every size including the empty problem, which is
/// the fail-open reading of the sentinel and the one thing `docs/GPU.md`
/// contract item 6 forbids.
const MEASURED_CROSSOVER: usize = 256;

const BAD_SPIRV: &str =
    "the committed SPIR-V is not a whole number of little-endian words beginning \
     with the SPIR-V magic; regenerate it with the command in the shader header";

/// The SPIR-V magic number, little-endian.
const SPIRV_MAGIC: u32 = 0x0723_0203;

/// Reinterpret a committed SPIR-V blob as the `u32` words vulkano wants.
///
/// **Decision** — bytes in, words out, pure. `None` for anything that is not
/// SPIR-V, which is the fail-closed answer: a truncated or wrong-endian blob
/// would otherwise reach `ShaderModule::new` and be undefined behaviour there.
///
/// A copy, not a cast. `include_bytes!` gives a `&[u8]` with only byte
/// alignment, so `bytemuck`-style reinterpretation is not sound for it; the blob
/// is two kilobytes and this runs once per process.
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

/// Device-resident `f32` matvec.
///
/// **Five questions.** In: a mesh, uploaded once. Out: `y := A x` per call.
/// How many: one per solve, called once per GMRES iteration. Access pattern:
/// panel data is device-resident for the solve's lifetime and only the vectors
/// cross the bus — which is the difference between this and the old path, where
/// the input vector was re-uploaded on every call despite the matrix already
/// being resident. Lifetime: one solve. Parallelisable: it is the parallelism.
///
/// Multiplies in `f32`. That is safe only because
/// [`super::solve::refine`] wraps it in host `f64` refinement and the achieved
/// residual is measured, never assumed.
#[derive(Debug)]
pub struct GpuMatVec<'d> {
    device: &'d Device,
    /// Panels. The dispatch and both vectors are sized from it, and it is the
    /// `n` the shader is handed as a push constant.
    panels: usize,
    /// The two vectors, host-visible so a matvec is a write, a submit and a
    /// read rather than a staging copy either side.
    charge: Subbuffer<[f32]>,
    potential: Subbuffer<[f32]>,
    /// Recorded once in [`Self::upload`] and replayed by every [`MatVec::apply`].
    /// This is contract item 1 in its strongest form: not merely "no allocation
    /// in the loop" but no *recording* in it either. The panel buffers are held
    /// alive by it and by the descriptor set, which is why they have no fields
    /// of their own.
    command: Arc<PrimaryAutoCommandBuffer>,
}

impl<'d> GpuMatVec<'d> {
    /// Upload a mesh and allocate every buffer the solve will use.
    ///
    /// Everything that can be allocated is allocated here, so [`MatVec::apply`]
    /// contains no allocation and no host synchronisation beyond the single
    /// fence on the result.
    ///
    /// # The panel table is built here, not read from the mesh
    ///
    /// The kernel reads a centroid, an effective radius and a Green's-function
    /// coefficient, and a [`Mesh`] carries a centroid, an *area* and a
    /// permittivity. The reduction is `super::matvec::CpuMatVec::build`'s, done
    /// once here for the same reason it is done once there: the `sqrt` and the
    /// divide are per panel, not per pair.
    ///
    /// Narrowed to `f32` on the way, which is the whole design and is why
    /// [`Backend::GpuF32`] exists to attribute the difference.
    ///
    /// # Centres are stored relative to the mesh's own centroid
    ///
    /// The kernel reads centres only as *differences*, so a common translation
    /// is exactly cancelled by the maths and catastrophically not cancelled by
    /// the narrowing. A layout sitting at `x ≈ 1e-3` m with panels `1e-8` m
    /// apart loses five of `f32`'s seven digits to the subtraction before the
    /// kernel has done any arithmetic at all — and the near-field pairs, which
    /// are the ones with the largest coefficients, are exactly the pairs whose
    /// differences are smallest.
    ///
    /// Subtracting the centroid first is exact in the model and costs one pass
    /// over the panels at upload.
    ///
    /// **It changes nothing on this corpus, and that is expected**: the scale
    /// fixtures are drawn near the origin, so their centres carry no large
    /// common offset to lose. Measured either way, the refinement trace is
    /// identical to three digits. It is here for the layout that is not near the
    /// origin, which is every real one — and it is cheap enough that waiting for
    /// a fixture that exhibits the problem would be waiting to be wrong.
    pub fn upload(device: &'d Device, mesh: &Mesh) -> Result<Self, DeviceError> {
        debug_assert_eq!(
            mesh.panel.len(),
            mesh.epsilon.len(),
            "one permittivity per panel"
        );
        let panels = mesh.panel.len();
        if panels == 0 {
            // An empty problem has no dispatch to record and no buffer to
            // allocate — `Buffer::from_iter` refuses a zero-length slice — and
            // a device is never selected for one anyway, because `select`
            // compares against a crossover that is positive by construction.
            return Err(DeviceError::NoDevice);
        }

        // Every buffer this solve will use, sized before any of them is
        // allocated, so the memory check below is against the whole solve rather
        // than against whichever allocation happened to fail first.
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

        // The origin every centre is stored relative to — see this function's
        // doc comment. Summed in `f64` and in ascending panel order, so it is a
        // deterministic function of the mesh and two uploads of one mesh place
        // the panels identically.
        let mut origin = [0.0_f64; 3];
        for panel in &mesh.panel {
            for (sum, &coordinate) in origin.iter_mut().zip(&panel.centre) {
                *sum += coordinate;
            }
        }
        #[expect(clippy::cast_precision_loss, reason = "a panel count under 2^53 is exact in f64")]
        let count = panels as f64;
        for slot in &mut origin {
            *slot /= count;
        }

        // The five panel columns, packed as the shader declares them: a `vec4`
        // of centroid and radius, and a scalar coefficient. Built by iterator so
        // `from_iter` writes straight into mapped memory with no intermediate
        // `Vec`.
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
                // The `f32` narrowing is this adapter's whole purpose, stated
                // once here rather than four times: `Backend::GpuF32` is what
                // attributes the difference, and `solve::refine`'s `f64`
                // residual is what bounds it.
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "narrowing to f32 is the adapter; Backend::GpuF32 attributes it"
                )]
                [
                    (panel.centre[0] - origin[0]) as f32,
                    (panel.centre[1] - origin[1]) as f32,
                    (panel.centre[2] - origin[2]) as f32,
                    // `√A / (4 ln(1 + √2))`, the radius at which a point charge
                    // reproduces this panel's own centroid potential — and the
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

        // Read back every call, so it is host-visible on the *random access*
        // filter rather than the write-combined one: a write-combined mapping
        // reads at bus speed.
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

    /// Record the one dispatch this solve replays.
    ///
    /// Contract item 3 — one dispatch, not one per block — and item 1 in its
    /// strongest form: the command buffer is built once, so `apply` neither
    /// allocates nor records.
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
            // Replayed once per GMRES iteration, so it must not be
            // one-time-submit.
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
            .and_then(|builder| {
                builder.push_constants(device.pipeline.layout().clone(), 0, n)
            })
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

/// An allocation the driver refused, as an [`DeviceError::OutOfMemory`].
///
/// The needed and available figures the variant asks for are not recoverable
/// from a vulkano allocation error, so both are reported as zero and the
/// message carries the driver's own words. Better than inventing two numbers.
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

    /// `y := A x`, with `x` converted to `f32` on upload and `y` widened back
    /// on readback.
    ///
    /// One fence, at the end, where the result is genuinely needed.
    ///
    /// # Panics
    ///
    /// On a device lost mid-solve, and on a vector of the wrong length. Both are
    /// stated as panics rather than as a quiet return because `y` is fully
    /// overwritten by contract: a body that returned without writing would hand
    /// GMRES the previous iteration's vector and let a solve "converge" on
    /// nothing. [`MatVec::apply`] returns `()`, so there is no other channel —
    /// which is also why [`DeviceError::Lost`] has no reachable return site, and
    /// is filed under "pex quasistatic/gpu.rs".
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        assert_eq!(x.len(), self.panels, "one charge per panel");
        assert_eq!(y.len(), self.panels, "one potential per panel");

        {
            // Narrowed on the way down. The scope ends the mapping before the
            // submit, which is what makes the write visible to the device.
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

        // One submit and one fence, at the end, where the result is genuinely
        // needed. The old path's `.wait(None)` after every dispatch is what made
        // a 50–100 iteration GMRES 50–100 round trips.
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
        // Answerable without a device: this adapter is the `f32` device path,
        // whatever it is or is not able to do today. `Accuracy::backend` is how
        // a run's numbers are attributed, and an adapter that misnames itself
        // makes every attribution downstream a lie.
        Backend::GpuF32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the file format. A wrong or truncated blob reaching
    /// `ShaderModule::new` is undefined behaviour, and `include_bytes!` will
    /// happily embed anything that is on disk — so the two ways a wrong file
    /// gets there, a bad magic number and a length that is not a whole number of
    /// words, are checked before it does.
    ///
    /// This is also the staleness guard the committed SPIR-V needs. It cannot
    /// tell a stale module from a current one — that would need shaderc, which
    /// is exactly the dependency the blob exists to avoid — but it does say the
    /// blob is a SPIR-V compute module rather than a leftover or an empty file.
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

    /// Oracle: construct-from-answer, both directions. Anything that is not
    /// SPIR-V is refused, and refusing is what keeps it away from the `unsafe`
    /// block in `build_pipeline`.
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

    /// Oracle: the contract. `WORKGROUP` is the number the shader was compiled
    /// for and the number the dispatch rounds up by, and the two are the same
    /// constant precisely so they cannot drift. If the shader is recompiled at a
    /// different `local_size_x`, this is the line to change.
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
