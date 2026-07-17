//! Session-based kernel execution: an arena of read-only device buffers.
//!
//! Upload data once, run pure kernel functions over it — each launch produces
//! a new immutable buffer — and read results only at the end. Nothing is ever
//! mutated on device; the first `read` is the only synchronization point
//! (GPU command streams pipeline enqueued launches for free).
//!
//! ```text
//! Host:   upload(data)                              read(flags)
//!           │                                            ▲
//!           ▼                                            │
//! Device: [xs] ──────┬──► rule_1(xs, ys, t) ──► [flags_1]
//!         [ys] ──────┴──► rule_2(xs, ys, u) ──► [flags_2]
//! ```
//!
//! [`Col<T>`] is the only currency — calling code never touches raw slices or
//! device handles. `#[verify_kernel]` emits a `bind(...)` constructor per
//! kernel returning a [`BoundKernel`] for [`Session::launch`].
//!
//! Backend note: `Session::new(Backend::Gpu)` HARD-ERRORS ([`NoGpu`]) when no
//! device is usable — the consumer owns the fallback and reports it
//! ([`warn_no_gpu`]). On the CPU arena ([`Session::cpu`]), `launch` runs the
//! same scalar kernel function eagerly.

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use crate::{Backend, BackendTelemetry};

/// Element types a session can move: fixed-size, byte-transparent scalars.
pub trait SessionElem: Copy + 'static {
    const SIZE: usize;
    fn write_to(self, out: &mut Vec<u8>);
    fn read_from(bytes: &[u8]) -> Self;
    /// Uniform encoding (64-bit slot).
    fn to_bits64(self) -> u64;
    fn from_bits64(bits: u64) -> Self;
}

macro_rules! session_elem {
    ($t:ty) => {
        impl SessionElem for $t {
            const SIZE: usize = core::mem::size_of::<$t>();
            fn write_to(self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_ne_bytes());
            }
            fn read_from(bytes: &[u8]) -> Self {
                Self::from_ne_bytes(bytes[..Self::SIZE].try_into().unwrap())
            }
            fn to_bits64(self) -> u64 {
                let mut b = [0u8; 8];
                b[..Self::SIZE].copy_from_slice(&self.to_ne_bytes());
                u64::from_ne_bytes(b)
            }
            fn from_bits64(bits: u64) -> Self {
                Self::from_ne_bytes(bits.to_ne_bytes()[..Self::SIZE].try_into().unwrap())
            }
        }
    };
}
session_elem!(f32);
session_elem!(i32);
session_elem!(u32);

/// Opaque handle to a read-only buffer living in the session. Cheap to copy;
/// typed so a `Col<f32>` cannot be fed where a `Col<u32>` is expected.
#[derive(Clone, Copy, Debug)]
pub struct Col<T> {
    id: u32,
    len: usize,
    _t: PhantomData<T>,
}

impl<T> Col<T> {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Untyped reference for kernel binding (generated code only).
    pub fn erased(&self) -> ColRef {
        ColRef {
            id: self.id,
            len: self.len,
        }
    }
}

/// Untyped (id, len) pair naming a session buffer.
#[derive(Clone, Copy, Debug)]
pub struct ColRef {
    pub id: u32,
    pub len: usize,
}

/// Byte-erased uniform stack for a bound kernel (generated code only).
#[derive(Default)]
pub struct Uniforms(Vec<u64>);

impl Uniforms {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push<T: SessionElem>(mut self, v: T) -> Self {
        self.0.push(v.to_bits64());
        self
    }
    pub fn get<T: SessionElem>(&self, i: usize) -> T {
        T::from_bits64(self.0[i])
    }
}

/// CPU arena the generated `cpu_fn`s read typed columns from.
pub struct CpuStore {
    bufs: Mutex<Vec<Option<Vec<u8>>>>,
}

impl CpuStore {
    /// Materialize a column as a typed vector (copies; the arena stays canonical).
    pub fn read_vec<T: SessionElem>(&self, col: ColRef) -> Vec<T> {
        let bufs = self.bufs.lock().unwrap();
        let bytes = bufs[col.id as usize].as_ref().expect("column was released");
        bytes.chunks_exact(T::SIZE).map(T::read_from).collect()
    }
}

/// A kernel + its column bindings + uniforms, ready to launch.
/// Construct through the generated `<kernel>_kernel::bind(...)`.
pub struct BoundKernel {
    pub cols: Vec<ColRef>,
    pub uniforms: Uniforms,
    /// Extra host-side data some shapes need (cross descriptors), byte-encoded.
    pub host: Vec<u8>,
    pub out_len: usize,
    pub out_elem_size: usize,
    /// CPU execution: read inputs from the arena, return output bytes.
    pub cpu_fn: fn(&CpuStore, &[ColRef], &Uniforms, &[u8], usize) -> Vec<u8>,
    /// GPU enqueue: input handles → writes into the preallocated output.
    /// Enqueues only; never syncs.
    #[cfg(feature = "gpu")]
    pub gpu_fn: fn(
        &'static crate::cube::Client,
        &[(cubecl::server::Handle, usize)],
        (cubecl::server::Handle, usize),
        &Uniforms,
        &[u8],
    ),
}

enum Inner {
    Cpu(CpuStore),
    #[cfg(feature = "gpu")]
    Gpu {
        client: &'static crate::cube::Client,
        handles: Mutex<Vec<Option<(cubecl::server::Handle, usize)>>>,
    },
}

/// Owns the device context and every buffer created through it. All `Col`s
/// stay valid (immutable) until [`Session::release`] or drop.
pub struct Session {
    inner: Inner,
    telem: Arc<Mutex<BackendTelemetry>>,
}

/// `Backend::Gpu` was requested but no usable device exists. The consumer
/// decides the fallback — and should say so (see [`warn_no_gpu`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoGpu;

impl std::fmt::Display for NoGpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GPU requested but no usable device (feature off, no driver, or no card)"
        )
    }
}

impl std::error::Error for NoGpu {}

/// One warning per process: consumers that fall back to CPU must say so.
pub fn warn_no_gpu(context: &str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        eprintln!("gdsverify: {context}: GPU requested but no usable device; falling back to CPU");
    });
}

impl Session {
    /// Create a session. `Backend::Gpu` is a HARD requirement: when no device
    /// is usable this errors instead of silently degrading, so the consumer
    /// handles (and reports) the fallback explicitly.
    pub fn new(backend: Backend) -> Result<Self, NoGpu> {
        match backend {
            Backend::Cpu => Ok(Self::cpu()),
            Backend::Gpu => {
                #[cfg(feature = "gpu")]
                if let Some(client) = crate::cube::client() {
                    return Ok(Self {
                        inner: Inner::Gpu {
                            client,
                            handles: Mutex::new(Vec::new()),
                        },
                        telem: Arc::new(Mutex::new(BackendTelemetry::new(
                            Backend::Gpu,
                            Backend::Gpu,
                        ))),
                    });
                }
                Err(NoGpu)
            }
        }
    }

    /// The CPU arena. Never fails.
    pub fn cpu() -> Self {
        Self {
            inner: Inner::Cpu(CpuStore {
                bufs: Mutex::new(Vec::new()),
            }),
            telem: Arc::new(Mutex::new(BackendTelemetry::new(
                Backend::Cpu,
                Backend::Cpu,
            ))),
        }
    }

    /// Snapshot of telemetry counters accumulated during this session.
    pub fn telemetry(&self) -> BackendTelemetry {
        self.telem.lock().unwrap().clone()
    }

    /// The backend actually in use.
    pub fn backend(&self) -> Backend {
        match &self.inner {
            Inner::Cpu(_) => Backend::Cpu,
            #[cfg(feature = "gpu")]
            Inner::Gpu { .. } => Backend::Gpu,
        }
    }

    /// Host → device. The returned `Col` is immutable for its lifetime.
    pub fn upload<T: SessionElem>(&self, data: &[T]) -> Col<T> {
        let len = data.len();
        self.telem.lock().unwrap().bytes_uploaded += (len * T::SIZE) as u64;
        let id = match &self.inner {
            Inner::Cpu(store) => {
                let mut bytes = Vec::with_capacity(len * T::SIZE);
                for &v in data {
                    v.write_to(&mut bytes);
                }
                let mut bufs = store.bufs.lock().unwrap();
                bufs.push(Some(bytes));
                (bufs.len() - 1) as u32
            }
            #[cfg(feature = "gpu")]
            Inner::Gpu { client, handles } => {
                let mut bytes = Vec::with_capacity(len * T::SIZE);
                for &v in data {
                    v.write_to(&mut bytes);
                }
                let handle = client.create(cubecl::bytes::Bytes::from_bytes_vec(bytes));
                let mut hs = handles.lock().unwrap();
                hs.push(Some((handle, len)));
                (hs.len() - 1) as u32
            }
        };
        Col {
            id,
            len,
            _t: PhantomData,
        }
    }

    /// Run one kernel. The output is a new immutable column. On GPU this
    /// enqueues without synchronizing; on CPU it runs eagerly.
    pub fn launch<T: SessionElem>(&self, kernel: BoundKernel) -> Col<T> {
        self.telem.lock().unwrap().kernel_launches += 1;
        assert_eq!(
            kernel.out_elem_size,
            T::SIZE,
            "launch::<T> type does not match the kernel's output element"
        );
        let len = kernel.out_len;
        let id = match &self.inner {
            Inner::Cpu(store) => {
                let out = (kernel.cpu_fn)(store, &kernel.cols, &kernel.uniforms, &kernel.host, len);
                debug_assert_eq!(out.len(), len * T::SIZE);
                let mut bufs = store.bufs.lock().unwrap();
                bufs.push(Some(out));
                (bufs.len() - 1) as u32
            }
            #[cfg(feature = "gpu")]
            Inner::Gpu { client, handles } => {
                let ins: Vec<(cubecl::server::Handle, usize)> = {
                    let hs = handles.lock().unwrap();
                    kernel
                        .cols
                        .iter()
                        .map(|c| hs[c.id as usize].clone().expect("column was released"))
                        .collect()
                };
                let out = client.empty(len * T::SIZE);
                (kernel.gpu_fn)(
                    client,
                    &ins,
                    (out.clone(), len),
                    &kernel.uniforms,
                    &kernel.host,
                );
                let mut hs = handles.lock().unwrap();
                hs.push(Some((out, len)));
                (hs.len() - 1) as u32
            }
        };
        Col {
            id,
            len,
            _t: PhantomData,
        }
    }

    /// Device → host. The only synchronization point.
    pub fn read<T: SessionElem>(&self, col: &Col<T>) -> Vec<T> {
        self.telem.lock().unwrap().bytes_downloaded += (col.len * T::SIZE) as u64;
        match &self.inner {
            Inner::Cpu(store) => store.read_vec(col.erased()),
            #[cfg(feature = "gpu")]
            Inner::Gpu { client, handles } => {
                let handle = handles.lock().unwrap()[col.id as usize]
                    .clone()
                    .expect("column was released");
                let bytes = client.read_one(handle.0).expect("device readback failed");
                bytes.chunks_exact(T::SIZE).map(T::read_from).collect()
            }
        }
    }

    /// Release a column's memory early. Subsequent reads of it panic.
    pub fn release<T>(&self, col: Col<T>) {
        match &self.inner {
            Inner::Cpu(store) => {
                store.bufs.lock().unwrap()[col.id as usize] = None;
            }
            #[cfg(feature = "gpu")]
            Inner::Gpu { handles, .. } => {
                handles.lock().unwrap()[col.id as usize] = None;
            }
        }
    }

    // ---- AtomicCol support ----

    /// Create a mutable copy of an existing column.
    pub fn scratch_from<T: SessionElem>(&self, col: &Col<T>) -> AtomicCol<T> {
        let len = col.len;
        let id = match &self.inner {
            Inner::Cpu(store) => {
                let src = {
                    let bufs = store.bufs.lock().unwrap();
                    bufs[col.id as usize]
                        .as_ref()
                        .expect("column was released")
                        .clone()
                };
                let mut bufs = store.bufs.lock().unwrap();
                bufs.push(Some(src));
                (bufs.len() - 1) as u32
            }
            #[cfg(feature = "gpu")]
            Inner::Gpu { client, handles } => {
                // ponytail: read-back + re-upload; cubecl doesn't expose device-copy
                let h = handles.lock().unwrap()[col.id as usize]
                    .clone()
                    .expect("column was released");
                let bytes = client.read_one(h.0).expect("device readback failed");
                let handle = client.create(cubecl::bytes::Bytes::from_bytes_vec(bytes.to_vec()));
                let mut hs = handles.lock().unwrap();
                hs.push(Some((handle, len)));
                (hs.len() - 1) as u32
            }
        };
        AtomicCol {
            id,
            len,
            _t: PhantomData,
        }
    }

    /// Create a mutable buffer filled with a constant value.
    pub fn scratch_fill<T: SessionElem>(&self, len: usize, val: T) -> AtomicCol<T> {
        let mut bytes = Vec::with_capacity(len * T::SIZE);
        for _ in 0..len {
            val.write_to(&mut bytes);
        }
        let id = match &self.inner {
            Inner::Cpu(store) => {
                let mut bufs = store.bufs.lock().unwrap();
                bufs.push(Some(bytes));
                (bufs.len() - 1) as u32
            }
            #[cfg(feature = "gpu")]
            Inner::Gpu { client, handles } => {
                let handle = client.create(cubecl::bytes::Bytes::from_bytes_vec(bytes));
                let mut hs = handles.lock().unwrap();
                hs.push(Some((handle, len)));
                (hs.len() - 1) as u32
            }
        };
        AtomicCol {
            id,
            len,
            _t: PhantomData,
        }
    }

    /// Enqueue a scatter kernel that writes atomically into an [`AtomicCol`].
    ///
    /// On CPU: sequential writes — determinism is guaranteed by the
    /// commutative-idempotent property of the scatter op.
    pub fn launch_scatter(&self, kernel: ScatterKernel) {
        match &self.inner {
            Inner::Cpu(store) => {
                let pairs = (kernel.cpu_fn)(store, &kernel.cols, &kernel.uniforms, kernel.work_len);
                let mut bufs = store.bufs.lock().unwrap();
                let buf = bufs[kernel.target.id as usize]
                    .as_mut()
                    .expect("target was released");
                for (idx, val) in pairs {
                    let off = (idx as usize) * 4;
                    if off + 4 > buf.len() {
                        continue;
                    }
                    let cur = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
                    let result = match kernel.op {
                        ScatterOp::Min => cur.min(val),
                        ScatterOp::Max => cur.max(val),
                        ScatterOp::Or => cur | val,
                        ScatterOp::And => cur & val,
                        ScatterOp::Write => val,
                    };
                    buf[off..off + 4].copy_from_slice(&result.to_ne_bytes());
                }
            }
            #[cfg(feature = "gpu")]
            Inner::Gpu { client, handles } => {
                let ins: Vec<(cubecl::server::Handle, usize)> = {
                    let hs = handles.lock().unwrap();
                    kernel
                        .cols
                        .iter()
                        .map(|c| hs[c.id as usize].clone().expect("column was released"))
                        .collect()
                };
                let target = {
                    let hs = handles.lock().unwrap();
                    hs[kernel.target.id as usize]
                        .clone()
                        .expect("target was released")
                };
                (kernel.gpu_fn)(client, &ins, target, &kernel.uniforms, kernel.op);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AtomicCol: controlled mutability escape hatch for scatter algorithms
// ---------------------------------------------------------------------------

/// Opaque handle to a mutable buffer living in the session.
///
/// Only commutative-idempotent operations (Min, Max, Or, And) are supported —
/// this guarantees determinism even when the CPU path executes sequentially
/// and the GPU path uses actual atomics.
///
/// Created via [`Session::scratch_from`] or [`Session::scratch_fill`].
/// Consumed by [`AtomicCol::freeze`] which yields an immutable [`Col<T>`].
pub struct AtomicCol<T> {
    id: u32,
    len: usize,
    _t: PhantomData<T>,
}

impl<T> AtomicCol<T> {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Untyped reference for scatter binding.
    pub fn erased(&self) -> ColRef {
        ColRef {
            id: self.id,
            len: self.len,
        }
    }
    /// Consume the mutable buffer and return an immutable [`Col<T>`].
    /// No copies — the buffer is simply reinterpreted as read-only.
    pub fn freeze(self, _session: &Session) -> Col<T> {
        Col {
            id: self.id,
            len: self.len,
            _t: PhantomData,
        }
    }
}

/// Which commutative-idempotent operation a scatter applies.
#[derive(Clone, Copy, Debug)]
pub enum ScatterOp {
    Min,
    Max,
    Or,
    And,
    /// Unconditional write — only sound when each index is written at most once.
    Write,
}

/// A scatter kernel: writes atomically into an [`AtomicCol`].
pub struct ScatterKernel {
    /// Input columns read by the scatter.
    pub cols: Vec<ColRef>,
    pub uniforms: Uniforms,
    /// Target mutable buffer (the AtomicCol).
    pub target: ColRef,
    pub op: ScatterOp,
    /// Number of work items (edge count, not target length).
    pub work_len: usize,
    /// CPU execution: for each work item, return (target_index, value) pairs.
    /// The session applies the scatter op.
    pub cpu_fn: fn(&CpuStore, &[ColRef], &Uniforms, usize) -> Vec<(u32, u32)>,
    #[cfg(feature = "gpu")]
    pub gpu_fn: fn(
        &'static crate::cube::Client,
        &[(cubecl::server::Handle, usize)],
        (cubecl::server::Handle, usize),
        &Uniforms,
        ScatterOp,
    ),
}

/// Encode host-side cross descriptors for [`BoundKernel::host`].
pub fn encode_descs4(descs: &[(u32, u32, u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(descs.len() * 16);
    for &(a, b, c, d) in descs {
        for v in [a, b, c, d] {
            out.extend_from_slice(&v.to_ne_bytes());
        }
    }
    out
}

pub fn decode_descs4(bytes: &[u8]) -> Vec<(u32, u32, u32, u32)> {
    bytes
        .chunks_exact(16)
        .map(|c| {
            let g = |i: usize| u32::from_ne_bytes(c[i * 4..i * 4 + 4].try_into().unwrap());
            (g(0), g(1), g(2), g(3))
        })
        .collect()
}

pub fn encode_descs2(descs: &[(u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(descs.len() * 8);
    for &(a, b) in descs {
        out.extend_from_slice(&a.to_ne_bytes());
        out.extend_from_slice(&b.to_ne_bytes());
    }
    out
}

pub fn decode_descs2(bytes: &[u8]) -> Vec<(u32, u32)> {
    bytes
        .chunks_exact(8)
        .map(|c| {
            (
                u32::from_ne_bytes(c[0..4].try_into().unwrap()),
                u32::from_ne_bytes(c[4..8].try_into().unwrap()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    use gdsverify_macros::verify_kernel;

    // One body per kernel; the macro compiles each for CPU (and GPU under
    // the `gpu` feature). These tests exercise the session CPU arena and the
    // one-shot API against each other.

    #[verify_kernel(shape = map)]
    fn scaled_sum(x: f32, y: f32, #[uniform] k: f32) -> f32 {
        x + y * k
    }

    #[verify_kernel(shape = map)]
    fn above(v: f32, #[uniform] cutoff: f32) -> u32 {
        let mut f = 0u32;
        if v > cutoff {
            f = 1u32;
        }
        f
    }

    #[verify_kernel(shape = min_over)]
    fn dist2(px: f32, py: f32, #[target] cx: f32, #[target] cy: f32) -> f32 {
        let dx = px - cx;
        let dy = py - cy;
        dx * dx + dy * dy
    }

    #[verify_kernel(shape = pair)]
    fn ranges_touch(a_lo: i32, a_hi: i32, b_lo: i32, b_hi: i32) -> u32 {
        let mut f = 0u32;
        if a_lo <= b_hi && b_lo <= a_hi {
            f = 1u32;
        }
        f
    }

    #[verify_kernel(shape = cross_self)]
    fn within(a_x: f32, b_x: f32, #[uniform] thr: f32) -> u32 {
        let mut d = a_x - b_x;
        if b_x > a_x {
            d = b_x - a_x;
        }
        let mut f = 0u32;
        if d < thr {
            f = 1u32;
        }
        f
    }

    #[verify_kernel(shape = segmented_min)]
    fn seg_min_val(v: u32, #[uniform] bias: u32) -> u32 {
        v + bias
    }

    #[test]
    fn session_map_matches_one_shot() {
        let s = Session::cpu();
        let xs = s.upload(&[1.0f32, 2.0, 3.0]);
        let ys = s.upload(&[10.0f32, 20.0, 30.0]);
        let out: Col<f32> = s.launch(scaled_sum_kernel::bind(&xs, &ys, 2.0));
        assert_eq!(s.read(&out), vec![21.0, 42.0, 63.0]);
        assert_eq!(
            s.read(&out),
            scaled_sum_kernel::run(Backend::Cpu, &[1.0, 2.0, 3.0], &[10.0, 20.0, 30.0], 2.0)
        );
    }

    #[test]
    fn session_chains_device_resident_columns() {
        let s = Session::cpu();
        let px = s.upload(&[0.0f32, 10.0]);
        let py = s.upload(&[0.0f32, 0.0]);
        let cx = s.upload(&[3.0f32, 8.0]);
        let cy = s.upload(&[4.0f32, 0.0]);
        // Stage 1: nearest squared distance per query point.
        let d: Col<f32> = s.launch(dist2_kernel::bind(&px, &py, &cx, &cy));
        // Stage 2: threshold the stage-1 output without reading it back.
        let flags: Col<u32> = s.launch(above_kernel::bind(&d, 10.0));
        assert_eq!(s.read(&d), vec![25.0, 4.0]);
        assert_eq!(s.read(&flags), vec![1, 0]);
    }

    #[test]
    fn session_segmented_min_reduces_csr_segments() {
        let s = Session::cpu();
        // vals gathered through idx; segments: [0..3), [3..3) empty, [3..5)
        let vals = s.upload(&[50u32, 20, 30, 40]);
        let idx = s.upload(&[0u32, 1, 2, 3, 1]);
        let seg = s.upload(&[0u32, 3, 3, 5]);
        let out: Col<u32> = s.launch(seg_min_val_kernel::bind(&vals, &idx, &seg, 1));
        // min(51,21,31)=21; empty=MAX; min(41,21)=21
        assert_eq!(s.read(&out), vec![21, u32::MAX, 21]);
        assert_eq!(
            s.read(&out),
            seg_min_val_kernel::run(
                Backend::Cpu,
                &[50, 20, 30, 40],
                &[0, 1, 2, 3, 1],
                &[0, 3, 3, 5],
                1
            )
        );
    }

    #[test]
    fn session_pair_and_cross_shapes() {
        let s = Session::cpu();
        let lo = s.upload(&[0i32, 10, 20]);
        let hi = s.upload(&[5i32, 15, 25]);
        let pa = s.upload(&[0u32, 0]);
        let pb = s.upload(&[1u32, 2]);
        let touch: Col<u32> = s.launch(ranges_touch_kernel::bind(&lo, &hi, &pa, &pb));
        assert_eq!(s.read(&touch), vec![0, 0]);

        let xs = s.upload(&[0.0f32, 1.0, 100.0]);
        let flags: Col<u32> = s.launch(within_kernel::bind(&xs, &[(0, 3), (1, 3)], 5.0));
        assert_eq!(s.read(&flags), vec![1, 0]);
        assert_eq!(
            s.read(&flags),
            within_kernel::cpu(&[0.0, 1.0, 100.0], &[(0, 3), (1, 3)], 5.0)
        );
    }

    #[test]
    fn gpu_without_device_is_a_hard_error_and_release_frees() {
        // No device in tests: the consumer must handle the fallback.
        #[cfg(not(feature = "gpu"))]
        assert!(Session::new(Backend::Gpu).is_err());
        let s = Session::cpu();
        assert_eq!(s.backend(), Backend::Cpu);
        let xs = s.upload(&[1.0f32]);
        s.release(xs);
    }
}

/// Run a session block that may touch the device, containing panics so a GPU
/// failure degrades to the caller's exact CPU path (`None`) instead of
/// aborting a verification run — the session analogue of the one-shot
/// launchers' behavior.
pub fn contained<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}
