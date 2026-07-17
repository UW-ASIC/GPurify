//! Execution backend selection, session-based kernel execution, and the Rule trait.

pub mod rule;
pub mod session;

// Self-alias so `crate::backend::Backend` and `crate::backend::cube::*`
// resolve within this crate (the verify_kernel proc macro emits those paths).
pub mod backend {
    pub use super::available_backends;
    #[cfg(feature = "gpu")]
    pub use super::cube;
    pub use super::gpu_ready;
    pub use super::Backend;
    pub use super::BackendTelemetry;
}

/// Where the per-element kernels run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Cpu,
    /// CubeCL (CUDA runtime). Requires the `gpu` feature + a device; falls back to CPU.
    Gpu,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Cpu => "cpu",
            Backend::Gpu => "gpu",
        }
    }
}

/// Telemetry captured during one engine run.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BackendTelemetry {
    pub requested: String,
    pub actual: String,
    pub gpu_device: Option<String>,
    pub kernel_launches: u32,
    pub fallback_count: u32,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
}

impl BackendTelemetry {
    pub fn new(requested: Backend, actual: Backend) -> Self {
        Self {
            requested: requested.as_str().into(),
            actual: actual.as_str().into(),
            ..Default::default()
        }
    }
}

/// Is a CUDA device actually usable right now?
pub fn gpu_ready() -> bool {
    #[cfg(feature = "gpu")]
    {
        return cube::ready();
    }
    #[cfg(not(feature = "gpu"))]
    false
}

/// Report which backends are usable in this build and on this machine.
pub fn available_backends() -> Vec<Backend> {
    let mut v = vec![Backend::Cpu];
    if gpu_ready() {
        v.push(Backend::Gpu);
    }
    v
}

/// Shared CubeCL runtime infrastructure for the `#[verify_kernel]`-generated
/// launchers.
#[cfg(feature = "gpu")]
pub(crate) mod cube {
    use cubecl::bytes::Bytes;
    use cubecl::cuda::{CudaDevice, CudaRuntime};
    use cubecl::prelude::*;
    use std::sync::OnceLock;

    pub(crate) const CUBE_DIM: u32 = 256;
    /// Evaluation budget per cross-product launch chunk.
    pub(crate) const CHUNK: usize = 16 << 20;

    pub(crate) type Client = ComputeClient<CudaRuntime>;

    pub(crate) fn client() -> Option<&'static Client> {
        static C: OnceLock<Option<Client>> = OnceLock::new();
        C.get_or_init(|| std::panic::catch_unwind(|| CudaRuntime::client(&CudaDevice::new(0))).ok())
            .as_ref()
    }

    pub(crate) fn ready() -> bool {
        client().is_some()
    }

    /// Contain kernel/driver panics: a GPU failure must degrade to the CPU
    /// path (`None`), never abort a verification run.
    pub(crate) fn contain<T>(f: impl FnOnce() -> Option<T>) -> Option<T> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(v) => {
                if v.is_none() && std::env::var_os("GDSVERIFY_GPU_LOG").is_some() {
                    eprintln!("gdsverify gpu: call returned None (non-panic failure)");
                }
                v
            }
            Err(p) => {
                if std::env::var_os("GDSVERIFY_GPU_LOG").is_some() {
                    let msg = p
                        .downcast_ref::<String>()
                        .map(|s| s.as_str())
                        .or_else(|| p.downcast_ref::<&str>().copied())
                        .unwrap_or("<non-string panic>");
                    eprintln!("gdsverify gpu: panic: {msg}");
                }
                None
            }
        }
    }

    pub(crate) fn log_time(what: &str, t0: std::time::Instant) {
        if std::env::var_os("GDSVERIFY_GPU_LOG").is_some() {
            eprintln!("gdsverify gpu: {what}: {:?}", t0.elapsed());
        }
    }

    /// Element types the generated launchers can move across the bus.
    pub(crate) trait DeviceElem: Copy + 'static {
        fn to_bytes(v: &[Self]) -> Bytes;
        fn from_bytes(b: &[u8], n: usize) -> Vec<Self>;
        fn ne_bytes(self) -> [u8; 4];
    }

    macro_rules! device_elem {
        ($t:ty) => {
            impl DeviceElem for $t {
                fn to_bytes(v: &[Self]) -> Bytes {
                    Bytes::from_elems(v.to_vec())
                }
                fn from_bytes(b: &[u8], n: usize) -> Vec<Self> {
                    b.chunks_exact(core::mem::size_of::<Self>())
                        .take(n)
                        .map(|c| Self::from_ne_bytes(c.try_into().unwrap()))
                        .collect()
                }
                fn ne_bytes(self) -> [u8; 4] {
                    self.to_ne_bytes()
                }
            }
        };
    }
    device_elem!(f32);
    device_elem!(i32);
    device_elem!(u32);

    /// Upload a column, memoized by CONTENT hash for large slices: the same
    /// layer's column set is uploaded by several rules per run and by every
    /// run in a steady-state loop. Full-content hashing (not sampling) keeps
    /// this sound — a false hit needs a 64-bit collision on the exact value
    /// stream. Bounded to 64 handles, evicting oldest.
    pub(crate) fn upload<E: DeviceElem>(client: &Client, v: &[E]) -> cubecl::server::Handle {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::sync::Mutex;
        const CACHE_MIN: usize = 4_096;
        static CACHE: Mutex<Vec<(u64, cubecl::server::Handle)>> = Mutex::new(Vec::new());

        if v.len() < CACHE_MIN {
            return client.create(E::to_bytes(v));
        }
        let mut h = DefaultHasher::new();
        std::any::TypeId::of::<E>().hash(&mut h);
        v.len().hash(&mut h);
        for e in v {
            e.ne_bytes().hash(&mut h);
        }
        let key = h.finish();
        let mut cache = CACHE.lock().unwrap();
        if let Some((_, handle)) = cache.iter().find(|(k, _)| *k == key) {
            return handle.clone();
        }
        let t0 = std::time::Instant::now();
        let handle = client.create(E::to_bytes(v));
        log_time(&format!("column upload ({} elems)", v.len()), t0);
        if cache.len() >= 64 {
            cache.remove(0);
        }
        cache.push((key, handle.clone()));
        handle
    }

    /// Read a device buffer back as `n` elements.
    pub(crate) fn read_out<E: DeviceElem>(
        client: &Client,
        handle: cubecl::server::Handle,
        n: usize,
    ) -> Option<Vec<E>> {
        Some(E::from_bytes(&client.read_one(handle).ok()?, n))
    }
}
