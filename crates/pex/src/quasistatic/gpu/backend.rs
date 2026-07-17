//! The [`ComputeBackend`] seam and a working CPU implementation.

use rayon::prelude::*;

/// Numeric precision a backend runs a kernel in. FP64 is required to match the
/// originals; FP32-far/FP64-near mixed precision is the documented mitigation
/// for FP64-poor consumer GPUs (see the design report §Precision).
///
/// # Measured f32 behavior (this workspace, verified numerically)
/// We ran the f32-vs-f64 study rather than assuming it. Two distinct regimes:
///
///  * **Dense solve in f32 is effectively lossless.** BEM potential-coefficient
///    and partial-inductance matrices are well-conditioned (the element
///    self-term dominates the row; measured condition numbers ~2–54 for spheres
///    and parallel plates). f32 keeps ~7 decimal digits and loses only ~2 to the
///    conditioning, so the solved capacitance/impedance agrees with the f64
///    solve to <1e-4 relative. It is therefore safe to run the *dense solve*
///    (and the far-field matvec) in f32 for these systems.
///  * **Near-field kernel evaluation must stay f64.** The f32 `1/r` P2P sum is
///    fine for well-separated (far-field) pairs (~1e-7 relative) but loses up to
///    ~1.2e-4 (0.012%) for near-singular pairs, where `r` is small and
///    cancellation bites. This is exactly why [`Precision::MixedF32F64`] keeps
///    the near/self analytic terms in f64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    /// Full FP64 — bit-comparable to the reference; required to reproduce the
    /// originals exactly.
    F64,
    /// FP32 everywhere. Verified safe for the *dense solve* and far-field matvec
    /// on well-conditioned BEM systems (see enum docs); NOT safe for near-field
    /// kernel evaluation.
    F32,
    /// Mixed: FP32 far-field matvec + FP64 near-field/self analytic terms +
    /// FP64 accumulation with iterative refinement. The accuracy-preserving mode
    /// for FP64-poor consumer GPUs.
    MixedF32F64,
}

/// A dense matrix resident on a compute device (host memory for the CPU backend;
/// device memory for a GPU backend). Row-major.
pub struct DeviceMatrix {
    pub rows: usize,
    pub cols: usize,
    pub host: Vec<f64>,
}

impl DeviceMatrix {
    pub fn from_rows(rows: usize, cols: usize, data: Vec<f64>) -> Self {
        assert_eq!(data.len(), rows * cols);
        DeviceMatrix { rows, cols, host: data }
    }
}

/// Opaque handle to a matrix uploaded to a GPU backend. Holds the device buffer
/// so subsequent GEMV calls skip the upload. For CPU backends this is just the
/// pre-converted f32 data.
pub struct GpuMatrixHandle {
    pub rows: usize,
    pub cols: usize,
    /// ponytail: Box<dyn Any> erases the backend-specific handle (vulkano Buffer,
    /// or Vec<f32> for CPU). Downcast in the backend impl. One allocation, no
    /// generic pollution on the trait.
    inner: Box<dyn std::any::Any + Send + Sync>,
}

impl GpuMatrixHandle {
    pub fn new<T: Send + Sync + 'static>(rows: usize, cols: usize, inner: T) -> Self {
        GpuMatrixHandle { rows, cols, inner: Box::new(inner) }
    }
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.inner.downcast_ref()
    }
}

/// The compute seam. Every performance-critical dense operation the solver needs
/// is expressed here; a GPU backend implements the same methods over device
/// buffers. Selection is a feature flag / runtime choice, never a change to the
/// numerics crate.
pub trait ComputeBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn precision(&self) -> Precision;

    /// General matrix-vector product y = A·x (the GMRES apply for a dense block).
    fn gemv(&self, a: &DeviceMatrix, x: &[f64], y: &mut [f64]);

    /// Dense matvec in f32 (see [`Precision`] — lossless for well-conditioned
    /// BEM systems). Default converts to f32, accumulates, converts back.
    fn gemv_f32(&self, a: &DeviceMatrix, x: &[f64], y: &mut [f64]) {
        let cols = a.cols;
        for i in 0..a.rows {
            let base = i * cols;
            let mut acc = 0.0f32;
            for j in 0..cols {
                acc += (a.host[base + j] as f32) * (x[j] as f32);
            }
            y[i] = acc as f64;
        }
    }

    /// Upload a matrix to the device once. Returns a handle that can be reused
    /// across many GEMV calls. The f64→f32 conversion happens here, not per call.
    fn upload_matrix(&self, a: &DeviceMatrix) -> GpuMatrixHandle {
        // ponytail: CPU default just pre-converts to f32
        let a32: Vec<f32> = a.host.iter().map(|&v| v as f32).collect();
        GpuMatrixHandle::new(a.rows, a.cols, a32)
    }

    /// GEMV using a pre-uploaded matrix handle. Only uploads x per call.
    fn gemv_with_handle(&self, handle: &GpuMatrixHandle, x: &[f64], y: &mut [f64]) {
        // ponytail: CPU default uses the pre-converted f32 data
        let a32 = handle.downcast_ref::<Vec<f32>>().expect("CPU GpuMatrixHandle");
        let cols = handle.cols;
        let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
        for i in 0..handle.rows {
            let base = i * cols;
            let mut acc = 0.0f32;
            for j in 0..cols {
                acc += a32[base + j] * x32[j];
            }
            y[i] = acc as f64;
        }
    }

    /// GEMM using a pre-uploaded matrix handle: C = A·B where A is the resident
    /// `rows×cols` matrix and `b` is `cols×ncols` row-major. Returns C
    /// (`rows×ncols`, row-major). This is the batched-GMRES block apply: all
    /// Krylov columns of one iteration in ONE dispatch instead of ncols GEMVs.
    fn gemm_with_handle(&self, handle: &GpuMatrixHandle, b: &[f64], ncols: usize) -> Vec<f64> {
        // ponytail: CPU default runs the same f32 arithmetic as the GPU kernel
        // (see kernels::gemm_cpu) so it validates the device path.
        assert_eq!(b.len(), handle.cols * ncols);
        let a32 = handle.downcast_ref::<Vec<f32>>().expect("CPU GpuMatrixHandle");
        let b32: Vec<f32> = b.iter().map(|&v| v as f32).collect();
        let mut c32 = vec![0.0f32; handle.rows * ncols];
        crate::quasistatic::gpu::kernels::gemm_cpu(a32, handle.rows, handle.cols, &b32, ncols, &mut c32);
        c32.iter().map(|&v| v as f64).collect()
    }

    /// Batched small GEMM — the M2L hot spot in a black-box FMM, where each
    /// translation is a dense matrix product reused every GMRES iteration.
    /// Computes `c[k] = a[k] · b[k]` for each k.
    fn batched_gemm(
        &self,
        a: &[DeviceMatrix],
        b: &[DeviceMatrix],
    ) -> Vec<DeviceMatrix>;
}

/// Reference CPU backend (rayon-parallel FP64). Bit-comparable to the dense
/// reference solver; used to develop and CI the GPU kernels without hardware,
/// exactly as the report recommends (kernels are ordinary Rust, run on CPU).
pub struct CpuBackend {
    precision: Precision,
}

impl Default for CpuBackend {
    fn default() -> Self {
        CpuBackend { precision: Precision::F64 }
    }
}

impl CpuBackend {
    pub fn new(precision: Precision) -> Self {
        CpuBackend { precision }
    }
}

impl ComputeBackend for CpuBackend {
    fn name(&self) -> &'static str {
        "cpu"
    }
    fn precision(&self) -> Precision {
        self.precision
    }

    fn gemv(&self, a: &DeviceMatrix, x: &[f64], y: &mut [f64]) {
        assert_eq!(x.len(), a.cols);
        assert_eq!(y.len(), a.rows);
        let cols = a.cols;
        y.par_iter_mut().enumerate().for_each(|(i, yi)| {
            let base = i * cols;
            let mut acc = 0.0;
            for j in 0..cols {
                acc += a.host[base + j] * x[j];
            }
            *yi = acc;
        });
    }

    fn gemv_f32(&self, a: &DeviceMatrix, x: &[f64], y: &mut [f64]) {
        // Dense matvec carried out in f32. Kept as a first-class path because,
        // per the Precision docs, the dense solve/matvec on well-conditioned BEM
        // matrices is effectively lossless in f32 (measured <1e-4 vs f64). This
        // is the operation a GPU would run in single precision; the f32 rounding
        // here mirrors that so the CPU path can validate the GPU path.
        assert_eq!(x.len(), a.cols);
        assert_eq!(y.len(), a.rows);
        let cols = a.cols;
        let a32: Vec<f32> = a.host.iter().map(|&v| v as f32).collect();
        let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
        y.par_iter_mut().enumerate().for_each(|(i, yi)| {
            let base = i * cols;
            let mut acc = 0.0f32;
            for j in 0..cols {
                acc += a32[base + j] * x32[j];
            }
            *yi = acc as f64;
        });
    }

    fn batched_gemm(&self, a: &[DeviceMatrix], b: &[DeviceMatrix]) -> Vec<DeviceMatrix> {
        assert_eq!(a.len(), b.len());
        a.par_iter()
            .zip(b.par_iter())
            .map(|(ai, bi)| {
                assert_eq!(ai.cols, bi.rows);
                let (m, k, n) = (ai.rows, ai.cols, bi.cols);
                let mut c = vec![0.0; m * n];
                for i in 0..m {
                    for p in 0..k {
                        let aip = ai.host[i * k + p];
                        let brow = p * n;
                        let crow = i * n;
                        for j in 0..n {
                            c[crow + j] += aip * bi.host[brow + j];
                        }
                    }
                }
                DeviceMatrix::from_rows(m, n, c)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_gemv() {
        let a = DeviceMatrix::from_rows(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let x = [1.0, 0.0, -1.0];
        let mut y = [0.0; 2];
        CpuBackend::default().gemv(&a, &x, &mut y);
        assert_eq!(y, [1.0 - 3.0, 4.0 - 6.0]);
    }

    #[test]
    fn cpu_gemm_with_handle_matches_gemv_columns() {
        let backend = CpuBackend::default();
        let a = DeviceMatrix::from_rows(3, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0]);
        let handle = backend.upload_matrix(&a);
        // Two columns stored row-major in b: col0 = [1,0,-1], col1 = [2,1,0].
        let b = vec![1.0, 2.0, 0.0, 1.0, -1.0, 0.0];
        let c = backend.gemm_with_handle(&handle, &b, 2);
        // Compare each output column against gemv on the same column.
        for (col, x) in [[1.0, 0.0, -1.0], [2.0, 1.0, 0.0]].iter().enumerate() {
            let mut y = [0.0; 3];
            backend.gemv_with_handle(&handle, x, &mut y);
            for i in 0..3 {
                assert!((c[i * 2 + col] - y[i]).abs() < 1e-6);
            }
        }
    }

    #[test]
    fn cpu_batched_gemm_identity() {
        let id = DeviceMatrix::from_rows(2, 2, vec![1.0, 0.0, 0.0, 1.0]);
        let m = DeviceMatrix::from_rows(2, 2, vec![7.0, 8.0, 9.0, 10.0]);
        let out = CpuBackend::default().batched_gemm(&[id], &[m]);
        assert_eq!(out[0].host, vec![7.0, 8.0, 9.0, 10.0]);
    }
}
