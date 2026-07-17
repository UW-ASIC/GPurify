//! GPU vs CPU benchmark: P2P, GEMV, batched GEMM at realistic sizes.

fn main() {
    #[cfg(not(feature = "gpu"))]
    {
        eprintln!("Run with: cargo run --release -p quasiss-gpu --features gpu --example gpu_bench");
        std::process::exit(1);
    }

    #[cfg(feature = "gpu")]
    run();
}

#[cfg(feature = "gpu")]
fn run() {
    use quasiss::gpu::backend::{ComputeBackend, CpuBackend, DeviceMatrix, Precision};
    use quasiss::gpu::VulkanoBackend;
    use std::time::Instant;

    let cpu = CpuBackend::new(Precision::F64);
    let gpu = VulkanoBackend::new();
    println!("GPU backend: {}", gpu.name());
    println!();

    // --- P2P benchmark ---
    println!("{:>8}  {:>10}  {:>10}  {:>8}", "N(P2P)", "CPU(ms)", "GPU(ms)", "speedup");
    println!("{}", "-".repeat(44));
    for &n in &[1000, 4000, 16000] {
        let sx: Vec<f32> = (0..n).map(|i| i as f32 * 0.01).collect();
        let sy = vec![0.0f32; n];
        let sz = vec![0.0f32; n];
        let sq = vec![1.0f32; n];
        let tx: Vec<f32> = (0..n).map(|i| i as f32 * 0.01 + 0.005).collect();
        let ty = vec![0.0f32; n];
        let tz = vec![0.0f32; n];

        // warmup GPU
        let _ = gpu.p2p_laplace(&tx, &ty, &tz, &sx, &sy, &sz, &sq);

        let t0 = Instant::now();
        let _ = gpu.p2p_laplace(&tx, &ty, &tz, &sx, &sy, &sz, &sq);
        let gpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // CPU reference (using the kernel module directly for f32)
        let t0 = Instant::now();
        let mut cpu_out = vec![0.0f32; n];
        quasiss::gpu::kernels::p2p_laplace_cpu(&tx, &ty, &tz, &sx, &sy, &sz, &sq, &mut cpu_out);
        let cpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        println!("{n:>8}  {cpu_ms:>10.2}  {gpu_ms:>10.2}  {s:>7.1}x",
            s = cpu_ms / gpu_ms);
    }
    println!();

    // --- GEMV benchmark (re-upload each call) ---
    println!("{:>8}  {:>10}  {:>10}  {:>8}", "N(GEMV)", "CPU(ms)", "GPU(ms)", "speedup");
    println!("{}", "-".repeat(60));
    for &n in &[512, 2048, 4096] {
        let data: Vec<f64> = (0..n*n).map(|i| (i % 97) as f64 * 0.01).collect();
        let a = DeviceMatrix::from_rows(n, n, data);
        let x: Vec<f64> = (0..n).map(|i| (i % 31) as f64 * 0.1).collect();
        let mut y_cpu = vec![0.0; n];
        let mut y_gpu = vec![0.0; n];

        // warmup
        gpu.gemv(&a, &x, &mut y_gpu);

        let t0 = Instant::now();
        gpu.gemv(&a, &x, &mut y_gpu);
        let gpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t0 = Instant::now();
        cpu.gemv(&a, &x, &mut y_cpu);
        let cpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // verify
        let max_err: f64 = y_cpu.iter().zip(&y_gpu).map(|(a, b)| (a - b).abs()).fold(0.0, f64::max);
        let max_val: f64 = y_cpu.iter().map(|v| v.abs()).fold(0.0, f64::max);
        let rel = if max_val > 0.0 { max_err / max_val } else { 0.0 };

        println!("{n:>8}  {cpu_ms:>10.2}  {gpu_ms:>10.2}  {s:>7.1}x  (rel_err={rel:.1e})",
            s = cpu_ms / gpu_ms);
    }
    println!();

    // --- GEMV benchmark (persistent buffer --- matrix uploaded once) ---
    println!("GEMV with persistent GPU buffer (matrix uploaded once):");
    println!("{:>8}  {:>10}  {:>10}  {:>8}", "N(GEMV)", "CPU(ms)", "GPU(ms)", "speedup");
    println!("{}", "-".repeat(60));
    for &n in &[512, 2048, 4096] {
        let data: Vec<f64> = (0..n*n).map(|i| (i % 97) as f64 * 0.01).collect();
        let a = DeviceMatrix::from_rows(n, n, data);
        let x: Vec<f64> = (0..n).map(|i| (i % 31) as f64 * 0.1).collect();
        let mut y_cpu = vec![0.0; n];
        let mut y_gpu = vec![0.0; n];

        // Upload matrix once
        let handle = gpu.upload_matrix(&a);

        // warmup
        gpu.gemv_with_handle(&handle, &x, &mut y_gpu);

        let t0 = Instant::now();
        gpu.gemv_with_handle(&handle, &x, &mut y_gpu);
        let gpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t0 = Instant::now();
        cpu.gemv(&a, &x, &mut y_cpu);
        let cpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let max_err: f64 = y_cpu.iter().zip(&y_gpu).map(|(a, b)| (a - b).abs()).fold(0.0, f64::max);
        let max_val: f64 = y_cpu.iter().map(|v| v.abs()).fold(0.0, f64::max);
        let rel = if max_val > 0.0 { max_err / max_val } else { 0.0 };

        println!("{n:>8}  {cpu_ms:>10.2}  {gpu_ms:>10.2}  {s:>7.1}x  (rel_err={rel:.1e})",
            s = cpu_ms / gpu_ms);
    }
    println!();

    // --- Batched GEMM benchmark ---
    println!("{:>8}  {:>10}  {:>10}  {:>8}", "batches", "CPU(ms)", "GPU(ms)", "speedup");
    println!("{}", "-".repeat(44));
    let k = 64; // typical M2L block size (chebyshev order 4 -> 4^3=64)
    for &nbatch in &[50, 200, 500] {
        let a_mats: Vec<DeviceMatrix> = (0..nbatch)
            .map(|b| DeviceMatrix::from_rows(k, k, (0..k*k).map(|i| ((b * 97 + i) % 53) as f64 * 0.01).collect()))
            .collect();
        let b_mats: Vec<DeviceMatrix> = (0..nbatch)
            .map(|b| DeviceMatrix::from_rows(k, k, (0..k*k).map(|i| ((b * 61 + i) % 41) as f64 * 0.01).collect()))
            .collect();

        // warmup
        let _ = gpu.batched_gemm(&a_mats, &b_mats);

        let t0 = Instant::now();
        let _ = gpu.batched_gemm(&a_mats, &b_mats);
        let gpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t0 = Instant::now();
        let _ = cpu.batched_gemm(&a_mats, &b_mats);
        let cpu_ms = t0.elapsed().as_secs_f64() * 1000.0;

        println!("{nbatch:>8}  {cpu_ms:>10.2}  {gpu_ms:>10.2}  {s:>7.1}x",
            s = cpu_ms / gpu_ms);
    }
}
