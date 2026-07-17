//! `fastcap` — drop-in-style CLI for capacitance extraction.
//!
//! Usage:
//!   fastcap <input.qui> [scale] [--fmm] [--gpu]
//!
//! Prints the Maxwell capacitance matrix [F], mirroring FastCap's output.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <input.qui> [scale] [--fmm] [--gpu]", args[0]);
        return ExitCode::FAILURE;
    }
    let path = &args[1];
    let use_fmm = args.iter().any(|a| a == "--fmm");
    let use_gpu = args.iter().any(|a| a == "--gpu");
    let use_dense = args.iter().any(|a| a == "--dense");
    let scale: f64 = args.iter().skip(2)
        .find(|a| !a.starts_with('-'))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0);

    // Kick off Vulkan init on a background thread NOW so the driver's
    // ~hundreds of ms overlap with parsing + P-matrix assembly.
    #[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
    let gpu_thread = quasiss::gpu::cli_spawn(use_gpu);

    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read '{path}': {e}");
            return ExitCode::FAILURE;
        }
    };
    let geo = match quasiss::cap::parse(&text, scale) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let n_panels = geo.panels.len();

    // ponytail: --gpu -> GPU dense iterative (P resident on device);
    // --fmm -> FMM CPU; neither -> auto by size.
    let cap = 'solve: {
        // NOTE: --gpu stays an explicit override here — the auto-selector
        // never routes capacitance to the GPU because the only GPU algorithm
        // is dense O(N²) and the CPU FMM (O(N)) beats it at every measured
        // size (e.g. 4096 panels: FMM 0.36s vs GPU dense 1.11s).
        #[cfg(feature = "gpu")]
        if let Some(t) = gpu_thread {
            match t.join() {
                Ok(gpu) => {
                    eprintln!("GPU backend ready (vulkano, dense GEMV resident)");
                    match quasiss::cap::solve_gpu(&geo, gpu) {
                        Ok(c) => break 'solve c,
                        Err(e) => {
                            eprintln!("solve error: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
                // No usable Vulkan device: fall through to the CPU paths.
                Err(_) => eprintln!("warning: GPU init failed, using CPU"),
            }
        }
        if use_fmm {
            break 'solve quasiss::cap::fmm_solver::solve(&geo, 5, 4, 1e-2);
        }
        if use_dense {
            match quasiss::cap::solve(&geo, quasiss::cap::Method::Direct) {
                Ok(c) => break 'solve c,
                Err(e) => {
                    eprintln!("solve error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        match quasiss::cap::auto_select(n_panels) {
            quasiss::cap::SolverStrategy::DenseCpu => {
                match quasiss::cap::solve(&geo, quasiss::cap::Method::Direct) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("solve error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            quasiss::cap::SolverStrategy::FmmCpu => quasiss::cap::fmm_solver::solve(&geo, 5, 4, 1e-2),
        }
    };

    let n = cap.num_conductors();
    println!("fastcap (quasiss) — {} conductor(s), {} panels", n, n_panels);
    println!("Maxwell capacitance matrix [F]:");
    for i in 0..n {
        let mut row = String::new();
        for j in 0..n {
            row.push_str(&format!("  {:+.6e}", cap.c[(i, j)]));
        }
        println!("{}  | {}", row, cap.conductor_names[i]);
    }
    // Also report capacitance in more familiar pF.
    println!("\n(in pF):");
    for i in 0..n {
        let mut row = String::new();
        for j in 0..n {
            row.push_str(&format!("  {:+.4}", cap.c[(i, j)] * 1e12));
        }
        println!("{row}");
    }
    ExitCode::SUCCESS
}
