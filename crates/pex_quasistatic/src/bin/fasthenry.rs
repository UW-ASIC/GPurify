//! `fasthenry` — drop-in-style CLI for inductance/resistance extraction.
//!
//! Usage:
//!   fasthenry <input.inp> [--iterative | --direct]
//!
//! Prints, for each frequency in the sweep, the port impedance matrix Z = R+jωL
//! and (for ω>0) the extracted L matrix, mirroring the information in FastHenry's
//! `Zc.mat` output.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let mut path: Option<&str> = None;
    let mut method: Option<quasiss::henry::Method> = None;
    let mut use_gpu = false;

    for arg in &args[1..] {
        match arg.as_str() {
            "--iterative" => method = Some(quasiss::henry::Method::Iterative),
            "--direct" => method = Some(quasiss::henry::Method::Direct),
            "--gpu" => use_gpu = true,
            s if s.starts_with('-') => {
                eprintln!("unknown flag: {s}");
                return ExitCode::FAILURE;
            }
            s => path = Some(s),
        }
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("usage: {} <input.inp> [--iterative | --direct | --gpu]", args[0]);
            return ExitCode::FAILURE;
        }
    };

    let deck = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read '{path}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let nl = match quasiss::henry::parse(&deck) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // GPU routing: --gpu forces it; with no explicit method flag the
    // auto-selector picks it for large decks (measured ~3x at 2048 branches;
    // below ~1k the init/dispatch floor loses to the CPU). Explicit
    // --direct/--iterative always stay on the CPU.
    #[cfg(feature = "gpu")]
    let want_gpu = use_gpu || (method.is_none() && quasiss::henry::auto_use_gpu(&nl));
    #[cfg(not(feature = "gpu"))]
    let want_gpu = use_gpu; // cli_spawn only prints the missing-feature warning
    #[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
    let gpu_thread = quasiss::gpu::cli_spawn(want_gpu);

    // ponytail: auto-select if no flag given, otherwise use the explicit method
    #[allow(unused_labels)] // label only used by the gpu-feature break
    let result = 'solve: {
        #[cfg(feature = "gpu")]
        if let Some(t) = gpu_thread {
            match t.join() {
                Ok(gpu) => {
                    eprintln!("GPU backend ready (vulkano, L resident for whole sweep)");
                    break 'solve quasiss::henry::solve_gpu(&nl, gpu);
                }
                // No usable Vulkan device: fall through to the CPU paths.
                Err(_) => eprintln!("warning: GPU init failed, using CPU"),
            }
        }
        match method {
            Some(m) => quasiss::henry::solve_with(&nl, m),
            None => quasiss::henry::solve(&nl), // auto-selects based on filament count
        }
    };
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("solve error: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("fasthenry (quasiss) — {} port(s): {:?}", result.port_names.len(), result.port_names);
    let np = result.port_names.len();
    for (fi, &f) in result.frequencies.iter().enumerate() {
        let w = 2.0 * std::f64::consts::PI * f;
        println!("\nFrequency = {:.6e} Hz", f);
        println!("Impedance matrix Z = R + jwL  [Ohm]:");
        let z = &result.z[fi];
        for i in 0..np {
            let mut row = String::new();
            for j in 0..np {
                row.push_str(&format!("  {:+.6e}{:+.6e}j", z[(i, j)].re, z[(i, j)].im));
            }
            println!("{row}");
        }
        if w > 0.0 {
            println!("Inductance matrix L = Im(Z)/w  [H]:");
            let l = result.inductance(fi);
            for i in 0..np {
                let mut row = String::new();
                for j in 0..np {
                    row.push_str(&format!("  {:+.6e}", l[(i, j)]));
                }
                println!("{row}");
            }
        }
    }
    ExitCode::SUCCESS
}
