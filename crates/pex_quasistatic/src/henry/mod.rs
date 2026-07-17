//! # fasthenry
//!
//! Inductance / resistance (magnetoquasistatic) front end, built on
//! `quasiss-core`. Parses the FastHenry `.inp` language, discretizes
//! conductors into rectangular current filaments, assembles the partial
//! R + jωL system, and extracts the multiport impedance matrix Z(ω) = R + jωL
//! across a frequency sweep.
//!
//! ```no_run
//! let deck = std::fs::read_to_string("wire.inp").unwrap();
//! let nl = quasiss::henry::parse(&deck).unwrap();
//! let result = quasiss::henry::solve(&nl).unwrap();
//! for (f, freq) in result.frequencies.iter().enumerate() {
//!     println!("f = {freq} Hz, Z[0,0] = {}", result.z[f][(0, 0)]);
//! }
//! ```

pub mod mesh_analysis;
pub mod netlist;
pub mod solver;
pub mod units;

pub use netlist::{parse, FreqSweep, Netlist, Node, Port, Segment};
pub use solver::{auto_use_gpu, solve, solve_full, solve_with, Formulation, Method, SolveError, SolveResult};
#[cfg(feature = "gpu")]
pub use solver::solve_gpu;

/// Convenience: parse a deck and solve it in one call.
pub fn run(deck: &str) -> Result<SolveResult, Box<dyn std::error::Error>> {
    let nl = parse(deck)?;
    Ok(solve(&nl)?)
}
