//! The CPU/GPU seam: multiply the dense influence matrix by a vector without
//! forming the matrix.
//!
//! GMRES, the residual and every decision about whether the answer is good
//! enough live once, on the host, in `f64`. An adapter multiplies, so the
//! precision boundary and the module boundary coincide. A device matvec runs in
//! `f32` inside host `f64` iterative refinement, so the answer is `f64`-accurate
//! and the accuracy is measured rather than assumed.

use gpurify_core::observe::{NoObserve, Observer};

/// Vacuum permittivity, F/m. CODATA 2018.
const VACUUM_PERMITTIVITY: f64 = 8.854_187_812_8e-12;

/// `4πε₀`, the denominator of the free-space Green's function.
pub(super) const FOUR_PI_EPS0: f64 = 4.0 * std::f64::consts::PI * VACUUM_PERMITTIVITY;

/// `4 ln(1 + √2)`, the shape factor in the self-potential of a uniformly charged
/// square panel.
///
/// `√A` over this is the panel's *effective radius*, the distance at which a
/// point charge produces the same potential — [`Collocation::radius`].
pub(super) const SELF_POTENTIAL_SHAPE: f64 = 3.525_494_348_078_172;

/// Multiply the influence matrix by a vector.
///
/// `y` is caller-owned and fully overwritten, never accumulated, so an adapter
/// cannot depend on its prior contents.
pub trait MatVec {
    /// Panel count. `x` and `y` are both this long.
    fn dim(&self) -> usize;

    /// `y := A x`.
    fn apply(&self, x: &[f64], y: &mut [f64]);

    /// Which adapter this is, for [`super::Accuracy::backend`].
    fn backend(&self) -> Backend;
}

/// Which adapter performed the matvec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Host, `f64` throughout.
    Cpu,
    /// Device, `f32` matvec inside host `f64` refinement.
    GpuF32,
}

/// Host matvec in `f64`: the exact reference the GPU adapter is differentially
/// tested against, and what runs with no device or below the crossover.
#[derive(Debug, Default)]
pub struct CpuMatVec {
    // ponytail: direct O(n²) evaluation, no tree, no expansions — every pair is
    // near-field. Ceiling: ~1e4 panels before the quadratic term dominates a
    // 400-iteration GMRES.
    //
    // An FMM cannot go here: its far field is a truncation and this type is the
    // exact reference the `f32` device adapter is differentially tested against.
    // It is a *third* adapter behind [`MatVec`], blocked on four frozen
    // signatures.
    //
    // AoS, for the reason `mesh::Panel` gives: the matvec reads every field of a
    // column panel together, so one 40-byte row per cache miss beats five
    // strided columns.
    panel: Vec<Collocation>,
}

/// One panel, reduced to exactly what the operator reads.
///
/// Area and permittivity do not survive into this table: both enter only through
/// `radius` and `coefficient`, so the sqrt and the divide are paid once per
/// panel at build time instead of `n` times per matvec.
#[derive(Debug, Clone, Copy, Default)]
struct Collocation {
    /// Centroid, metres.
    centre: [f64; 3],
    /// `√A / (4 ln(1 + √2))` — the radius at which a point charge reproduces
    /// this panel's own centroid potential.
    ///
    /// Also the softening length that keeps the diagonal off the singularity:
    /// the kernel squares distance as `|Δc|² + radius_i · radius_j`, which is
    /// exactly `radius_i²` on the diagonal and symmetric off it, so the matvec
    /// needs no `i == j` branch.
    radius: f64,
    /// `1 / (4π ε₀ ε_r)` for the dielectric above this panel.
    coefficient: f64,
}

impl CpuMatVec {
    /// Build the collocation table from a mesh. Infallible: there is no device
    /// to run out of.
    pub fn build(mesh: &super::mesh::Mesh) -> Self {
        // A length mismatch would fold over the shorter column and silently
        // build a smaller operator.
        debug_assert_eq!(
            mesh.panel.len(),
            mesh.epsilon.len(),
            "one permittivity per panel"
        );
        // A zero-area panel has no self-potential and a zero permittivity has no
        // Green's function; either makes `radius` or `coefficient` infinite and
        // the whole solve NaN. The typed refusal lives in `mesh::build_into`.
        debug_assert!(
            {
                let mut ok = true;
                for i in 0..mesh.panel.len() {
                    ok &= (mesh.panel[i].area > 0.0) & (mesh.epsilon[i] > 0.0);
                }
                ok
            },
            "a panel with no area or no permittivity has no potential coefficient"
        );

        let mut panel = Vec::with_capacity(mesh.panel.len());
        for (row, &epsilon) in mesh.panel.iter().zip(&mesh.epsilon) {
            panel.push(Collocation {
                centre: row.centre,
                // ponytail: the square-panel shape factor applied to a
                // rectangle. Exact at unit aspect ratio; ρ is low by 3.5% at
                // 2:1, 12.5% at 4:1, 28% at 10:1 and 64% at 100:1 against the
                // closed form below, and since the diagonal is k_i/ρ_i that is
                // a self-potential *high* by 3.6%, 14%, 39% and 180%. A high P
                // inverts to a low C, so the error is one-signed and
                // optimistic: this under-reports capacitance, it never
                // over-reports it.
                //
                // Which panels see it is decided by `mesh_box`, not by the
                // layout: `du = wu/ceil(wu/edge)` lands in `(edge/2, edge]`
                // whenever `wu >= edge`, so a face both of whose dimensions
                // reach `max_edge` is cut below 2:1 and costs at most 3.5%.
                // Every figure above that comes from a face dimension *under*
                // the limit, which `cuts` emits uncut at `n.max(1)`. Two of
                // those are ordinary rather than pathological: a layer's side
                // face is (footprint × thickness), 5:1 to 10:1 for a 50 nm
                // layer under a 0.5 µm edge, and those are the faces carrying
                // lateral coupling; and a wire narrower than the edge limit is
                // a sliver on its *top* face too, so a 100 nm wire under the
                // same limit is meshed slivers on every face it has.
                //
                // Upgrade path: the closed-form rectangle self-potential, which
                // is the same one line with `a` and `b` instead of `√A` —
                // `A / (2a·ln((b + √(a²+b²))/a) + 2b·ln((a + √(a²+b²))/b))`,
                // which collapses to exactly this expression when `a == b`.
                // Blocked on `mesh::Panel` carrying those two numbers:
                // `mesh_box` has them as `du`/`dv` and keeps only their
                // product, and they
                // are not recoverable here: centroid spacing within a face
                // gives one edge back only when that face was cut more than
                // once along it, which is exactly the case that was never in
                // error.
                radius: row.area.sqrt() / SELF_POTENTIAL_SHAPE,
                coefficient: 1.0 / (FOUR_PI_EPS0 * epsilon),
            });
        }

        debug_assert_eq!(panel.len(), mesh.panel.len(), "one row per panel");
        // What the kernel relies on: a strictly positive coefficient makes
        // `k_i + k_j` a safe divisor for the harmonic mean, and a strictly
        // positive radius keeps the softened radical off zero on the diagonal.
        debug_assert!(
            {
                let mut ok = true;
                for row in &panel {
                    ok &= (row.radius > 0.0) & (row.coefficient > 0.0);
                    ok &= row.radius.is_finite() & row.coefficient.is_finite();
                }
                ok
            },
            "every panel has a positive finite radius and potential coefficient"
        );
        Self { panel }
    }

    /// [`MatVec::apply`] with an [`ObserveMatVec`] installed.
    fn apply_observed<O: ObserveMatVec>(&self, x: &[f64], y: &mut [f64], observer: &mut O) {
        // The operator is the panel potential-coefficient matrix `P`: `x` is one
        // *charge* per panel, not a charge density — `A_j / r` would make `P`
        // asymmetric whenever two panels differ in area, and reciprocity is the
        // headline law this module is checked against.
        //
        //   P_ij = 2 k_i k_j / (k_i + k_j) / √(|c_i − c_j|² + ρ_i ρ_j),
        //                                              k = 1/(4πε₀ε_r)
        //
        // On the diagonal the radical collapses to ρ_i and the coefficient to
        // k_i, so the entry is the panel's exact self-potential. The `ρ_i ρ_j`
        // softening is symmetric, so `P` is symmetric exactly.
        //
        // The pair coefficient is the *harmonic* mean, which is the two-medium
        // closed form (Jackson §4.4, the transmitted image) rather than a
        // convenient symmetric function: averaging the permittivities in the
        // denominator is averaging the coefficients harmonically in the
        // numerator. It is symmetric, and it collapses to k on a uniform stack.
        //
        // ponytail: still only the *two*-medium result, and its ceiling is far
        // lower than the "exact for two half-spaces" this comment used to
        // claim. Two half-spaces are exact only for a pair *straddling* the
        // interface, where the transmitted image is the whole answer. A pair on
        // the *same* side of one needs the reflected image as well —
        // `K/|r − r'*|`, `K = (ε_i − ε_j)/(ε_i + ε_j)`, `r'*` the source
        // mirrored in the plane — and gets none of it: both panels carry the
        // same ε, so the harmonic mean above collapses to `k` and the kernel
        // returns the homogeneous answer. Zero interfaces crossed is not the
        // safe case, it is the *blind* case, and it is every coupling pair
        // inside one metal level — which is where a crosstalk number comes
        // from.
        //
        // Measured against the image series, on the geometry that produces it.
        // A low-k ILD slab, ε_r 2.7, 180 nm thick between SiN etch stops,
        // ε_r 7.0, both panels at mid-height: `P_ij` here is high by 14% at
        // 30 nm lateral separation, 24% at 50 nm, 54% at 100 nm, 105% at
        // 200 nm, tending to `ε_stop/ε_ILD − 1` = 159% once separation outruns
        // the slab. Two panels 50 nm above a silicon substrate (oxide 3.9 over
        // Si 11.9) are the same story at 17% / 29% / 56%. `C = P⁻¹`, so
        // coupling is under-predicted by that much, and worst at long range.
        // Only the diagonal and the touching pairs are safe — the correction
        // vanishes as separation goes to zero, which is exactly why the
        // reciprocity and self-potential tests in `crates/quasistatic/tests`
        // are blind to it.
        //
        // Upgrade path: the layered Green's function, `Σ_n A_n/|r − r'_n|` over
        // the images of the source in every interface, each `A_n` a product of
        // those interfaces' reflection coefficients. It needs each interface
        // plane and the permittivity either side of it. `Mesh::epsilon`
        // collapses all of that to the one value above a panel and `build` is
        // handed nothing else, so this is a signature change and not a body:
        // it needs a layered Green's function. The stack is one argument
        // away: `quasistatic::extract_into`
        // holds a `&ProcessStack` and calls `CpuMatVec::build(&mesh)`.
        let n = self.panel.len();
        debug_assert_eq!(x.len(), n, "one charge per panel");
        debug_assert_eq!(y.len(), n, "one potential per panel");

        let table = &self.panel[..];
        // Reslicing to exactly `n` is a fail-closed length check that survives
        // into release: a short vector panics here rather than solving the
        // leading rows and reporting convergence.
        let x = &x[..n];
        let y = &mut y[..n];

        for i in 0..n {
            let row = table[i];
            // A strict left fold in ascending `j`, deliberately: `Accuracy` and
            // the exported netlist are byte-gated, so this sum must not be
            // reassociated. The loop is therefore not meant to vectorise.
            let mut potential = 0.0_f64;
            for j in 0..n {
                let col = table[j];
                let dx = row.centre[0] - col.centre[0];
                let dy = row.centre[1] - col.centre[1];
                let dz = row.centre[2] - col.centre[2];
                let r2 = dx * dx + dy * dy + dz * dz + row.radius * col.radius;
                // `k_i + k_j > 0` is what `build`'s exit assert establishes, so
                // this divide cannot be by zero.
                potential += 2.0 * row.coefficient * col.coefficient * x[j]
                    / ((row.coefficient + col.coefficient) * r2.sqrt());
            }
            // Overwritten, never accumulated.
            y[i] = potential;
        }

        debug_assert!(
            {
                let mut finite = true;
                for &potential in &*y {
                    finite &= potential.is_finite();
                }
                finite
            },
            "the operator produced a non-finite potential"
        );

        let panels = u64::try_from(n).unwrap_or(u64::MAX);
        // Every pair is evaluated directly, so the near-field count is the whole
        // matrix and there are no far-field expansions to report.
        observer.near_blocks(panels.saturating_mul(panels));
        observer.far_expansions(0);
        // Host adapter: the vectors never leave memory.
        observer.bytes_transferred(0);
    }
}

impl MatVec for CpuMatVec {
    fn dim(&self) -> usize {
        self.panel.len()
    }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        self.apply_observed(x, y, &mut NoObserve);
    }
    fn backend(&self) -> Backend {
        Backend::Cpu
    }
}

/// Choose an adapter: GPU only above the panel count at which that device was
/// *measured* to win, and only when a device is present. Never a user flag.
#[cfg(feature = "gpu")]
pub fn select(panels: usize, device: Option<&gpu::Device>) -> Backend {
    // A crossover of zero would select the device at every size, including the
    // sizes it was never measured at and the empty problem — the fail-open
    // reading of the sentinel.
    debug_assert!(
        device.is_none_or(|device| device.crossover() > 0),
        "a measured crossover is the first panel count at which the device won"
    );

    match device {
        Some(device) if panels >= device.crossover() => Backend::GpuF32,
        // Fail closed: anything else runs on the `f64` reference adapter.
        _ => Backend::Cpu,
    }
}

/// What the matvec seam did: near-field blocks, far-field expansions, bytes
/// transferred.
pub trait ObserveMatVec: Observer {
    fn near_blocks(&mut self, count: u64);
    fn far_expansions(&mut self, count: u64);
    fn bytes_transferred(&mut self, bytes: u64);
}

/// The null adapter; empty bodies are the whole point.
impl ObserveMatVec for NoObserve {
    fn near_blocks(&mut self, _count: u64) {}
    fn far_expansions(&mut self, _count: u64) {}
    fn bytes_transferred(&mut self, _bytes: u64) {}
}

#[cfg(feature = "gpu")]
use super::gpu;
