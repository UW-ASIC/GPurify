//! The seam.
//!
//! Everything expensive about a quasi-static solve is one operation: multiply
//! the dense influence matrix by a vector, without forming the matrix. So that
//! is where the CPU and GPU adapters meet, and it is the *only* place they
//! differ.
//!
//! # Why this seam and not the solver
//!
//! Putting the seam at the whole solver would give each adapter its own
//! iteration strategy and its own accuracy story — and an accuracy story each
//! adapter tells separately is how the old implementation ended up silently
//! computing a signoff number in `f32`. Here, GMRES, the residual, the
//! refinement loop and every decision about whether the answer is good enough
//! live once, on the host, in `f64`. An adapter multiplies. That is all it can
//! do, so that is all it can get wrong.
//!
//! The precision boundary and the module boundary coincide, which is the
//! property worth having.
//!
//! # Mixed precision
//!
//! On the development target — an Ada consumer part — `f64` runs at 1/64 of
//! `f32` rate, so a straight `f64` port would be slower than the host. The
//! resolution is iterative refinement: the matvec runs in `f32` on the device,
//! the residual and correction are computed in `f64` on the host, and iteration
//! continues until the `f64` residual meets tolerance. The answer is
//! `f64`-accurate and the accuracy is *measured*, not assumed.

use gpurify_core::observe::{NoObserve, Observer};

/// Vacuum permittivity, F/m. CODATA 2018.
const VACUUM_PERMITTIVITY: f64 = 8.854_187_812_8e-12;

/// `4πε₀`, the denominator of the free-space Green's function, hoisted so the
/// per-panel coefficient is one divide at build time rather than per matvec.
pub(super) const FOUR_PI_EPS0: f64 = 4.0 * std::f64::consts::PI * VACUUM_PERMITTIVITY;

/// `4 ln(1 + √2)`.
///
/// The shape factor in the self-potential of a uniformly charged square panel:
/// `∫ dA/r` taken from the panel's own centroid is `4 a ln(1 + √2)` for side
/// `a`, so a panel of area `A` carrying charge `q` sits at
/// `q / (4πε · √A / (4 ln(1 + √2)))`. That denominator is the panel's
/// *effective radius* — the distance at which a point charge would produce the
/// same potential — and it is what [`Collocation::radius`] stores.
pub(super) const SELF_POTENTIAL_SHAPE: f64 = 3.525_494_348_078_172;

/// Multiply the influence matrix by a vector.
///
/// The interface is deliberately this small. An adapter receives a vector and
/// fills another; it has no access to the tolerance, the iteration count, or
/// the decision to stop.
///
/// `y` is caller-owned and fully overwritten — not accumulated — so the caller
/// keeps one buffer for the whole solve and an adapter cannot accidentally
/// depend on `y`'s prior contents.
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

/// FMM-accelerated matvec on the host, in `f64`.
///
/// The reference implementation in every sense: it is what the GPU adapter is
/// differentially tested against, and it is what runs whenever no device is
/// present or the problem is below the crossover.
///
/// **Five questions.** In: a panel mesh. Out: the machinery to apply the
/// operator. How many: one per solve. Access pattern: the near-field is a
/// sparse block product over spatially sorted panels; the far-field is a tree
/// traversal — so panels are stored in tree order and both passes are
/// contiguous. Lifetime: one solve; every buffer is reused across iterations.
/// Parallelisable: yes, but the reduction order is fixed, because a
/// reassociated sum is a different `f64` and the output is byte-gated.
#[derive(Debug, Default)]
pub struct CpuMatVec {
    // ponytail: direct O(n²) evaluation, no tree, no expansions — every pair is
    // near-field. Ceiling: ~1e4 panels before the quadratic term dominates a
    // 400-iteration GMRES.
    //
    // Blocked, not unstarted — `docs/SIGNATURE_DEFECTS.md`, "pex
    // quasistatic/matvec.rs, third `ponytail:` spend-down pass". An earlier
    // version of this comment said the octree could simply be built here and
    // nothing above the line would move. Both halves are wrong, and the
    // correction is the content of the block:
    //
    // The FMM does not go *here*. Its far field is a truncation, and this type
    // is the exact `f64` reference the `f32` device adapter is differentially
    // tested against — `gpu.rs` header, contract item 5. An approximate
    // reference stops that comparison isolating the device's error, which is
    // the only thing it exists to measure. So an FMM is a *third* adapter
    // behind [`MatVec`], and four frozen signatures stand between here and one:
    //
    //   - [`Backend`] has two variants and no `#[non_exhaustive]`, and
    //     `quasistatic::extract_into` matches it exhaustively. There is nothing
    //     for [`MatVec::backend`] to return and nothing for `Accuracy::backend`
    //     to attribute the run to.
    //   - [`select`] is the entire dispatch decision and reads a panel count
    //     and a device. An FMM crossover is a property of neither.
    //   - `build` takes no expansion order or target error to bound the
    //     truncation with.
    //   - `Accuracy` has no field to report the truncation that resulted. This
    //     module's header says the accuracy is measured rather than assumed;
    //     behind that signature an FMM's would be assumed.
    //
    // What does *not* block it, recorded because the obvious reading says it
    // should and the previous pass filed it as one: the byte gate. Every
    // determinism test in this crate compares two runs of one input, so a fixed
    // tree traversal satisfies them exactly as the ascending-`j` fold below
    // does. That fold is interface against *nondeterministic* reassociation —
    // rayon, fast-math, an atomic device accumulation — not against a
    // different-but-fixed association.
    //
    // AoS, for the reason `mesh::Panel` gives: the matvec reads every field of a
    // column panel together, and reads them in tree order, so one 40-byte row
    // per cache miss beats five strided columns.
    panel: Vec<Collocation>,
}

/// One panel, reduced to exactly what the operator reads.
///
/// **Five questions.** In: a [`super::mesh::Panel`] and the relative
/// permittivity above it. Out: a centroid, an effective radius and a Green's
/// function coefficient. How many: one per panel. Access pattern: every field
/// together, per pair. Lifetime: one solve. Parallelisable: built row by row.
///
/// The area and the permittivity do not survive into this table: both enter
/// only through `radius` and `coefficient`, so the sqrt and the divide are paid
/// once per panel at build time instead of `n` times per matvec.
#[derive(Debug, Clone, Copy, Default)]
struct Collocation {
    /// Centroid, metres.
    centre: [f64; 3],
    /// `√A / (4 ln(1 + √2))` — the radius at which a point charge reproduces
    /// this panel's own centroid potential.
    ///
    /// It is also the softening length that keeps the diagonal off the
    /// singularity: the kernel below squares distance as
    /// `|Δc|² + radius_i · radius_j`, which is exactly `radius_i²` on the
    /// diagonal and is symmetric off it. That is what lets the whole matvec be
    /// one straight-line expression rather than a loop carrying an `i == j`
    /// branch.
    radius: f64,
    /// `1 / (4π ε₀ ε_r)` for the dielectric above this panel.
    coefficient: f64,
}

impl CpuMatVec {
    /// Build the panel tree, the expansions and the near-field block list from a
    /// mesh.
    ///
    /// The host counterpart of [`gpu::GpuMatVec::upload`], and infallible for the
    /// same reason that one is not: there is no device to run out of. Added in
    /// the Testing-Phase — `Default` was the only way to obtain a `CpuMatVec`,
    /// so [`MatVec::dim`] could only ever be zero and [`MatVec::apply`] had no
    /// operator to apply, which left the reference adapter for every GPU number
    /// untestable.
    pub fn build(mesh: &super::mesh::Mesh) -> Self {
        // Columns agree, hoisted above both loops below as a uniform: they read
        // the same two columns in lockstep, so a length mismatch would fold
        // over the shorter one and silently build a smaller operator.
        debug_assert_eq!(
            mesh.panel.len(),
            mesh.epsilon.len(),
            "one permittivity per panel"
        );
        // A zero-area panel has no self-potential and a zero permittivity has no
        // Green's function; either makes `radius` or `coefficient` infinite and
        // the whole solve NaN. `build` is infallible by signature — the typed
        // refusal lives in `mesh::build_into`, which is what constructs a
        // `Mesh` — so the check here is an assert over what the signature
        // exposes, not a `Result` this cannot return.
        debug_assert!(
            {
                // `&=` and not `&&`: the fold is over per-element data, so a
                // short-circuit here would be a data-dependent branch. Two
                // compares and an `and` per row, unconditionally.
                let mut ok = true;
                for i in 0..mesh.panel.len() {
                    ok &= (mesh.panel[i].area > 0.0) & (mesh.epsilon[i] > 0.0);
                }
                ok
            },
            "a panel with no area or no permittivity has no potential coefficient"
        );

        let mut panel = Vec::with_capacity(mesh.panel.len());
        // Zipped rather than indexed: this runs once per solve, not per matvec,
        // so the boring form that cannot index out of bounds is the right one.
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
                // Blocked on `mesh::Panel` carrying those two numbers —
                // `docs/SIGNATURE_DEFECTS.md`, "pex quasistatic". `mesh_box`
                // has them as `du`/`dv` and keeps only their product, and they
                // are not recoverable here: centroid spacing within a face
                // gives one edge back only when that face was cut more than
                // once along it, which is exactly the case that was never in
                // error.
                radius: row.area.sqrt() / SELF_POTENTIAL_SHAPE,
                coefficient: 1.0 / (FOUR_PI_EPS0 * epsilon),
            });
        }

        debug_assert_eq!(panel.len(), mesh.panel.len(), "one row per panel");
        // The shape the kernel relies on, asserted where the table is produced
        // rather than once per matvec: a strictly positive coefficient is what
        // makes `k_i + k_j` a safe divisor for the harmonic mean, and a
        // strictly positive radius is what keeps the softened radical off zero
        // on the diagonal. Both follow from the entry assert above, but they
        // follow through a `sqrt` and a divide, so they are worth restating
        // over the values the kernel actually reads.
        debug_assert!(
            {
                // `&=` and not `&&`: no short-circuit, so no data-dependent
                // branch over the table.
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

    /// [`MatVec::apply`] with the seam exposed.
    ///
    /// Private: the observer is a test concern and does not belong in the
    /// [`MatVec`] interface, which every adapter has to implement. Adapter tests
    /// are therefore unit tests in this crate — the trade recorded in
    /// [`gpurify_core::observe`], and the same shape as
    /// `core::index::candidate_pairs_observed` and
    /// `derived::prefilter::candidates_observed`.
    ///
    /// Added in the Testing-Phase: [`ObserveMatVec`] and its [`NoObserve`] impl
    /// existed, but nothing in the workspace was generic over the trait, so there
    /// was nowhere to install an adapter and `near_blocks`, `far_expansions` and
    /// `bytes_transferred` were unobservable.
    fn apply_observed<O: ObserveMatVec>(&self, x: &[f64], y: &mut [f64], observer: &mut O) {
        // The operator is the panel potential-coefficient matrix `P`: `x` is one
        // *charge* per panel, `y` is the potential each panel then sees. Charge
        // rather than charge density on purpose — `A_j / r` would make `P`
        // asymmetric whenever two panels differ in area, and reciprocity is the
        // headline law this whole module is checked against.
        //
        //   P_ij = 2 k_i k_j / (k_i + k_j) / √(|c_i − c_j|² + ρ_i ρ_j),
        //                                              k = 1/(4πε₀ε_r)
        //
        // On the diagonal the radical collapses to ρ_i and the coefficient
        // collapses to k_i, so the entry is the panel's exact self-potential.
        // Off it, `ρ_i ρ_j` is a softening of order the panel size — the same
        // order as the centroid approximation already in the numerator — and it
        // is symmetric, so `P` is symmetric exactly and the diagonal dominates
        // by construction.
        //
        // The pair coefficient is the *harmonic* mean of the two panels'
        // coefficients, and that is the two-medium closed form rather than a
        // convenient symmetric function. A charge sitting in ε_i, observed
        // across a planar interface from ε_j, produces `q / (4πε₀ ½(ε_i + ε_j)
        // r)` — Jackson §4.4, the transmitted image, whose strength is
        // `2ε_j/(ε_i + ε_j)`. Averaging the *permittivities* in the denominator
        // is averaging the *coefficients* harmonically in the numerator:
        // `1/(4πε₀ ½(ε_i + ε_j)) = 2 k_i k_j/(k_i + k_j)`. It is symmetric, so
        // reciprocity survives, and it equals k on a uniform stack, so it moves
        // nothing where every ε_r already agrees. The arithmetic mean this
        // replaces was the other symmetric function with those two properties,
        // and it is the one no interface condition produces.
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
        // reciprocity and self-potential tests in `crates/pex/tests` are blind
        // to it.
        //
        // Upgrade path: the layered Green's function, `Σ_n A_n/|r − r'_n|` over
        // the images of the source in every interface, each `A_n` a product of
        // those interfaces' reflection coefficients. It needs each interface
        // plane and the permittivity either side of it. `Mesh::epsilon`
        // collapses all of that to the one value above a panel and `build` is
        // handed nothing else, so this is a signature change and not a body —
        // `docs/SIGNATURE_DEFECTS.md`, "pex quasistatic, layered Green's
        // function". The stack is one argument away: `quasistatic::extract_into`
        // holds a `&ProcessStack` and calls `CpuMatVec::build(&mesh)`.
        let n = self.panel.len();
        debug_assert_eq!(x.len(), n, "one charge per panel");
        debug_assert_eq!(y.len(), n, "one potential per panel");

        let table = &self.panel[..];
        // Reslicing to exactly `n` is both the bounds-check elision and a
        // fail-closed length check that survives into release: a
        // release build handed a short vector panics here rather than solving
        // the leading rows and reporting convergence. The `debug_assert_eq!`s
        // above add the other direction, an over-long vector, in debug.
        let x = &x[..n];
        let y = &mut y[..n];

        for i in 0..n {
            let row = table[i];
            // A strict left fold in ascending `j`, deliberately: `Accuracy` and
            // the exported netlist are byte-gated, so this sum must not be
            // reassociated. That also means the inner loop does not vectorise
            // and is not meant to — LLVM cannot reorder `f64` adds without
            // fast-math, and fast-math is exactly what is being refused.
            //
            // No branch in the body: the `ρ_i ρ_j` softening in `r2` is what
            // removes the `i == j` case, so the diagonal falls out of the same
            // expression as every other entry.
            let mut potential = 0.0_f64;
            for j in 0..n {
                let col = table[j];
                let dx = row.centre[0] - col.centre[0];
                let dy = row.centre[1] - col.centre[1];
                let dz = row.centre[2] - col.centre[2];
                let r2 = dx * dx + dy * dy + dz * dz + row.radius * col.radius;
                // One divide, not two: the harmonic mean's own denominator is
                // folded into the radical's, so the pair costs the same
                // `sqrt` + `div` the arithmetic mean did, plus two multiplies.
                // `k_i + k_j > 0` is what `build`'s exit assert establishes, so
                // this divide cannot be by zero.
                potential += 2.0 * row.coefficient * col.coefficient * x[j]
                    / ((row.coefficient + col.coefficient) * r2.sqrt());
            }
            // Overwritten, never accumulated — `y`'s prior contents are not
            // read, which is what lets the caller keep one buffer per solve.
            y[i] = potential;
        }

        debug_assert!(
            {
                // `&=` and not `&&`: no short-circuit, so no data-dependent
                // branch over the output vector.
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
        // matrix and there are no far-field expansions to report. An FMM behind
        // this same seam is exactly the adapter that makes the second number
        // non-zero, which is why the pair count and not "one dense block" is
        // what a differential test would compare.
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

/// Choose an adapter.
///
/// **Decision** — pure, and automatic. GPU is selected only above the panel
/// count at which it was *measured* to win, and only when a device is actually
/// present. Not a user flag: a flag would let someone select a slower path, or
/// a path their machine cannot run, and neither is a choice worth offering.
///
/// The crossover is a measured constant, and where it came from is recorded
/// next to it.
pub fn select(panels: usize, device: Option<&gpu::Device>) -> Backend {
    // The crossover is [`gpu::Device::crossover`] — a property of the device
    // that was measured, not a constant here. `None` is the whole fallback
    // contract: no device, no selection, the reference adapter at every size.
    //
    // `>=` and not `>`: the crossover is defined as the first panel count at
    // which the device was seen to win, and `tests/quasistatic.rs`
    // `the_device_is_selected_only_above_its_own_measured_crossover` pins both
    // sides of that boundary.
    // A crossover of zero selects the device at every size, including the sizes
    // it was never measured at and the empty problem — the fail-*open* reading
    // of the sentinel, and the one thing `docs/GPU.md` contract item 6 forbids.
    // Asserted here rather than in `crossover` because this is the only place
    // the number is ever used.
    debug_assert!(
        device.is_none_or(|device| device.crossover() > 0),
        "a measured crossover is the first panel count at which the device won"
    );

    match device {
        Some(device) if panels >= device.crossover() => Backend::GpuF32,
        // Fail closed: anything else runs on the `f64` reference adapter. The
        // fail-*open* mistake is the other direction — routing a signoff number
        // onto an `f32` path that was never measured to be faster or checked to
        // be right.
        _ => Backend::Cpu,
    }
}

/// What the matvec seam did.
///
/// Iteration count is visible in [`super::Accuracy`], but the work *inside* a
/// matvec is not: how many near-field blocks were evaluated, how many
/// far-field expansions, how much time went to transfer rather than compute.
/// That is the difference between a GPU path that wins and one that loses, and
/// it is invisible in the result.
pub trait ObserveMatVec: Observer {
    fn near_blocks(&mut self, count: u64);
    fn far_expansions(&mut self, count: u64);
    fn bytes_transferred(&mut self, bytes: u64);
}

/// The null adapter. Empty bodies are the whole point — see
/// [`gpurify_core::observe`] and the identical impl at
/// `derived::prefilter::ObservePrefilter for NoObserve`.
impl ObserveMatVec for NoObserve {
    fn near_blocks(&mut self, _count: u64) {}
    fn far_expansions(&mut self, _count: u64) {}
    fn bytes_transferred(&mut self, _bytes: u64) {}
}

use super::gpu;
