//! Magnetoquasistatic assembly and solve.
//!
//! Pipeline (matching FastHenry's physics, with a dense direct solve as the
//! exact reference path):
//!  1. Discretize each segment into an `nhinc × nwinc` bundle of rectangular
//!     filaments (parallel branches between the segment's two nodes).
//!  2. Assemble the diagonal DC resistance `R` and the dense partial-inductance
//!     matrix `L` (self via the Grover rectangular-bar formula, mutual via the
//!     Grover/Hoer parallel closed form or Neumann quadrature).
//!  3. For each frequency ω, form the complex branch impedance `Zb = R + jωL`,
//!     and extract the port impedance matrix `Z(ω)` by a nodal solve
//!     `A Zb⁻¹ Aᵀ V = I_inj` — mathematically the same `MZMᵗ` system FastHenry
//!     solves iteratively, done here as a dense factorization for exactness.
//!
//! The dense factorization is the O(B³) reference; the iterative
//! `LinearOperator`/GMRES path in `quasiss-core` is the drop-in accelerated
//! alternative for large B.

use crate::henry::netlist::{GroundPlane, Netlist};
use crate::geometry::Vec3;
use crate::integrals::filament::{self, Filament};
use crate::krylov::{gmres_complex, GmresOptions};
use crate::linalg::{DenseMatrix, LuDecomposition};
use crate::operator::{BlockJacobiComplex, DenseComplexOperator};
use num_complex::Complex64;

/// Optional GPU backend threaded through the solve (a real type only when the
/// `gpu` feature is on; `Infallible` keeps the plumbing zero-cost otherwise).
#[cfg(feature = "gpu")]
type GpuOpt = Option<std::sync::Arc<crate::gpu::VulkanoBackend>>;
#[cfg(not(feature = "gpu"))]
type GpuOpt = Option<std::convert::Infallible>;

#[cfg(feature = "gpu")]
fn gpu_is_some(g: &GpuOpt) -> bool { g.is_some() }
#[cfg(not(feature = "gpu"))]
fn gpu_is_some(_: &GpuOpt) -> bool { false }

#[cfg(feature = "gpu")]
use crate::gpu::op::GpuZbOp;

/// Circuit formulation used to reduce the branch system to the port impedance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Formulation {
    /// Nodal admittance `A Zb⁻¹ Aᵀ` (compact; dense inverse of Zb).
    Nodal,
    /// FastHenry's mesh analysis `M Zb Mᵀ Iₘ = Vₛ` over fundamental loops.
    Mesh,
}

/// How the dense branch-impedance system Zb·x = rhs is solved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Dense complex LU factorization (exact reference; factor once per
    /// frequency, reuse for every node right-hand side).
    Direct,
    /// Complex GMRES through the `ComplexOperator` trait with a block-Jacobi
    /// preconditioner — FastHenry's iterative style, and the drop-in path for an
    /// FMM/H²-accelerated matvec. Converges to the same answer within tolerance.
    Iterative,
}

/// Solve-time filament data, hot/cold split (data-oriented layout): the
/// geometry lane feeds the mutual-inductance kernels — every field of a
/// [`Filament`] is consumed together there, so it stays an array of Copy
/// structs — while the DC resistance and node indices get their own lanes for
/// the incidence/resistance loops that never touch geometry.
struct FilamentSet {
    fils: Vec<Filament>,
    /// DC resistance [Ω] per filament.
    r: Vec<f64>,
    /// Circuit node indices each filament connects (from, to).
    n1: Vec<u32>,
    n2: Vec<u32>,
}

impl FilamentSet {
    #[inline]
    fn len(&self) -> usize {
        self.fils.len()
    }
}

/// Result of a full frequency-sweep solve.
#[derive(Debug, Clone)]
pub struct SolveResult {
    pub port_names: Vec<String>,
    pub frequencies: Vec<f64>,
    /// Port impedance matrix per frequency (rows/cols indexed like `port_names`).
    pub z: Vec<DenseMatrix<Complex64>>,
}

impl SolveResult {
    /// Extract the resistance matrix Re(Z) at frequency index `f`.
    pub fn resistance(&self, f: usize) -> DenseMatrix<f64> {
        let z = &self.z[f];
        let mut r = DenseMatrix::zeros(z.rows, z.cols);
        for i in 0..z.rows {
            for j in 0..z.cols {
                r[(i, j)] = z[(i, j)].re;
            }
        }
        r
    }

    /// Extract the inductance matrix Im(Z)/ω at frequency index `f`
    /// (undefined at ω = 0, where it returns the partial-inductance-free zeros).
    pub fn inductance(&self, f: usize) -> DenseMatrix<f64> {
        let z = &self.z[f];
        let w = 2.0 * std::f64::consts::PI * self.frequencies[f];
        let mut l = DenseMatrix::zeros(z.rows, z.cols);
        if w != 0.0 {
            for i in 0..z.rows {
                for j in 0..z.cols {
                    l[(i, j)] = z[(i, j)].im / w;
                }
            }
        }
        l
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SolveError {
    #[error("node '{0}' referenced by a segment/port was never defined")]
    UnknownNode(String),
    #[error("no external ports defined (.external)")]
    NoPorts,
    #[error("no frequency sweep defined (.freq)")]
    NoFreq,
    #[error("singular system at frequency {0} Hz")]
    Singular(f64),
}

#[inline]
fn v3(p: [f64; 3]) -> Vec3 {
    Vec3::new(p[0], p[1], p[2])
}

/// Build an orthonormal (axis, wdir, hdir) frame for a segment.
fn cross_section_frame(axis: Vec3, wdir_hint: Option<[f64; 3]>) -> (Vec3, Vec3) {
    let axis = axis.normalized();
    let wdir = if let Some(w) = wdir_hint {
        let w = v3(w);
        // Remove the component along the axis.
        let perp = w - axis * w.dot(axis);
        if perp.norm() > 1e-12 {
            perp.normalized()
        } else {
            default_wdir(axis)
        }
    } else {
        default_wdir(axis)
    };
    let hdir = axis.cross(wdir).normalized();
    (wdir, hdir)
}

use crate::integrals::filament::default_wdir;

/// Discretize all segments into branch filaments (SoA lanes).
fn build_filaments(nl: &Netlist) -> Result<FilamentSet, SolveError> {
    let mut set = FilamentSet { fils: Vec::new(), r: Vec::new(), n1: Vec::new(), n2: Vec::new() };
    for seg in &nl.segments {
        let i1 = nl.node_idx(&seg.n1).ok_or_else(|| SolveError::UnknownNode(seg.n1.clone()))?;
        let i2 = nl.node_idx(&seg.n2).ok_or_else(|| SolveError::UnknownNode(seg.n2.clone()))?;
        let p1 = v3(nl.nodes[i1].pos);
        let p2 = v3(nl.nodes[i2].pos);
        let axis = (p2 - p1).normalized();
        let (wdir, hdir) = cross_section_frame(axis, seg.wdir);

        let length = (p2 - p1).norm();
        // FastHenry-style geometric filament partition: finer toward edges.
        let wparts = filament_partition(seg.w, seg.nwinc, seg.rw);
        let hparts = filament_partition(seg.h, seg.nhinc, seg.rh);

        for &(off_w, sub_w) in &wparts {
            for &(off_h, sub_h) in &hparts {
                let sub_area = sub_w * sub_h;
                let r_sub = length / (seg.sigma * sub_area);
                let shift = wdir * off_w + hdir * off_h;
                let a = p1 + shift;
                let b = p2 + shift;
                // Frame carried so close-pair mutuals use the exact brick
                // (Hoer–Love) formula with the true cross-section.
                set.fils.push(Filament::with_frame(a, b, sub_w, sub_h, wdir));
                set.r.push(r_sub);
                set.n1.push(i1 as u32);
                set.n2.push(i2 as u32);
            }
        }
    }
    Ok(set)
}

/// Partition a cross-section dimension of length `total` into `n` filaments
/// whose adjacent widths differ by `ratio`, symmetric and finer toward the two
/// edges (FastHenry's rw/rh scheme, resolving skin/proximity effects). Returns
/// (centre offset from the midline, width) for each filament.
fn filament_partition(total: f64, n: usize, ratio: f64) -> Vec<(f64, f64)> {
    if n <= 1 {
        return vec![(0.0, total)];
    }
    let r = if ratio <= 0.0 { 1.0 } else { ratio };
    // Relative widths: edge filament (distance 0) is smallest; width grows by a
    // factor `r` per step toward the centre.
    let rel: Vec<f64> = (0..n)
        .map(|i| {
            let d = i.min(n - 1 - i) as i32;
            r.powi(d)
        })
        .collect();
    let sum: f64 = rel.iter().sum();
    let widths: Vec<f64> = rel.iter().map(|w| w / sum * total).collect();
    let mut out = Vec::with_capacity(n);
    let mut edge = -total / 2.0;
    for w in &widths {
        out.push((edge + w / 2.0, *w));
        edge += w;
    }
    out
}

/// Reflect a point across the plane through `p0` with unit normal `n`.
fn mirror_point(p: Vec3, p0: Vec3, n: Vec3) -> Vec3 {
    p - n * (2.0 * (p - p0).dot(n))
}

/// The image of a filament across the ground plane. Its current is −mirror(û),
/// which the assembly accounts for by subtracting the mutual to this geometry.
fn mirror_filament(f: &Filament, p0: Vec3, n: Vec3) -> Filament {
    // Reflect the frame direction too (direction vector: no translation part).
    let wdir = f.wdir - n * (2.0 * f.wdir.dot(n));
    Filament::with_frame(mirror_point(f.a, p0, n), mirror_point(f.b, p0, n), f.w, f.t, wdir)
}

/// Assemble the dense partial-inductance matrix L [H] (real, symmetric).
///
/// With an ideal (flux-excluding) ground plane, each conductor filament has an
/// image filament — its mirror reflection carrying the reflected-and-negated
/// current. The image's contribution to the vector potential adds
///   −mutual(fil_i, mirror(fil_j))
/// to every entry (self included), reproducing the boundary condition B·n̂ = 0
/// on the plane. This yields, e.g., the wire-over-ground-plane inductance
/// L = (µ₀ l/2π) ln(2h/r).
fn assemble_inductance(set: &FilamentSet, gplane: Option<GroundPlane>) -> DenseMatrix<f64> {
    use rayon::prelude::*;
    let fils = &set.fils;
    let b = fils.len();
    let mut l = DenseMatrix::<f64>::zeros(b, b);

    let images: Option<Vec<Filament>> = gplane.map(|gp| {
        let p0 = v3(gp.point);
        let n = v3(gp.normal).normalized();
        fils.iter().map(|f| mirror_filament(f, p0, n)).collect()
    });

    // Upper-triangle rows are independent -> rayon; mirror afterwards
    // (mutual(i, img[j]) == mutual(j, img[i]) since reflection is an isometry).
    let rows: Vec<Vec<f64>> = (0..b)
        .into_par_iter()
        .map(|i| {
            let mut row = vec![0.0; b - i];
            let mut lii = filament::self_inductance(&fils[i]);
            if let Some(img) = &images {
                // Image of self: current is anti-parallel across the plane.
                lii -= filament::mutual(&fils[i], &img[i]);
            }
            row[0] = lii;
            for j in (i + 1)..b {
                let mut m = filament::mutual(&fils[i], &fils[j]);
                if let Some(img) = &images {
                    m -= filament::mutual(&fils[i], &img[j]);
                }
                row[j - i] = m;
            }
            row
        })
        .collect();
    for i in 0..b {
        for j in i..b {
            let v = rows[i][j - i];
            l[(i, j)] = v;
            l[(j, i)] = v;
        }
    }
    l
}

/// Total branch (filament) count of a netlist — the size driver for both
/// auto-selections below.
fn branch_count(nl: &Netlist) -> usize {
    nl.segments.iter().map(|s| s.nhinc * s.nwinc).sum()
}

/// Auto-select the solve method based on problem size.
/// ponytail: nb < 100 -> direct (LU is fast enough), nb >= 100 -> iterative
fn auto_method(nl: &Netlist) -> Method {
    if branch_count(nl) < 100 { Method::Direct } else { Method::Iterative }
}

/// Should the auto-selector route this problem to the GPU (when compiled in
/// and a device initializes)? ponytail: measured on bus_big-class decks —
/// batched-GEMM GPU wins ~3x at nb=2048 but carries a ~0.3s Vulkan-init +
/// dispatch floor that loses below ~1k branches; re-measure if kernels change.
pub fn auto_use_gpu(nl: &Netlist) -> bool {
    branch_count(nl) >= 1024
}

/// Solve a parsed netlist over its frequency sweep, auto-selecting method.
pub fn solve(nl: &Netlist) -> Result<SolveResult, SolveError> {
    solve_full(nl, auto_method(nl), Formulation::Nodal)
}

/// Solve with an explicit branch-solve method (nodal formulation).
pub fn solve_with(nl: &Netlist, method: Method) -> Result<SolveResult, SolveError> {
    solve_full(nl, method, Formulation::Nodal)
}

/// Solve with an explicit method and circuit formulation.
pub fn solve_full(nl: &Netlist, method: Method, formulation: Formulation) -> Result<SolveResult, SolveError> {
    solve_impl(nl, method, formulation, None)
}

/// GPU-accelerated iterative solve (nodal formulation): the partial-inductance
/// matrix L is uploaded to the GPU once and every GMRES matvec of the whole
/// frequency sweep runs there. Block-Jacobi preconditioning stays on the CPU.
#[cfg(feature = "gpu")]
pub fn solve_gpu(
    nl: &Netlist,
    gpu: std::sync::Arc<crate::gpu::VulkanoBackend>,
) -> Result<SolveResult, SolveError> {
    solve_impl(nl, Method::Iterative, Formulation::Nodal, Some(gpu))
}

fn solve_impl(nl: &Netlist, method: Method, formulation: Formulation, gpu: GpuOpt) -> Result<SolveResult, SolveError> {
    let use_gpu = gpu_is_some(&gpu);
    #[cfg(not(feature = "gpu"))]
    let _ = &gpu;
    if nl.ports.is_empty() {
        return Err(SolveError::NoPorts);
    }
    let sweep = nl.freq.ok_or(SolveError::NoFreq)?;

    // Resolve port node indices.
    let mut port_pairs = Vec::new();
    for p in &nl.ports {
        let a = nl.node_idx(&p.n1).ok_or_else(|| SolveError::UnknownNode(p.n1.clone()))?;
        let c = nl.node_idx(&p.n2).ok_or_else(|| SolveError::UnknownNode(p.n2.clone()))?;
        port_pairs.push((a, c));
    }

    let set = build_filaments(nl)?;
    let nb = set.len();
    let nn = nl.nodes.len();
    let l = assemble_inductance(&set, nl.ground_plane);
    let r = &set.r;

    // Ground references: one node per galvanically-connected component. A
    // network with several isolated conductors (e.g. two uncoupled wires, or a
    // signal line plus a floating shield) has a floating common-mode potential
    // per component; each needs its own reference or the nodal system is
    // singular. This mirrors FastHenry's per-component mesh treatment.
    let comp = connected_components(&set, nn);
    let ncomp = comp.iter().copied().max().map(|m| m + 1).unwrap_or(0);
    let mut ground_of_comp = vec![usize::MAX; ncomp.max(1)];
    // Prefer a port's negative terminal as the component ground.
    for &(_, c) in &port_pairs {
        let g = &mut ground_of_comp[comp[c]];
        if *g == usize::MAX {
            *g = c;
        }
    }
    // Any remaining components: ground their lowest-index node.
    for n in 0..nn {
        let g = &mut ground_of_comp[comp[n]];
        if *g == usize::MAX {
            *g = n;
        }
    }
    let mut is_ground = vec![false; nn];
    for &g in &ground_of_comp {
        if g != usize::MAX {
            is_ground[g] = true;
        }
    }

    // Map full node index -> reduced index (skipping all grounds).
    let mut red_of = vec![usize::MAX; nn];
    let mut count = 0;
    for n in 0..nn {
        if !is_ground[n] {
            red_of[n] = count;
            count += 1;
        }
    }
    let nred = count;

    // Branch node-pair list (for the mesh formulation).
    let edges: Vec<(usize, usize)> =
        set.n1.iter().zip(&set.n2).map(|(&a, &b)| (a as usize, b as usize)).collect();

    // GPU: upload L once for the whole sweep (device-resident, f32).
    #[cfg(feature = "gpu")]
    let l_handle = gpu.as_ref().map(|g| {
        use crate::gpu::ComputeBackend;
        g.upload_matrix(&crate::gpu::DeviceMatrix::from_rows(nb, nb, l.data.clone()))
    });

    let freqs = sweep.frequencies();
    let mut z_all = Vec::with_capacity(freqs.len());

    for &f in &freqs {
        let w = 2.0 * std::f64::consts::PI * f;
        // Branch impedance Zb = R (diag) + jωL (dense).
        let mut zb = DenseMatrix::<Complex64>::zeros(nb, nb);
        for i in 0..nb {
            for j in 0..nb {
                let mut val = Complex64::new(0.0, w * l[(i, j)]);
                if i == j {
                    val += Complex64::new(r[i], 0.0);
                }
                zb[(i, j)] = val;
            }
        }

        // Mesh-analysis formulation: solve the fundamental-loop system directly.
        if formulation == Formulation::Mesh {
            let zmat = crate::henry::mesh_analysis::solve_ports(&zb, &edges, &port_pairs, nn);
            z_all.push(zmat);
            continue;
        }

        // Prepare the chosen solver for Zb once per frequency, reused for every
        // node right-hand side.
        let lu = match method {
            Method::Direct => Some(LuDecomposition::factor(&zb).map_err(|_| SolveError::Singular(f))?),
            Method::Iterative => None,
        };
        let bs = 16.min(nb).max(1);
        // GPU path skips the dense CPU operator (avoids the O(nb²) clone);
        // block-Jacobi preconditioning stays on the CPU either way.
        let iterative = match method {
            Method::Iterative if !use_gpu => Some((
                DenseComplexOperator::new(zb.clone()),
                BlockJacobiComplex::contiguous(&zb, bs),
            )),
            _ => None,
        };
        #[cfg(feature = "gpu")]
        let gpu_parts = match (method, &gpu, &l_handle) {
            (Method::Iterative, Some(g), Some(h)) => Some((
                GpuZbOp { gpu: g, l_handle: h, r: &r, omega: w },
                BlockJacobiComplex::contiguous(&zb, bs),
            )),
            _ => None,
        };

        // ponytail: match C FastHenry2's default tolerance (0.001)
        let opts = GmresOptions { tol: 1e-3, restart: 60, max_restarts: 40 };
        let solve_iterative = |rhs: &[Complex64]| -> Vec<Complex64> {
            let (op, precond) = iterative.as_ref().unwrap();
            gmres_complex(op, rhs, Some(precond), opts).0
        };

        // Solve Zb X = Aᵀ, i.e. for each (non-ground) node n a rhs = column n of
        // Aᵀ (length nb): (Aᵀ)[b, n] = +1 if branch b's n1==n, -1 if n2==n.
        // X[:, n] = Zb⁻¹ (Aᵀ column n).
        use rayon::prelude::*;
        let build_rhs = |n: usize| -> Vec<Complex64> {
            let mut rhs = vec![Complex64::new(0.0, 0.0); nb];
            for bidx in 0..nb {
                if set.n1[bidx] as usize == n {
                    rhs[bidx] += Complex64::new(1.0, 0.0);
                }
                if set.n2[bidx] as usize == n {
                    rhs[bidx] -= Complex64::new(1.0, 0.0);
                }
            }
            rhs
        };

        // GPU path: all non-ground columns of this frequency advance in ONE
        // batched GMRES, so each iteration is a single GEMM dispatch on the
        // resident L instead of ncols×2 GEMV round trips.
        #[cfg(feature = "gpu")]
        let gpu_xcols: Option<Vec<Option<Vec<Complex64>>>> =
            gpu_parts.as_ref().map(|(op, precond)| {
                let idxs: Vec<usize> = (0..nn).filter(|&n| !is_ground[n]).collect();
                let rhs_cols: Vec<Vec<Complex64>> = idxs.iter().map(|&n| build_rhs(n)).collect();
                let sols = crate::krylov::gmres_complex_batched(
                    |x: &[Complex64], y: &mut [Complex64], ncols: usize| {
                        op.apply_batch(x, y, ncols)
                    },
                    &rhs_cols,
                    Some(precond as &(dyn crate::kernel::ComplexOperator + Sync)),
                    opts,
                );
                let mut out: Vec<Option<Vec<Complex64>>> = vec![None; nn];
                for (&n, (x, _meta)) in idxs.iter().zip(sols) {
                    out[n] = Some(x);
                }
                out
            });
        #[cfg(not(feature = "gpu"))]
        let gpu_xcols: Option<Vec<Option<Vec<Complex64>>>> = None;

        // CPU path: columns are independent -> rayon.
        let xcols: Vec<Option<Vec<Complex64>>> = match gpu_xcols {
            Some(x) => x,
            None => (0..nn)
                .into_par_iter()
                .map(|n| {
                    if is_ground[n] {
                        return None; // column never read below
                    }
                    let rhs = build_rhs(n);
                    Some(if let Some(lu) = &lu {
                        lu.solve(&rhs)
                    } else {
                        solve_iterative(&rhs)
                    })
                })
                .collect(),
        };

        // Reduced nodal admittance Yn[m,n] = (A X)[m,n] = Σ_b A[m,b] X[b,n].
        // A has exactly two nonzeros per branch -> scatter per branch, O(nn·nb)
        // instead of the dense O(nn²·nb) triple loop.
        let mut yn = DenseMatrix::<Complex64>::zeros(nred, nred);
        for n in 0..nn {
            let Some(xc) = &xcols[n] else { continue };
            let rn = red_of[n];
            for bidx in 0..nb {
                let xb = xc[bidx];
                let (b1, b2) = (set.n1[bidx] as usize, set.n2[bidx] as usize);
                if !is_ground[b1] {
                    yn[(red_of[b1], rn)] += xb;
                }
                if !is_ground[b2] {
                    yn[(red_of[b2], rn)] -= xb;
                }
            }
        }

        let yn_lu = LuDecomposition::factor(&yn).map_err(|_| SolveError::Singular(f))?;

        // For each port p, inject unit current, solve for node potentials,
        // read port voltages -> column p of Z.
        let np = port_pairs.len();
        let mut zmat = DenseMatrix::<Complex64>::zeros(np, np);
        for (p, &(a, c)) in port_pairs.iter().enumerate() {
            let mut iinj = vec![Complex64::new(0.0, 0.0); nred];
            if !is_ground[a] {
                iinj[red_of[a]] += Complex64::new(1.0, 0.0);
            }
            if !is_ground[c] {
                iinj[red_of[c]] -= Complex64::new(1.0, 0.0);
            }
            let vred = yn_lu.solve(&iinj);
            let volt = |node: usize| -> Complex64 {
                if is_ground[node] {
                    Complex64::new(0.0, 0.0)
                } else {
                    vred[red_of[node]]
                }
            };
            for (q, &(aq, cq)) in port_pairs.iter().enumerate() {
                zmat[(q, p)] = volt(aq) - volt(cq);
            }
        }
        z_all.push(zmat);
    }

    Ok(SolveResult {
        port_names: nl.ports.iter().map(|p| p.name.clone()).collect(),
        frequencies: freqs,
        z: z_all,
    })
}

/// Assign each node a galvanically-connected-component id via union-find over
/// the branch node pairs. Nodes with no incident branch form singleton
/// components.
fn connected_components(set: &FilamentSet, nn: usize) -> Vec<usize> {
    let mut parent: Vec<usize> = (0..nn).collect();
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        // Path compression.
        let mut c = x;
        while parent[c] != r {
            let next = parent[c];
            parent[c] = r;
            c = next;
        }
        r
    }
    for (&a, &b) in set.n1.iter().zip(&set.n2) {
        let ra = find(&mut parent, a as usize);
        let rb = find(&mut parent, b as usize);
        if ra != rb {
            parent[ra] = rb;
        }
    }
    // Compact root ids into 0..ncomp.
    let mut comp = vec![0usize; nn];
    let mut label = std::collections::HashMap::new();
    let mut next = 0;
    for n in 0..nn {
        let r = find(&mut parent, n);
        let id = *label.entry(r).or_insert_with(|| {
            let v = next;
            next += 1;
            v
        });
        comp[n] = id;
    }
    comp
}
