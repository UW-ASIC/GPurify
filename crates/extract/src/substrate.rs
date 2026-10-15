//! Substrate resistance network (catalog PEX-013): the resistive coupling
//! through the silicon between the nets that touch it, the taps and wells,
//! and from each of them to the backside.
//!
//! **The model.** The die's silicon is a stack of horizontal layers, each
//! of a uniform resistivity, under the die's whole extent; the deck states
//! the stack top-down (`pex_substrate … profile [(thickness, Ω·cm), …]`)
//! because no public deck states one. A *port* is every shape on the deck's
//! port layers (the taps, the wells), grouped by net: each net's shapes are
//! one equipotential contact on the silicon's top face. The rest of the top
//! face and the die's four sides carry no current; the backside is either a
//! grounded contact or carries none (`backside grounded | floating`).
//!
//! **The solve.** Laplace's equation `∇·(σ∇V) = 0` on a tensor-product grid,
//! discretised by box integration: every grid cell, of one layer's
//! conductivity `σ`, contributes to each of its twelve edges the conductance
//! `σ · (its face area / 4) / (edge length)`, so the grid is a resistor
//! network and its nodal matrix is symmetric positive definite: the
//! resistive substrate mesh of Verghese, Schmerbeck and Allstot,
//! *Simulation Techniques and Solutions for Mixed-Signal Coupling in
//! Integrated Circuits* (Kluwer, 1995), on a graded grid. Grid lines lie on
//! every port edge and every layer interface, and between them the cells
//! grow geometrically from `h₀` at each line by a ratio `r`: refinement
//! level `k` takes `h₀` as the shortest gap between lines over `2^(k+1)`
//! and `r = 1 + 2^-(k+1)`. Each port held at 1 V in turn, the others and a
//! grounded backside at 0 V, conjugate gradients (Jacobi-preconditioned)
//! solve the free nodes; the currents into the ports are one column of the
//! port admittance matrix `Y`. The network written is `Y` as resistors:
//! `R_pq = −1/Y_pq` between two ports, and `1/Σ_q Y_pq` from port `p` to
//! the backside (zero conductance with a floating backside, which adds no
//! resistor).
//!
//! **What checks it.** The closed forms below and the network laws: a
//! contact on a uniform half-space spreads as an isolated plate's
//! capacitance (the plate in full space is the half-space problem mirrored,
//! so `G = σC/(2ε)`): a disk of radius `a` gives Holm's `R = ρ/(4a)`
//! (Holm, *Electric Contacts*, 4th ed., Springer 1967) and a square of
//! side `s`, whose capacitance is `4πε · 0.3667874 s` (Read, *J. Comput.
//! Phys.* 133, 1997), `R = ρ/(2π · 0.3667874 · s)`. A grounded backside at
//! depth `D` adds the image series of a point source on a slab, which
//! sums to `−ρ ln 2 / (2πD)`. A contact covering a block's whole top over a
//! grounded backside is `R = Σ ρᵢtᵢ / A`, Ohm's law through the layers in
//! series. `Y` is symmetric (reciprocity), a mirrored layout gives the
//! same network, and refining the grid converges.
//!
//! **Limits.** Resistive and quasi-static only: no substrate capacitance,
//! no well-to-substrate junction (a well is an equipotential contact on the
//! top face, not a doped volume with a depth), no lateral doping (a layer
//! is uniform across the die), no contact resistance, no channel stop or
//! trench isolation, and the die's sides carry no current. The stack and
//! the backside are the deck's; nothing is calibrated against silicon.
//! The current crowds at a contact's edge, where the grid errs: the
//! error falls fourfold a level, and the level the engine extracts at
//! ([`LEVEL`]) reads a 1 µm contact's spreading resistance 1.4 % low.
//! An axis of more than [`MAX_LINES`] grid lines is refused, which bounds
//! the ports a design can have to some hundreds.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{GeometryStore, Grid, LayerId, PolyId, Qty};

/// A layered substrate: the layers top-down, and its backside.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// Each layer's `(thickness µm, resistivity Ω·µm)`, top-down; both
    /// positive.
    pub layers: Vec<(f64, f64)>,
    /// Whether the backside is a grounded contact; else it carries no
    /// current.
    pub grounded: bool,
}

/// The port admittance matrix of a solve.
#[derive(Debug, Clone, PartialEq)]
pub struct Admittance {
    /// Port count.
    pub ports: usize,
    /// `y[p * ports + q]`: the current, A, into the silicon at port `p`
    /// with port `q` at 1 V and every other port (and a grounded backside)
    /// at 0 V.
    pub y: Vec<f64>,
    /// The grid's node count.
    pub nodes: usize,
}

impl Admittance {
    /// `Y[p][q]`, siemens.
    pub fn at(&self, p: usize, q: usize) -> f64 {
        self.y[p * self.ports + q]
    }

    /// The conductance from port `p` to the backside, siemens: the row
    /// sum, symmetrised with the column's.
    pub fn to_backside(&self, p: usize) -> f64 {
        (0..self.ports)
            .map(|q| 0.5 * (self.at(p, q) + self.at(q, p)))
            .sum()
    }

    /// The conductance between ports `p` and `q`, siemens, symmetrised.
    pub fn between(&self, p: usize, q: usize) -> f64 {
        -0.5 * (self.at(p, q) + self.at(q, p))
    }
}

/// Why no network was solved.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SubstrateError {
    /// An axis of the grid would hold more lines than [`MAX_LINES`].
    #[error("the substrate grid needs {0} lines on an axis, more than {MAX_LINES}")]
    TooLarge(usize),
    /// Conjugate gradients did not reach the tolerance.
    #[error("the substrate solve did not converge")]
    NoConvergence,
}

/// The most lines on one lateral axis of a grid solved: the axis's modes
/// are dense, `n²` values, and found in `O(n³)`.
pub const MAX_LINES: usize = 1500;

/// The refinement level the engine extracts at.
pub const LEVEL: u32 = 2;

/// Lines from `breaks` (sorted), each gap filled with cells growing from
/// `h0` at both ends by `ratio`, mirrored about its midpoint.
fn graded(breaks: &[f64], h0: f64, ratio: f64) -> Vec<f64> {
    let mut out = vec![breaks[0]];
    for gap in breaks.windows(2) {
        let (a, b) = (gap[0], gap[1]);
        let half = (b - a) / 2.0;
        let mut steps = Vec::new();
        let (mut step, mut sum) = (h0, 0.0);
        while sum + step <= half {
            steps.push(step);
            sum += step;
            step *= ratio;
        }
        if steps.is_empty() {
            steps.push(half);
            sum = half;
        }
        // Stretched to reach the midpoint exactly.
        let scale = half / sum;
        let mut at = a;
        for s in &steps {
            at += s * scale;
            out.push(at);
        }
        out.pop();
        out.push(a + half);
        for s in steps.iter().rev().take(steps.len() - 1) {
            at = *out.last().expect("a line") + s * scale;
            out.push(at);
        }
        out.push(b);
    }
    out
}

/// The sorted distinct values of `v`.
fn distinct(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(f64::total_cmp);
    v.dedup();
    v
}

/// The eigenvalues and orthonormal eigenvectors of the symmetric
/// tridiagonal matrix with diagonal `d` and off-diagonal `e` (`e[i]`
/// joining `i` and `i + 1`): implicit QL with shifts (Bowdler, Martin,
/// Reinsch and Wilkinson, *Numer. Math.* 11, 1968, EISPACK's `tql2`).
/// `z[k * n + i]` is component `k` of eigenvector `i`; `None` when an
/// eigenvalue takes more than 64 sweeps.
fn tridiagonal_eigen(mut d: Vec<f64>, mut e: Vec<f64>) -> Option<(Vec<f64>, Vec<f64>)> {
    let n = d.len();
    let mut z = vec![0.0; n * n];
    for i in 0..n {
        z[i * n + i] = 1.0;
    }
    e.resize(n, 0.0);
    for l in 0..n {
        let mut sweeps = 0;
        loop {
            let mut m = l;
            while m + 1 < n {
                let scale = d[m].abs() + d[m + 1].abs();
                if e[m].abs() <= f64::EPSILON * scale {
                    break;
                }
                m += 1;
            }
            if m == l {
                break;
            }
            sweeps += 1;
            if sweeps > 64 {
                return None;
            }
            let mut g = (d[l + 1] - d[l]) / (2.0 * e[l]);
            let mut r = g.hypot(1.0);
            g = d[m] - d[l] + e[l] / (g + r.copysign(g));
            let (mut s, mut c, mut p) = (1.0, 1.0, 0.0);
            let mut i = m;
            let mut deflated = false;
            while i > l {
                i -= 1;
                let f = s * e[i];
                let b = c * e[i];
                r = f.hypot(g);
                e[i + 1] = r;
                if r == 0.0 {
                    d[i + 1] -= p;
                    e[m] = 0.0;
                    deflated = true;
                    break;
                }
                s = f / r;
                c = g / r;
                g = d[i + 1] - p;
                r = (d[i] - g) * s + 2.0 * c * b;
                p = s * r;
                d[i + 1] = g + p;
                g = c * r - b;
                for k in 0..n {
                    let f = z[k * n + i + 1];
                    z[k * n + i + 1] = s * z[k * n + i] + c * f;
                    z[k * n + i] = c * z[k * n + i] - s * f;
                }
            }
            if deflated {
                continue;
            }
            d[l] -= p;
            e[l] = g;
            e[m] = 0.0;
        }
    }
    Some((d, z))
}

/// One axis's grid as modes: the generalised eigenproblem `K v = λ D v` of
/// its 1D Neumann stiffness `K` (`1/Δ` per gap) and its dual lengths `D`,
/// as `(λ, U)` with `U = D^½ W` (`W` orthonormal), so that `K = U Λ Uᵀ`
/// and `D = U Uᵀ`. `u[i * n + a]` is line `i`'s entry of mode `a`.
fn modes(lines: &[f64]) -> Option<(Vec<f64>, Vec<f64>)> {
    let n = lines.len();
    let gap: Vec<f64> = lines.windows(2).map(|w| w[1] - w[0]).collect();
    let dual: Vec<f64> = (0..n)
        .map(|i| {
            0.5 * (i.checked_sub(1).map_or(0.0, |j| gap[j]) + gap.get(i).copied().unwrap_or(0.0))
        })
        .collect();
    let diag: Vec<f64> = (0..n)
        .map(|i| {
            (i.checked_sub(1).map_or(0.0, |j| 1.0 / gap[j]) + gap.get(i).map_or(0.0, |g| 1.0 / g))
                / dual[i]
        })
        .collect();
    let off: Vec<f64> = (0..n.saturating_sub(1))
        .map(|i| -1.0 / (gap[i] * (dual[i] * dual[i + 1]).sqrt()))
        .collect();
    let (lambda, mut w) = tridiagonal_eigen(diag, off)?;
    for i in 0..n {
        let root = dual[i].sqrt();
        for a in 0..n {
            w[i * n + a] *= root;
        }
    }
    Some((lambda, w))
}

/// Solves the substrate under `domain` (`[x0, y0, x1, y1]`, µm) for
/// `ports` ports at refinement `level`. `xs` and `ys` are the coordinates
/// of every port edge (µm); `port_at(x, y)` names the port whose contact
/// covers the top-face point, boundary included.
///
/// The grid's operator separates: with `σ` a function of depth alone it is
/// `Kx⊗Dy⊗Bz + Dx⊗Ky⊗Bz + Dx⊗Dy⊗Kz`, so in the modes of the two lateral
/// axes ([`modes`]) each mode `(a, b)` is a tridiagonal system in depth,
/// `Kz + (λa + λb) Bz`, whose elimination down to the top face is one
/// number `s_ab`: the top face's operator is `S = (Ux⊗Uy) diag(s) (Ux⊗Uy)ᵀ`
/// exactly (the eigenfunction method of substrate solvers, here on a
/// graded grid). Conjugate gradients, Jacobi-preconditioned, then solve
/// `S` on the top face's free nodes with each port held at 1 V in turn.
///
/// # Errors
///
/// [`SubstrateError::TooLarge`] for an axis of more than [`MAX_LINES`]
/// lines and [`SubstrateError::NoConvergence`] for a solve that stalls.
#[allow(
    clippy::too_many_lines,
    reason = "one grid, its modes and its solve read best together"
)]
pub fn admittance(
    profile: &Profile,
    domain: [f64; 4],
    xs: &[f64],
    ys: &[f64],
    port_at: impl Fn(f64, f64) -> Option<usize>,
    ports: usize,
    level: u32,
) -> Result<Admittance, SubstrateError> {
    const FREE: u32 = u32::MAX;
    let inside = |v: f64, lo: f64, hi: f64| v > lo && v < hi;
    let xb = distinct(
        [domain[0], domain[2]]
            .into_iter()
            .chain(
                xs.iter()
                    .copied()
                    .filter(|&x| inside(x, domain[0], domain[2])),
            )
            .collect(),
    );
    let yb = distinct(
        [domain[1], domain[3]]
            .into_iter()
            .chain(
                ys.iter()
                    .copied()
                    .filter(|&y| inside(y, domain[1], domain[3])),
            )
            .collect(),
    );
    let mut zb = vec![0.0];
    for &(t, _) in &profile.layers {
        zb.push(zb.last().expect("a line") + t);
    }
    let shortest = xb
        .windows(2)
        .chain(yb.windows(2))
        .map(|w| w[1] - w[0])
        .fold(f64::INFINITY, f64::min);
    let halving = f64::from(1u32 << level.min(14));
    let (h0, ratio) = (shortest / (4.0 * halving * halving), 1.0 + 0.5 / halving);
    let (x, y, z) = (
        graded(&xb, h0, ratio),
        graded(&yb, h0, ratio),
        graded(&zb, h0, ratio),
    );
    let (nx, ny, nz) = (x.len(), y.len(), z.len());
    let lines = nx.max(ny);
    if lines > MAX_LINES {
        return Err(SubstrateError::TooLarge(lines));
    }
    let ((lx, ux), (ly, uy)) = (
        modes(&x).ok_or(SubstrateError::NoConvergence)?,
        modes(&y).ok_or(SubstrateError::NoConvergence)?,
    );

    // Depth: each cell's conductivity, the conductance per unit area
    // across each gap, and each line's half-cell weight `Bz`.
    let dz: Vec<f64> = z.windows(2).map(|w| w[1] - w[0]).collect();
    let sigma: Vec<f64> = (0..nz - 1)
        .map(|k| {
            let mid = 0.5 * (z[k] + z[k + 1]);
            let layer = zb[1..].partition_point(|&bottom| bottom < mid);
            1.0 / profile.layers[layer.min(profile.layers.len() - 1)].1
        })
        .collect();
    let edge: Vec<f64> = (0..nz - 1).map(|k| sigma[k] / dz[k]).collect();
    let bz: Vec<f64> = (0..nz)
        .map(|k| {
            0.5 * (k.checked_sub(1).map_or(0.0, |c| sigma[c] * dz[c])
                + sigma.get(k).map_or(0.0, |s| s * dz[k]))
        })
        .collect();
    // A grounded backside holds the last line, which leaves the system;
    // its gap's conductance stays on the line above.
    let last = if profile.grounded { nz - 2 } else { nz - 1 };
    let top = |mu: f64| {
        let diag = |k: usize| {
            k.checked_sub(1).map_or(0.0, |c| edge[c])
                + edge.get(k).copied().unwrap_or(0.0)
                + mu * bz[k]
        };
        let mut q = diag(last);
        for k in (1..last).rev() {
            q = diag(k) - edge[k] * edge[k] / q;
        }
        if last == 0 {
            diag(0)
        } else {
            diag(0) - edge[0] * edge[0] / q
        }
    };
    let s: Vec<f64> = (0..nx * ny)
        .map(|ab| top(lx[ab / ny] + ly[ab % ny]))
        .collect();

    // `out = S v` on the top face, `v[i * ny + j]`.
    let mut work = vec![0.0; nx * ny];
    let mut apply = |v: &[f64], out: &mut [f64]| {
        // Each product row by row, so every inner loop runs along memory.
        let axpy = |row: &mut [f64], c: f64, from: &[f64]| {
            for (r, f) in row.iter_mut().zip(from) {
                *r += c * f;
            }
        };
        // work = Uxᵀ v
        work.fill(0.0);
        for i in 0..nx {
            for a in 0..nx {
                let c = ux[i * nx + a];
                axpy(&mut work[a * ny..(a + 1) * ny], c, &v[i * ny..(i + 1) * ny]);
            }
        }
        // out = (work Uy) ∘ s
        out.fill(0.0);
        for a in 0..nx {
            for j in 0..ny {
                let c = work[a * ny + j];
                axpy(&mut out[a * ny..(a + 1) * ny], c, &uy[j * ny..(j + 1) * ny]);
            }
        }
        for (o, weight) in out.iter_mut().zip(&s) {
            *o *= weight;
        }
        // work = Ux out
        work.fill(0.0);
        for i in 0..nx {
            for a in 0..nx {
                let c = ux[i * nx + a];
                axpy(
                    &mut work[i * ny..(i + 1) * ny],
                    c,
                    &out[a * ny..(a + 1) * ny],
                );
            }
        }
        // out = work Uyᵀ
        for i in 0..nx {
            for j in 0..ny {
                out[i * ny + j] = work[i * ny..(i + 1) * ny]
                    .iter()
                    .zip(&uy[j * ny..(j + 1) * ny])
                    .map(|(p, q)| p * q)
                    .sum();
            }
        }
    };
    // S's diagonal: Σ_ab s_ab Ux[i, a]² Uy[j, b]².
    let diag: Vec<f64> = (0..nx * ny)
        .map(|ij| {
            let (i, j) = (ij / ny, ij % ny);
            (0..nx)
                .map(|a| {
                    ux[i * nx + a].powi(2)
                        * (0..ny)
                            .map(|b| s[a * ny + b] * uy[j * ny + b].powi(2))
                            .sum::<f64>()
                })
                .sum()
        })
        .collect();

    let n = nx * ny;
    let mut held = vec![FREE; n];
    for i in 0..nx {
        for j in 0..ny {
            if let Some(p) = port_at(x[i], y[j]) {
                held[i * ny + j] = u32::try_from(p).expect("a port fits a u32");
            }
        }
    }
    let dot = |a: &[f64], b: &[f64]| a.iter().zip(b).map(|(p, q)| p * q).sum::<f64>();
    let free = |out: &mut [f64]| {
        for (k, value) in out.iter_mut().enumerate() {
            if held[k] != FREE {
                *value = 0.0;
            }
        }
    };
    let mut y_matrix = vec![0.0; ports * ports];
    let (mut v, mut r, mut zv, mut p, mut ap) = (
        vec![0.0; n],
        vec![0.0; n],
        vec![0.0; n],
        vec![0.0; n],
        vec![0.0; n],
    );
    for driven in 0..ports {
        // The held nodes at their voltages; r = −S v on the free ones.
        for k in 0..n {
            v[k] = f64::from(u8::from(held[k] as usize == driven));
        }
        apply(&v, &mut r);
        for value in &mut r {
            *value = -*value;
        }
        free(&mut r);
        let norm_b = dot(&r, &r).sqrt();
        if norm_b > 0.0 {
            for k in 0..n {
                zv[k] = r[k] / diag[k];
            }
            free(&mut zv);
            p.copy_from_slice(&zv);
            let mut rz = dot(&r, &zv);
            let mut converged = false;
            for _ in 0..10 * n.max(100) {
                apply(&p, &mut ap);
                free(&mut ap);
                let alpha = rz / dot(&p, &ap);
                for k in 0..n {
                    v[k] += alpha * p[k];
                    r[k] -= alpha * ap[k];
                }
                if dot(&r, &r).sqrt() <= 1e-12 * norm_b {
                    converged = true;
                    break;
                }
                for k in 0..n {
                    zv[k] = r[k] / diag[k];
                }
                free(&mut zv);
                let next = dot(&r, &zv);
                let beta = next / rz;
                rz = next;
                for k in 0..n {
                    p[k] = zv[k] + beta * p[k];
                }
            }
            if !converged {
                return Err(SubstrateError::NoConvergence);
            }
        }
        // The current into the silicon at each port's nodes.
        apply(&v, &mut ap);
        for k in 0..n {
            if held[k] != FREE {
                y_matrix[held[k] as usize * ports + driven] += ap[k];
            }
        }
    }
    Ok(Admittance {
        ports,
        y: y_matrix,
        nodes: nx * ny * nz,
    })
}

/// Every net's shapes on the port layers, solved under `domain` (database
/// units) and appended to `network` as
/// [`Parasitic::SubstrateResistance`]s between the nets' first nodes and
/// from each to ground, then put back in canonical order. A shape on no
/// net, or a net with no node, is no port.
///
/// # Errors
///
/// As [`admittance`].
pub fn add_into(
    network: &mut ParasiticNetwork,
    store: &GeometryStore,
    nets: &NetTable,
    profile: &Profile,
    port_layers: &[LayerId],
    domain: gpurify_geom::Bbox,
    grid: Grid,
) -> Result<(), SubstrateError> {
    let first_node = |net: NetId| network.first_node(net);
    // The ports: each net's polygons, nets ascending.
    let mut shapes: Vec<(NetId, PolyId)> = port_layers
        .iter()
        .flat_map(|&layer| store.polys_on_layer(layer).map(PolyId))
        .map(|poly| (nets.net_of(poly), poly))
        .filter(|&(net, _)| net != NetId::NONE && first_node(net).is_some())
        .collect();
    shapes.sort_unstable();
    let port_nets: Vec<NetId> = {
        let mut v: Vec<NetId> = shapes.iter().map(|s| s.0).collect();
        v.dedup();
        v
    };
    if port_nets.is_empty() {
        return Ok(());
    }
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = grid.dbu_per_um() as f64;
    #[expect(clippy::cast_precision_loss, reason = "coordinates far below 2^53")]
    let um = |d: i64| d as f64 / per_um;
    let (mut xs, mut ys) = (Vec::new(), Vec::new());
    for &(_, poly) in &shapes {
        let (px, py) = store.poly_verts(poly);
        xs.extend(px.iter().map(|v| um(v.raw())));
        ys.extend(py.iter().map(|v| um(v.raw())));
    }
    let port_at = |x: f64, y: f64| {
        #[expect(clippy::cast_possible_truncation, reason = "a coordinate in range")]
        let point = gpurify_geom::ops::Point {
            x: gpurify_geom::Dbu::new_unchecked((x * per_um).round() as i64),
            y: gpurify_geom::Dbu::new_unchecked((y * per_um).round() as i64),
        };
        // ponytail: a linear scan per top-face node; index the shapes when
        // port counts grow past thousands.
        shapes
            .iter()
            .find(|&&(_, poly)| {
                let b = store.poly_bbox(poly);
                b.xlo <= point.x
                    && point.x <= b.xhi
                    && b.ylo <= point.y
                    && point.y <= b.yhi
                    && store.poly_contains_point(poly, point)
            })
            .map(|&(net, _)| port_nets.binary_search(&net).expect("a port net"))
    };
    let solved = admittance(
        profile,
        [
            um(domain.xlo.raw()),
            um(domain.ylo.raw()),
            um(domain.xhi.raw()),
            um(domain.yhi.raw()),
        ],
        &xs,
        &ys,
        port_at,
        port_nets.len(),
        LEVEL,
    )?;
    let nodes: Vec<NodeId> = port_nets
        .iter()
        .map(|&net| first_node(net).expect("a port has a node"))
        .collect();
    let node = |p: usize| nodes[p];
    let n = port_nets.len();
    for p in 0..n {
        for q in p + 1..n {
            let g = solved.between(p, q);
            if g > 0.0 {
                network.push(
                    node(p),
                    Some(node(q)),
                    Parasitic::SubstrateResistance(Qty::new(1.0 / g)),
                );
            }
        }
        let g = solved.to_backside(p);
        // A floating backside leaves a rounding residue, not a path.
        if profile.grounded && g > 0.0 {
            network.push(
                node(p),
                None,
                Parasitic::SubstrateResistance(Qty::new(1.0 / g)),
            );
        }
    }
    network.sort_canonical();
    Ok(())
}
