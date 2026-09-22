//! Quasi-static inductance: `GeometryStore` polygons in, per-net series L and R out.
//!
//! Data in: selected nets; each polygon's bbox becomes one filament along its
//! long axis (short side × layer thickness), one port per net across its two
//! most distant filament endpoints.
//! Data out: [`InductMatrix`] — the port impedance diagonal at one frequency,
//! `L = Im(Z)/ω`, `R = Re(Z)`, from a dense nodal solve of `Zb = R + jωL`.

#![expect(
    clippy::needless_range_loop,
    reason = "assembly kernels index several lanes in lockstep; ranged loops keep the fold order explicit"
)]

use crate::field::filament::{self, default_wdir, Filament, Vec3};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{GeometryStore, Grid};
use gpurify_ingest::deck::ProcessStack;
use num_complex::Complex64;
use rayon::prelude::*;

#[derive(Debug, Clone, Copy)]
pub struct InductanceOptions {
    /// The single frequency the impedance is extracted at, Hz. Positive.
    pub frequency_hz: f64,
}

impl Default for InductanceOptions {
    /// 1 MHz: skin effect negligible on chip, ωL still well above round-off next to R.
    fn default() -> Self {
        InductanceOptions { frequency_hz: 1e6 }
    }
}

/// Per-net self inductance (H) and series resistance (Ω), one row per selected
/// net in ascending [`NetId`] order.
#[derive(Debug, Default)]
pub struct InductMatrix {
    pub net: Vec<NetId>,
    pub l_henry: Vec<f64>,
    pub r_ohm: Vec<f64>,
}

#[derive(Debug, thiserror::Error)]
pub enum InductanceError {
    #[error(
        "layer {0} has no positive sheet resistance in the process stack, so \
         its conductivity is undefined and net inductance cannot be solved"
    )]
    NoSheetResistance(u16),
    #[error("layer {0} has no positive thickness in the process stack")]
    NoThickness(u16),
    #[error("net {0} has no geometry to build a filament from")]
    EmptyNet(u32),
    #[error("singular system at frequency {0} Hz")]
    Singular(f64),
}

/// A quantized filament endpoint: dbu coordinates plus layer. Sorted = dedup order.
type NodeKey = (i64, i64, u16);

/// Solve per-net L and R for `selected` in one magnetoquasistatic solve.
// ponytail: one filament per poly bbox; centerline decomposition when L-shaped nets need it.
pub fn extract_inductance_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    options: &InductanceOptions,
    out: &mut InductMatrix,
) -> Result<(), InductanceError> {
    out.net.clear();
    out.l_henry.clear();
    out.r_ohm.clear();

    let mut order = selected.to_vec();
    order.sort_unstable();

    #[expect(
        clippy::cast_precision_loss,
        reason = "a grid resolution is a small count"
    )]
    let scale = 1e-6 / grid.dbu_per_um() as f64;
    let nm = 1e-9;
    let stack_rows = stack
        .sheet_res_ohm_sq
        .len()
        .min(stack.thickness_nm.len())
        .min(stack.height_nm.len());

    let mut nodes: Vec<Vec3> = Vec::new();
    let mut set = FilamentSet::default();
    let mut ports: Vec<(usize, usize)> = Vec::new();
    for &net in &order {
        let polys = nets.polys_of(net);
        if polys.is_empty() {
            return Err(InductanceError::EmptyNet(net.0));
        }

        // Node order is the sorted key order: a function of the geometry alone.
        let mut keys: Vec<NodeKey> = Vec::with_capacity(polys.len() * 2);
        for &poly in polys {
            let (a, b) = filament_endpoints(store.poly_bbox(poly));
            let layer = store.poly_layer(poly).0;
            keys.push((a.0, a.1, layer));
            keys.push((b.0, b.1, layer));
        }
        keys.sort_unstable();
        keys.dedup();

        let base = nodes.len();
        for &(x, y, layer) in &keys {
            let row = usize::from(layer);
            let z = (stack.height_nm.get(row).copied().unwrap_or(0.0)
                + stack.thickness_nm.get(row).copied().unwrap_or(0.0) / 2.0)
                * nm;
            #[expect(
                clippy::cast_precision_loss,
                reason = "|coordinate| < 2^41, exact in f64"
            )]
            nodes.push(Vec3::new(x as f64 * scale, y as f64 * scale, z));
        }
        let node_of = |key: NodeKey| {
            base + keys
                .binary_search(&key)
                .expect("every endpoint was pushed as a key")
        };

        for &poly in polys {
            let layer = store.poly_layer(poly);
            let row = usize::from(layer.0);
            let sheet = stack.sheet_res_ohm_sq.get(row).copied().unwrap_or(0.0);
            let thickness_m = stack.thickness_nm.get(row).copied().unwrap_or(0.0) * nm;
            if row >= stack_rows || !(sheet > 0.0) || !sheet.is_finite() {
                return Err(InductanceError::NoSheetResistance(layer.0));
            }
            if !(thickness_m > 0.0) {
                return Err(InductanceError::NoThickness(layer.0));
            }
            // σ = 1/(Rsq · t) reproduces the sheet resistance through the thickness.
            let sigma = 1.0 / (sheet * thickness_m);

            let bbox = store.poly_bbox(poly);
            let (a, b) = filament_endpoints(bbox);
            #[expect(clippy::cast_precision_loss, reason = "|side| < 2^41, exact in f64")]
            let w = bbox.width().raw().min(bbox.height().raw()) as f64 * scale;
            let n1 = node_of((a.0, a.1, layer.0));
            let n2 = node_of((b.0, b.1, layer.0));
            set.push(nodes[n1], nodes[n2], w, thickness_m, sigma, n1, n2);
        }

        let (pa, pb) = most_distant_pair(&nodes[base..]);
        ports.push((base + pa, base + pb));
        out.net.push(net);
    }

    let f = options.frequency_hz;
    let z = port_impedance_diagonal(&set, nodes.len(), &ports, f)?;
    let w = 2.0 * std::f64::consts::PI * f;
    for zp in z {
        out.l_henry.push(if w == 0.0 { 0.0 } else { zp.im / w });
        out.r_ohm.push(zp.re);
    }
    Ok(())
}

/// Centre line of a bbox along its long axis, in dbu. A square runs along x.
fn filament_endpoints(bbox: gpurify_geom::Bbox) -> ((i64, i64), (i64, i64)) {
    let (xlo, xhi) = (bbox.xlo.raw(), bbox.xhi.raw());
    let (ylo, yhi) = (bbox.ylo.raw(), bbox.yhi.raw());
    if xhi - xlo >= yhi - ylo {
        let yc = i64::midpoint(ylo, yhi);
        ((xlo, yc), (xhi, yc))
    } else {
        let xc = i64::midpoint(xlo, xhi);
        ((xc, ylo), (xc, yhi))
    }
}

/// The two most distant nodes; ties keep the first pair in scan order.
// ponytail: O(n²) over one net's nodes; rotating calipers if nets grow large.
fn most_distant_pair(nodes: &[Vec3]) -> (usize, usize) {
    let n = nodes.len();
    if n == 1 {
        return (0, 0);
    }
    let (mut best, mut pair) = (-1.0_f64, (0, 1));
    for i in 0..n {
        for j in (i + 1)..n {
            let (a, b) = (nodes[i], nodes[j]);
            let d = (a.x - b.x).powi(2) + (a.y - b.y).powi(2) + (a.z - b.z).powi(2);
            if d > best {
                best = d;
                pair = (i, j);
            }
        }
    }
    pair
}

/// Branch filaments, `SoA`: geometry, DC resistance, and node pair.
#[derive(Default)]
struct FilamentSet {
    fils: Vec<Filament>,
    r: Vec<f64>,
    n1: Vec<usize>,
    n2: Vec<usize>,
}

impl FilamentSet {
    fn push(&mut self, p1: Vec3, p2: Vec3, w: f64, h: f64, sigma: f64, n1: usize, n2: usize) {
        // Normalized twice, as the width frame always was: the bits depend on it.
        let wdir = default_wdir((p2 - p1).normalized().normalized());
        let length = (p2 - p1).norm();
        self.fils.push(Filament::with_frame(p1, p2, w, h, wdir));
        self.r.push(length / (sigma * (w * h)));
        self.n1.push(n1);
        self.n2.push(n2);
    }
}

/// `Z[p][p]` for every port at frequency `f`: nodal solve `A Zb⁻¹ Aᵀ V = I`
/// with one ground node per galvanically connected component.
fn port_impedance_diagonal(
    set: &FilamentSet,
    nn: usize,
    ports: &[(usize, usize)],
    f: f64,
) -> Result<Vec<Complex64>, InductanceError> {
    let fils = &set.fils;
    let nb = fils.len();

    // Partial inductance, upper triangle by rows (order-preserving collect).
    let rows: Vec<Vec<f64>> = (0..nb)
        .into_par_iter()
        .map(|i| {
            let mut row = vec![0.0; nb - i];
            row[0] = filament::self_inductance(&fils[i]);
            for j in (i + 1)..nb {
                row[j - i] = filament::mutual(&fils[i], &fils[j]);
            }
            row
        })
        .collect();

    // Ground: a port's negative terminal, else the component's lowest node.
    let comp = connected_components(set, nn);
    let ncomp = comp.iter().copied().max().map_or(0, |m| m + 1);
    let mut ground_of_comp = vec![usize::MAX; ncomp.max(1)];
    for &(_, c) in ports {
        let g = &mut ground_of_comp[comp[c]];
        if *g == usize::MAX {
            *g = c;
        }
    }
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
    let mut red_of = vec![usize::MAX; nn];
    let mut nred = 0;
    for n in 0..nn {
        if !is_ground[n] {
            red_of[n] = nred;
            nred += 1;
        }
    }

    // Zb = R (diagonal) + jωL.
    let w = 2.0 * std::f64::consts::PI * f;
    let mut zb = vec![Complex64::new(0.0, 0.0); nb * nb];
    for i in 0..nb {
        for j in 0..nb {
            let l = if j >= i {
                rows[i][j - i]
            } else {
                rows[j][i - j]
            };
            let mut val = Complex64::new(0.0, w * l);
            if i == j {
                val += Complex64::new(set.r[i], 0.0);
            }
            zb[i * nb + j] = val;
        }
    }
    let lu = Lu::factor(zb, nb).ok_or(InductanceError::Singular(f))?;

    // X[:, n] = Zb⁻¹ (Aᵀ column n) for every non-ground node.
    let xcols: Vec<Option<Vec<Complex64>>> = (0..nn)
        .into_par_iter()
        .map(|n| {
            if is_ground[n] {
                return None;
            }
            let mut rhs = vec![Complex64::new(0.0, 0.0); nb];
            for b in 0..nb {
                if set.n1[b] == n {
                    rhs[b] += Complex64::new(1.0, 0.0);
                }
                if set.n2[b] == n {
                    rhs[b] -= Complex64::new(1.0, 0.0);
                }
            }
            Some(lu.solve(&rhs))
        })
        .collect();

    // Reduced nodal admittance Yn = A X, scattered per branch.
    let mut yn = vec![Complex64::new(0.0, 0.0); nred * nred];
    for n in 0..nn {
        let Some(xc) = &xcols[n] else { continue };
        let rn = red_of[n];
        for b in 0..nb {
            let (b1, b2) = (set.n1[b], set.n2[b]);
            if !is_ground[b1] {
                yn[red_of[b1] * nred + rn] += xc[b];
            }
            if !is_ground[b2] {
                yn[red_of[b2] * nred + rn] -= xc[b];
            }
        }
    }
    let yn_lu = Lu::factor(yn, nred).ok_or(InductanceError::Singular(f))?;

    // Unit current into each port; its own voltage is Z[p][p].
    Ok(ports
        .iter()
        .map(|&(a, c)| {
            let mut iinj = vec![Complex64::new(0.0, 0.0); nred];
            if !is_ground[a] {
                iinj[red_of[a]] += Complex64::new(1.0, 0.0);
            }
            if !is_ground[c] {
                iinj[red_of[c]] -= Complex64::new(1.0, 0.0);
            }
            let v = yn_lu.solve(&iinj);
            let volt = |node: usize| {
                if is_ground[node] {
                    Complex64::new(0.0, 0.0)
                } else {
                    v[red_of[node]]
                }
            };
            volt(a) - volt(c)
        })
        .collect())
}

/// Component id per node (union-find over branches), numbered in ascending
/// order of each component's first node.
fn connected_components(set: &FilamentSet, nn: usize) -> Vec<usize> {
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        let mut c = x;
        while parent[c] != r {
            let next = parent[c];
            parent[c] = r;
            c = next;
        }
        r
    }
    let mut parent: Vec<usize> = (0..nn).collect();
    for (&a, &b) in set.n1.iter().zip(&set.n2) {
        let ra = find(&mut parent, a);
        let rb = find(&mut parent, b);
        if ra != rb {
            parent[ra] = rb;
        }
    }
    let mut label = vec![usize::MAX; nn];
    let mut next = 0;
    let mut comp = vec![0usize; nn];
    for n in 0..nn {
        let r = find(&mut parent, n);
        if label[r] == usize::MAX {
            label[r] = next;
            next += 1;
        }
        comp[n] = label[r];
    }
    comp
}

/// Dense complex LU with partial pivoting (PA = LU), row-major `n × n`.
struct Lu {
    factors: Vec<Complex64>,
    piv: Vec<usize>,
    n: usize,
}

impl Lu {
    /// `None` when a pivot column is exactly zero.
    fn factor(mut lu: Vec<Complex64>, n: usize) -> Option<Self> {
        let mut piv: Vec<usize> = (0..n).collect();
        for k in 0..n {
            let mut p = k;
            let mut max = lu[k * n + k].norm();
            for i in (k + 1)..n {
                let m = lu[i * n + k].norm();
                if m > max {
                    max = m;
                    p = i;
                }
            }
            if max == 0.0 {
                return None;
            }
            if p != k {
                for j in 0..n {
                    lu.swap(k * n + j, p * n + j);
                }
                piv.swap(k, p);
            }

            // Rows are independent, so rayon is bit-identical to serial.
            let pivot = lu[k * n + k];
            let (top, tail) = lu.split_at_mut((k + 1) * n);
            let pivot_row = &top[k * n..(k + 1) * n];
            let update = |row: &mut [Complex64]| {
                let factor = row[k] / pivot;
                row[k] = factor;
                for j in (k + 1)..n {
                    row[j] -= factor * pivot_row[j];
                }
            };
            if (n - k - 1) * (n - k) > 64 * 64 {
                tail.par_chunks_mut(n).for_each(update);
            } else {
                tail.chunks_mut(n).for_each(update);
            }
        }
        Some(Lu {
            factors: lu,
            piv,
            n,
        })
    }

    fn solve(&self, b: &[Complex64]) -> Vec<Complex64> {
        let n = self.n;
        let mut x: Vec<Complex64> = self.piv.iter().map(|&p| b[p]).collect();
        for i in 0..n {
            let mut sum = x[i];
            for j in 0..i {
                sum -= self.factors[i * n + j] * x[j];
            }
            x[i] = sum;
        }
        for i in (0..n).rev() {
            let mut sum = x[i];
            for j in (i + 1)..n {
                sum -= self.factors[i * n + j] * x[j];
            }
            x[i] = sum / self.factors[i * n + i];
        }
        x
    }
}
