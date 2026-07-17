//! Black-box (kernel-independent) FMM for the Laplace potential
//!   φ(xᵢ) = Σ_{j≠i} q_j / ‖xᵢ − x_j‖.
//!
//! Sources and targets are the same point set (the collocation points). The
//! operator implements [`LinearOperator`], so it is a drop-in replacement for the
//! dense apply inside GMRES — the whole point of the integral-equation
//! formulation. Accuracy is controlled by the Chebyshev order `n`; raising it
//! drives the FMM matvec to the dense result (spectral convergence for 1/r).
//!
//! Passes: P2M (anterpolate charges to Chebyshev nodes) → M2M (up) → M2L
//! (well-separated box interactions, the hot spot, a dense product per pair) →
//! L2L (down) → L2P (interpolate local field to points) + P2P (near-field direct).

use super::chebyshev;
use super::tree::Octree;
use crate::quasistatic::geometry::Vec3;
use crate::quasistatic::kernel::LinearOperator;
use crate::quasistatic::linalg::LowRankApprox;

/// M2L offsets live in [-3, 3]³ → flat 7³ table, no hashing in the hot loop.
const M2L_SPAN: i32 = 7;
#[inline]
fn m2l_index(off: [i32; 3]) -> usize {
    (((off[0] + 3) * M2L_SPAN + off[1] + 3) * M2L_SPAN + off[2] + 3) as usize
}

pub struct LaplaceFmm {
    tree: Octree,
    n: usize,
    n3: usize,
    ref3d: Vec<[f64; 3]>,
    points: Vec<Vec3>,
    /// Interpolation weights of each point at its leaf's Chebyshev nodes (n³).
    point_weights: Vec<Vec<f64>>,
    /// ponytail: 1D M2M matrices per octant per axis for O(n⁴) tensor-product apply.
    /// m2m_1d[octant * 3 + axis][m * n + k] = weight of child node k on parent node m.
    m2m_1d: Vec<Vec<f64>>,
    /// ponytail: low-rank compressed M2L operators, ~2-3× faster apply.
    /// Indexed by [`m2l_index`] (flat 7³ offset table).
    m2l_table: Vec<Option<LowRankApprox>>,
}

impl LaplaceFmm {
    /// Build an FMM over `points` with Chebyshev order `n` and tree depth
    /// `max_level`.
    pub fn new(points: &[Vec3], n: usize, max_level: usize) -> Self {
        let tree = Octree::build(points, max_level);
        let nodes1d = chebyshev::nodes(n);
        let ref3d = chebyshev::nodes_3d(n, &nodes1d);
        let n3 = n * n * n;

        // Per-point interpolation weights + leaf assignment.
        let mut point_weights = vec![Vec::new(); points.len()];
        for &leaf in tree.leaves() {
            for &pi in &tree.nodes[leaf].points {
                let local = tree.to_local(leaf, points[pi]);
                point_weights[pi] = chebyshev::interp_weights_3d(local, n, &nodes1d);
            }
        }

        // M2M octant matrices: child reference node k sits at parent-local
        // position (child_center_local + 0.5·ref3d[k]); its weights on the parent
        // grid form column k.
        let mut m2m = vec![vec![0.0; n3 * n3]; 8];
        for oz in 0..2 {
            for oy in 0..2 {
                for ox in 0..2 {
                    let o = ox + 2 * oy + 4 * oz;
                    let cc = [
                        (2.0 * ox as f64 - 1.0) * 0.5,
                        (2.0 * oy as f64 - 1.0) * 0.5,
                        (2.0 * oz as f64 - 1.0) * 0.5,
                    ];
                    for k in 0..n3 {
                        let pos = [
                            cc[0] + 0.5 * ref3d[k][0],
                            cc[1] + 0.5 * ref3d[k][1],
                            cc[2] + 0.5 * ref3d[k][2],
                        ];
                        let w = chebyshev::interp_weights_3d(pos, n, &nodes1d);
                        for mp in 0..n3 {
                            m2m[o][mp * n3 + k] = w[mp];
                        }
                    }
                }
            }
        }

        // ponytail: 1D interpolation matrices for tensor-product M2M/L2L (O(n⁴) vs O(n⁶))
        let mut m2m_1d = vec![vec![0.0; n * n]; 24]; // 8 octants * 3 axes
        for oz in 0..2 {
            for oy in 0..2 {
                for ox in 0..2 {
                    let o = ox + 2 * oy + 4 * oz;
                    let cc = [
                        (2.0 * ox as f64 - 1.0) * 0.5,
                        (2.0 * oy as f64 - 1.0) * 0.5,
                        (2.0 * oz as f64 - 1.0) * 0.5,
                    ];
                    for axis in 0..3 {
                        let mat = &mut m2m_1d[o * 3 + axis];
                        for k in 0..n {
                            let child_pos = cc[axis] + 0.5 * nodes1d[k];
                            let w = chebyshev::interp_weights(child_pos, n, &nodes1d);
                            for m in 0..n {
                                mat[m * n + k] = w[m];
                            }
                        }
                    }
                }
            }
        }

        // ponytail: m2m dense matrices only needed during construction, not stored
        drop(m2m);
        let mut fmm = LaplaceFmm {
            tree,
            n,
            n3,
            ref3d,
            points: points.to_vec(),
            point_weights,
            m2m_1d,
            m2l_table: (0..(M2L_SPAN * M2L_SPAN * M2L_SPAN) as usize).map(|_| None).collect(),
        };
        fmm.precompute_m2l();
        fmm
    }

    /// Precompute the dimensionless M2L operator for every distinct box offset
    /// that appears in an interaction list. G_off[m·n³+l] = 1/‖ref[m]−ref[l]−2·off‖.
    fn precompute_m2l(&mut self) {
        let mut offsets = std::collections::HashSet::new();
        for node in &self.tree.nodes {
            for &c in &node.interaction {
                let cc = self.tree.nodes[c].cell;
                let off = [
                    cc[0] as i32 - node.cell[0] as i32,
                    cc[1] as i32 - node.cell[1] as i32,
                    cc[2] as i32 - node.cell[2] as i32,
                ];
                offsets.insert(off);
            }
        }
        let n3 = self.n3;
        let ref3d = &self.ref3d;
        // Compression eps tracks the Chebyshev order so M2L truncation never
        // dominates the interpolation error: 1e-8 at n=5 (previous fixed
        // value), tightening ×10 per extra order.
        let eps = (1e-3 * 0.1f64.powi(self.n as i32)).max(1e-14);
        use rayon::prelude::*;
        let offsets: Vec<[i32; 3]> = offsets.into_iter().collect();
        let built: Vec<_> = offsets
            .par_iter()
            .map(|&off| {
                let mut g = vec![0.0; n3 * n3];
                let shift = [2.0 * off[0] as f64, 2.0 * off[1] as f64, 2.0 * off[2] as f64];
                for m in 0..n3 {
                    for l in 0..n3 {
                        let dx = ref3d[m][0] - ref3d[l][0] - shift[0];
                        let dy = ref3d[m][1] - ref3d[l][1] - shift[1];
                        let dz = ref3d[m][2] - ref3d[l][2] - shift[2];
                        let r = (dx * dx + dy * dy + dz * dz).sqrt();
                        g[m * n3 + l] = if r > 0.0 { 1.0 / r } else { 0.0 };
                    }
                }
                let lr = LowRankApprox::compress(&g, n3, n3, eps);
                (off, lr)
            })
            .collect();
        for (off, lr) in built {
            self.m2l_table[m2l_index(off)] = Some(lr);
        }
    }

    /// Full matvec y = K q (far-field expansion + near-field direct).
    pub fn matvec(&self, q: &[f64]) -> Vec<f64> {
        self.run(q, true)
    }

    /// Far-field-only matvec: the potential from all *well-separated* boxes
    /// (P2M→M2M→M2L→L2L→L2P), with the near-field (leaf + neighbours) left out.
    /// Used by the precorrected BEM operator, which supplies the near block from
    /// exact analytic (Wilton) integrals instead of the point kernel.
    pub fn matvec_farfield(&self, q: &[f64]) -> Vec<f64> {
        self.run(q, false)
    }

    /// For each leaf: (target point indices, source point indices from the leaf
    /// and its neighbours). This is exactly the near-field coverage the
    /// far-field matvec omits, so a BEM operator can fill it analytically.
    pub fn near_blocks(&self) -> Vec<(Vec<usize>, Vec<usize>)> {
        let mut out = Vec::new();
        for &leaf in self.tree.leaves() {
            let targets = self.tree.nodes[leaf].points.clone();
            if targets.is_empty() {
                continue;
            }
            let mut sources = targets.clone();
            for &c in &self.tree.nodes[leaf].neighbors {
                sources.extend_from_slice(&self.tree.nodes[c].points);
            }
            out.push((targets, sources));
        }
        out
    }

    /// The core matvec y = K q; `with_p2p` toggles the near-field direct block.
    fn run(&self, q: &[f64], with_p2p: bool) -> Vec<f64> {
        let n3 = self.n3;
        let nb = self.tree.nodes.len();
        let mut w = vec![vec![0.0f64; n3]; nb]; // multipole
        let mut local = vec![vec![0.0f64; n3]; nb]; // local

        // --- Upward: P2M at leaves ---
        for &leaf in self.tree.leaves() {
            let wl = &mut w[leaf];
            for &pi in &self.tree.nodes[leaf].points {
                let qi = q[pi];
                if qi == 0.0 {
                    continue;
                }
                let pw = &self.point_weights[pi];
                for m in 0..n3 {
                    wl[m] += pw[m] * qi;
                }
            }
        }

        // --- Upward: M2M from finest to coarsest ---
        // ponytail: t1/t2 scratch hoisted out of the node loop (every entry is
        // overwritten before use, so no re-zeroing needed)
        let mut t1 = vec![0.0f64; n3];
        let mut t2 = vec![0.0f64; n3];
        for level in (1..=self.tree.max_level).rev() {
            for &id in &self.tree.levels[level] {
                let parent = match self.tree.nodes[id].parent {
                    Some(p) => p,
                    None => continue,
                };
                let o = self.octant(id, parent);
                // ponytail: accumulate M2M contribution via split borrow
                // (id != parent always holds in a tree)
                let (w_child, w_parent) = if id < parent {
                    let (lo, hi) = w.split_at_mut(parent);
                    (&lo[id], &mut hi[0])
                } else {
                    let (lo, hi) = w.split_at_mut(id);
                    (&hi[0], &mut lo[parent])
                };
                // ponytail: tensor-product M2M in O(n⁴) instead of O(n⁶)
                let n = self.n;
                let mx = &self.m2m_1d[o * 3];
                let my = &self.m2m_1d[o * 3 + 1];
                let mz = &self.m2m_1d[o * 3 + 2];
                // Apply 1D transforms: z, then y, then x
                // Contract z: for each (a,b), transform c -> c'
                for a in 0..n {
                    for b in 0..n {
                        for cp in 0..n {
                            let mut s = 0.0;
                            for c in 0..n {
                                s += mz[cp * n + c] * w_child[a * n * n + b * n + c];
                            }
                            t1[a * n * n + b * n + cp] = s;
                        }
                    }
                }
                // Contract y: for each (a,c'), transform b -> b'
                for a in 0..n {
                    for bp in 0..n {
                        for cp in 0..n {
                            let mut s = 0.0;
                            for b in 0..n {
                                s += my[bp * n + b] * t1[a * n * n + b * n + cp];
                            }
                            t2[a * n * n + bp * n + cp] = s;
                        }
                    }
                }
                // Contract x: transform a -> a'
                for ap in 0..n {
                    for bp in 0..n {
                        for cp in 0..n {
                            let mut s = 0.0;
                            for a in 0..n {
                                s += mx[ap * n + a] * t2[a * n * n + bp * n + cp];
                            }
                            w_parent[ap * n * n + bp * n + cp] += s;
                        }
                    }
                }
            }
        }

        // --- Downward: M2L over interaction lists at each level ≥ 2 ---
        // Each box's local update depends only on read-only multipoles, so the
        // per-box work runs in parallel (this is the FMM hot spot / GPU target).
        use rayon::prelude::*;
        for level in 2..=self.tree.max_level {
            let half = self.tree.nodes[self.tree.levels[level][0]].half;
            let inv_half = 1.0 / half;
            let ids = &self.tree.levels[level];
            // ponytail: use compressed M2L operators (low-rank QR)
            let m2l_map = |&id: &usize| {
                let cell = self.tree.nodes[id].cell;
                let mut acc_local = vec![0.0f64; n3];
                // ponytail: one scratch per box, reused across all its M2L pairs
                let mut scratch = vec![0.0f64; n3];
                for &c in &self.tree.nodes[id].interaction {
                    let cc = self.tree.nodes[c].cell;
                    let off = [
                        cc[0] as i32 - cell[0] as i32,
                        cc[1] as i32 - cell[1] as i32,
                        cc[2] as i32 - cell[2] as i32,
                    ];
                    let wc = &w[c];
                    if let Some(lr) = &self.m2l_table[m2l_index(off)] {
                        lr.apply_add(wc, &mut acc_local, inv_half, &mut scratch);
                    }
                }
                (id, acc_local)
            };
            // ponytail: par_iter overhead dominates below ~512 items
            let updates: Vec<(usize, Vec<f64>)> = if ids.len() < 512 {
                ids.iter().map(m2l_map).collect()
            } else {
                ids.par_iter().map(m2l_map).collect()
            };
            for (id, acc) in updates {
                for m in 0..n3 {
                    local[id][m] += acc[m];
                }
            }
        }

        // --- Downward: L2L from coarse to fine ---
        for level in 2..self.tree.max_level {
            for &id in &self.tree.levels[level] {
                let children: Vec<usize> = self.tree.nodes[id].children.clone();
                for &child in &children {
                    let o = self.octant(child, id);
                    // (full M2M matrix kept for reference but tensor-product used below)
                    // ponytail: split borrow avoids cloning parent_local
                    let (l_parent, l_child) = if id < child {
                        let (lo, hi) = local.split_at_mut(child);
                        (&lo[id], &mut hi[0])
                    } else {
                        let (lo, hi) = local.split_at_mut(id);
                        (&hi[0], &mut lo[child])
                    };
                    // ponytail: tensor-product L2L (transpose of M2M) in O(n⁴)
                    let n = self.n;
                    let mx = &self.m2m_1d[o * 3];
                    let my = &self.m2m_1d[o * 3 + 1];
                    let mz = &self.m2m_1d[o * 3 + 2];
                    // L2L = M2M^T, so 1D transforms use transposed 1D matrices
                    // Apply x^T, then y^T, then z^T
                    // Contract x (transposed): for each (b,c), transform a -> a'
                    for ap in 0..n {
                        for b in 0..n {
                            for c in 0..n {
                                let mut s = 0.0;
                                for a in 0..n {
                                    // M^T[ap, a] = M[a, ap] = mx[a * n + ap]
                                    s += mx[a * n + ap] * l_parent[a * n * n + b * n + c];
                                }
                                t1[ap * n * n + b * n + c] = s;
                            }
                        }
                    }
                    // Contract y (transposed)
                    for a in 0..n {
                        for bp in 0..n {
                            for c in 0..n {
                                let mut s = 0.0;
                                for b in 0..n {
                                    s += my[b * n + bp] * t1[a * n * n + b * n + c];
                                }
                                t2[a * n * n + bp * n + c] = s;
                            }
                        }
                    }
                    // Contract z (transposed)
                    for a in 0..n {
                        for b in 0..n {
                            for cp in 0..n {
                                let mut s = 0.0;
                                for c in 0..n {
                                    s += mz[c * n + cp] * t2[a * n * n + b * n + c];
                                }
                                l_child[a * n * n + b * n + cp] += s;
                            }
                        }
                    }
                }
            }
        }

        // --- Evaluate: L2P + P2P at leaves (parallel; each leaf writes only its
        // own target points, which are disjoint across leaves). ---
        let mut y = vec![0.0f64; self.points.len()];
        let leaves = self.tree.leaves();
        // ponytail: skip rayon overhead for small leaf counts
        let leaf_map = |&leaf: &usize| {
                let ll = &local[leaf];
                let pts = &self.tree.nodes[leaf].points;
                let mut out = Vec::with_capacity(pts.len());
                // ponytail: iterate neighbours ∪ self without cloning the list
                let near = self.tree.nodes[leaf].neighbors.iter().chain(std::iter::once(&leaf));
                for &pi in pts {
                    // L2P far field.
                    let pw = &self.point_weights[pi];
                    let mut acc = 0.0;
                    for m in 0..n3 {
                        acc += pw[m] * ll[m];
                    }
                    // P2P near field.
                    if with_p2p {
                        let xi = self.points[pi];
                        for &c in near.clone() {
                            for &sj in &self.tree.nodes[c].points {
                                if sj == pi {
                                    continue;
                                }
                                let r = xi.dist(self.points[sj]);
                                if r > 0.0 {
                                    acc += q[sj] / r;
                                }
                            }
                        }
                    }
                    out.push((pi, acc));
                }
                out
        };
        let contributions: Vec<Vec<(usize, f64)>> = if leaves.len() < 512 {
            leaves.iter().map(leaf_map).collect()
        } else {
            leaves.par_iter().map(leaf_map).collect()
        };
        for block in contributions {
            for (pi, v) in block {
                y[pi] += v;
            }
        }
        y
    }

    /// Octant of `child` within `parent` (0..7).
    #[inline]
    fn octant(&self, child: usize, parent: usize) -> usize {
        let cc = self.tree.nodes[child].cell;
        let pc = self.tree.nodes[parent].cell;
        let ox = (cc[0] - 2 * pc[0]) as usize;
        let oy = (cc[1] - 2 * pc[1]) as usize;
        let oz = (cc[2] - 2 * pc[2]) as usize;
        ox + 2 * oy + 4 * oz
    }
}

impl LinearOperator for LaplaceFmm {
    fn dim(&self) -> usize {
        self.points.len()
    }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        let out = self.matvec(x);
        y.copy_from_slice(&out);
    }
}
