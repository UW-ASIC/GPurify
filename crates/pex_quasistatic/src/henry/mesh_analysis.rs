//! FastHenry's authentic **mesh-analysis** formulation, `M Z Mᵀ Iₘ = Vₛ`.
//!
//! Instead of the nodal admittance `A Zb⁻¹ Aᵀ`, this builds a fundamental-loop
//! (mesh) basis `M` from a spanning forest of the branch graph and solves the
//! dense loop system directly per frequency. It is mathematically equivalent to
//! the nodal path and validated against it; it is also the formulation the
//! iterative FMM/GMRES path would use, with the block-Jacobi "local inversion"
//! preconditioner on `M Z Mᵀ`.
//!
//! Port impedance extraction: for a unit current forced through port p, a
//! particular branch current `Ib₀` along the tree path a_p→b_p satisfies KCL;
//! the loop currents correct it so KVL holds on every mesh:
//!   M Z Mᵀ Iₘ = −M Z Ib₀,   Ib = Ib₀ + Mᵀ Iₘ,   Vb = Z·Ib,
//! and Z[q,p] is the branch-voltage sum along the tree path a_q→b_q.

use crate::linalg::{DenseMatrix, LuDecomposition};
use num_complex::Complex64;

/// A spanning forest of the branch graph, with per-node tree parent links so we
/// can extract the tree path between any two connected nodes.
pub struct SpanningForest {
    /// For each node: `Some((parent_node, branch_index, sign))` where `sign` is
    /// +1 if the tree branch is oriented parent→node, −1 otherwise. Roots have
    /// `None`.
    parent: Vec<Option<(usize, usize, f64)>>,
    /// Branch indices that are tree edges (the rest are chords).
    is_tree: Vec<bool>,
    depth: Vec<usize>,
}

impl SpanningForest {
    /// Build a spanning forest by BFS over the branch graph. `edges[b] = (n1,n2)`.
    pub fn build(edges: &[(usize, usize)], nn: usize) -> Self {
        let mut adj: Vec<Vec<(usize, usize)>> = vec![Vec::new(); nn]; // (neighbor, branch)
        for (b, &(a, c)) in edges.iter().enumerate() {
            adj[a].push((c, b));
            adj[c].push((a, b));
        }
        let mut parent: Vec<Option<(usize, usize, f64)>> = vec![None; nn];
        let mut visited = vec![false; nn];
        let mut is_tree = vec![false; edges.len()];
        let mut depth = vec![0usize; nn];
        let mut queue = std::collections::VecDeque::new();
        for start in 0..nn {
            if visited[start] {
                continue;
            }
            visited[start] = true;
            queue.push_back(start);
            while let Some(u) = queue.pop_front() {
                for &(v, b) in &adj[u] {
                    if !visited[v] {
                        visited[v] = true;
                        // Tree branch b connects u (parent) and v. Orientation:
                        // sign is +1 if branch is oriented u->v (edges[b].0==u).
                        let sign = if edges[b].0 == u { 1.0 } else { -1.0 };
                        parent[v] = Some((u, b, sign));
                        is_tree[b] = true;
                        depth[v] = depth[u] + 1;
                        queue.push_back(v);
                    }
                }
            }
        }
        SpanningForest { parent, is_tree, depth }
    }

    /// The tree path from `a` to `b` as a list of `(branch_index, sign)` where
    /// `sign` is +1 if traversed in the branch's own orientation. Empty if a==b.
    pub fn tree_path(&self, a: usize, b: usize) -> Vec<(usize, f64)> {
        let mut pa = Vec::new(); // a up to LCA
        let mut pb = Vec::new(); // b up to LCA
        let mut x = a;
        let mut y = b;
        // Equalize depths.
        while self.depth[x] > self.depth[y] {
            let (p, br, sgn) = self.parent[x].expect("path node has no parent");
            pa.push((br, sgn)); // traversing x -> parent is against branch orientation? see below
            x = p;
        }
        while self.depth[y] > self.depth[x] {
            let (p, br, sgn) = self.parent[y].expect("path node has no parent");
            pb.push((br, sgn));
            y = p;
        }
        while x != y {
            let (px, bx, sx) = self.parent[x].expect("no parent");
            pa.push((bx, sx));
            x = px;
            let (py, by, sy) = self.parent[y].expect("no parent");
            pb.push((by, sy));
            y = py;
        }
        // Assemble a->LCA (each parent link is oriented parent->child with `sign`
        // meaning branch is parent->child when sign>0; moving child->parent is
        // the reverse, so negate) then LCA->b (moving parent->child, keep sign).
        let mut path = Vec::with_capacity(pa.len() + pb.len());
        for (br, sgn) in pa {
            path.push((br, -sgn)); // child -> parent = reverse of parent->child
        }
        for (br, sgn) in pb.into_iter().rev() {
            path.push((br, sgn)); // parent -> child
        }
        path
    }

    /// Indices of chord (non-tree) branches — one fundamental mesh each.
    pub fn chords(&self) -> Vec<usize> {
        (0..self.is_tree.len()).filter(|&b| !self.is_tree[b]).collect()
    }
}

/// Build the mesh matrix M (nmesh × nbranch): each row is a fundamental loop =
/// chord + tree path closing it.
pub fn mesh_matrix(edges: &[(usize, usize)], forest: &SpanningForest) -> DenseMatrix<f64> {
    let chords = forest.chords();
    let nb = edges.len();
    let mut m = DenseMatrix::<f64>::zeros(chords.len(), nb);
    for (row, &c) in chords.iter().enumerate() {
        let (n1, n2) = edges[c];
        // Loop: chord c oriented n1->n2 (sign +1), then tree path n2 back to n1.
        m[(row, c)] = 1.0;
        for (br, sgn) in forest.tree_path(n2, n1) {
            m[(row, br)] += sgn;
        }
    }
    m
}

/// Solve the port impedance matrix at one frequency via the mesh formulation.
/// `zb` is the dense branch impedance, `edges` the branch node pairs, `ports`
/// the (a,b) node index pairs.
pub fn solve_ports(
    zb: &DenseMatrix<Complex64>,
    edges: &[(usize, usize)],
    ports: &[(usize, usize)],
    nn: usize,
) -> DenseMatrix<Complex64> {
    let forest = SpanningForest::build(edges, nn);
    let m = mesh_matrix(edges, &forest);
    let nmesh = m.rows;
    let nb = edges.len();
    let np = ports.len();

    // Precompute M Z Mᵀ (nmesh × nmesh).
    // First MZ = M * Zb (nmesh × nb), then (MZ) * Mᵀ.
    let mut mz = DenseMatrix::<Complex64>::zeros(nmesh, nb);
    for r in 0..nmesh {
        for c in 0..nb {
            let mut acc = Complex64::new(0.0, 0.0);
            for k in 0..nb {
                let mrk = m[(r, k)];
                if mrk != 0.0 {
                    acc += Complex64::new(mrk, 0.0) * zb[(k, c)];
                }
            }
            mz[(r, c)] = acc;
        }
    }
    let mut mzmt = DenseMatrix::<Complex64>::zeros(nmesh, nmesh);
    for r in 0..nmesh {
        for s in 0..nmesh {
            let mut acc = Complex64::new(0.0, 0.0);
            for k in 0..nb {
                let msk = m[(s, k)];
                if msk != 0.0 {
                    acc += mz[(r, k)] * Complex64::new(msk, 0.0);
                }
            }
            mzmt[(r, s)] = acc;
        }
    }
    let lu = LuDecomposition::factor(&mzmt).expect("singular mesh system");

    let mut zmat = DenseMatrix::<Complex64>::zeros(np, np);
    for (p, &(ap, bp)) in ports.iter().enumerate() {
        // Particular branch current: unit along tree path a_p -> b_p.
        let mut ib0 = vec![Complex64::new(0.0, 0.0); nb];
        for (br, sgn) in forest.tree_path(ap, bp) {
            ib0[br] += Complex64::new(sgn, 0.0);
        }
        // rhs = -M Zb Ib0.
        let zib0 = zb.matvec(&ib0);
        let mut rhs = vec![Complex64::new(0.0, 0.0); nmesh];
        for r in 0..nmesh {
            let mut acc = Complex64::new(0.0, 0.0);
            for k in 0..nb {
                let mrk = m[(r, k)];
                if mrk != 0.0 {
                    acc += Complex64::new(mrk, 0.0) * zib0[k];
                }
            }
            rhs[r] = -acc;
        }
        let im = lu.solve(&rhs);
        // Ib = Ib0 + Mᵀ Im.
        let mut ib = ib0.clone();
        for r in 0..nmesh {
            let imr = im[r];
            for k in 0..nb {
                let mrk = m[(r, k)];
                if mrk != 0.0 {
                    ib[k] += Complex64::new(mrk, 0.0) * imr;
                }
            }
        }
        let vb = zb.matvec(&ib);
        // Z[q,p] = branch-voltage sum along tree path a_q -> b_q.
        for (q, &(aq, bq)) in ports.iter().enumerate() {
            let mut v = Complex64::new(0.0, 0.0);
            for (br, sgn) in forest.tree_path(aq, bq) {
                v += Complex64::new(sgn, 0.0) * vb[br];
            }
            zmat[(q, p)] = v;
        }
    }
    zmat
}
