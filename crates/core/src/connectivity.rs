//! Connected components over an edge list.
//!
//! Each node is labeled with the **minimum node index** in its component, so
//! two runs on the same graph give identical labels and two graphs with the
//! same partition give identical labels.
//!
//! On the CPU this is a weighted union-find with path halving — the direct,
//! cache-friendly way to do it. (The previous design ran a parallel
//! label-propagation, FastSV / ECL-CC, through a device session so the *same*
//! code could target the GPU via a transpiling macro. With hand-written GLSL
//! that shared path is gone: the GPU gets its own label-propagation kernels in
//! the `gpu` module, and the CPU gets the algorithm that is actually fastest on
//! a CPU.)

/// Weighted union-find that always roots a component at its smallest index, so
/// `find` yields the min-index label directly. Path halving keeps `find`
/// near-constant amortized.
struct MinUnionFind {
    parent: Vec<u32>,
}

impl MinUnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..u32::try_from(n).unwrap_or(u32::MAX)).collect(),
        }
    }

    fn find(&mut self, x: u32) -> u32 {
        let mut x = x;
        while self.parent[x as usize] != x {
            // Path halving: point each node to its grandparent.
            let grand = self.parent[self.parent[x as usize] as usize];
            self.parent[x as usize] = grand;
            x = grand;
        }
        x
    }

    /// Union `a` and `b`, keeping the smaller root so labels stay min-indexed.
    fn union(&mut self, a: u32, b: u32) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        let (lo, hi) = (ra.min(rb), ra.max(rb));
        self.parent[hi as usize] = lo;
    }

    /// Flatten every node to its (min-index) root.
    fn into_labels(mut self) -> Vec<u32> {
        for i in 0..self.parent.len() {
            let root = self.find(u32::try_from(i).unwrap_or(u32::MAX));
            self.parent[i] = root;
        }
        self.parent
    }
}

/// Component labels for `n` nodes over `edges`, each node labeled with the
/// minimum node index in its component.
///
/// Edges to out-of-range endpoints and self-loops are ignored. Isolated nodes
/// (including every node when `edges` is empty) are their own component.
#[must_use]
pub fn connected_components(edges: &[(u32, u32)], n: usize) -> Vec<u32> {
    let mut uf = MinUnionFind::new(n);
    for &(u, v) in edges {
        if (u as usize) < n && (v as usize) < n && u != v {
            uf.union(u, v);
        }
    }
    uf.into_labels()
}

/// Alias kept for callers that name the host union-find explicitly (LVS net
/// extraction). Identical semantics to [`connected_components`].
#[must_use]
pub fn host_union_find(edges: &[(u32, u32)], n: usize) -> Vec<u32> {
    connected_components(edges, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference union-find oracle (independent implementation).
    fn oracle(edges: &[(u32, u32)], n: usize) -> Vec<u32> {
        let mut parent: Vec<u32> = (0..n as u32).collect();
        fn find(p: &mut [u32], x: u32) -> u32 {
            let mut r = x;
            while p[r as usize] != r {
                p[r as usize] = p[p[r as usize] as usize];
                r = p[r as usize];
            }
            r
        }
        for &(u, v) in edges {
            if (u as usize) >= n || (v as usize) >= n {
                continue;
            }
            let (ru, rv) = (find(&mut parent, u), find(&mut parent, v));
            if ru != rv {
                let (lo, hi) = (ru.min(rv), ru.max(rv));
                parent[hi as usize] = lo;
            }
        }
        for i in 0..n {
            parent[i] = find(&mut parent, i as u32);
        }
        parent
    }

    /// Two labelings are equivalent iff they induce the same partition.
    fn partition_equiv(a: &[u32], b: &[u32]) -> bool {
        a.len() == b.len()
            && (0..a.len()).all(|i| {
                ((i + 1)..a.len()).all(|j| (a[i] == a[j]) == (b[i] == b[j]))
            })
    }

    #[test]
    fn empty_graph() {
        assert_eq!(connected_components(&[], 0), Vec::<u32>::new());
    }

    #[test]
    fn isolated_nodes() {
        assert_eq!(connected_components(&[], 5), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn line_graph_is_one_component_labeled_zero() {
        let edges = [(0, 1), (1, 2), (2, 3), (3, 4)];
        let r = connected_components(&edges, 5);
        assert!(partition_equiv(&r, &oracle(&edges, 5)));
        assert!(r.iter().all(|&v| v == 0));
    }

    #[test]
    fn star_graph_labels_center_min() {
        let edges = [(0, 1), (0, 2), (0, 3), (0, 4)];
        let r = connected_components(&edges, 5);
        assert!(r.iter().all(|&v| v == 0));
        assert!(partition_equiv(&r, &oracle(&edges, 5)));
    }

    #[test]
    fn duplicate_and_reversed_edges() {
        let edges = [(0, 1), (1, 0), (0, 1), (2, 3), (3, 2)];
        let r = connected_components(&edges, 4);
        assert!(partition_equiv(&r, &oracle(&edges, 4)));
    }

    #[test]
    fn self_loops_ignored() {
        let edges = [(0, 0), (1, 1), (2, 3)];
        let r = connected_components(&edges, 4);
        assert!(partition_equiv(&r, &oracle(&edges, 4)));
        assert_eq!(r, vec![0, 1, 2, 2]);
    }

    #[test]
    fn two_components() {
        let edges = [(0, 1), (1, 2), (3, 4)];
        let r = connected_components(&edges, 5);
        assert_eq!(r[0], r[1]);
        assert_eq!(r[1], r[2]);
        assert_eq!(r[3], r[4]);
        assert_ne!(r[0], r[3]);
        assert!(partition_equiv(&r, &oracle(&edges, 5)));
    }

    #[test]
    fn out_of_range_endpoints_ignored() {
        let edges = [(0, 1), (1, 99)];
        let r = connected_components(&edges, 3);
        assert_eq!(r, vec![0, 0, 2]);
    }

    #[test]
    fn random_graph_matches_oracle_and_is_deterministic() {
        let mut edges = Vec::new();
        let mut rng: u64 = 0xDEAD_BEEF;
        let mut next = || {
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((rng >> 32) % 200) as u32
        };
        for _ in 0..300 {
            edges.push((next(), next()));
        }
        let r1 = connected_components(&edges, 200);
        let r2 = connected_components(&edges, 200);
        assert_eq!(r1, r2);
        assert!(partition_equiv(&r1, &oracle(&edges, 200)));
    }
}
