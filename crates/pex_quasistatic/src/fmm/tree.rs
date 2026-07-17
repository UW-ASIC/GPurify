//! A uniform octree over a point set, with neighbor and well-separated
//! interaction lists — the spatial structure the black-box FMM walks.
//!
//! "Uniform" (all leaves at the same level) keeps the interaction lists simple
//! and correct; empty cells are simply not stored, so surface point sets (most
//! cells empty) cost only what they use.

use crate::geometry::Vec3;
use std::collections::HashMap;

/// One octree box.
#[derive(Debug, Clone)]
pub struct Node {
    pub level: usize,
    pub cell: [u32; 3],
    pub center: [f64; 3],
    /// Half-width of the (cubic) box.
    pub half: f64,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Point indices (leaves only).
    pub points: Vec<usize>,
    /// Same-level adjacent boxes (|Δcell| ≤ 1). Includes leaf P2P neighbors.
    pub neighbors: Vec<usize>,
    /// Same-level well-separated boxes in the parent's neighborhood (M2L list).
    pub interaction: Vec<usize>,
}

/// The built tree.
pub struct Octree {
    pub nodes: Vec<Node>,
    pub max_level: usize,
    /// Node ids by level.
    pub levels: Vec<Vec<usize>>,
    /// Root node id.
    pub root: usize,
}

impl Octree {
    /// Build a uniform octree of depth `max_level` over `points`.
    pub fn build(points: &[Vec3], max_level: usize) -> Octree {
        assert!(max_level >= 1);
        // Cubic bounding box with a little padding.
        let mut lo = [f64::INFINITY; 3];
        let mut hi = [f64::NEG_INFINITY; 3];
        for p in points {
            let a = [p.x, p.y, p.z];
            for d in 0..3 {
                lo[d] = lo[d].min(a[d]);
                hi[d] = hi[d].max(a[d]);
            }
        }
        let mut half = 0.0f64;
        let mut center = [0.0; 3];
        for d in 0..3 {
            center[d] = 0.5 * (lo[d] + hi[d]);
            half = half.max(0.5 * (hi[d] - lo[d]));
        }
        half *= 1.0 + 1e-6;
        if half == 0.0 {
            half = 1.0;
        }

        let mut nodes: Vec<Node> = Vec::new();
        let mut maps: Vec<HashMap<[u32; 3], usize>> = vec![HashMap::new(); max_level + 1];

        // Root.
        nodes.push(Node {
            level: 0,
            cell: [0, 0, 0],
            center,
            half,
            parent: None,
            children: Vec::new(),
            points: Vec::new(),
            neighbors: Vec::new(),
            interaction: Vec::new(),
        });
        maps[0].insert([0, 0, 0], 0);

        let ncell = 1u32 << max_level;
        let leaf_size = 2.0 * half / ncell as f64;
        let origin = [center[0] - half, center[1] - half, center[2] - half];

        // Assign each point to a leaf cell, creating boxes lazily up the tree.
        for (pi, p) in points.iter().enumerate() {
            let a = [p.x, p.y, p.z];
            let mut cell = [0u32; 3];
            for d in 0..3 {
                let idx = ((a[d] - origin[d]) / leaf_size).floor() as i64;
                cell[d] = idx.clamp(0, ncell as i64 - 1) as u32;
            }
            let leaf = Self::ensure_box(&mut nodes, &mut maps, max_level, cell, center, half);
            nodes[leaf].points.push(pi);
        }

        // Group node ids by level.
        let mut levels: Vec<Vec<usize>> = vec![Vec::new(); max_level + 1];
        for (id, n) in nodes.iter().enumerate() {
            levels[n.level].push(id);
        }

        let mut tree = Octree { nodes, max_level, levels, root: 0 };
        tree.build_lists();
        tree
    }

    /// Ensure the box at (level, cell) exists (creating ancestors); return its id.
    fn ensure_box(
        nodes: &mut Vec<Node>,
        maps: &mut [HashMap<[u32; 3], usize>],
        level: usize,
        cell: [u32; 3],
        root_center: [f64; 3],
        root_half: f64,
    ) -> usize {
        if let Some(&id) = maps[level].get(&cell) {
            return id;
        }
        // Ensure parent exists.
        let parent_id = if level == 0 {
            None
        } else {
            let pcell = [cell[0] / 2, cell[1] / 2, cell[2] / 2];
            Some(Self::ensure_box(nodes, maps, level - 1, pcell, root_center, root_half))
        };
        let half = root_half / (1u32 << level) as f64;
        let origin = [root_center[0] - root_half, root_center[1] - root_half, root_center[2] - root_half];
        let center = [
            origin[0] + (cell[0] as f64 + 0.5) * 2.0 * half,
            origin[1] + (cell[1] as f64 + 0.5) * 2.0 * half,
            origin[2] + (cell[2] as f64 + 0.5) * 2.0 * half,
        ];
        let id = nodes.len();
        nodes.push(Node {
            level,
            cell,
            center,
            half,
            parent: parent_id,
            children: Vec::new(),
            points: Vec::new(),
            neighbors: Vec::new(),
            interaction: Vec::new(),
        });
        maps[level].insert(cell, id);
        if let Some(pid) = parent_id {
            nodes[pid].children.push(id);
        }
        id
    }

    /// Compute neighbor and interaction lists for every node.
    fn build_lists(&mut self) {
        // Per-level cell -> id maps.
        let mut maps: Vec<HashMap<[u32; 3], usize>> = vec![HashMap::new(); self.max_level + 1];
        for (id, n) in self.nodes.iter().enumerate() {
            maps[n.level].insert(n.cell, id);
        }
        let ncell_at = |lev: usize| 1u32 << lev;

        for id in 0..self.nodes.len() {
            let level = self.nodes[id].level;
            let cell = self.nodes[id].cell;
            let nc = ncell_at(level) as i64;
            // Neighbors: ±1 in each dim (existing boxes).
            let mut neighbors = Vec::new();
            for dx in -1..=1i64 {
                for dy in -1..=1i64 {
                    for dz in -1..=1i64 {
                        if dx == 0 && dy == 0 && dz == 0 {
                            continue;
                        }
                        let c = [cell[0] as i64 + dx, cell[1] as i64 + dy, cell[2] as i64 + dz];
                        if c.iter().any(|&v| v < 0 || v >= nc) {
                            continue;
                        }
                        let key = [c[0] as u32, c[1] as u32, c[2] as u32];
                        if let Some(&nid) = maps[level].get(&key) {
                            neighbors.push(nid);
                        }
                    }
                }
            }
            self.nodes[id].neighbors = neighbors;
        }

        // Interaction list needs neighbors computed first.
        for id in 0..self.nodes.len() {
            let level = self.nodes[id].level;
            if level < 2 {
                continue;
            }
            let parent = self.nodes[id].parent.unwrap();
            let own_neighbors: std::collections::HashSet<usize> =
                self.nodes[id].neighbors.iter().copied().collect();
            let mut interaction = Vec::new();
            // Parent's neighbors (and parent itself) → their children.
            let mut parent_family = self.nodes[parent].neighbors.clone();
            parent_family.push(parent);
            for &pn in &parent_family {
                for &child in &self.nodes[pn].children {
                    if child != id && !own_neighbors.contains(&child) {
                        interaction.push(child);
                    }
                }
            }
            self.nodes[id].interaction = interaction;
        }
    }

    /// Map a world point into the box's local [-1,1]³ coordinates.
    #[inline]
    pub fn to_local(&self, node: usize, p: Vec3) -> [f64; 3] {
        let n = &self.nodes[node];
        [
            (p.x - n.center[0]) / n.half,
            (p.y - n.center[1]) / n.half,
            (p.z - n.center[2]) / n.half,
        ]
    }

    pub fn leaves(&self) -> &[usize] {
        &self.levels[self.max_level]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grid_points(n: usize) -> Vec<Vec3> {
        let mut v = Vec::new();
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    v.push(Vec3::new(i as f64, j as f64, k as f64));
                }
            }
        }
        v
    }

    #[test]
    fn tree_covers_all_points() {
        let pts = grid_points(4);
        let tree = Octree::build(&pts, 3);
        let total: usize = tree.leaves().iter().map(|&l| tree.nodes[l].points.len()).sum();
        assert_eq!(total, pts.len());
    }

    #[test]
    fn neighbors_and_interaction_are_disjoint_and_cover() {
        let pts = grid_points(8);
        let tree = Octree::build(&pts, 3);
        for &id in &tree.levels[3] {
            let nbr: std::collections::HashSet<_> = tree.nodes[id].neighbors.iter().copied().collect();
            // Interaction list must be disjoint from neighbors and exclude self.
            for &c in &tree.nodes[id].interaction {
                assert!(!nbr.contains(&c));
                assert_ne!(c, id);
                // Interaction boxes share a parent-neighbor: their centers are
                // within ~3 box-widths but beyond 1 (well separated).
                let d = dist(tree.nodes[id].center, tree.nodes[c].center);
                let w = 2.0 * tree.nodes[id].half;
                assert!(d > 1.5 * w, "interaction box too close: {d} vs {w}");
            }
        }
    }

    fn dist(a: [f64; 3], b: [f64; 3]) -> f64 {
        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
    }
}
