//! Sort, scan, and grid-bin candidate primitives (CPU).
//!
//! These were session/kernel routines — a bitonic sort and a Hilbert–Steele
//! scan — shaped that way only so one code path could target the GPU through a
//! transpiling macro. On the CPU the honest implementations are a stable sort
//! and a running sum; the data-parallel bitonic / Hilbert–Steele forms are a
//! GPU-determinism concern and live with the phase-2 GLSL kernels.

/// Sort `(key, value)` pairs by ascending key, stably (equal keys keep input
/// order). Returns the reordered keys and values.
#[must_use]
pub fn sort_by_key(keys: &[u32], vals: &[u32]) -> (Vec<u32>, Vec<u32>) {
    assert_eq!(keys.len(), vals.len(), "keys and vals must be equal length");
    let mut order: Vec<u32> = (0..u32::try_from(keys.len()).unwrap_or(u32::MAX)).collect();
    order.sort_by_key(|&i| keys[i as usize]);
    let sk = order.iter().map(|&i| keys[i as usize]).collect();
    let sv = order.iter().map(|&i| vals[i as usize]).collect();
    (sk, sv)
}

/// Exclusive prefix sum: `out[i] = vals[0] + .. + vals[i-1]` (`out[0] == 0`),
/// saturating on overflow.
#[must_use]
pub fn prefix_sum_exclusive(vals: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(vals.len());
    let mut acc = 0u32;
    for &v in vals {
        out.push(acc);
        acc = acc.saturating_add(v);
    }
    out
}

/// Closed bbox overlap test (touching counts).
#[must_use]
#[inline]
#[allow(clippy::too_many_arguments)]
fn bbox_overlap(
    ax0: i32,
    ay0: i32,
    ax1: i32,
    ay1: i32,
    bx0: i32,
    by0: i32,
    bx1: i32,
    by1: i32,
) -> bool {
    ax0 <= bx1 && bx0 <= ax1 && ay0 <= by1 && by0 <= ay1
}

/// Grid-bin bbox-overlap candidate generation. Bins each bbox by its centroid,
/// then tests overlap within same/neighbor cells. Returns sorted, deduplicated
/// `(lo, hi)` index pairs whose bboxes overlap (closed test) — a superset of the
/// exact-overlap set, suitable as a prefilter before exact geometry tests.
///
/// The four arrays are parallel; `n == xmin.len()`.
#[must_use]
pub fn grid_bin_candidates(
    xmin: &[i32],
    ymin: &[i32],
    xmax: &[i32],
    ymax: &[i32],
) -> Vec<(u32, u32)> {
    let n = xmin.len();
    if n <= 1 {
        return Vec::new();
    }

    // Global extents.
    let (mut gxmin, mut gymin) = (i32::MAX, i32::MAX);
    let (mut gxmax, mut gymax) = (i32::MIN, i32::MIN);
    for i in 0..n {
        gxmin = gxmin.min(xmin[i]);
        gymin = gymin.min(ymin[i]);
        gxmax = gxmax.max(xmax[i]);
        gymax = gymax.max(ymax[i]);
    }

    // ponytail: uniform grid, ~sqrt(n) cells per axis. Adaptive index (k-d/R-tree)
    // only if density skew makes the uniform grid degenerate.
    let grid_side = (n as f64).sqrt().ceil().max(1.0) as i64;
    let span_x = (i64::from(gxmax) - i64::from(gxmin)).max(1);
    let span_y = (i64::from(gymax) - i64::from(gymin)).max(1);
    let cell_w = ((span_x + grid_side - 1) / grid_side).max(1);
    let cell_h = ((span_y + grid_side - 1) / grid_side).max(1);
    let grid_w = ((span_x + cell_w - 1) / cell_w) as u32;
    let grid_h = ((span_y + cell_h - 1) / cell_h) as u32;

    // Bin each bbox centroid.
    let indices: Vec<u32> = (0..n as u32).collect();
    let mut bin_ids: Vec<u32> = Vec::with_capacity(n);
    for i in 0..n {
        let cx = ((i64::from(xmin[i]) + i64::from(xmax[i])) / 2 - i64::from(gxmin)) / cell_w;
        let cy = ((i64::from(ymin[i]) + i64::from(ymax[i])) / 2 - i64::from(gymin)) / cell_h;
        let bx = (cx as u32).min(grid_w - 1);
        let by = (cy as u32).min(grid_h - 1);
        bin_ids.push(bx * grid_h + by);
    }

    let (sorted_bin, sorted_idx) = sort_by_key(&bin_ids, &indices);

    // Bin ranges via occupancy prefix sum.
    let max_bin = (grid_w as usize) * (grid_h as usize);
    let mut bin_start: Vec<usize> = vec![0; max_bin + 1];
    for &b in &sorted_bin {
        bin_start[b as usize + 1] += 1;
    }
    for i in 1..=max_bin {
        bin_start[i] += bin_start[i - 1];
    }

    let neighbor_offsets: [(i32, i32); 9] = [
        (-1, -1),
        (-1, 0),
        (-1, 1),
        (0, -1),
        (0, 0),
        (0, 1),
        (1, -1),
        (1, 0),
        (1, 1),
    ];

    let mut candidates = Vec::new();
    let push_if_overlap = |ia: u32, ib: u32, candidates: &mut Vec<(u32, u32)>| {
        let (lo, hi) = if ia < ib { (ia, ib) } else { (ib, ia) };
        if bbox_overlap(
            xmin[lo as usize],
            ymin[lo as usize],
            xmax[lo as usize],
            ymax[lo as usize],
            xmin[hi as usize],
            ymin[hi as usize],
            xmax[hi as usize],
            ymax[hi as usize],
        ) {
            candidates.push((lo, hi));
        }
    };

    for bx in 0..grid_w as i32 {
        for by in 0..grid_h as i32 {
            let bin = (bx as u32) * grid_h + (by as u32);
            let (s0, e0) = (bin_start[bin as usize], bin_start[bin as usize + 1]);
            for &(dx, dy) in &neighbor_offsets {
                let (nx, ny) = (bx + dx, by + dy);
                if nx < 0 || ny < 0 || nx >= grid_w as i32 || ny >= grid_h as i32 {
                    continue;
                }
                let nbin = (nx as u32) * grid_h + (ny as u32);
                // Each unordered bin pair visited once (nbin >= bin).
                if nbin < bin {
                    continue;
                }
                let (s1, e1) = (bin_start[nbin as usize], bin_start[nbin as usize + 1]);
                if nbin == bin {
                    for a in s0..e0 {
                        for b in (a + 1)..e0 {
                            push_if_overlap(sorted_idx[a], sorted_idx[b], &mut candidates);
                        }
                    }
                } else {
                    for a in s0..e0 {
                        for b in s1..e1 {
                            push_if_overlap(sorted_idx[a], sorted_idx[b], &mut candidates);
                        }
                    }
                }
            }
        }
    }

    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn brute_force_bbox_candidates(
        xmin: &[i32],
        ymin: &[i32],
        xmax: &[i32],
        ymax: &[i32],
    ) -> Vec<(u32, u32)> {
        let n = xmin.len();
        let mut out = Vec::new();
        for i in 0..n {
            for j in (i + 1)..n {
                if bbox_overlap(
                    xmin[i], ymin[i], xmax[i], ymax[i], xmin[j], ymin[j], xmax[j], ymax[j],
                ) {
                    out.push((i as u32, j as u32));
                }
            }
        }
        out
    }

    #[test]
    fn sort_by_key_orders_and_tracks_values() {
        let keys = [5u32, 3, 8, 1, 9, 2, 7, 4];
        let vals: Vec<u32> = (0..8).collect();
        let (sk, sv) = sort_by_key(&keys, &vals);
        assert_eq!(sk, vec![1, 2, 3, 4, 5, 7, 8, 9]);
        for (i, &key) in sk.iter().enumerate() {
            assert_eq!(keys[sv[i] as usize], key);
        }
    }

    #[test]
    fn sort_by_key_already_sorted_and_reverse() {
        let vals: Vec<u32> = (0..8).collect();
        let (_, sv) = sort_by_key(&[1, 2, 3, 4, 5, 6, 7, 8], &vals);
        assert_eq!(sv, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        let (sk, sv) = sort_by_key(&[8, 7, 6, 5, 4, 3, 2, 1], &vals);
        assert_eq!(sk, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(sv, vec![7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn sort_by_key_stable_on_duplicates() {
        let keys = [3u32, 1, 3, 1, 2];
        let vals: Vec<u32> = (0..5).collect();
        let (sk, sv) = sort_by_key(&keys, &vals);
        assert_eq!(sk, vec![1, 1, 2, 3, 3]);
        assert_eq!(sv, vec![1, 3, 4, 0, 2]); // stable: equal keys keep order
    }

    #[test]
    fn sort_by_key_edge_sizes() {
        assert_eq!(sort_by_key(&[], &[]), (vec![], vec![]));
        assert_eq!(sort_by_key(&[42], &[0]), (vec![42], vec![0]));
    }

    #[test]
    fn prefix_sum_cases() {
        assert_eq!(prefix_sum_exclusive(&[1, 2, 3, 4, 5]), vec![0, 1, 3, 6, 10]);
        assert_eq!(prefix_sum_exclusive(&[42]), vec![0]);
        assert!(prefix_sum_exclusive(&[]).is_empty());
        assert_eq!(prefix_sum_exclusive(&[0, 0, 0, 0]), vec![0, 0, 0, 0]);
        assert_eq!(
            prefix_sum_exclusive(&[1, 1, 1, 1, 1, 1, 1, 1]),
            vec![0, 1, 2, 3, 4, 5, 6, 7]
        );
    }

    #[test]
    fn grid_bin_superset_of_brute_force() {
        let xmin = [0i32, 10, 20, 5, 50, 0];
        let ymin = [0i32, 0, 0, 5, 50, 90];
        let xmax = [15i32, 25, 30, 20, 60, 10];
        let ymax = [15i32, 10, 10, 20, 60, 100];
        let cands = grid_bin_candidates(&xmin, &ymin, &xmax, &ymax);
        for pair in &brute_force_bbox_candidates(&xmin, &ymin, &xmax, &ymax) {
            assert!(cands.contains(pair), "grid-bin missed {pair:?}");
        }
    }

    #[test]
    fn grid_bin_no_false_negatives_random() {
        use std::collections::HashSet;
        let mut seed: u32 = 12345;
        let mut rng = || -> i32 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            ((seed >> 16) % 200) as i32
        };
        let n = 30;
        let (mut xmin, mut ymin, mut xmax, mut ymax) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for _ in 0..n {
            let x0 = rng();
            let y0 = rng();
            let w = (rng() % 30).max(1);
            let h = (rng() % 30).max(1);
            xmin.push(x0);
            ymin.push(y0);
            xmax.push(x0 + w);
            ymax.push(y0 + h);
        }
        let cands: HashSet<(u32, u32)> =
            grid_bin_candidates(&xmin, &ymin, &xmax, &ymax).into_iter().collect();
        for pair in &brute_force_bbox_candidates(&xmin, &ymin, &xmax, &ymax) {
            assert!(cands.contains(pair), "grid-bin missed {pair:?}");
        }
    }

    #[test]
    fn grid_bin_empty_and_single() {
        assert!(grid_bin_candidates(&[], &[], &[], &[]).is_empty());
        assert!(grid_bin_candidates(&[0], &[0], &[10], &[10]).is_empty());
    }

    #[test]
    fn grid_bin_touching_boxes() {
        let cands = grid_bin_candidates(&[0, 10], &[0, 0], &[10, 20], &[10, 10]);
        assert_eq!(cands, vec![(0, 1)]);
    }
}
