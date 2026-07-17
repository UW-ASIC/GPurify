//! Session-kernel primitives: bitonic sort, prefix scan, and grid-bin candidate
//! generation.
//!
//! ponytail: host-side compute per round; the Session model lacks a gather
//! kernel shape, so each bitonic round and scan round reads back, computes,
//! and re-uploads. Upgrade: add a `gather_swap` kernel shape so the GPU
//! can execute all rounds without readback.

use crate::session::{Col, Session};

fn next_power_of_2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    1 << (usize::BITS - (n - 1).leading_zeros())
}

/// Bitonic sort (ascending) by key, carrying associated values.
/// Pads to the next power of 2 with `u32::MAX` sentinel keys (and 0 vals),
/// then strips the padding from the result.
pub fn bitonic_sort_by_key(
    session: &Session,
    keys: &Col<u32>,
    vals: &Col<u32>,
) -> (Col<u32>, Col<u32>) {
    let n = keys.len();
    if n <= 1 {
        return (
            session.upload(&session.read(keys)),
            session.upload(&session.read(vals)),
        );
    }

    let m = next_power_of_2(n);

    // Pad to power-of-2
    let mut k_data = session.read(keys);
    let mut v_data = session.read(vals);
    k_data.resize(m, u32::MAX);
    v_data.resize(m, 0);

    let mut cur_keys = session.upload(&k_data);
    let mut cur_vals = session.upload(&v_data);

    // Bitonic sort: ceil(log2(m)) phases
    let log_m = m.trailing_zeros(); // m is a power of 2
    for step in 0..log_m {
        for substep in (0..=step).rev() {
            let half = 1u32 << substep;
            let k = session.read(&cur_keys);
            let v = session.read(&cur_vals);
            session.release(cur_keys);
            session.release(cur_vals);

            let mut new_k = Vec::with_capacity(m);
            let mut new_v = Vec::with_capacity(m);
            for i in 0..m {
                let pi = (i as u32 ^ half) as usize;
                let ascending = ((i as u32) >> (step + 1)) & 1 == 0;
                let keep_min = if (i as u32) < (pi as u32) {
                    ascending
                } else {
                    !ascending
                };
                if keep_min {
                    if k[i] <= k[pi] {
                        new_k.push(k[i]);
                        new_v.push(v[i]);
                    } else {
                        new_k.push(k[pi]);
                        new_v.push(v[pi]);
                    }
                } else {
                    #[allow(clippy::collapsible_else_if)]
                    if k[i] >= k[pi] {
                        new_k.push(k[i]);
                        new_v.push(v[i]);
                    } else {
                        new_k.push(k[pi]);
                        new_v.push(v[pi]);
                    }
                }
            }

            cur_keys = session.upload(&new_k);
            cur_vals = session.upload(&new_v);
        }
    }

    // Strip padding
    let final_k = session.read(&cur_keys);
    let final_v = session.read(&cur_vals);
    session.release(cur_keys);
    session.release(cur_vals);

    (session.upload(&final_k[..n]), session.upload(&final_v[..n]))
}

// ---------------------------------------------------------------------------
// Exclusive prefix sum (Hilbert–Steele)
// ---------------------------------------------------------------------------

/// Exclusive prefix sum via Hilbert–Steele double-buffered scan.
/// Returns a column where `out[i] = sum(vals[0..i])`.
pub fn prefix_sum_exclusive(session: &Session, vals: &Col<u32>) -> Col<u32> {
    let n = vals.len();
    if n == 0 {
        return session.upload(&[]);
    }

    // ponytail: host-side scan. O(n log n) work, O(n) space.
    // Upgrade: proper GPU scan kernel shape when n is large enough to matter.
    let data = session.read(vals);

    // Inclusive Hilbert–Steele scan
    let mut cur = data;
    let mut offset = 1usize;
    while offset < n {
        let mut next = cur.clone();
        for i in offset..n {
            next[i] = cur[i].saturating_add(cur[i - offset]);
        }
        cur = next;
        offset *= 2;
    }

    // Shift right by 1 for exclusive scan
    let mut result = vec![0u32; n];
    for i in 1..n {
        result[i] = cur[i - 1];
    }

    session.upload(&result)
}

// ---------------------------------------------------------------------------
// Grid-bin candidate generation
// ---------------------------------------------------------------------------

/// GPU-ready grid-bin candidate generation. Assigns each bounding box to grid
/// cells, sorts by cell, then checks bbox overlap within same/neighbor cells.
///
/// Returns candidate pairs `(i, j)` where `i < j` and the bboxes of polygon
/// `i` and `j` overlap (closed test — touching counts). This is a superset of
/// the exact overlap set, suitable as a filter before exact geometry tests.
pub fn grid_bin_candidates(
    session: &Session,
    bbox_xmin: &Col<i32>,
    bbox_ymin: &Col<i32>,
    bbox_xmax: &Col<i32>,
    bbox_ymax: &Col<i32>,
    n: usize,
) -> Vec<(u32, u32)> {
    if n <= 1 {
        return Vec::new();
    }

    // Read all bbox data
    let xmin = session.read(bbox_xmin);
    let ymin = session.read(bbox_ymin);
    let xmax = session.read(bbox_xmax);
    let ymax = session.read(bbox_ymax);

    // Compute global extents
    let (mut gxmin, mut gymin) = (i32::MAX, i32::MAX);
    let (mut gxmax, mut gymax) = (i32::MIN, i32::MIN);
    for i in 0..n {
        gxmin = gxmin.min(xmin[i]);
        gymin = gymin.min(ymin[i]);
        gxmax = gxmax.max(xmax[i]);
        gymax = gymax.max(ymax[i]);
    }

    // Grid cell size: target ~sqrt(n) cells on each axis for O(n) expected pairs
    // ponytail: simple uniform grid. Adaptive grid (k-d tree, R-tree) when
    // density skew makes uniform degenerate.
    let grid_side = (n as f64).sqrt().ceil().max(1.0) as i64;
    let span_x = (gxmax as i64 - gxmin as i64).max(1);
    let span_y = (gymax as i64 - gymin as i64).max(1);
    let cell_w = ((span_x + grid_side - 1) / grid_side).max(1);
    let cell_h = ((span_y + grid_side - 1) / grid_side).max(1);
    let grid_w = ((span_x + cell_w - 1) / cell_w) as u32;
    let grid_h = ((span_y + cell_h - 1) / cell_h) as u32;

    // Assign each polygon's centroid to a bin
    let mut bin_ids: Vec<u32> = Vec::with_capacity(n);
    let indices: Vec<u32> = (0..n as u32).collect();
    for i in 0..n {
        let cx = ((xmin[i] as i64 + xmax[i] as i64) / 2 - gxmin as i64) / cell_w;
        let cy = ((ymin[i] as i64 + ymax[i] as i64) / 2 - gymin as i64) / cell_h;
        let bx = (cx as u32).min(grid_w - 1);
        let by = (cy as u32).min(grid_h - 1);
        bin_ids.push(bx * grid_h + by);
    }

    // Sort by bin_id using bitonic sort (through session)
    let keys_col = session.upload(&bin_ids);
    let vals_col = session.upload(&indices);
    let (sorted_keys, sorted_vals) = bitonic_sort_by_key(session, &keys_col, &vals_col);
    let sorted_bin = session.read(&sorted_keys);
    let sorted_idx = session.read(&sorted_vals);
    session.release(keys_col);
    session.release(vals_col);
    session.release(sorted_keys);
    session.release(sorted_vals);

    // Build bin ranges: for each bin_id, find [start, end) in sorted array
    // ponytail: linear scan over sorted array. Binary search if bin count >> n.
    let max_bin = (grid_w as usize) * (grid_h as usize);
    let mut bin_start: Vec<usize> = vec![0; max_bin + 1];
    // Count occupancy
    for &b in &sorted_bin {
        bin_start[b as usize + 1] += 1;
    }
    // Prefix sum for starts
    for i in 1..=max_bin {
        bin_start[i] += bin_start[i - 1];
    }

    // For each polygon, check against all polygons in same and neighboring bins
    let mut candidates = Vec::new();
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

    // Iterate by bin to avoid duplicate pair enumeration
    for bx in 0..grid_w as i32 {
        for by in 0..grid_h as i32 {
            let bin = (bx as u32) * grid_h + (by as u32);
            let s0 = bin_start[bin as usize];
            let e0 = bin_start[bin as usize + 1];

            for &(dx, dy) in &neighbor_offsets {
                let nx = bx + dx;
                let ny = by + dy;
                if nx < 0 || ny < 0 || nx >= grid_w as i32 || ny >= grid_h as i32 {
                    continue;
                }
                let nbin = (nx as u32) * grid_h + (ny as u32);

                // Only look at neighbor bins with id >= current to avoid
                // generating each pair twice across bin boundaries.
                // For same-bin (nbin == bin), enumerate upper triangle.
                if nbin < bin {
                    continue;
                }

                let s1 = bin_start[nbin as usize];
                let e1 = bin_start[nbin as usize + 1];

                if nbin == bin {
                    // Same bin: upper triangle
                    for a in s0..e0 {
                        for b in (a + 1)..e0 {
                            let ia = sorted_idx[a];
                            let ib = sorted_idx[b];
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
                        }
                    }
                } else {
                    // Cross-bin: all pairs
                    for a in s0..e0 {
                        for b in s1..e1 {
                            let ia = sorted_idx[a];
                            let ib = sorted_idx[b];
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
                        }
                    }
                }
            }
        }
    }

    // Deduplicate (cross-bin enumeration can produce duplicates when a polygon
    // spans multiple neighbor relationships)
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

/// Closed bbox overlap test (touching counts).
#[inline]
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

// ---------------------------------------------------------------------------
// Brute-force reference for testing
// ---------------------------------------------------------------------------

/// O(n^2) brute-force bbox overlap enumeration. Returns sorted (lo, hi) pairs.
#[cfg(test)]
fn brute_force_bbox_candidates(
    xmin: &[i32],
    ymin: &[i32],
    xmax: &[i32],
    ymax: &[i32],
    n: usize,
) -> Vec<(u32, u32)> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- bitonic sort ---

    #[test]
    fn bitonic_sort_random() {
        let s = Session::cpu();
        let keys = [5u32, 3, 8, 1, 9, 2, 7, 4];
        let vals: Vec<u32> = (0..8).collect();
        let k = s.upload(&keys);
        let v = s.upload(&vals);
        let (sk, sv) = bitonic_sort_by_key(&s, &k, &v);
        let rk = s.read(&sk);
        let rv = s.read(&sv);
        assert_eq!(rk, vec![1, 2, 3, 4, 5, 7, 8, 9]);
        // Each value should track its original key
        for (i, &key) in rk.iter().enumerate() {
            assert_eq!(
                keys[rv[i] as usize], key,
                "value doesn't track key at pos {i}"
            );
        }
    }

    #[test]
    fn bitonic_sort_already_sorted() {
        let s = Session::cpu();
        let keys = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let vals: Vec<u32> = (0..8).collect();
        let k = s.upload(&keys);
        let v = s.upload(&vals);
        let (sk, sv) = bitonic_sort_by_key(&s, &k, &v);
        assert_eq!(s.read(&sk), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(s.read(&sv), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn bitonic_sort_reverse() {
        let s = Session::cpu();
        let keys = [8u32, 7, 6, 5, 4, 3, 2, 1];
        let vals: Vec<u32> = (0..8).collect();
        let k = s.upload(&keys);
        let v = s.upload(&vals);
        let (sk, sv) = bitonic_sort_by_key(&s, &k, &v);
        assert_eq!(s.read(&sk), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(s.read(&sv), vec![7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn bitonic_sort_non_power_of_2() {
        let s = Session::cpu();
        let keys = [10u32, 3, 7, 1, 5]; // 5 elements
        let vals: Vec<u32> = (0..5).collect();
        let k = s.upload(&keys);
        let v = s.upload(&vals);
        let (sk, sv) = bitonic_sort_by_key(&s, &k, &v);
        let rk = s.read(&sk);
        let rv = s.read(&sv);
        assert_eq!(rk, vec![1, 3, 5, 7, 10]);
        assert_eq!(rk.len(), 5);
        assert_eq!(rv.len(), 5);
        for (i, &key) in rk.iter().enumerate() {
            assert_eq!(keys[rv[i] as usize], key);
        }
    }

    #[test]
    fn bitonic_sort_single_element() {
        let s = Session::cpu();
        let k = s.upload(&[42u32]);
        let v = s.upload(&[0u32]);
        let (sk, sv) = bitonic_sort_by_key(&s, &k, &v);
        assert_eq!(s.read(&sk), vec![42]);
        assert_eq!(s.read(&sv), vec![0]);
    }

    #[test]
    fn bitonic_sort_empty() {
        let s = Session::cpu();
        let k = s.upload::<u32>(&[]);
        let v = s.upload::<u32>(&[]);
        let (sk, sv) = bitonic_sort_by_key(&s, &k, &v);
        assert!(s.read(&sk).is_empty());
        assert!(s.read(&sv).is_empty());
    }

    #[test]
    fn bitonic_sort_duplicates() {
        let s = Session::cpu();
        let keys = [3u32, 1, 3, 1, 2];
        let vals: Vec<u32> = (0..5).collect();
        let k = s.upload(&keys);
        let v = s.upload(&vals);
        let (sk, _sv) = bitonic_sort_by_key(&s, &k, &v);
        assert_eq!(s.read(&sk), vec![1, 1, 2, 3, 3]);
    }

    // --- prefix sum ---

    #[test]
    fn prefix_sum_basic() {
        let s = Session::cpu();
        let vals = s.upload(&[1u32, 2, 3, 4, 5]);
        let out = prefix_sum_exclusive(&s, &vals);
        assert_eq!(s.read(&out), vec![0, 1, 3, 6, 10]);
    }

    #[test]
    fn prefix_sum_single() {
        let s = Session::cpu();
        let vals = s.upload(&[42u32]);
        let out = prefix_sum_exclusive(&s, &vals);
        assert_eq!(s.read(&out), vec![0]);
    }

    #[test]
    fn prefix_sum_empty() {
        let s = Session::cpu();
        let vals = s.upload::<u32>(&[]);
        let out = prefix_sum_exclusive(&s, &vals);
        assert!(s.read(&out).is_empty());
    }

    #[test]
    fn prefix_sum_zeros() {
        let s = Session::cpu();
        let vals = s.upload(&[0u32, 0, 0, 0]);
        let out = prefix_sum_exclusive(&s, &vals);
        assert_eq!(s.read(&out), vec![0, 0, 0, 0]);
    }

    #[test]
    fn prefix_sum_power_of_2_len() {
        let s = Session::cpu();
        let vals = s.upload(&[1u32, 1, 1, 1, 1, 1, 1, 1]);
        let out = prefix_sum_exclusive(&s, &vals);
        assert_eq!(s.read(&out), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    // --- grid-bin candidates ---

    #[test]
    fn grid_bin_superset_of_brute_force() {
        let s = Session::cpu();
        // Small test: 6 rectangles, some overlapping
        let xmin_d = vec![0i32, 10, 20, 5, 50, 0];
        let ymin_d = vec![0i32, 0, 0, 5, 50, 90];
        let xmax_d = vec![15i32, 25, 30, 20, 60, 10];
        let ymax_d = vec![15i32, 10, 10, 20, 60, 100];

        let n = xmin_d.len();
        let bx0 = s.upload(&xmin_d);
        let by0 = s.upload(&ymin_d);
        let bx1 = s.upload(&xmax_d);
        let by1 = s.upload(&ymax_d);

        let cands = grid_bin_candidates(&s, &bx0, &by0, &bx1, &by1, n);
        let brute = brute_force_bbox_candidates(&xmin_d, &ymin_d, &xmax_d, &ymax_d, n);

        // Grid-bin must be a superset
        for pair in &brute {
            assert!(
                cands.contains(pair),
                "grid-bin missed brute-force pair {:?}",
                pair
            );
        }
    }

    #[test]
    fn grid_bin_no_false_negatives_random() {
        use std::collections::HashSet;
        let s = Session::cpu();

        // Deterministic "random" data via simple LCG
        let mut seed: u32 = 12345;
        let mut rng = || -> i32 {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            ((seed >> 16) % 200) as i32
        };

        let n = 30;
        let mut xmin_d = Vec::with_capacity(n);
        let mut ymin_d = Vec::with_capacity(n);
        let mut xmax_d = Vec::with_capacity(n);
        let mut ymax_d = Vec::with_capacity(n);
        for _ in 0..n {
            let x0 = rng();
            let y0 = rng();
            let w = (rng() % 30).max(1);
            let h = (rng() % 30).max(1);
            xmin_d.push(x0);
            ymin_d.push(y0);
            xmax_d.push(x0 + w);
            ymax_d.push(y0 + h);
        }

        let bx0 = s.upload(&xmin_d);
        let by0 = s.upload(&ymin_d);
        let bx1 = s.upload(&xmax_d);
        let by1 = s.upload(&ymax_d);

        let cands: HashSet<(u32, u32)> = grid_bin_candidates(&s, &bx0, &by0, &bx1, &by1, n)
            .into_iter()
            .collect();
        let brute: HashSet<(u32, u32)> =
            brute_force_bbox_candidates(&xmin_d, &ymin_d, &xmax_d, &ymax_d, n)
                .into_iter()
                .collect();

        for pair in &brute {
            assert!(
                cands.contains(pair),
                "grid-bin missed brute-force pair {:?}; brute has {}, grid has {}",
                pair,
                brute.len(),
                cands.len(),
            );
        }
    }

    #[test]
    fn grid_bin_empty_and_single() {
        let s = Session::cpu();
        assert!(grid_bin_candidates(
            &s,
            &s.upload::<i32>(&[]),
            &s.upload::<i32>(&[]),
            &s.upload::<i32>(&[]),
            &s.upload::<i32>(&[]),
            0,
        )
        .is_empty());

        assert!(grid_bin_candidates(
            &s,
            &s.upload(&[0i32]),
            &s.upload(&[0i32]),
            &s.upload(&[10i32]),
            &s.upload(&[10i32]),
            1,
        )
        .is_empty());
    }

    #[test]
    fn grid_bin_touching_boxes() {
        let s = Session::cpu();
        // Two boxes that share an edge
        let xmin_d = vec![0i32, 10];
        let ymin_d = vec![0i32, 0];
        let xmax_d = vec![10i32, 20];
        let ymax_d = vec![10i32, 10];

        let bx0 = s.upload(&xmin_d);
        let by0 = s.upload(&ymin_d);
        let bx1 = s.upload(&xmax_d);
        let by1 = s.upload(&ymax_d);

        let cands = grid_bin_candidates(&s, &bx0, &by0, &bx1, &by1, 2);
        // Touching boxes should be found (closed test)
        assert_eq!(cands, vec![(0, 1)]);
    }
}
