//! Clustering a large result set for triage (catalog FLOW-010): the
//! violations of one rule that lie together are one cluster, so a
//! systematic error (one cell placed a thousand times, one bad strap) reads
//! as one line rather than a thousand.
//!
//! **Definition.** Single-linkage clustering (Sibson, "SLINK", *The Computer
//! Journal* 16(1), 1973) of each rule's violation markers under the
//! Euclidean distance: two markers of one rule at most `reach` apart are in
//! one cluster, and so is everything linked to them through such pairs.
//! Calibre RVE and Vision AI group results by rule and by location (Siemens
//! public material); how they weigh other signatures is not public, so
//! nothing else is used here.
//!
//! **Order.** Clusters are listed largest first, then by rule id, then by
//! their lower-left corner, so the output depends only on the violations.

use gpurify_check::report::Violations;
use gpurify_geom::{ops::Point, Dbu, StrId};
use std::collections::BTreeMap;

/// One cluster: a rule, its violations (row indices), and their markers'
/// bounding box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    /// The rule every member violates.
    pub rule: StrId,
    /// The members' rows in the violation table, ascending.
    pub rows: Vec<usize>,
    /// The lower-left corner of the members' markers' bounding box.
    pub lo: Point,
    /// The upper-right corner.
    pub hi: Point,
}

/// The single-linkage clusters of `violations` at `reach` database units
/// (`reach` 0 joins only markers at one point).
///
/// # Time complexity
///
/// *O*(n · k) for n violations with at most k markers in a `reach`-sized
/// cell's neighbourhood: markers are bucketed into square cells of side
/// `reach` and only the 3 × 3 cells around one are searched.
pub fn cluster(violations: &Violations, reach: Dbu) -> Vec<Cluster> {
    let reach = reach.raw().max(0);
    let mut by_rule: BTreeMap<StrId, Vec<usize>> = BTreeMap::new();
    for row in 0..violations.len() {
        by_rule.entry(violations.rule[row]).or_default().push(row);
    }
    let mut out = Vec::new();
    for (&rule, rows) in &by_rule {
        let at = |k: usize| violations.at[rows[k]];
        let cell = |p: Point| {
            let side = reach.max(1);
            (p.x.raw().div_euclid(side), p.y.raw().div_euclid(side))
        };
        let mut cells: BTreeMap<(i64, i64), Vec<usize>> = BTreeMap::new();
        for k in 0..rows.len() {
            cells.entry(cell(at(k))).or_default().push(k);
        }
        let mut parent: Vec<usize> = (0..rows.len()).collect();
        let reach2 = i128::from(reach) * i128::from(reach);
        for k in 0..rows.len() {
            let (cx, cy) = cell(at(k));
            for dx in -1..=1 {
                for dy in -1..=1 {
                    let Some(near) = cells.get(&(cx + dx, cy + dy)) else {
                        continue;
                    };
                    for &j in near.iter().filter(|&&j| j > k) {
                        let (a, b) = (at(k), at(j));
                        let ddx = i128::from(a.x.raw() - b.x.raw());
                        let ddy = i128::from(a.y.raw() - b.y.raw());
                        if ddx * ddx + ddy * ddy <= reach2 {
                            let (ra, rb) = (root(&mut parent, k), root(&mut parent, j));
                            parent[ra.max(rb)] = ra.min(rb);
                        }
                    }
                }
            }
        }
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (k, &row) in rows.iter().enumerate() {
            let r = root(&mut parent, k);
            groups.entry(r).or_default().push(row);
        }
        for members in groups.into_values() {
            let fold = |pick: fn(i64, i64) -> i64, of: fn(Point) -> Dbu| {
                members
                    .iter()
                    .map(|&row| of(violations.at[row]).raw())
                    .reduce(pick)
                    .expect("a cluster has a member")
            };
            out.push(Cluster {
                rule,
                lo: Point {
                    x: Dbu::new_unchecked(fold(i64::min, |p| p.x)),
                    y: Dbu::new_unchecked(fold(i64::min, |p| p.y)),
                },
                hi: Point {
                    x: Dbu::new_unchecked(fold(i64::max, |p| p.x)),
                    y: Dbu::new_unchecked(fold(i64::max, |p| p.y)),
                },
                rows: members,
            });
        }
    }
    out.sort_by_key(|c| {
        (
            std::cmp::Reverse(c.rows.len()),
            c.rule,
            c.lo.x.raw(),
            c.lo.y.raw(),
        )
    });
    out
}

/// The union-find root of `k`, halving the path.
fn root(parent: &mut [usize], mut k: usize) -> usize {
    while parent[k] != k {
        parent[k] = parent[parent[k]];
        k = parent[k];
    }
    k
}

#[cfg(test)]
mod tests {
    use super::cluster;
    use gpurify_check::report::{Measurement, Severity, Violation, Violations};
    use gpurify_geom::{ops::Point, Dbu, LayerId, PolyId, StrId};

    fn table(rows: &[(u32, i64, i64)]) -> Violations {
        let mut out = Violations::default();
        for &(rule, x, y) in rows {
            out.push(Violation {
                rule: StrId(rule),
                layer: LayerId(0),
                severity: Severity::Error,
                at: Point {
                    x: Dbu::new_unchecked(x),
                    y: Dbu::new_unchecked(y),
                },
                measured: Measurement::Count(0),
                limit: Measurement::Count(1),
                shapes: (PolyId(0), None),
            });
        }
        out
    }

    /// Oracle: hand-derived single linkage at reach 10: a chain 0–8–16 is
    /// one cluster though its ends are 16 apart; a marker 11 away stays
    /// alone; another rule's marker on the chain is its own cluster; the
    /// largest comes first.
    #[test]
    fn a_chain_links_and_a_far_marker_stays_alone() {
        let v = table(&[(1, 0, 0), (1, 8, 0), (1, 16, 0), (1, 27, 0), (2, 8, 0)]);
        let got = cluster(&v, Dbu::new_unchecked(10));
        let rows: Vec<Vec<usize>> = got.iter().map(|c| c.rows.clone()).collect();
        assert_eq!(rows, [vec![0, 1, 2], vec![3], vec![4]]);
        assert_eq!((got[0].lo.x.raw(), got[0].hi.x.raw()), (0, 16));
    }

    /// Proves catalog FLOW-010.
    ///
    /// Oracle: naive reference: on 40 seeded tables, the clusters are the
    /// connected components of the "same rule and at most reach apart"
    /// graph, found by a brute-force flood fill over all pairs.
    #[test]
    fn clusters_match_a_brute_force_flood_fill() {
        for seed in 0..40 {
            let mut rng = gpurify_testgen::Rng::new(seed);
            let rows: Vec<(u32, i64, i64)> = (0..rng.range(1, 60))
                .map(|_| {
                    let rule = u32::try_from(rng.range(0, 3)).expect("small");
                    (rule, rng.range(-100, 100), rng.range(-100, 100))
                })
                .collect();
            let reach = rng.range(0, 30);
            let v = table(&rows);
            let mut got: Vec<Vec<usize>> = cluster(&v, Dbu::new_unchecked(reach))
                .into_iter()
                .map(|c| c.rows)
                .collect();
            got.sort();
            let near = |a: usize, b: usize| {
                let ((ra, xa, ya), (rb, xb, yb)) = (rows[a], rows[b]);
                ra == rb && (xa - xb).pow(2) + (ya - yb).pow(2) <= reach * reach
            };
            let mut seen = vec![false; rows.len()];
            let mut want = Vec::new();
            for start in 0..rows.len() {
                if seen[start] {
                    continue;
                }
                let (mut group, mut stack) = (Vec::new(), vec![start]);
                seen[start] = true;
                while let Some(a) = stack.pop() {
                    group.push(a);
                    for (b, done) in seen.iter_mut().enumerate() {
                        if !*done && near(a, b) {
                            *done = true;
                            stack.push(b);
                        }
                    }
                }
                group.sort_unstable();
                want.push(group);
            }
            want.sort();
            assert_eq!(got, want, "seed {seed}");
        }
    }
}
