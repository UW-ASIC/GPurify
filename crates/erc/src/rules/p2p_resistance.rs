//! Point-to-point resistance: for each net with device terminals, solve the
//! effective resistance of the net's polygon resistor graph between device
//! attach points and flag the WORST pair when it exceeds the threshold.
//! Limit comes from deck.erc.p2p_r_limit_ohm; real signoff would use per-net targets.
//!
//! Model: each polygon is a 1-D resistor along its long bbox axis (total R
//! from its PEX sheet squares / via_res_ohm), tapped with a sub-node at each
//! connection position — overlaps with same-net polygons, MOS gate attach
//! points, and the polygon's own endpoints. Adjacent taps are chained with
//! the proportional share of the polygon's R; polygon-polygon and
//! attach-point contacts are ~0 ohm. Effective resistance on this network is
//! Rayleigh-monotone: added parallel metal can only reduce the reported
//! value — unlike the old sum-of-squares proxy, which grew when straps were
//! added.
//! ponytail: 1-D taps at overlap centers, no 2-D current spreading; move to
//! real region splitting if L-shaped high-R routes need per-corner accuracy.

use std::collections::BTreeMap;

use crate::backend::Backend;
use crate::geometry::Bbox;
use crate::pex::run_pex_by_net;
use crate::{ErcCtx, ErcViolation};

pub struct PointToPointResistanceCheck;

/// Worst-pair effective resistance on a resistor graph.
/// `edges` are `(a, b, ohm)`; parallel edges add conductance. Pairs are taken
/// over `terminal` nodes within each connected component (a terminal pair
/// split across components has no interconnect path — e.g. joined only
/// through an excluded device poly — and is skipped).
/// ponytail: dense Gauss-Jordan on the reduced Laplacian, O(m^3) per
/// component — nets are tens-to-hundreds of polys; go sparse/CG if that grows.
fn worst_pair_r(n: usize, edges: &[(usize, usize, f64)], terminal: &[bool]) -> f64 {
    if n < 2 {
        return 0.0;
    }
    let mut cond = vec![vec![0.0f64; n]; n];
    for &(a, b, ohm) in edges {
        let g = 1.0 / ohm.max(1e-9);
        cond[a][b] += g;
        cond[b][a] += g;
    }
    // Connected components (DFS over the conductance matrix).
    let mut comp = vec![usize::MAX; n];
    let mut ncomp = 0;
    for s in 0..n {
        if comp[s] != usize::MAX {
            continue;
        }
        comp[s] = ncomp;
        let mut stack = vec![s];
        while let Some(u) = stack.pop() {
            for v in 0..n {
                if cond[u][v] > 0.0 && comp[v] == usize::MAX {
                    comp[v] = ncomp;
                    stack.push(v);
                }
            }
        }
        ncomp += 1;
    }
    let mut worst = 0.0f64;
    for c in 0..ncomp {
        let members: Vec<usize> = (0..n).filter(|&i| comp[i] == c).collect();
        let terms: Vec<usize> = members.iter().copied().filter(|&i| terminal[i]).collect();
        if terms.len() < 2 {
            continue;
        }
        // Ground members[0]; invert the reduced Laplacian by Gauss-Jordan.
        // R_eff(i,j) = G_ii + G_jj - 2*G_ij, with the grounded node's G = 0.
        let m = members.len() - 1;
        let idx = |i: usize| members[1..].iter().position(|&x| x == i);
        let mut a = vec![vec![0.0f64; 2 * m]; m];
        for (ri, &i) in members[1..].iter().enumerate() {
            let mut diag = 0.0;
            for &j in &members {
                if j == i {
                    continue;
                }
                diag += cond[i][j];
                if let Some(cj) = idx(j) {
                    a[ri][cj] = -cond[i][j];
                }
            }
            a[ri][ri] = diag;
            a[ri][m + ri] = 1.0;
        }
        for col in 0..m {
            let mut piv = col;
            for r2 in col + 1..m {
                if a[r2][col].abs() > a[piv][col].abs() {
                    piv = r2;
                }
            }
            a.swap(col, piv);
            let p = a[col][col];
            if p.abs() < 1e-12 {
                continue; // singular row; components make this unreachable
            }
            for c2 in col..2 * m {
                a[col][c2] /= p;
            }
            for r2 in 0..m {
                if r2 == col {
                    continue;
                }
                let f = a[r2][col];
                if f != 0.0 {
                    for c2 in col..2 * m {
                        a[r2][c2] -= f * a[col][c2];
                    }
                }
            }
        }
        let ginv = |i: usize, j: usize| a[i][m + j];
        let reff = |i: usize, j: usize| match (idx(i), idx(j)) {
            (Some(x), Some(y)) => ginv(x, x) + ginv(y, y) - 2.0 * ginv(x, y),
            (None, Some(y)) => ginv(y, y),
            (Some(x), None) => ginv(x, x),
            (None, None) => 0.0,
        };
        for x in 0..terms.len() {
            for y in x + 1..terms.len() {
                worst = worst.max(reff(terms[x], terms[y]));
            }
        }
    }
    worst
}

impl<'a> crate::rule::Rule<ErcCtx<'a>> for PointToPointResistanceCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "p2p_resistance" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, deck, ext) = (ctx.store, ctx.deck, ctx.ext);
        let mut out = Vec::new();
        let device_nets = crate::device_connected_nets(ext);
        let n = ext.net_of_poly.len();
        if n == 0 {
            return out;
        }

        // Per-poly resistance from the analytical PEX: give every polygon its
        // own net id so the per-net aggregation returns per-poly r_ohm (sheet
        // squares or via_res_ohm) through the existing public API.
        let identity: Vec<u32> = (0..n as u32).collect();
        let per_poly = run_pex_by_net(store, deck, &identity);
        let r_of = |p: usize| per_poly.get(&(p as u32)).map_or(0.0, |x| x.r_ohm);

        // Device-intrinsic resistance is a device property, not interconnect:
        // recognized MOS gate polys (gate_layer poly overlapping a
        // channel_layer poly) are excluded as graph nodes; their bboxes stay
        // as terminal attach points.
        // ponytail: whole-poly exclusion on bbox overlap — a gate poly's
        // routing tail is under-counted; split at the channel boundary if
        // that matters.
        let mut gate_mask = vec![false; n];
        let mut attach: Vec<Bbox> = Vec::new();
        for rule in &deck.devices.mos_rules {
            let channels: Vec<Bbox> = store
                .polys_on_layer(rule.channel_layer)
                .map(|p| store.poly_bbox[p.0 as usize])
                .collect();
            if channels.is_empty() { continue; }
            for g in store.polys_on_layer(rule.gate_layer) {
                let gb = store.poly_bbox[g.0 as usize];
                if channels.iter().any(|cb| gb.overlaps(cb)) {
                    gate_mask[g.0 as usize] = true;
                    attach.push(gb);
                }
            }
        }

        // Interconnect nodes per device net (BTreeMap: deterministic output).
        let mut nets: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (i, &nid) in ext.net_of_poly.iter().enumerate() {
            if nid != u32::MAX && device_nets.contains(&nid) && !gate_mask[i] {
                nets.entry(nid).or_default().push(i);
            }
        }

        for (&net, polys) in &nets {
            let base = polys.len();
            let bbs: Vec<Bbox> = polys.iter().map(|&p| store.poly_bbox[p]).collect();
            let rs: Vec<f64> = polys.iter().map(|&p| r_of(p)).collect();
            let axis_x: Vec<bool> = bbs
                .iter()
                .map(|b| (b.xmax - b.xmin) >= (b.ymax - b.ymin))
                .collect();
            // Center of the overlap with `o`, projected on poly i's long axis.
            let pos_of = |i: usize, o: &Bbox| -> i64 {
                let (a, b) = if axis_x[i] {
                    (o.xmin.max(bbs[i].xmin), o.xmax.min(bbs[i].xmax))
                } else {
                    (o.ymin.max(bbs[i].ymin), o.ymax.min(bbs[i].ymax))
                };
                (i64::from(a) + i64::from(b)) / 2
            };
            let ends = |i: usize| -> (i64, i64) {
                if axis_x[i] {
                    (i64::from(bbs[i].xmin), i64::from(bbs[i].xmax))
                } else {
                    (i64::from(bbs[i].ymin), i64::from(bbs[i].ymax))
                }
            };

            // Connections: same-net polygon overlaps, and gate attach points.
            let mut cross: Vec<(usize, i64, usize, i64)> = Vec::new();
            for i in 0..base {
                for j in i + 1..base {
                    if bbs[i].overlaps(&bbs[j]) {
                        cross.push((i, pos_of(i, &bbs[j]), j, pos_of(j, &bbs[i])));
                    }
                }
            }
            let mut attach_conns: Vec<(usize, usize, i64)> = Vec::new();
            for (ai, ab) in attach.iter().enumerate() {
                for i in 0..base {
                    if bbs[i].overlaps(ab) {
                        attach_conns.push((ai, i, pos_of(i, ab)));
                    }
                }
            }

            // Tap sub-nodes per poly: endpoints + every connection position.
            let mut taps: Vec<Vec<i64>> = (0..base)
                .map(|i| {
                    let (lo, hi) = ends(i);
                    vec![lo, hi]
                })
                .collect();
            for &(i, pi, j, pj) in &cross {
                taps[i].push(pi);
                taps[j].push(pj);
            }
            for &(_, i, p) in &attach_conns {
                taps[i].push(p);
            }
            let mut id_of: Vec<std::collections::HashMap<i64, usize>> = Vec::with_capacity(base);
            let mut nn = 0usize;
            let mut edges: Vec<(usize, usize, f64)> = Vec::new();
            for i in 0..base {
                taps[i].sort_unstable();
                taps[i].dedup();
                let mut ids = std::collections::HashMap::new();
                for &p in &taps[i] {
                    ids.insert(p, nn);
                    nn += 1;
                }
                let (lo, hi) = ends(i);
                let len = (hi - lo).max(1) as f64;
                for w in taps[i].windows(2) {
                    edges.push((ids[&w[0]], ids[&w[1]], rs[i] * (w[1] - w[0]) as f64 / len));
                }
                id_of.push(ids);
            }
            let mut terminal = vec![false; nn];
            for &(i, pi, j, pj) in &cross {
                edges.push((id_of[i][&pi], id_of[j][&pj], 0.0)); // contact
            }
            // One virtual terminal node per gate attach point on this net.
            let mut term_of_attach: std::collections::HashMap<usize, usize> =
                std::collections::HashMap::new();
            for &(ai, i, p) in &attach_conns {
                let t = *term_of_attach.entry(ai).or_insert_with(|| {
                    terminal.push(true);
                    nn += 1;
                    nn - 1
                });
                edges.push((t, id_of[i][&p], 0.0));
            }
            if term_of_attach.len() < 2 {
                // ponytail: BJT/two-terminal attach polys aren't identified;
                // fall back to worst pair over all taps — including polygon
                // far ends — pessimistic, but still Rayleigh-monotone.
                for t in terminal.iter_mut().take(nn - term_of_attach.len()) {
                    *t = true;
                }
            }
            let r = worst_pair_r(nn, &edges, &terminal);
            if r > deck.erc.p2p_r_limit_ohm {
                let pos = polys.first().map(|&p| store.poly_bbox[p]).unwrap_or(Bbox::empty());
                out.push(ErcViolation {
                    check: "p2p_resistance".into(),
                    detail: format!("net {} R={:.1} ohm exceeds limit", net, r),
                    x: pos.xmin, y: pos.ymin,
                });
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(PointToPointResistanceCheck)))
}
pub static FACTORY: super::Factory = factory;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::GeometryStore;
    use crate::lvs::extract_netlist;
    use crate::params::Deck;
    use crate::rule::Rule;
    use crate::SignoffConfig;

    // poly: 48.2 ohm/sq (a 2x164 um gate bar alone is ~3950 ohm), met1 cheap,
    // p2p limit 500 ohm.
    fn p2p_deck() -> Deck {
        Deck::from_json(
            r#"{
            "layers": {
                "diff": {"layer": 1, "datatype": 0},
                "poly": {"layer": 2, "datatype": 0},
                "nsdm": {"layer": 3, "datatype": 0},
                "met1": {"layer": 4, "datatype": 0}
            },
            "drc": {},
            "pex": {
                "poly": {
                    "sheet_res_ohm_sq": 48.2,
                    "area_cap_af_um2": 0.0,
                    "fringe_cap_af_um": 0.0,
                    "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 0.0
                },
                "met1": {
                    "sheet_res_ohm_sq": 0.1,
                    "area_cap_af_um2": 0.0,
                    "fringe_cap_af_um": 0.0,
                    "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 0.0
                }
            },
            "connectivity": {"conductors": ["diff", "poly", "met1"]},
            "device_recognition": {
                "mos": [{
                    "name": "nmos",
                    "gate_layer": "poly",
                    "channel_layer": "diff",
                    "type_implant": "nsdm",
                    "device_type": "nmos"
                }]
            },
            "erc": {"p2p_r_limit_ohm": 500.0}
        }"#,
        )
        .unwrap()
    }

    fn run_check(store: &GeometryStore, deck: &Deck) -> Vec<ErcViolation> {
        let ext = extract_netlist(store, deck).unwrap();
        let ctx = ErcCtx {
            store,
            deck,
            ext: &ext,
            config: &SignoffConfig::default(),
            power: None,
        };
        PointToPointResistanceCheck.check(&ctx, Backend::Cpu)
    }

    #[test]
    fn device_gate_poly_excluded_from_net_resistance() {
        let deck = p2p_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        // 160 um tall transistor: the 2x168 um gate bar alone is ~4050 ohm.
        st.add_rect(diff, 0, 0, 4000, 160_000);
        st.add_rect(nsdm, -1000, -1000, 6000, 162_000);
        st.add_rect(poly, 1000, -4000, 2000, 168_000);
        // Thin met1 interconnect on the gate net: 5 squares at 0.1 ohm/sq.
        st.add_rect(met1, 0, -4000, 10_000, 2000);

        let v = run_check(&st, &deck);
        assert!(
            v.is_empty(),
            "gate poly is device-intrinsic, net R must be interconnect only: {v:?}"
        );
    }

    #[test]
    fn plain_poly_routing_still_counts() {
        let deck = p2p_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        let mut st = GeometryStore::new();
        // Small transistor (gate bar ~3 squares, masked either way)...
        st.add_rect(diff, 0, 0, 4000, 4000);
        st.add_rect(nsdm, -1000, -1000, 6000, 6000);
        st.add_rect(poly, 1000, -1000, 2000, 6000);
        // ...plus a 2x200 um poly ROUTING strip (no channel overlap) on the
        // gate net: 100 squares -> ~4820 ohm, over the 500 ohm limit.
        st.add_rect(poly, 1000, 4900, 2000, 200_000);

        let v = run_check(&st, &deck);
        assert_eq!(v.len(), 1, "poly routing must still count: {v:?}");
        assert_eq!(v[0].check, "p2p_resistance");
    }

    // --- solver-level tests ---

    #[test]
    fn chain_resistance_matches_squares() {
        // 4-node chain of 1-ohm links: end-to-end R = 3.
        let edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0)];
        let term = [true, false, false, true];
        let r = worst_pair_r(4, &edges, &term);
        assert!((r - 3.0).abs() < 1e-9, "chain R {r} != 3");
    }

    #[test]
    fn parallel_edge_reduces_resistance() {
        let edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0)];
        let term = [true, false, false, true];
        let base = worst_pair_r(4, &edges, &term);
        // Add a 3-ohm strap directly across the terminals: 3 || 3 = 1.5.
        let strapped = [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (0, 3, 3.0)];
        let r = worst_pair_r(4, &strapped, &term);
        assert!(r < base, "parallel strap must reduce R: {r} vs {base}");
        assert!((r - 1.5).abs() < 1e-9, "3||3 must be 1.5, got {r}");
    }

    #[test]
    fn worst_terminal_pair_selected() {
        // Star with unbalanced arms 1/3/6 ohm off hub node 0; terminals are
        // the three leaves. Worst pair is (arm3, arm6) = 9 ohm.
        let edges = [(0, 1, 1.0), (0, 2, 3.0), (0, 3, 6.0)];
        let term = [false, true, true, true];
        let r = worst_pair_r(4, &edges, &term);
        assert!((r - 9.0).abs() < 1e-9, "worst pair must be 3+6=9, got {r}");
    }

    // --- the regression that motivated the rework ---

    #[test]
    fn parallel_strap_reduces_reported_net_resistance() {
        let deck = p2p_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        let met1 = deck.layers.id("met1").unwrap();

        // Two transistors 300 um apart, gates joined by a 2x302 um poly strip
        // (151 squares at 48.2 -> ~7278 ohm).
        let build = |with_strap: bool| {
            let mut st = GeometryStore::new();
            st.add_rect(diff, 0, 0, 4000, 4000);
            st.add_rect(poly, 1000, -1000, 2000, 6000);
            st.add_rect(diff, 300_000, 0, 4000, 4000);
            st.add_rect(poly, 301_000, -1000, 2000, 6000);
            st.add_rect(nsdm, -1000, -1000, 306_000, 6000);
            st.add_rect(poly, 1000, 4900, 302_000, 2000);
            if with_strap {
                // met1 strap in parallel over the strip: ~15 ohm.
                st.add_rect(met1, 1000, 4900, 302_000, 2000);
            }
            st
        };

        let v = run_check(&build(false), &deck);
        assert_eq!(v.len(), 1, "poly-only gate route must violate: {v:?}");
        // Squares sanity: attach centers sit 300 um apart on the 2 um strip,
        // so the reported R is ~150 squares of poly sheet (within the PEX
        // equivalent-dimension rounding).
        let reported: f64 = v[0]
            .detail
            .split("R=")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let expect = 48.2 * 150.0;
        assert!(
            (reported / expect - 1.0).abs() < 0.01,
            "reported R {reported} not within 1% of {expect}: '{}'",
            v[0].detail
        );

        let v = run_check(&build(true), &deck);
        assert!(
            v.is_empty(),
            "parallel met1 strap must REDUCE reported R below the limit: {v:?}"
        );
    }
}
