//! Antenna CAR (cumulative, per fabrication stage).
//! During fab, metal-k is etched while only layers <= k exist. So the check runs
//! once per stack stage: connectivity is rebuilt with conductors up to layers[k]
//! (plus gate layers and any via whose endpoints are all present), and the
//! cumulative collecting area of layers[0..=k] on each gate's net is compared to
//! ratio × gate area. A shape on the diode layer connected to the net waives the
//! gate (junction leaks the charge off).
//! ponytail: connection = bbox overlap, matching extract's convention on the
//! rectangle geometry the suite uses; diffusion is NOT in the graph (poly-over-diff
//! is a gate, not a connection), so relief is explicit via the diode marker.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::Deck;
use super::super::{candidate_pairs, DrcCtx, Violation};

pub struct AntennaCarRule { pub id: String, pub layers: Vec<LayerId>, pub ratio: f64, pub diode: Option<LayerId> }

fn check_antenna_car(
    store: &GeometryStore, deck: &Deck, stack: &[LayerId], ratio: f64,
    diode: Option<LayerId>, rule_id: &str, out: &mut Vec<Violation>,
) {
    let lt = &deck.layers;
    // gate polys and their areas: gate_layer ∩ channel_layer per MOS rule
    let mut gates: Vec<(PolyId, i64)> = Vec::new(); // (gate poly, gate area)
    let mut gate_layers: Vec<LayerId> = Vec::new();
    for mr in &deck.devices.mos_rules {
        if !gate_layers.contains(&mr.gate_layer) { gate_layers.push(mr.gate_layer); }
        for g in store.polys_on_layer(mr.gate_layer) {
            let gb = store.poly_bbox[g.0 as usize];
            let mut area = 0i64;
            for d in store.polys_on_layer(mr.channel_layer) {
                let db = store.poly_bbox[d.0 as usize];
                let ix = gb.xmax.min(db.xmax) - gb.xmin.max(db.xmin);
                let iy = gb.ymax.min(db.ymax) - gb.ymin.max(db.ymin);
                if ix > 0 && iy > 0 { area += (ix as i64) * (iy as i64); }
            }
            if area > 0 && !gates.iter().any(|&(p, _)| p == g) { gates.push((g, area)); }
        }
    }
    if gates.is_empty() { return; }

    // worst cumulative ratio per gate poly across stages
    let mut worst: std::collections::HashMap<u32, f64> = std::collections::HashMap::new();

    for k in 0..stack.len() {
        // stage-active layers: gates + metals up to k + diode + vias fully present
        let metals = &stack[..=k];
        let mut active: Vec<LayerId> = gate_layers.clone();
        active.extend_from_slice(metals);
        if let Some(dl) = diode { active.push(dl); }
        // a via exists at this stage iff every layer it connects already exists
        for &(vl, ref connects) in &deck.connectivity.vias {
            if !active.contains(&vl) && connects.iter().all(|c| active.contains(c)) {
                active.push(vl);
            }
        }

        // union-find over active polys, connected on bbox overlap
        let polys: Vec<PolyId> = active.iter()
            .flat_map(|&l| store.polys_on_layer(l)).collect();
        let idx: std::collections::HashMap<u32, usize> =
            polys.iter().enumerate().map(|(i, p)| (p.0, i)).collect();
        let mut parent: Vec<usize> = (0..polys.len()).collect();
        fn find(parent: &mut Vec<usize>, i: usize) -> usize {
            let mut r = i;
            while parent[r] != r { r = parent[r]; }
            let mut c = i;
            while parent[c] != r { let n = parent[c]; parent[c] = r; c = n; }
            r
        }
        for (pa, pb) in candidate_pairs(store, &polys, None, 0) {
            let ba = store.poly_bbox[pa.0 as usize];
            let bb = store.poly_bbox[pb.0 as usize];
            if ba.overlaps(&bb) {
                let (ra, rb) = (find(&mut parent, idx[&pa.0]), find(&mut parent, idx[&pb.0]));
                if ra != rb { parent[ra] = rb; }
            }
        }

        // per-component: cumulative metal area + diode presence
        let mut metal_area: std::collections::HashMap<usize, i64> = std::collections::HashMap::new();
        let mut relieved: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &p in &polys {
            let root = find(&mut parent, idx[&p.0]);
            let l = store.poly_layer[p.0 as usize];
            if metals.contains(&l) {
                *metal_area.entry(root).or_insert(0) += store.area(p);
            }
            if diode == Some(l) { relieved.insert(root); }
        }

        for &(g, ga) in &gates {
            if !idx.contains_key(&g.0) { continue; }
            let root = find(&mut parent, idx[&g.0]);
            if relieved.contains(&root) { continue; }
            let ma = *metal_area.get(&root).unwrap_or(&0);
            let r = ma as f64 / ga as f64;
            let w = worst.entry(g.0).or_insert(0.0);
            if r > *w { *w = r; }
        }
    }

    for (&g, &r) in &worst {
        if r > ratio {
            let bb = store.poly_bbox[g as usize];
            out.push(Violation {
                rule_id: rule_id.into(), kind: "antenna_car".into(),
                layer: lt.name(stack[stack.len() - 1]).into(),
                measured: (r * 1000.0) as i64,
                limit: (ratio * 1000.0) as i64,
                x: bb.xmin, y: bb.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for AntennaCarRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_antenna_car(ctx.store, ctx.deck, &self.layers, self.ratio, self.diode, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::AntennaCar { id, layers, ratio, diode } =>
            Some(Box::new(AntennaCarRule { id: id.clone(), layers: layers.clone(), ratio: *ratio, diode: *diode })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
