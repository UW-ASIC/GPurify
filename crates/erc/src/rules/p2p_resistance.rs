//! Point-to-point resistance: for each net with device terminals, estimate total
//! wire resistance using PEX and flag if R exceeds a threshold.
//! Limit comes from deck.erc.p2p_r_limit_ohm; real signoff would use per-net targets.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;
use crate::pex::run_pex_by_net;

pub struct PointToPointResistanceCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for PointToPointResistanceCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "p2p_resistance" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, deck, ext) = (ctx.store, ctx.deck, ctx.ext);
        let mut out = Vec::new();
        // Device terminal nets
        let mut device_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            device_nets.insert(d.gate);
            device_nets.insert(d.source);
            device_nets.insert(d.drain);
        }

        // Device-intrinsic resistance is a device property, not interconnect:
        // mask recognized MOS gate polys (a gate_layer poly overlapping a
        // channel_layer poly) out of the accumulation so a transistor's own
        // channel squares don't swamp the wire budget.
        // ponytail: whole-poly exclusion on bbox overlap — a gate poly's
        // routing tail is under-counted; split at the channel boundary if
        // that matters.
        let mut masked = ext.net_of_poly.to_vec();
        for rule in &deck.devices.mos_rules {
            let channels: Vec<Bbox> = store
                .polys_on_layer(rule.channel_layer)
                .map(|p| store.poly_bbox[p.0 as usize])
                .collect();
            if channels.is_empty() { continue; }
            for g in store.polys_on_layer(rule.gate_layer) {
                let gb = store.poly_bbox[g.0 as usize];
                if channels.iter().any(|cb| gb.overlaps(cb)) {
                    masked[g.0 as usize] = u32::MAX;
                }
            }
        }

        let by_net = run_pex_by_net(store, deck, &masked);

        for (&net, par) in &by_net {
            if net == u32::MAX || !device_nets.contains(&net) { continue; }
            if par.r_ohm > deck.erc.p2p_r_limit_ohm {
                let pos = ext.net_of_poly.iter().enumerate()
                    .find(|(_, &n)| n == net)
                    .map(|(i, _)| store.poly_bbox[i])
                    .unwrap_or(Bbox::empty());
                out.push(ErcViolation {
                    check: "p2p_resistance".into(),
                    detail: format!("net {} R={:.1} ohm exceeds limit", net, par.r_ohm),
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
}
