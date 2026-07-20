//! Unconnected pin: metal polygon not connected to any device terminal.

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};

pub struct UnconnectedPinCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for UnconnectedPinCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "unconnected_pin" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let mut out = Vec::new();
        let metal_layers: Vec<_> = ["met1", "met2"].iter()
            .filter_map(|n| lt.id(n)).collect();

        // Nets used by devices (MOS + BJT + two-terminal)
        let device_nets = crate::device_connected_nets(ext);

        for &ml in &metal_layers {
            for mp in store.polys_on_layer(ml) {
                let net = ext.net_of_poly[mp.0 as usize];
                if net == u32::MAX || !device_nets.contains(&net) {
                    let bb = store.poly_bbox[mp.0 as usize];
                    out.push(ErcViolation {
                        check: "unconnected_pin".into(),
                        detail: format!("metal on {} not connected to any device", lt.name(ml)),
                        x: bb.xmin, y: bb.ymin,
                    });
                }
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(UnconnectedPinCheck)))
}
pub static FACTORY: super::Factory = factory;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::GeometryStore;
    use crate::lvs::{
        BjtDevice, DeviceKind, ExtractedNetlist, TwoTerminalDevice, TwoTerminalKind,
    };
    use crate::params::Deck;
    use crate::rule::Rule;
    use crate::SignoffConfig;
    use std::collections::HashMap;

    fn met1_deck() -> Deck {
        Deck::from_json(
            r#"{
            "layers": {"met1": {"layer": 1, "datatype": 0}},
            "drc": {},
            "pex": {}
        }"#,
        )
        .unwrap()
    }

    // Store with one met1 rect per entry of `net_of_poly`.
    fn metal_store(deck: &Deck, nets: &[u32]) -> GeometryStore {
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        for (i, _) in nets.iter().enumerate() {
            st.add_rect(met1, i as i32 * 300, 0, 100, 100);
        }
        st
    }

    fn ext(net_of_poly: Vec<u32>) -> ExtractedNetlist {
        ExtractedNetlist {
            devices: Vec::new(),
            bjt_devices: Vec::new(),
            net_count: net_of_poly.len(),
            used_nets: 0,
            net_of_poly,
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        }
    }

    fn run(store: &GeometryStore, deck: &Deck, ext: &ExtractedNetlist) -> Vec<ErcViolation> {
        let ctx = ErcCtx {
            store,
            deck,
            ext,
            config: &SignoffConfig::default(),
            power: None,
        };
        UnconnectedPinCheck.check(&ctx, Backend::Cpu)
    }

    #[test]
    fn bjt_terminal_nets_not_flagged() {
        let deck = met1_deck();
        let nets = [0, 1, 2]; // C, B, E routing
        let st = metal_store(&deck, &nets);
        let mut e = ext(nets.to_vec());
        e.bjt_devices.push(BjtDevice {
            kind: DeviceKind::Npn,
            collector: 0,
            base: 1,
            emitter: 2,
            name: "npn".into(),
        });
        assert!(run(&st, &deck, &e).is_empty(), "BJT nets are device nets");
    }

    #[test]
    fn resistor_terminal_nets_not_flagged() {
        let deck = met1_deck();
        let nets = [0, 1];
        let st = metal_store(&deck, &nets);
        let mut e = ext(nets.to_vec());
        e.two_terminal.push(TwoTerminalDevice {
            kind: TwoTerminalKind::Resistor,
            name: "r1".into(),
            terminal_a: 0,
            terminal_b: 1,
            value: 100.0,
        });
        assert!(
            run(&st, &deck, &e).is_empty(),
            "resistor nets are device nets"
        );
    }

    #[test]
    fn deviceless_net_still_flagged() {
        let deck = met1_deck();
        let nets = [0];
        let st = metal_store(&deck, &nets);
        let e = ext(nets.to_vec());
        let v = run(&st, &deck, &e);
        assert_eq!(v.len(), 1, "floating metal must still be flagged");
        assert_eq!(v[0].check, "unconnected_pin");
    }
}
