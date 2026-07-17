//! Topology check: the refined device-class and net-class multisets must
//! agree between layout and reference. Two-terminal devices (R, C, diode)
//! are full graph participants, so this single multiset check covers them —
//! there is no separate two-terminal topology pass.
//!
//! Fails fatally on the first divergent class, device classes before net
//! classes, matching the old inline early-return.

use std::collections::{HashMap, HashSet};

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::Mismatch;
use crate::LvsCtx;
use crate::rule::Rule;

pub struct TopologyRule;

impl<'a> Rule<LvsCtx<'a>> for TopologyRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "topology" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        let r = ctx.refined.expect("topology rule runs post-refinement");

        // Device class multiset comparison
        let mut dev_buckets_a: HashMap<u32, usize> = HashMap::new();
        let mut dev_buckets_b: HashMap<u32, usize> = HashMap::new();
        for &c in &r.dev_cls_a { *dev_buckets_a.entry(c).or_default() += 1; }
        for &c in &r.dev_cls_b { *dev_buckets_b.entry(c).or_default() += 1; }
        let all_dev_cls: HashSet<u32> =
            dev_buckets_a.keys().chain(dev_buckets_b.keys()).copied().collect();
        for &c in &all_dev_cls {
            let ca = dev_buckets_a.get(&c).copied().unwrap_or(0);
            let cb = dev_buckets_b.get(&c).copied().unwrap_or(0);
            if ca != cb {
                let desc = format!(
                    "device class {} has {} in layout vs {} in reference", c, ca, cb);
                ctx.fail(format!("topology mismatch: {}", desc));
                return vec![Mismatch::TopologyMismatch { description: desc }];
            }
        }

        // Net class multiset comparison (skip floating nets)
        let mut net_buckets_a: HashMap<u32, usize> = HashMap::new();
        let mut net_buckets_b: HashMap<u32, usize> = HashMap::new();
        for &c in &r.net_cls_a { if c != u32::MAX { *net_buckets_a.entry(c).or_default() += 1; } }
        for &c in &r.net_cls_b { if c != u32::MAX { *net_buckets_b.entry(c).or_default() += 1; } }
        let all_net_cls: HashSet<u32> =
            net_buckets_a.keys().chain(net_buckets_b.keys()).copied().collect();
        for &c in &all_net_cls {
            let ca = net_buckets_a.get(&c).copied().unwrap_or(0);
            let cb = net_buckets_b.get(&c).copied().unwrap_or(0);
            if ca != cb {
                let desc = format!(
                    "net class {} has {} nets in layout vs {} in reference", c, ca, cb);
                ctx.fail(format!("topology mismatch: {}", desc));
                return vec![Mismatch::TopologyMismatch { description: desc }];
            }
        }

        Vec::new()
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(TopologyRule));
