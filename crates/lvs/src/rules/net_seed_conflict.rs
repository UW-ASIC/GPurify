//! Net seed conflict check: two seeded reference nets (e.g. VDD and VSS)
//! landing in the same refined class means the layout cannot tell them apart
//! — the classic supply-swap escape.

use std::collections::HashMap;

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::Mismatch;
use crate::LvsCtx;
use crate::rule::Rule;

pub struct NetSeedConflictRule;

impl<'a> Rule<LvsCtx<'a>> for NetSeedConflictRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "net_seed_conflict" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        let r = ctx.refined.expect("net seed conflict rule runs post-refinement");
        if ctx.reference.net_seeds.is_empty() {
            return Vec::new();
        }
        let mut seed_class_to_names: HashMap<u32, Vec<&str>> = HashMap::new();
        for (net_name, _) in &ctx.reference.net_seeds {
            if let Some(&local_id) = r.ref_net_remap.get(net_name) {
                let c = r.net_cls_b[local_id as usize];
                if c != u32::MAX {
                    seed_class_to_names.entry(c).or_default().push(net_name.as_str());
                }
            }
        }
        for (_, names) in &seed_class_to_names {
            if names.len() > 1 {
                let nets: Vec<String> = names.iter().map(|s| s.to_string()).collect();
                ctx.fail(format!("net seed conflict: {} are isomorphic", names.join(" and ")));
                return vec![Mismatch::NetSeedConflict { nets }];
            }
        }
        Vec::new()
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(NetSeedConflictRule));
