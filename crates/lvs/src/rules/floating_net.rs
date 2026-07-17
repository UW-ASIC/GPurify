//! Non-fatal check: every floating net in the extracted netlist is recorded
//! as a finding. Runs first, before the device-count fast-fails.

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::Mismatch;
use crate::LvsCtx;
use crate::rule::Rule;

pub struct FloatingNetRule;

impl<'a> Rule<LvsCtx<'a>> for FloatingNetRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "floating_net" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        ctx.extracted
            .floating_nets
            .iter()
            .map(|fnet| Mismatch::FloatingNet { net_id: fnet.net_id, label: fnet.label.clone() })
            .collect()
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(FloatingNetRule));
