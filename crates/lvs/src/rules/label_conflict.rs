//! Non-fatal check: every net-label conflict found during extraction is
//! recorded as a finding.

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::Mismatch;
use crate::LvsCtx;
use crate::rule::Rule;

pub struct LabelConflictRule;

impl<'a> Rule<LvsCtx<'a>> for LabelConflictRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "label_conflict" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        ctx.extracted
            .label_conflicts
            .iter()
            .map(|conflict| Mismatch::LabelConflict { net_id: 0, labels: vec![conflict.clone()] })
            .collect()
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(LabelConflictRule));
