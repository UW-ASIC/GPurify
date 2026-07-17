//! Fast-fail check: NMOS/PMOS device counts must match before any graph
//! refinement is attempted.

use crate::backend::Backend;
use crate::rules::Factory;
use crate::types::{DeviceKind, Mismatch};
use crate::LvsCtx;
use crate::rule::Rule;

pub struct DeviceCountMosRule;

impl<'a> Rule<LvsCtx<'a>> for DeviceCountMosRule {
    type Finding = Mismatch;
    fn id(&self) -> &str { "device_count_mos" }
    fn check(&self, ctx: &LvsCtx<'a>, _backend: Backend) -> Vec<Mismatch> {
        let ext_n = ctx.extracted.devices.iter().filter(|d| d.kind == DeviceKind::Nmos).count();
        let ext_p = ctx.extracted.devices.iter().filter(|d| d.kind == DeviceKind::Pmos).count();
        let ref_n = ctx.reference.devices.iter().filter(|d| d.kind == DeviceKind::Nmos).count();
        let ref_p = ctx.reference.devices.iter().filter(|d| d.kind == DeviceKind::Pmos).count();

        let mut findings = Vec::new();
        if ext_n != ref_n {
            findings.push(Mismatch::DeviceCount {
                kind: "Nmos".into(), extracted: ext_n, reference: ref_n,
            });
        }
        if ext_p != ref_p {
            findings.push(Mismatch::DeviceCount {
                kind: "Pmos".into(), extracted: ext_p, reference: ref_p,
            });
        }
        if !findings.is_empty() {
            ctx.fail(format!(
                "device count mismatch (ext {}N/{}P vs ref {}N/{}P)", ext_n, ext_p, ref_n, ref_p));
        }
        findings
    }
}

pub const FACTORY: Factory = |_opts| Some(Box::new(DeviceCountMosRule));
